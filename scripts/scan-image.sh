#!/usr/bin/env bash
# Scans the container image — the layer neither the source scan nor the working-tree scan can see.
#
# Two outputs answering different questions:
#   out/sbom-image.json  cdxgen -> OS packages: openssl, libssl3, libcrypto.so.3, gnutls, p11-kit
#   out/cbom-image.json  theia  -> the system trust store, openssl.cnf, and the app's baked-in PKI
#
# Worth being precise about: openssl shows up as an operating-system *package*, not as a
# cryptographic-asset. A CBOM's crypto assets are algorithms, certificates, protocols and key
# material; openssl is the library that provides them. Both facts matter, in different sections.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p out out/work

IMAGE="${IMAGE:-cbom-demo:latest}"

if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
	echo "==> Building $IMAGE"
	docker build -t "$IMAGE" .
fi

# --- OS and application packages ---------------------------------------------
# cdxgen is handed an exported tar rather than the image name: when a containerd-based runtime
# (k3s, Rancher Desktop) is also installed, cdxgen picks its socket and cannot see images that
# live in the Docker daemon.
echo "==> Exporting $IMAGE"
docker save "$IMAGE" -o out/work/image.tar

echo "==> cdxgen (container: OS packages + application dependencies)"
npx --yes @cyclonedx/cdxgen@latest \
	-t docker --include-crypto \
	--spec-version 1.6 --json-pretty \
	-o out/sbom-image.json out/work/image.tar > out/work/cdxgen-image.log 2>&1 || {
		echo "cdxgen failed; see out/work/cdxgen-image.log" >&2
		exit 1
	}

python3 - <<'PY'
import json, collections, re
bom = json.load(open("out/sbom-image.json"))
comps = bom.get("components", [])
print("   " + ", ".join(f"{k}={v}" for k, v in
                        sorted(collections.Counter(c.get("type") for c in comps).items())))
# Only packages, so certificate names in the trust store do not masquerade as libraries.
pattern = re.compile(r"openssl|libssl|libcrypto|gnutls|nettle|gcrypt|k5crypto|p11-kit|ca-certificates")
libs = sorted({c["name"] for c in comps
               if c.get("type") == "library" and pattern.search(c["name"].lower())})
print(f"   crypto-providing OS packages ({len(libs)}):")
for name in libs:
    version = next((c.get("version", "?") for c in comps
                    if c.get("type") == "library" and c["name"] == name), "?")
    print(f"     {name} {version}")
PY

# --- Crypto assets inside the image ------------------------------------------
# The source CBOM is passed as --bom so theia's javasecurity plugin runs at all: without it the
# plugin disables itself. It verifies TLS cipher suites against the image's java.security policy,
# so it only reaches assets that carry cipher-suite detail.
echo "==> cbomkit-theia (image: trust store, openssl.cnf, java.security)"
BIN="${THEIA_BIN:-${TMPDIR:-/tmp}/cbomkit-theia/cbomkit-theia}"
if [ ! -x "$BIN" ]; then
	echo "cbomkit-theia is not built. Run ./scripts/scan-theia.sh first." >&2
	exit 1
fi

bom_flag=()
[ -f out/cbom-sonar.json ] && bom_flag=(--bom out/cbom-sonar.json)

"$BIN" image "$IMAGE" "${bom_flag[@]}" > out/cbom-image.json 2> out/work/theia-image.log || {
	echo "cbomkit-theia failed; see out/work/theia-image.log" >&2
	exit 1
}

python3 - <<'PY'
import json, collections
bom = json.load(open("out/cbom-image.json"))
assets = [c for c in bom.get("components", []) if c.get("type") == "cryptographic-asset"]
print("   " + ", ".join(f"{k}={v}" for k, v in sorted(
    collections.Counter(a["cryptoProperties"]["assetType"] for a in assets).items())))

certs = [a for a in assets if a["cryptoProperties"]["assetType"] == "certificate"]
app = [a for a in certs if any("/app/" in (o.get("location") or "")
                               for o in a.get("evidence", {}).get("occurrences", []))]
print(f"   certificates: {len(certs)} total, {len(app)} from the app's own PKI:")
for a in app:
    loc = a["evidence"]["occurrences"][0]["location"]
    print(f"     {a['name']} <- {loc}")
PY

grep -oE "OpenSSL config detected .*" out/work/theia-image.log | sed 's/^/   /' | sort -u

# What the java.security plugin actually concluded. The "affected by java.security file" lines
# mark every merged asset as in scope of the policy -- that is coverage, not a verdict. A real
# verdict needs cipher-suite detail, which the source CBOM does not carry.
if grep -q "java security check is automatically disabled" out/work/theia-image.log; then
	echo "   java.security: skipped (pass --bom out/cbom-sonar.json to enable it)"
else
	scoped="$(grep -c "affected by java.security file" out/work/theia-image.log || true)"
	blocked="$(grep -cE "not enough information \(cipherSuites\)" out/work/theia-image.log || true)"
	echo "   java.security: policy loaded, $scoped assets in scope, 0 verdicts"
	echo "   ($blocked protocol assets could not be verified: no cipherSuites in the source CBOM)"
fi

echo
echo "==> out/sbom-image.json (packages) and out/cbom-image.json (crypto assets)"
