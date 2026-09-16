#!/usr/bin/env bash
# Runs cbomkit-theia over the working tree.
#
# theia scans the filesystem rather than the source: it finds X.509 certificates, keys, secrets,
# the java.security policy and OpenSSL config. That is the half of the CBOM a source scanner
# structurally cannot produce, so run CbomDemoRunner first to lay down target/demo-pki.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p out out/work

if [ ! -d target/demo-pki ]; then
	echo "==> Generating demo PKI material (target/demo-pki)"
	mvn -q -B compile exec:java
fi

BIN="${THEIA_BIN:-}"
if [ -z "$BIN" ]; then
	# Kept outside the repo: theia scans the whole directory tree, and its own test fixtures
	# would otherwise show up as certificates and leaked secrets belonging to this project.
	work="${THEIA_DIR:-${TMPDIR:-/tmp}/cbomkit-theia}"
	if [ ! -x "$work/cbomkit-theia" ]; then
		echo "==> Building cbomkit-theia (needs Go)"
		rm -rf "$work"
		git clone --depth 1 https://github.com/cbomkit/cbomkit-theia.git "$work"
		# go.sum in the repo is incomplete for some transitive deps.
		(cd "$work" && go mod tidy && go build -o cbomkit-theia .)
	fi
	BIN="$work/cbomkit-theia"
fi

# All plugins: certificates, javasecurity, secrets, opensslconf, keys, vex. The upstream README
# example only passes -p certificates, which leaves the key and java.security findings behind.
echo "==> cbomkit-theia (all plugins)"
"$BIN" dir "$ROOT" > out/cbom-theia.json 2> out/work/theia.log || {
	echo "cbomkit-theia failed; see out/work/theia.log" >&2
	exit 1
}

python3 - <<'PY'
import json
bom = json.load(open("out/cbom-theia.json"))
assets = [c for c in bom.get("components", []) if c.get("type") == "cryptographic-asset"]
by_type = {}
for a in assets:
    t = a["cryptoProperties"]["assetType"]
    by_type.setdefault(t, []).append(a["name"])
print(f"   {len(assets)} cryptographic assets")
for t, names in sorted(by_type.items()):
    print(f"   {t}: {', '.join(sorted(set(names)))}")
PY
