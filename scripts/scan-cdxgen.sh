#!/usr/bin/env bash
# Runs cdxgen for comparison against the Sonar CBOM.
#
# cdxgen's --include-crypto does real constant propagation for JavaScript/TypeScript and calls
# dosai for .NET. For Java it maps algorithm keywords to OIDs, so treat its output as a baseline
# showing what keyword matching can and cannot recover.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p out out/work

echo "==> cdxgen (dependency SBOM + keyword-derived crypto assets)"
npx --yes @cyclonedx/cdxgen@latest \
	-t java --include-crypto --evidence \
	--spec-version 1.6 --json-pretty \
	-o out/cbom-cdxgen.json . > out/work/cdxgen.log 2>&1 || {
		echo "cdxgen failed; see out/work/cdxgen.log" >&2
		exit 1
	}

# cdxgen drops its atom slices and the evidence .map file next to the BOM. They are large
# intermediates, not results, so they are swept into out/work/ where git ignores them.
for f in out/cbom-cdxgen.json.map out/java-app.atom out/java-*.slices*.json; do
	[ -e "$f" ] && mv "$f" out/work/
done

python3 - <<'PY'
import json
bom = json.load(open("out/cbom-cdxgen.json"))
comps = bom.get("components", [])
assets = [c for c in comps if c.get("type") == "cryptographic-asset"]
print(f"   {len(comps)} components total, {len(assets)} cryptographic assets")
for a in assets:
    cp = a.get("cryptoProperties", {})
    print(f"   - {a['name']:<12} oid={cp.get('oid','-'):<28} "
          f"primitive={cp.get('algorithmProperties',{}).get('primitive','-')} "
          f"occurrences={len(a.get('evidence',{}).get('occurrences',[]))}")
PY
