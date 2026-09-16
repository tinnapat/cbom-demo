#!/usr/bin/env bash
# Prints one table comparing what each scanner found, so the difference between AST-based and
# keyword-based detection is a number rather than an opinion.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - <<'PY'
import json, os, collections

def load(path):
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        return json.load(handle)

def assets(bom):
    return [c for c in (bom.get("components") or []) if c.get("type") == "cryptographic-asset"]

def summarise(name, path):
    bom = load(path)
    if bom is None:
        return {"scanner": name, "missing": True}
    a = assets(bom)
    types = collections.Counter(x.get("cryptoProperties", {}).get("assetType", "?") for x in a)
    with_oid = sum(1 for x in a if x.get("cryptoProperties", {}).get("oid"))
    with_occ = sum(1 for x in a if x.get("evidence", {}).get("occurrences"))
    with_mode = sum(1 for x in a
                    if x.get("cryptoProperties", {}).get("algorithmProperties", {}).get("mode"))
    with_fn = sum(1 for x in a
                  if x.get("cryptoProperties", {}).get("algorithmProperties", {}).get("cryptoFunctions"))
    return {
        "scanner": name, "missing": False, "total": len(a), "types": types,
        "oid": with_oid, "occ": with_occ, "mode": with_mode, "fn": with_fn,
        "names": sorted({x["name"] for x in a}),
    }

rows = [
    summarise("sonar-cryptography (AST)", "out/cbom-sonar.json"),
    summarise("cdxgen (keyword)", "out/cbom-cdxgen.json"),
    summarise("cbomkit-theia (filesystem)", "out/cbom-theia.json"),
]

hdr = f"{'scanner':<28}{'assets':>7}{'with OID':>10}{'w/ source':>11}{'w/ mode':>9}{'w/ funcs':>10}"
print(hdr)
print("-" * len(hdr))
for r in rows:
    if r["missing"]:
        print(f"{r['scanner']:<28}{'not run':>7}")
        continue
    print(f"{r['scanner']:<28}{r['total']:>7}{r['oid']:>10}{r['occ']:>11}{r['mode']:>9}{r['fn']:>10}")

print("\nasset types per scanner")
for r in rows:
    if r["missing"]:
        continue
    detail = ", ".join(f"{k}={v}" for k, v in sorted(r["types"].items()))
    print(f"  {r['scanner']:<28}{detail}")

sonar, cdx, theia = rows
if not sonar["missing"] and not theia["missing"]:
    only_theia = sorted(set(theia["names"]) - set(sonar["names"]))
    print(f"\nfound only by cbomkit-theia ({len(only_theia)}): {', '.join(only_theia) or '-'}")
if not sonar["missing"] and not cdx["missing"]:
    only_cdx = sorted(set(cdx["names"]) - set(sonar["names"]))
    print(f"found only by cdxgen ({len(only_cdx)}): {', '.join(only_cdx) or '-'}")

report = "target/runtime-evidence.md"
if os.path.exists(report):
    ran = sum(1 for line in open(report) if line.startswith("| `") and "~~" not in line)
    print(f"\nruntime evidence: {ran} algorithm usages actually executed ({report})")
PY
