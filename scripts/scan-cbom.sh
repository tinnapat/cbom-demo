#!/usr/bin/env bash
# Runs the SonarQube analysis that produces the CBOM.
#
# The Java rules resolve types through the compiled classes, so the project is built first:
# without sonar.java.binaries the analyzer cannot tell org.bouncycastle.crypto.modes.GCMBlockCipher
# from any other symbol, and most detections silently disappear.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SONAR_URL="${SONAR_URL:-http://localhost:9000}"
PROJECT_KEY="${PROJECT_KEY:-cbom-demo}"
SCANNER_IMAGE="${SCANNER_IMAGE:-sonarsource/sonar-scanner-cli:11}"

if [ ! -f .sonarqube/token ]; then
	echo "No .sonarqube/token found. Run ./scripts/sonarqube-up.sh first." >&2
	exit 1
fi
token="$(cat .sonarqube/token)"

echo "==> Building (the analyzer needs target/classes and target/libs)"
mvn -q -B package -DskipTests

echo "==> Scanning"
# The scanner container reaches SonarQube over the compose network, and cbom.json lands in
# the mounted project directory.
docker run --rm \
	--network "$(docker compose ps --format '{{.Name}}' | head -1 | xargs -I{} docker inspect {} --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')" \
	-e SONAR_HOST_URL="http://cbom-sonarqube:9000" \
	-e SONAR_TOKEN="$token" \
	-v "$ROOT:/usr/src" \
	"$SCANNER_IMAGE" \
	-Dsonar.projectKey="$PROJECT_KEY" \
	-Dsonar.sources=src/main/java \
	-Dsonar.java.source=21 \
	-Dsonar.java.binaries=target/classes \
	-Dsonar.java.libraries='target/libs/*.jar' \
	-Dsonar.cryptoScanner.cbom=cbom \
	-Dsonar.scm.disabled=true

if [ ! -f cbom.json ]; then
	echo "No cbom.json was produced. Is the 'Cryptographic Inventory (CBOM)' rule active?" >&2
	exit 1
fi

mkdir -p out out/work
mv cbom.json out/cbom-sonar.json
echo
echo "==> CBOM written to out/cbom-sonar.json"
python3 - <<'PY'
import json
bom = json.load(open("out/cbom-sonar.json"))
assets = [c for c in bom.get("components", []) if c.get("type") == "cryptographic-asset"]
by_type = {}
for a in assets:
    by_type[a["cryptoProperties"]["assetType"]] = by_type.get(a["cryptoProperties"]["assetType"], 0) + 1
print(f"   spec {bom.get('specVersion')}, {len(assets)} cryptographic assets")
for k, v in sorted(by_type.items()):
    print(f"   {v:4d}  {k}")
PY
