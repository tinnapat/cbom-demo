#!/usr/bin/env bash
# Brings up SonarQube with the PQCA Sonar Cryptography plugin and prepares it for a CBOM scan:
# builds the plugin if it is missing, starts the stack, creates a quality profile that has the
# "Cryptographic Inventory (CBOM)" rule activated, and creates the project plus an analysis token.
#
# Writes the token to .sonarqube/token so scripts/scan-cbom.sh can pick it up.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SONAR_URL="${SONAR_URL:-http://localhost:9000}"
SONAR_ADMIN_USER="${SONAR_ADMIN_USER:-admin}"
SONAR_ADMIN_PASSWORD="${SONAR_ADMIN_PASSWORD:-admin}"
PROJECT_KEY="${PROJECT_KEY:-cbom-demo}"
PROFILE_NAME="${PROFILE_NAME:-cbom}"
PLUGIN_REPO="https://github.com/PQCA/sonar-cryptography.git"

api() {
	local method="$1" path="$2"; shift 2
	curl -sS -u "$SONAR_ADMIN_USER:$SONAR_ADMIN_PASSWORD" -X "$method" "$SONAR_URL$path" "$@"
}

# --- 1. Build the plugin -----------------------------------------------------
# The plugin is published only to GitHub Packages (which needs auth), so we build from source.
if ! compgen -G ".sonarqube/plugins/sonar-cryptography-plugin-*.jar" > /dev/null; then
	echo "==> Building the Sonar Cryptography plugin from source"
	mkdir -p .sonarqube/plugins
	work="$(mktemp -d)"
	git clone --depth 1 "$PLUGIN_REPO" "$work/sonar-cryptography"
	# spotless pins an older google-java-format that rejects newer JVMs; it is irrelevant here.
	(cd "$work/sonar-cryptography" && mvn -B -DskipTests -Dspotless.apply.skip=true -Dspotless.check.skip=true package)
	cp "$work/sonar-cryptography/sonar-cryptography-plugin/target/sonar-cryptography-plugin-"*.jar .sonarqube/plugins/
	rm -rf "$work"
fi
echo "==> Plugin: $(ls .sonarqube/plugins/)"

# --- 2. Start the stack ------------------------------------------------------
echo "==> Starting SonarQube"
docker compose up -d

printf '==> Waiting for SonarQube to become operational'
for _ in $(seq 1 80); do
	if [ "$(curl -sS "$SONAR_URL/api/system/status" 2>/dev/null | sed -n 's/.*"status":"\([A-Z]*\)".*/\1/p')" = "UP" ]; then
		echo " up"
		break
	fi
	printf '.'
	sleep 5
done

status="$(curl -sS "$SONAR_URL/api/system/status" | sed -n 's/.*"status":"\([A-Z]*\)".*/\1/p')"
if [ "$status" != "UP" ]; then
	echo "SonarQube did not start (status=$status). Check: docker compose logs sonarqube" >&2
	exit 1
fi

if ! api GET "/api/plugins/installed" | grep -q '"key":"crypto"'; then
	echo "The crypto plugin is not loaded. Check that .sonarqube/plugins is mounted." >&2
	exit 1
fi

# --- 3. Quality profile with the CBOM rule activated -------------------------
# Only the crypto rules are activated: this demo wants a CBOM, not a code-quality report.
echo "==> Configuring quality profile '$PROFILE_NAME'"
api POST "/api/qualityprofiles/create" -d "name=$PROFILE_NAME" -d "language=java" > /dev/null 2>&1 || true

# activate_rule wants the profile's internal key (a UUID), not "java:<name>".
profile_key="$(api GET "/api/qualityprofiles/search?language=java" \
	| python3 -c "import json,sys;print(next(p['key'] for p in json.load(sys.stdin)['profiles'] if p['name']=='$PROFILE_NAME'))")"

for rule in sonar-java-crypto:Inventory sonar-java-crypto:JavaNoMD5use; do
	api POST "/api/qualityprofiles/activate_rule" -d "key=$profile_key" -d "rule=$rule" -f > /dev/null
done
api POST "/api/qualityprofiles/set_default" -d "qualityProfile=$PROFILE_NAME" -d "language=java" > /dev/null

active="$(api GET "/api/rules/search?qprofile=$profile_key&activation=true" \
	| python3 -c "import json,sys;print(json.load(sys.stdin)['total'])")"
echo "==> Crypto rules active in profile '$PROFILE_NAME': $active"
if [ "$active" -lt 1 ]; then
	echo "The Cryptographic Inventory rule is not active; no CBOM would be written." >&2
	exit 1
fi

# --- 4. Project and analysis token -------------------------------------------
echo "==> Creating project '$PROJECT_KEY'"
api POST "/api/projects/create" -d "project=$PROJECT_KEY" -d "name=CBOM Demo" > /dev/null 2>&1 || true

api POST "/api/user_tokens/revoke" -d "name=$PROJECT_KEY" > /dev/null 2>&1 || true
token="$(api POST "/api/user_tokens/generate" -d "name=$PROJECT_KEY" \
	| sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
if [ -z "$token" ]; then
	echo "Could not generate an analysis token." >&2
	exit 1
fi
printf '%s' "$token" > .sonarqube/token
chmod 600 .sonarqube/token

echo
echo "SonarQube ready at $SONAR_URL (admin/$SONAR_ADMIN_PASSWORD)"
echo "Token written to .sonarqube/token"
echo "Next: ./scripts/scan-cbom.sh"
