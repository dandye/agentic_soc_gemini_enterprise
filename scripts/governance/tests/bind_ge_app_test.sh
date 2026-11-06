#!/usr/bin/env bash
#
# Offline branch tests for scripts/governance/bind_ge_app.sh.
#
# Stubs curl and gcloud on PATH, so this makes no network calls and never
# touches a real Gemini Enterprise app. GOOGLE_OAUTH_ACCESS_TOKEN is set to a
# fake value so the shim never shells out to gcloud; the gcloud stub exists
# only to prove that.
#
#     bash scripts/governance/tests/bind_ge_app_test.sh
#
# The cases that matter most are the two refusals: binding when already bound
# elsewhere, and unbinding when nothing is bound. That is the difference
# between a no-op and an outage on someone else's app.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly SCRIPT_DIR
readonly TARGET="${SCRIPT_DIR}/bind_ge_app.sh"

readonly PROJECT_ID="example-project"
readonly PROJECT_NUMBER="123456789012"
readonly ENGINE_ID="secops-ge-app"
readonly GATEWAY="projects/${PROJECT_ID}/locations/us-central1/agentGateways/agw-secops-egress"
readonly OTHER_GATEWAY="projects/${PROJECT_ID}/locations/us-central1/agentGateways/someone-elses"
# The host is per-location and `us` is NOT global. See the host cases below.
readonly ENGINE_URL="https://us-discoveryengine.googleapis.com/v1/projects/${PROJECT_NUMBER}/locations/us/collections/default_collection/engines/${ENGINE_ID}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# --- stubs -----------------------------------------------------------------

cat >"$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Replays $STUB_DIR/<n> ("code\nbody") in call order. Logs "-X METHOD URL"
# per call to calls.log, request bodies to bodies.log, and every raw argv to
# argv.log. The shim sends bodies via `--data-binary @-`, i.e. on stdin.
printf '%s\n' "$*" >>"$STUB_DIR/argv.log"
[[ "$*" == *"--data-binary @-"* ]] && cat >>"$STUB_DIR/bodies.log"
echo "$*" | grep -oE '(-X [A-Z]+|https://[^ ]+)' | tr '\n' ' ' >>"$STUB_DIR/calls.log"
echo >>"$STUB_DIR/calls.log"
n=$(cat "$STUB_DIR/n" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$STUB_DIR/n"
if [[ ! -f "$STUB_DIR/$n" ]]; then
  echo "curl stub: no fixture staged for call $n" >&2
  exit 7
fi
code=$(head -1 "$STUB_DIR/$n")
# Mirror curl -w '\n%{http_code}': body, newline, status code.
printf '%s\n%s' "$(tail -n +2 "$STUB_DIR/$n")" "$code"
STUB
# gcloud must never run: GOOGLE_OAUTH_ACCESS_TOKEN is always set below. The
# stub records any call so the harness can prove that, and fails loudly.
cat >"$WORK/bin/gcloud" <<'STUB'
#!/usr/bin/env bash
printf 'gcloud %s\n' "$*" >>"$STUB_DIR/gcloud.log"
exit 1
STUB
chmod +x "$WORK/bin"/*

# --- harness ---------------------------------------------------------------

PASS=0
FAIL=0
CASE=0

# stage CODE BODY... : queue canned responses for the next case
stage() {
  STUB_DIR="$WORK/case-$((++CASE))"
  mkdir -p "$STUB_DIR"
  local i=0
  while (($#)); do
    i=$((i + 1))
    printf '%s\n%s\n' "$1" "$2" >"$STUB_DIR/$i"
    shift 2
  done
}

# invoke ACTION [VAR=value...] : run the shim; sets OUT, RC, CALLS, BODIES,
# GCLOUD_CALLS. Extra "VAR=value" arguments are exported for that run only.
invoke() {
  local action=$1
  shift
  set +e
  OUT=$(
    for kv in "$@"; do export "${kv?}"; done
    PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" \
      GOOGLE_OAUTH_ACCESS_TOKEN="${GOOGLE_OAUTH_ACCESS_TOKEN-fake}" \
      GE_PROJECT_ID="$PROJECT_ID" \
      GE_PROJECT_NUMBER="$PROJECT_NUMBER" \
      GE_LOCATION="${GE_LOCATION:-us}" \
      GE_ENGINE_ID="$ENGINE_ID" \
      GE_AGENT_GATEWAY="$GATEWAY" \
      bash "$TARGET" "$action" 2>&1
  )
  RC=$?
  set -e
  CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
  BODIES=$(cat "$STUB_DIR/bodies.log" 2>/dev/null || true)
  ARGV=$(cat "$STUB_DIR/argv.log" 2>/dev/null || true)
  GCLOUD_CALLS=$(cat "$STUB_DIR/gcloud.log" 2>/dev/null || true)
}

check() { # check DESCRIPTION HAYSTACK NEEDLE
  if [[ "$2" == *"$3"* ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       expected to find: %s\n       in: %s\n' "$1" "$3" "$2"
    FAIL=$((FAIL + 1))
  fi
}

refute() { # refute DESCRIPTION HAYSTACK NEEDLE
  if [[ "$2" != *"$3"* ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       did NOT expect: %s\n       in: %s\n' "$1" "$3" "$2"
    FAIL=$((FAIL + 1))
  fi
}

equal() { # equal DESCRIPTION ACTUAL EXPECTED
  if [[ "$2" == "$3" ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$3" "$2"
    FAIL=$((FAIL + 1))
  fi
}

# count_calls PATTERN : number of curl calls whose "-X METHOD URL" line matches
count_calls() {
  printf '%s\n' "$CALLS" | grep -c -- "$1" || true
}

OK='200'
UNBOUND="{\"name\":\"${ENGINE_URL#*/v1/}\",\"displayName\":\"SecOps app\"}"
BOUND="{\"name\":\"${ENGINE_URL#*/v1/}\",\"displayName\":\"SecOps app\",\"agentGatewaySetting\":{\"defaultEgressAgentGateway\":{\"name\":\"${GATEWAY}\"}}}"
BOUND_OTHER="{\"name\":\"${ENGINE_URL#*/v1/}\",\"displayName\":\"SecOps app\",\"agentGatewaySetting\":{\"defaultEgressAgentGateway\":{\"name\":\"${OTHER_GATEWAY}\"}}}"

# --- cases -----------------------------------------------------------------

echo "status when unbound"
stage "$OK" "$UNBOUND"
invoke status
equal "exits 0" "$RC" "0"
check "reads the engine" "$CALLS" "-X GET ${ENGINE_URL}"
check "says no gateway is set" "$OUT" "${ENGINE_ID} has no egress Agent Gateway set"
check "prints the JSON projection" "$OUT" '"agentGatewaySetting": null'
check "projection carries displayName" "$OUT" '"displayName": "SecOps app"'
refute "reads only" "$CALLS" "-X PATCH"
equal "exactly one curl call" "$(count_calls '-X GET')" "1"
equal "gcloud is never invoked" "$GCLOUD_CALLS" ""

echo "status when bound"
stage "$OK" "$BOUND"
invoke status
equal "exits 0" "$RC" "0"
check "reports the current binding" "$OUT" "${ENGINE_ID} is bound to ${GATEWAY}"
check "projection names the gateway" "$OUT" "\"name\": \"${GATEWAY}\""
refute "reads only" "$CALLS" "-X PATCH"

echo "no action argument defaults to status"
stage "$OK" "$BOUND"
invoke ""
equal "exits 0" "$RC" "0"
check "reports the current binding" "$OUT" "is bound to ${GATEWAY}"
refute "reads only" "$CALLS" "-X PATCH"

echo "request headers"
stage "$OK" "$UNBOUND"
invoke status
check "sends the bearer token" "$ARGV" "Authorization: Bearer fake"
check "bills the project by ID, not number" "$ARGV" "X-Goog-User-Project: ${PROJECT_ID}"
check "sends JSON content type" "$ARGV" "Content-Type: application/json"
check "asks curl for the status code on its own line" "$ARGV" '-w \n%{http_code}'
check "fails on HTTP errors silently, not with progress bars" "$ARGV" "-sS"

echo "unbound -> bind"
stage "$OK" "$UNBOUND" "$OK" "$BOUND"
invoke bind
equal "exits 0" "$RC" "0"
check "reads the engine first" "$CALLS" "-X GET ${ENGINE_URL}"
check "PATCHes with the leaf-field updateMask" "$CALLS" \
  "-X PATCH ${ENGINE_URL}?updateMask=agentGatewaySetting.defaultEgressAgentGateway.name"
equal "GET then PATCH, in that order" \
  "$(printf '%s\n' "$CALLS" | grep -oE '^-X [A-Z]+' | tr '\n' ' ')" "-X GET -X PATCH "
# The URL takes the project NUMBER, the body's gateway takes the project ID.
# Mixing them up is the whole trap; assert both.
check "URL uses the project number" "$CALLS" "/projects/${PROJECT_NUMBER}/"
refute "URL does not use the project ID" "$CALLS" "/projects/${PROJECT_ID}/"
equal "body names the gateway by project ID" \
  "$(jq -r '.agentGatewaySetting.defaultEgressAgentGateway.name' <<<"$BODIES")" "$GATEWAY"
equal "body carries nothing but the gateway setting" \
  "$(jq -c 'keys' <<<"$BODIES")" '["agentGatewaySetting"]'
check "body is sent on stdin via --data-binary @-" "$ARGV" "--data-binary @-"
check "path carries the collection segment" "$CALLS" "/collections/default_collection/engines/"
check "announces the bind" "$OUT" "binding ${ENGINE_ID} to ${GATEWAY}"
check "confirms success" "$OUT" "ok: all agent traffic for ${ENGINE_ID} now egresses through ${GATEWAY}"
equal "gcloud is never invoked" "$GCLOUD_CALLS" ""

echo "already bound to the same gateway -> no write"
stage "$OK" "$BOUND"
invoke bind
equal "exits 0" "$RC" "0"
check "says nothing to do" "$OUT" "already bound to ${GATEWAY} -- nothing to do"
refute "issues no PATCH" "$CALLS" "-X PATCH"
equal "no request body sent" "$BODIES" ""
equal "exactly one curl call" "$(count_calls 'https://')" "1"

echo "bound to a DIFFERENT gateway -> refuses"
stage "$OK" "$BOUND_OTHER"
invoke bind
equal "exits 1" "$RC" "1"
check "names the gateway it is bound to" "$OUT" "already bound to a different gateway (${OTHER_GATEWAY})"
check "explains how to proceed" "$OUT" "GE_FORCE_REBIND=1"
check "suggests unbind as the alternative" "$OUT" "bind_ge_app.sh unbind"
refute "mutates nothing" "$CALLS" "-X PATCH"
refute "does not claim success" "$OUT" "ok:"

echo "bound elsewhere + GE_FORCE_REBIND=0 -> still refuses"
stage "$OK" "$BOUND_OTHER"
invoke bind GE_FORCE_REBIND=0
equal "exits 1" "$RC" "1"
refute "mutates nothing" "$CALLS" "-X PATCH"

echo "bound elsewhere + GE_FORCE_REBIND=1 -> proceeds"
stage "$OK" "$BOUND_OTHER" "$OK" "$BOUND"
invoke bind GE_FORCE_REBIND=1
equal "exits 0" "$RC" "0"
check "PATCHes" "$CALLS" "-X PATCH ${ENGINE_URL}?updateMask=agentGatewaySetting.defaultEgressAgentGateway.name"
equal "body names the NEW gateway" \
  "$(jq -r '.agentGatewaySetting.defaultEgressAgentGateway.name' <<<"$BODIES")" "$GATEWAY"
refute "body does not carry the old gateway" "$BODIES" "$OTHER_GATEWAY"

echo "bind without GE_AGENT_GATEWAY -> refuses before any call"
stage "$OK" "$UNBOUND"
set +e
OUT=$(PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" GOOGLE_OAUTH_ACCESS_TOKEN=fake \
  GE_PROJECT_ID="$PROJECT_ID" GE_PROJECT_NUMBER="$PROJECT_NUMBER" \
  GE_LOCATION=us GE_ENGINE_ID="$ENGINE_ID" \
  bash "$TARGET" bind 2>&1)
RC=$?
set -e
CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
equal "exits 1" "$RC" "1"
check "names the missing variable" "$OUT" "GE_AGENT_GATEWAY must be set"
equal "no curl call made" "$CALLS" ""

echo "status does not need GE_AGENT_GATEWAY"
stage "$OK" "$UNBOUND"
set +e
OUT=$(PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" GOOGLE_OAUTH_ACCESS_TOKEN=fake \
  GE_PROJECT_ID="$PROJECT_ID" GE_PROJECT_NUMBER="$PROJECT_NUMBER" \
  GE_LOCATION=us GE_ENGINE_ID="$ENGINE_ID" \
  bash "$TARGET" status 2>&1)
RC=$?
set -e
equal "exits 0" "$RC" "0"
check "reports status" "$OUT" "has no egress Agent Gateway set"

echo "collection override is honoured"
stage "$OK" "$UNBOUND" "$OK" "$BOUND"
invoke bind GE_COLLECTION_ID=custom_collection
equal "exits 0" "$RC" "0"
check "uses the override in the path" "$CALLS" "/collections/custom_collection/engines/${ENGINE_ID}"
refute "drops the default collection" "$CALLS" "default_collection"

echo "unbind when bound"
stage "$OK" "$BOUND" "$OK" "$UNBOUND"
invoke unbind
equal "exits 0" "$RC" "0"
check "reads the engine first" "$CALLS" "-X GET ${ENGINE_URL}"
check "clears the parent message, not the leaf" "$CALLS" "-X PATCH ${ENGINE_URL}?updateMask=agentGatewaySetting "
refute "does not mask the leaf field" "$CALLS" "updateMask=agentGatewaySetting.default"
equal "sends an empty JSON object" "$(jq -c . <<<"$BODIES")" "{}"
check "announces the clear" "$OUT" "clearing the egress gateway on ${ENGINE_ID}"
check "confirms success" "$OUT" "ok: ${ENGINE_ID} no longer routes through an Agent Gateway"

echo "unbind when bound to someone else's gateway -> still clears (no force needed)"
stage "$OK" "$BOUND_OTHER" "$OK" "$UNBOUND"
invoke unbind
equal "exits 0" "$RC" "0"
check "PATCHes" "$CALLS" "-X PATCH ${ENGINE_URL}?updateMask=agentGatewaySetting "

echo "unbind when not bound -> no write (idempotent)"
stage "$OK" "$UNBOUND"
invoke unbind
equal "exits 0" "$RC" "0"
check "says nothing to do" "$OUT" "${ENGINE_ID} is not bound to a gateway -- nothing to do"
refute "issues no PATCH" "$CALLS" "-X PATCH"
equal "no request body sent" "$BODIES" ""

echo "unbind PATCH rejected -> surfaces the status"
stage "$OK" "$BOUND" 500 '{"error":{"message":"backend unavailable"}}'
invoke unbind
equal "exits 1" "$RC" "1"
check "reports the HTTP code" "$OUT" "unbind failed (HTTP 500)"
check "includes the server message" "$OUT" "backend unavailable"
refute "does not claim success" "$OUT" "no longer routes"

echo "404 on read -> dies with a clear message"
stage 404 '{"error":{"code":404,"message":"Engine not found"}}'
invoke bind
equal "exits 1" "$RC" "1"
check "says there is no app" "$OUT" "no Gemini Enterprise app at ${ENGINE_URL#*/v1/}"
check "includes the server message" "$OUT" "Engine not found"
check "is prefixed with the script name" "$OUT" "bind_ge_app.sh: "
refute "attempts no write" "$CALLS" "-X PATCH"

echo "403 on read -> actionable, no write attempted"
stage 403 '{"error":{"code":403,"status":"PERMISSION_DENIED"}}'
invoke bind
equal "exits 1" "$RC" "1"
check "names the HTTP code and resource" "$OUT" "HTTP 403 reading ${ENGINE_URL#*/v1/}"
check "includes the server status" "$OUT" "PERMISSION_DENIED"
refute "attempts no write" "$CALLS" "-X PATCH"

echo "other HTTP error on read -> dies with the code"
stage 500 '{"error":{"code":500}}'
invoke status
equal "exits 1" "$RC" "1"
check "reports the unexpected code" "$OUT" "unexpected HTTP 500 reading ${ENGINE_URL#*/v1/}"

echo "bind PATCH rejected -> surfaces the status"
stage "$OK" "$UNBOUND" 400 '{"error":{"message":"immutable field"}}'
invoke bind
equal "exits 1" "$RC" "1"
check "reports the HTTP code" "$OUT" "bind failed (HTTP 400)"
check "includes the server message" "$OUT" "immutable field"
refute "does not claim success" "$OUT" "ok: all agent traffic"

echo "unknown action -> usage error before any call"
stage "$OK" "$UNBOUND"
invoke rebind
equal "exits 1" "$RC" "1"
check "prints usage" "$OUT" "usage: bind_ge_app.sh status|bind|unbind"
equal "no curl call made" "$CALLS" ""

echo "missing required env -> refuses before any call"
stage "$OK" "$UNBOUND"
set +e
OUT=$(PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" GOOGLE_OAUTH_ACCESS_TOKEN=fake \
  GE_PROJECT_ID="$PROJECT_ID" \
  bash "$TARGET" bind 2>&1)
RC=$?
set -e
CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
equal "exits 1" "$RC" "1"
check "names the first missing variable" "$OUT" "GE_PROJECT_NUMBER must be set"
equal "no curl call made" "$CALLS" ""

for var in GE_PROJECT_ID GE_LOCATION GE_ENGINE_ID; do
  stage "$OK" "$UNBOUND"
  set +e
  OUT=$(
    export GOOGLE_OAUTH_ACCESS_TOKEN=fake GE_PROJECT_ID="$PROJECT_ID" \
      GE_PROJECT_NUMBER="$PROJECT_NUMBER" GE_LOCATION=us GE_ENGINE_ID="$ENGINE_ID"
    unset "$var"
    PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" bash "$TARGET" status 2>&1
  )
  RC=$?
  set -e
  equal "missing ${var}: exits 1" "$RC" "1"
  check "missing ${var}: names it" "$OUT" "${var} must be set"
done

echo "no token and no working gcloud -> dies before any call"
stage "$OK" "$UNBOUND"
set +e
OUT=$(
  unset GOOGLE_OAUTH_ACCESS_TOKEN
  PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" \
    GE_PROJECT_ID="$PROJECT_ID" GE_PROJECT_NUMBER="$PROJECT_NUMBER" \
    GE_LOCATION=us GE_ENGINE_ID="$ENGINE_ID" \
    bash "$TARGET" status 2>&1
)
RC=$?
set -e
CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
GCLOUD_CALLS=$(cat "$STUB_DIR/gcloud.log" 2>/dev/null || true)
equal "exits 1" "$RC" "1"
check "falls back to ADC via gcloud" "$GCLOUD_CALLS" "gcloud auth application-default print-access-token"
check "explains the remedy" "$OUT" "could not obtain an ADC access token"
check "names the env override" "$OUT" "GOOGLE_OAUTH_ACCESS_TOKEN"
equal "no curl call made" "$CALLS" ""

# The host is derived from GE_LOCATION; only `global` is bare. A hardcoded
# global host 400s on a `us` app (the console's default) with "Incorrect API
# endpoint used".
echo "the API host is derived from GE_LOCATION"

stage "$OK" "$UNBOUND"
invoke status
check "us is prefixed" "$CALLS" "https://us-discoveryengine.googleapis.com/v1/projects/${PROJECT_NUMBER}/locations/us/"
refute "us does not fall back to the global host" "$CALLS" "https://discoveryengine.googleapis.com/"

stage "$OK" "$UNBOUND"
invoke status GE_LOCATION=eu
check "eu is prefixed" "$CALLS" "https://eu-discoveryengine.googleapis.com/v1/projects/${PROJECT_NUMBER}/locations/eu/"

stage "$OK" "$UNBOUND"
invoke status GE_LOCATION=global
check "global is the one unprefixed host" "$CALLS" "https://discoveryengine.googleapis.com/v1/projects/${PROJECT_NUMBER}/locations/global/"
refute "global is not itself prefixed" "$CALLS" "global-discoveryengine.googleapis.com"

# --- result ----------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
