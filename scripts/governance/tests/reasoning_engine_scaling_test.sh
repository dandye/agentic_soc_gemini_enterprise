#!/usr/bin/env bash
#
# Offline branch tests for scripts/governance/reasoning_engine_scaling.sh.
#
# Stubs curl and gcloud on PATH; makes zero network calls. Proves that:
#   1. Explicit live minInstances=0 is a 1-GET no-op (zero PATCH).
#   2. Omitted minInstances (as left by hashicorp/google-beta IsEmptyValue(0))
#      triggers a field-masked PATCH (?updateMask=spec.deploymentSpec.minInstances)
#      with {"spec":{"deploymentSpec":{"minInstances":0}}}, polls the LRO to
#      completion, and verifies both minInstances=0 and agentGateway retention.
#   3. LRO errors, gateway drift, and invalid RE_MIN_INSTANCES fail loudly.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly SCRIPT_DIR
readonly TARGET="${SCRIPT_DIR}/reasoning_engine_scaling.sh"

readonly PROJECT_ID="example-project"
readonly REGION="us-central1"
readonly ENGINE_ID="1111111111111111111"
readonly ENGINE_NAME="projects/${PROJECT_ID}/locations/${REGION}/reasoningEngines/${ENGINE_ID}"
readonly GATEWAY="projects/${PROJECT_ID}/locations/${REGION}/agentGateways/agw-secops-egress"
readonly ENGINE_URL="https://${REGION}-aiplatform.googleapis.com/v1beta1/${ENGINE_NAME}"
readonly OP_NAME="${ENGINE_NAME}/operations/999999999"
readonly OP_URL="https://${REGION}-aiplatform.googleapis.com/v1beta1/${OP_NAME}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

cat >"$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_DIR/argv.log"
if [[ "$*" == *"--data-binary @-"* ]]; then
  cat >>"$STUB_DIR/bodies.log"
  printf '\n' >>"$STUB_DIR/bodies.log"
fi
echo "$*" | grep -oE '(-X [A-Z]+|https://[^ ]+)' | tr '\n' ' ' >>"$STUB_DIR/calls.log"
echo >>"$STUB_DIR/calls.log"
n=$(cat "$STUB_DIR/n" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" >"$STUB_DIR/n"
if [[ ! -f "$STUB_DIR/$n" ]]; then
  echo "curl stub: no fixture staged for call $n" >&2
  exit 7
fi
code=$(head -1 "$STUB_DIR/$n")
printf '%s\n%s' "$(tail -n +2 "$STUB_DIR/$n")" "$code"
STUB

cat >"$WORK/bin/gcloud" <<'STUB'
#!/usr/bin/env bash
printf 'gcloud %s\n' "$*" >>"$STUB_DIR/gcloud.log"
exit 1
STUB
chmod +x "$WORK/bin"/*

PASS=0
FAIL=0
CASE=0

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

invoke() {
  local action=$1
  shift
  set +e
  OUT=$(
    for kv in "$@"; do export "${kv?}"; done
    PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" \
      GOOGLE_OAUTH_ACCESS_TOKEN="${GOOGLE_OAUTH_ACCESS_TOKEN-fake-token}" \
      RE_PROJECT_ID="${RE_PROJECT_ID-$PROJECT_ID}" \
      RE_REGION="${RE_REGION-$REGION}" \
      RE_ENGINE_NAME="${RE_ENGINE_NAME-$ENGINE_NAME}" \
      RE_EXPECTED_GATEWAY="${RE_EXPECTED_GATEWAY-$GATEWAY}" \
      RE_POLL_SECONDS=0 \
      RE_WAIT_SECONDS="${RE_WAIT_SECONDS-5}" \
      bash "$TARGET" "$action" 2>&1
  )
  RC=$?
  set -e
  CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
  BODIES=$(cat "$STUB_DIR/bodies.log" 2>/dev/null || true)
  GCLOUD_CALLS=$(cat "$STUB_DIR/gcloud.log" 2>/dev/null || true)
}

check() {
  if [[ "$2" == *"$3"* ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       expected to find: %s\n       in: %s\n' "$1" "$3" "$2"
    FAIL=$((FAIL + 1))
  fi
}

refute() {
  if [[ "$2" != *"$3"* ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       expected NOT to find: %s\n       in: %s\n' "$1" "$3" "$2"
    FAIL=$((FAIL + 1))
  fi
}

eq() {
  if [[ "$2" == "$3" ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       expected: %s\n       got:      %s\n' "$1" "$3" "$2"
    FAIL=$((FAIL + 1))
  fi
}

ENGINE_OMITTED_MIN=$(jq -nc --arg gw "$GATEWAY" '{
  name: "projects/example-project/locations/us-central1/reasoningEngines/1111111111111111111",
  spec: {
    deploymentSpec: {
      agentGatewayConfig: {agentToAnywhereConfig: {agentGateway: $gw}}
    }
  }
}')

ENGINE_ZERO_MIN=$(jq -nc --arg gw "$GATEWAY" '{
  name: "projects/example-project/locations/us-central1/reasoningEngines/1111111111111111111",
  spec: {
    deploymentSpec: {
      minInstances: 0,
      agentGatewayConfig: {agentToAnywhereConfig: {agentGateway: $gw}}
    }
  }
}')

ENGINE_ONE_MIN=$(jq -nc --arg gw "$GATEWAY" '{
  name: "projects/example-project/locations/us-central1/reasoningEngines/1111111111111111111",
  spec: {
    deploymentSpec: {
      minInstances: 1,
      maxInstances: 4,
      agentGatewayConfig: {agentToAnywhereConfig: {agentGateway: $gw}}
    }
  }
}')

ENGINE_MISSING_GW=$(jq -nc '{
  name: "projects/example-project/locations/us-central1/reasoningEngines/1111111111111111111",
  spec: {deploymentSpec: {minInstances: 0}}
}')

# 1. status reports unset vs explicit 0 vs explicit 1/4
stage 200 "$ENGINE_OMITTED_MIN"
invoke status
eq "status exit 0 when minInstances omitted" "$RC" "0"
check "status prints minInstances=unset" "$OUT" "${ENGINE_ID} minInstances=unset maxInstances=unset agentGateway=${GATEWAY}"
eq "status never invokes gcloud when token set" "$GCLOUD_CALLS" ""

stage 200 "$ENGINE_ZERO_MIN"
invoke status
eq "status exit 0 when minInstances=0" "$RC" "0"
check "status prints minInstances=0" "$OUT" "${ENGINE_ID} minInstances=0 maxInstances=unset agentGateway=${GATEWAY}"

stage 200 "$ENGINE_ONE_MIN"
invoke status
eq "status exit 0 when minInstances=1" "$RC" "0"
check "status prints minInstances=1 maxInstances=4" "$OUT" "${ENGINE_ID} minInstances=1 maxInstances=4 agentGateway=${GATEWAY}"

# 2. ensure fast-path no-op when live minInstances already matches 0
stage 200 "$ENGINE_ZERO_MIN"
invoke ensure RE_MIN_INSTANCES=0
eq "ensure no-op exit 0" "$RC" "0"
check "ensure logs already minInstances=0" "$OUT" "already minInstances=0"
check "ensure no-op issues GET" "$CALLS" "-X GET ${ENGINE_URL}"
refute "ensure no-op issues zero PATCH" "$CALLS" "PATCH"
eq "ensure no-op sends empty body log" "$BODIES" ""

# 3. ensure patches omitted minInstances -> 0, polls LRO, verifies persistence + gateway
stage \
  200 "$ENGINE_OMITTED_MIN" \
  200 "{\"name\":\"${OP_NAME}\",\"done\":false}" \
  200 "{\"name\":\"${OP_NAME}\",\"done\":false}" \
  200 "{\"name\":\"${OP_NAME}\",\"done\":true}" \
  200 "$ENGINE_ZERO_MIN"
invoke ensure RE_MIN_INSTANCES=0
eq "ensure patch omitted->0 exit 0" "$RC" "0"
check "ensure uses exact minInstances updateMask" "$CALLS" "-X PATCH ${ENGINE_URL}?updateMask=spec.deploymentSpec.minInstances"
check "ensure polls LRO URL" "$CALLS" "-X GET ${OP_URL}"
check "ensure sends explicit integer 0 in JSON body" "$BODIES" '{"spec":{"deploymentSpec":{"minInstances":0}}}'
check "ensure logs completion" "$OUT" "ok: ${ENGINE_ID} persisted minInstances=0"

# 4. ensure fails loudly if LRO reports an error
stage \
  200 "$ENGINE_OMITTED_MIN" \
  200 "{\"name\":\"${OP_NAME}\",\"done\":false}" \
  200 "{\"name\":\"${OP_NAME}\",\"done\":true,\"error\":{\"code\":13,\"message\":\"internal deploy error\"}}"
invoke ensure RE_MIN_INSTANCES=0
eq "ensure exits 1 on LRO error" "$RC" "1"
check "ensure surfaces LRO error message" "$OUT" "internal deploy error"

# 5. ensure fails loudly if gateway was detached
stage 200 "$ENGINE_MISSING_GW"
invoke ensure RE_MIN_INSTANCES=0
eq "ensure exits 1 when expected gateway missing" "$RC" "1"
check "ensure reports gateway mismatch" "$OUT" "gateway mismatch"

# 6. ensure rejects invalid RE_MIN_INSTANCES before any network call
stage
invoke ensure RE_MIN_INSTANCES=-1
eq "ensure rejects negative RE_MIN_INSTANCES" "$RC" "1"
check "ensure explains non-negative integer rule" "$OUT" "RE_MIN_INSTANCES must be a non-negative integer"
eq "invalid input makes zero HTTP calls" "$CALLS" ""

if ((FAIL > 0)); then
  printf 'FAILED: %d failed, %d passed\n' "$FAIL" "$PASS"
  exit 1
fi
printf 'PASSED: %d checks\n' "$PASS"
