#!/usr/bin/env bash
#
# Reasoning Engine scaling shim — ensure spec.deploymentSpec.minInstances is
# explicitly persisted on Vertex AI Reasoning Engines via field-masked REST
# PATCH.
#
# Why this shim exists:
#   hashicorp/google-beta treats int 0 as empty in tpgresource.IsEmptyValue, so
#   setting min_instances = 0 on google_vertex_ai_reasoning_engine omits
#   "minInstances" from both Create and Update JSON payloads. On the Vertex AI
#   API, an omitted optional min_instances defaults to 1 warm instance in
#   regions such as us-central1 (~$24/mo idle memory per engine), and any
#   subsequent Terraform spec update clears a previously patched 0.
#   Driven by terraform/41-agents.tf (terraform_data.reasoning_engine_min_instances).
#
#   reasoning_engine_scaling.sh status   print live minInstances/maxInstances/gateway
#   reasoning_engine_scaling.sh ensure   no-op if live minInstances matches, else PATCH

set -euo pipefail

note() { printf 'reasoning_engine_scaling.sh: %s\n' "$*" >&2; }
die() {
  printf 'reasoning_engine_scaling.sh: %s\n' "$*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

require_env() {
  local var=$1
  [[ -n ${!var:-} ]] || die "$var must be set"
}

action=${1:-status}
case "$action" in
status | ensure) ;;
*) die "usage: reasoning_engine_scaling.sh status|ensure" ;;
esac

need curl
need jq

require_env RE_PROJECT_ID
require_env RE_REGION
require_env RE_ENGINE_NAME

if [[ $action == "ensure" ]]; then
  if [[ -z ${RE_MIN_INSTANCES+x} || -z ${RE_MIN_INSTANCES} ]]; then
    die "RE_MIN_INSTANCES must be set"
  fi
  [[ $RE_MIN_INSTANCES =~ ^[0-9]+$ ]] ||
    die "RE_MIN_INSTANCES must be a non-negative integer, got '${RE_MIN_INSTANCES}'"
fi

ENGINE_ID=${RE_ENGINE_NAME##*/}
[[ -n $ENGINE_ID ]] || die "could not extract engine ID from RE_ENGINE_NAME='${RE_ENGINE_NAME}'"
readonly ENGINE_ID
readonly ENGINE_PATH="projects/${RE_PROJECT_ID}/locations/${RE_REGION}/reasoningEngines/${ENGINE_ID}"
readonly API_BASE="${RE_API_BASE:-https://${RE_REGION}-aiplatform.googleapis.com/v1beta1}"

RE_WAIT_SECONDS=${RE_WAIT_SECONDS:-900}
RE_POLL_SECONDS=${RE_POLL_SECONDS:-10}
RE_EXPECTED_GATEWAY=${RE_EXPECTED_GATEWAY:-}

if [[ -z ${GOOGLE_OAUTH_ACCESS_TOKEN:-} ]]; then
  need gcloud
  GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth application-default print-access-token 2>/dev/null) ||
    die "could not obtain an ADC access token. Run 'gcloud auth login <ACCOUNT> --update-adc' or set GOOGLE_OAUTH_ACCESS_TOKEN."
fi
readonly ACCESS_TOKEN="$GOOGLE_OAUTH_ACCESS_TOKEN"

REQ_CODE=""
REQ_BODY=""
req() {
  local method=$1 path=$2 body=${3-} out attempt=0
  local -a args=(
    -sS --max-time 60 -X "$method"
    -H "Authorization: Bearer ${ACCESS_TOKEN}"
    -H "X-Goog-User-Project: ${RE_PROJECT_ID}"
    -H "Content-Type: application/json"
    -w '\n%{http_code}'
  )
  while true; do
    attempt=$((attempt + 1))
    if [[ -n $body ]]; then
      out=$(printf '%s' "$body" | curl "${args[@]}" --data-binary @- "${API_BASE}/${path}")
    else
      out=$(curl "${args[@]}" "${API_BASE}/${path}")
    fi
    REQ_CODE=${out##*$'\n'}
    REQ_BODY=${out%$'\n'*}
    case "$REQ_CODE" in
    429 | 500 | 502 | 503 | 504)
      if ((attempt < 3)); then
        sleep 2
        continue
      fi
      ;;
    esac
    break
  done
}

ENGINE_BODY=""
read_engine() {
  req GET "$ENGINE_PATH"
  case "$REQ_CODE" in
  200) ENGINE_BODY=$REQ_BODY ;;
  403) die "HTTP 403 reading ${ENGINE_PATH}: $REQ_BODY" ;;
  404) die "no Reasoning Engine at ${ENGINE_PATH}: $REQ_BODY" ;;
  *) die "unexpected HTTP ${REQ_CODE} reading ${ENGINE_PATH}: $REQ_BODY" ;;
  esac
}

verify_gateway_intact() {
  local live_gw
  live_gw=$(jq -r '.spec.deploymentSpec.agentGatewayConfig.agentToAnywhereConfig.agentGateway // ""' <<<"$ENGINE_BODY")
  if [[ -n $RE_EXPECTED_GATEWAY && $live_gw != "$RE_EXPECTED_GATEWAY" ]]; then
    die "gateway mismatch on ${ENGINE_ID}: expected '${RE_EXPECTED_GATEWAY}', got '${live_gw:-<unset>}'"
  fi
}

min_matches() {
  local want=$1
  jq -e --argjson want "$want" '
    (.spec.deploymentSpec // {})
    | (type == "object") and has("minInstances") and (.minInstances == $want)
  ' <<<"$ENGINE_BODY" >/dev/null 2>&1
}

wait_op() {
  local op_name=$1 waited=0 done_flag err_msg
  [[ -n $op_name ]] || return 0
  while ((waited <= RE_WAIT_SECONDS)); do
    req GET "$op_name"
    [[ $REQ_CODE == 200 ]] || die "unexpected HTTP ${REQ_CODE} polling ${op_name}: $REQ_BODY"
    err_msg=$(jq -r 'if .error then (.error.message // (.error | tostring)) else "" end' <<<"$REQ_BODY")
    [[ -z $err_msg ]] || die "operation ${op_name} failed on ${ENGINE_ID}: ${err_msg}"
    done_flag=$(jq -r '.done // false' <<<"$REQ_BODY")
    if [[ $done_flag == "true" ]]; then
      return 0
    fi
    if ((waited >= RE_WAIT_SECONDS)); then
      break
    fi
    note "${ENGINE_ID}: waiting for minInstances=${RE_MIN_INSTANCES} LRO (${waited}s/${RE_WAIT_SECONDS}s)"
    sleep "$RE_POLL_SECONDS"
    waited=$((waited + RE_POLL_SECONDS))
  done
  die "operation ${op_name} did not complete within ${RE_WAIT_SECONDS}s on ${ENGINE_ID}"
}

case "$action" in
status)
  read_engine
  jq -r --arg id "$ENGINE_ID" '
    (.spec.deploymentSpec // {}) as $ds
    | "\($id) minInstances=\(if ($ds | has("minInstances")) then ($ds.minInstances | tostring) else "unset" end) maxInstances=\(if ($ds | has("maxInstances")) then ($ds.maxInstances | tostring) else "unset" end) agentGateway=\($ds.agentGatewayConfig.agentToAnywhereConfig.agentGateway // "unset")"
  ' <<<"$ENGINE_BODY"
  ;;
ensure)
  read_engine
  verify_gateway_intact
  if min_matches "$RE_MIN_INSTANCES"; then
    note "${ENGINE_ID} already minInstances=${RE_MIN_INSTANCES}"
    exit 0
  fi
  patch_body=$(jq -nc --argjson min "$RE_MIN_INSTANCES" '{spec: {deploymentSpec: {minInstances: $min}}}')
  note "patching ${ENGINE_ID} spec.deploymentSpec.minInstances=${RE_MIN_INSTANCES}"
  req PATCH "${ENGINE_PATH}?updateMask=spec.deploymentSpec.minInstances" "$patch_body"
  [[ $REQ_CODE == 200 ]] || die "HTTP ${REQ_CODE} patching ${ENGINE_PATH}: $REQ_BODY"
  op_name=$(jq -r '.name // ""' <<<"$REQ_BODY")
  done_now=$(jq -r '.done // false' <<<"$REQ_BODY")
  if [[ $done_now != "true" && -n $op_name ]]; then
    wait_op "$op_name"
  else
    err_msg=$(jq -r 'if .error then (.error.message // (.error | tostring)) else "" end' <<<"$REQ_BODY")
    [[ -z $err_msg ]] || die "operation failed on ${ENGINE_ID}: ${err_msg}"
  fi
  read_engine
  verify_gateway_intact
  min_matches "$RE_MIN_INSTANCES" ||
    die "${ENGINE_ID} did not persist minInstances=${RE_MIN_INSTANCES} after PATCH"
  note "ok: ${ENGINE_ID} persisted minInstances=${RE_MIN_INSTANCES}"
  ;;
esac
