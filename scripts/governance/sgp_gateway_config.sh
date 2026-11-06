#!/usr/bin/env bash
#
# Semantic Governance shim — attach or detach the policy engine's VPC gateway
# config so Agent Gateway can reach it over Private Service Connect.
# Driven by terraform/65-semantic-governance.tf.
#
#   sgp_gateway_config.sh status    print engine state and gatewayConfigs
#   sgp_gateway_config.sh attach    add or update this stack's gateway config
#   sgp_gateway_config.sh detach    remove this stack's gateway config

set -euo pipefail

note() { printf 'sgp_gateway_config.sh: %s\n' "$*" >&2; }
die() {
  printf 'sgp_gateway_config.sh: %s\n' "$*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

require_env() {
  local var=$1
  [[ -n ${!var:-} ]] || die "$var must be set"
}

action=${1:-status}
case "$action" in
status | attach | detach) ;;
*) die "usage: sgp_gateway_config.sh status|attach|detach" ;;
esac

need curl
need jq

require_env SGP_PROJECT_ID
require_env SGP_REGION
require_env SGP_GATEWAY_KEY

readonly API_BASE="https://${SGP_REGION}-aiplatform.googleapis.com/v1beta1"
readonly ENGINE_NAME="projects/${SGP_PROJECT_ID}/locations/${SGP_REGION}/semanticGovernancePolicyEngine"

SGP_WAIT_SECONDS=${SGP_WAIT_SECONDS:-900}
SGP_POLL_SECONDS=${SGP_POLL_SECONDS:-15}

if [[ -z ${GOOGLE_OAUTH_ACCESS_TOKEN:-} ]]; then
  need gcloud
  GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth application-default print-access-token 2>/dev/null) ||
    die "could not obtain an ADC access token. Run 'gcloud auth login <ACCOUNT> --update-adc' or set GOOGLE_OAUTH_ACCESS_TOKEN."
fi
readonly ACCESS_TOKEN="$GOOGLE_OAUTH_ACCESS_TOKEN"

REQ_CODE=""
REQ_BODY=""
req() {
  local method=$1 path=$2 body=${3-} out
  local -a args=(
    -sS -X "$method"
    -H "Authorization: Bearer ${ACCESS_TOKEN}"
    -H "X-Goog-User-Project: ${SGP_PROJECT_ID}"
    -H "Content-Type: application/json"
    -w '\n%{http_code}'
  )
  if [[ -n $body ]]; then
    out=$(printf '%s' "$body" | curl "${args[@]}" --data-binary @- "${API_BASE}/${path}")
  else
    out=$(curl "${args[@]}" "${API_BASE}/${path}")
  fi
  REQ_CODE=${out##*$'\n'}
  REQ_BODY=${out%$'\n'*}
}

req_abs() {
  local url=$1 out
  out=$(curl -sS -X GET \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "X-Goog-User-Project: ${SGP_PROJECT_ID}" \
    -w '\n%{http_code}' "$url")
  REQ_CODE=${out##*$'\n'}
  REQ_BODY=${out%$'\n'*}
}

ENDPOINT_IP=""
endpoint_ok() {
  local url status
  ENDPOINT_IP=""
  url="https://compute.googleapis.com/compute/v1/projects/${SGP_PROJECT_ID}"
  url="${url}/regions/${SGP_REGION}/forwardingRules/sgpe-psce-${SGP_GATEWAY_KEY}"

  req_abs "$url"
  [[ $REQ_CODE == 200 ]] || return 1

  status=$(jq -r '.pscConnectionStatus // ""' <<<"$REQ_BODY")
  [[ $status == "ACCEPTED" ]] || return 1

  ENDPOINT_IP=$(jq -r '.IPAddress // ""' <<<"$REQ_BODY")
  [[ -n $ENDPOINT_IP ]]
}

ENGINE_BODY=""
read_engine() {
  req GET "$ENGINE_NAME"
  case "$REQ_CODE" in
  200) ENGINE_BODY=$REQ_BODY ;;
  403)
    die "HTTP 403 reading policy engine at ${ENGINE_NAME}: $REQ_BODY"
    ;;
  404)
    die "no policy engine at ${ENGINE_NAME}. Apply google_vertex_ai_semantic_governance_policy_engine first: $REQ_BODY"
    ;;
  *) die "unexpected HTTP ${REQ_CODE} reading ${ENGINE_NAME}: $REQ_BODY" ;;
  esac
}

existing_configs() {
  jq -c '(.gatewayConfigs // {})
         | map_values({network, subnetwork, dnsZoneName}
                      | with_entries(select(.value != null)))' <<<"$ENGINE_BODY"
}

patch_configs() {
  local body
  body=$(jq -nc --argjson gc "$1" '{gatewayConfigs: $gc}')
  req PATCH "${ENGINE_NAME}?updateMask=gatewayConfigs" "$body"
  [[ $REQ_CODE == 200 ]] || die "gatewayConfigs update failed (HTTP ${REQ_CODE}): $REQ_BODY"
}

wait_engine_active() {
  local waited=0 engine_state
  while ((waited < SGP_WAIT_SECONDS)); do
    read_engine
    engine_state=$(jq -r '.state // "?"' <<<"$ENGINE_BODY")
    case "$engine_state" in
    ACTIVE) return 0 ;;
    PROVISIONING | INACTIVE)
      note "policy engine state=${engine_state}; waiting (${waited}s/${SGP_WAIT_SECONDS}s)"
      ;;
    *)
      die "policy engine is in state ${engine_state}, expected ACTIVE"
      ;;
    esac
    sleep "$SGP_POLL_SECONDS"
    waited=$((waited + SGP_POLL_SECONDS))
  done
  die "policy engine remained in state ${engine_state} after ${SGP_WAIT_SECONDS}s"
}

wait_active() {
  local waited=0 state
  while ((waited < SGP_WAIT_SECONDS)); do
    read_engine
    state=$(jq -r --arg k "$SGP_GATEWAY_KEY" '.gatewayConfigs[$k].state // "MISSING"' <<<"$ENGINE_BODY")
    case "$state" in
    ACTIVE)
      note "gateway config '${SGP_GATEWAY_KEY}' is ACTIVE"
      jq -r --arg k "$SGP_GATEWAY_KEY" \
        '.gatewayConfigs[$k] | "  endpoint IP: \(.ipAddress // "?")\n  DNS record:  \(.dnsRecord // "?")"' \
        <<<"$ENGINE_BODY" >&2
      return 0
      ;;
    FAILED)
      if endpoint_ok; then
        note "WARNING: gateway config '${SGP_GATEWAY_KEY}' reports state FAILED, but"
        note "         PSC endpoint sgpe-psce-${SGP_GATEWAY_KEY} exists at ${ENDPOINT_IP} with"
        note "         pscConnectionStatus ACCEPTED. Treating data plane as healthy."
        note "         Terraform writes the private DNS A record in 65-semantic-governance.tf."
        return 0
      fi
      die "gateway config '${SGP_GATEWAY_KEY}' reached state FAILED and PSC endpoint sgpe-psce-${SGP_GATEWAY_KEY} is missing or not ACCEPTED."
      ;;
    esac
    note "state=${state}; waiting (${waited}s/${SGP_WAIT_SECONDS}s)"
    sleep "$SGP_POLL_SECONDS"
    waited=$((waited + SGP_POLL_SECONDS))
  done
  die "timed out after ${SGP_WAIT_SECONDS}s waiting for '${SGP_GATEWAY_KEY}' to become ACTIVE"
}

wait_gone() {
  local waited=0 state
  while ((waited < SGP_WAIT_SECONDS)); do
    read_engine
    state=$(jq -r --arg k "$SGP_GATEWAY_KEY" '.gatewayConfigs[$k].state // "GONE"' <<<"$ENGINE_BODY")
    if [[ $state == "GONE" ]]; then
      note "gateway config '${SGP_GATEWAY_KEY}' is gone"
      return 0
    fi
    note "teardown state=${state}; waiting (${waited}s/${SGP_WAIT_SECONDS}s)"
    sleep "$SGP_POLL_SECONDS"
    waited=$((waited + SGP_POLL_SECONDS))
  done
  note "WARNING: '${SGP_GATEWAY_KEY}' still present after ${SGP_WAIT_SECONDS}s. Continuing anyway."
}

do_status() {
  read_engine
  note "engine state: $(jq -r '.state // "?"' <<<"$ENGINE_BODY")"
  jq '{state, pscServiceAttachment, gatewayConfigs}' <<<"$ENGINE_BODY"
}

do_attach() {
  require_env SGP_NETWORK
  require_env SGP_SUBNETWORK
  require_env SGP_DNS_ZONE_FQDN

  wait_engine_active

  local desired current merged our_state
  desired=$(jq -nc --arg n "$SGP_NETWORK" --arg s "$SGP_SUBNETWORK" --arg z "$SGP_DNS_ZONE_FQDN" \
    '{network: $n, subnetwork: $s, dnsZoneName: $z}')
  current=$(existing_configs)
  our_state=$(jq -r --arg k "$SGP_GATEWAY_KEY" '.gatewayConfigs[$k].state // ""' <<<"$ENGINE_BODY")

  local settled=""
  if [[ $our_state == "ACTIVE" ]]; then
    settled="ACTIVE"
  elif [[ $our_state == "FAILED" ]] && endpoint_ok; then
    settled="FAILED-but-up"
  fi

  if [[ $(jq -c --arg k "$SGP_GATEWAY_KEY" '.[$k] // {}' <<<"$current") == "$desired" &&
    -n $settled ]]; then
    if [[ $settled == "ACTIVE" ]]; then
      note "gateway config '${SGP_GATEWAY_KEY}' is already ACTIVE with matching settings"
    else
      note "gateway config '${SGP_GATEWAY_KEY}' reports FAILED, but endpoint ${ENDPOINT_IP} is ACCEPTED with matching settings"
    fi
    return 0
  fi

  if [[ -n $our_state && $our_state != "ACTIVE" ]]; then
    note "gateway config '${SGP_GATEWAY_KEY}' is in state ${our_state}; clearing before retry"
    patch_configs "$(jq -c --arg k "$SGP_GATEWAY_KEY" 'del(.[$k])' <<<"$current")"
    wait_gone
    read_engine
    current=$(existing_configs)
  fi

  merged=$(jq -c --arg k "$SGP_GATEWAY_KEY" --argjson v "$desired" '.[$k] = $v' <<<"$current")
  local count
  count=$(jq 'length' <<<"$merged")
  ((count <= 5)) || die "attaching '${SGP_GATEWAY_KEY}' would exceed the 5-config limit (${count})"

  note "attaching '${SGP_GATEWAY_KEY}' to ${SGP_NETWORK} (${SGP_SUBNETWORK}), zone ${SGP_DNS_ZONE_FQDN}"
  patch_configs "$merged"
  wait_active
}

do_detach() {
  read_engine

  local current
  current=$(existing_configs)
  if [[ $(jq -r --arg k "$SGP_GATEWAY_KEY" 'has($k)' <<<"$current") != "true" ]]; then
    note "no gateway config '${SGP_GATEWAY_KEY}' -- nothing to do"
    return 0
  fi

  note "detaching '${SGP_GATEWAY_KEY}'"
  patch_configs "$(jq -c --arg k "$SGP_GATEWAY_KEY" 'del(.[$k])' <<<"$current")"
  wait_gone
  note "ok"
}

case "$action" in
status) do_status ;;
attach) do_attach ;;
detach) do_detach ;;
esac
