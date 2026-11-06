#!/usr/bin/env bash
#
# Gemini Enterprise binding shim — bind or unbind a Gemini Enterprise app to
# the egress Agent Gateway via Discovery Engine UpdateEngine REST API.
# Driven by terraform/55-ge-binding.tf.
#
#   bind_ge_app.sh status    print the app's current agentGatewaySetting
#   bind_ge_app.sh bind      point the app at $GE_AGENT_GATEWAY
#   bind_ge_app.sh unbind    clear agentGatewaySetting (refuses if bound to a gateway other than $GE_AGENT_GATEWAY unless GE_FORCE_REBIND=1)

set -euo pipefail

note() { printf 'bind_ge_app.sh: %s\n' "$*" >&2; }
die() {
  printf 'bind_ge_app.sh: %s\n' "$*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

require_env() {
  local var=$1
  [[ -n ${!var:-} ]] || die "$var must be set"
}

action=${1:-status}
case "$action" in
status | bind | unbind) ;;
*) die "usage: bind_ge_app.sh status|bind|unbind" ;;
esac

need curl
need jq

require_env GE_PROJECT_ID
require_env GE_PROJECT_NUMBER
require_env GE_LOCATION
require_env GE_ENGINE_ID

GE_COLLECTION_ID=${GE_COLLECTION_ID:-default_collection}
readonly ENGINE_NAME="projects/${GE_PROJECT_NUMBER}/locations/${GE_LOCATION}/collections/${GE_COLLECTION_ID}/engines/${GE_ENGINE_ID}"

if [[ $GE_LOCATION == "global" ]]; then
  readonly API_BASE="https://discoveryengine.googleapis.com/v1"
else
  readonly API_BASE="https://${GE_LOCATION}-discoveryengine.googleapis.com/v1"
fi

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
    -H "X-Goog-User-Project: ${GE_PROJECT_ID}"
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

ENGINE_BODY=""
read_engine() {
  req GET "$ENGINE_NAME"
  case "$REQ_CODE" in
  200) ENGINE_BODY=$REQ_BODY ;;
  403) die "HTTP 403 reading ${ENGINE_NAME}: $REQ_BODY" ;;
  404) die "no Gemini Enterprise app at ${ENGINE_NAME}: $REQ_BODY" ;;
  *) die "unexpected HTTP ${REQ_CODE} reading ${ENGINE_NAME}: $REQ_BODY" ;;
  esac
}

bound_gateway() {
  jq -r '.agentGatewaySetting.defaultEgressAgentGateway.name // ""' <<<"$ENGINE_BODY"
}

do_status() {
  read_engine
  local current
  current=$(bound_gateway)
  if [[ -n $current ]]; then
    note "${GE_ENGINE_ID} is bound to ${current}"
  else
    note "${GE_ENGINE_ID} has no egress Agent Gateway set"
  fi
  jq '{name, displayName, agentGatewaySetting}' <<<"$ENGINE_BODY"
}

do_bind() {
  require_env GE_AGENT_GATEWAY
  read_engine

  local current
  current=$(bound_gateway)

  if [[ $current == "$GE_AGENT_GATEWAY" ]]; then
    note "already bound to ${GE_AGENT_GATEWAY} -- nothing to do"
    return 0
  fi

  if [[ -n $current && ${GE_FORCE_REBIND:-} != "1" ]]; then
    die "${GE_ENGINE_ID} is already bound to a different gateway (${current}). Run 'bind_ge_app.sh unbind' first or set GE_FORCE_REBIND=1."
  fi

  local body
  body=$(jq -n --arg gw "$GE_AGENT_GATEWAY" \
    '{agentGatewaySetting: {defaultEgressAgentGateway: {name: $gw}}}')

  note "binding ${GE_ENGINE_ID} to ${GE_AGENT_GATEWAY}"
  req PATCH "${ENGINE_NAME}?updateMask=agentGatewaySetting.defaultEgressAgentGateway.name" "$body"
  [[ $REQ_CODE == 200 ]] || die "bind failed (HTTP ${REQ_CODE}): $REQ_BODY"

  note "ok: all agent traffic for ${GE_ENGINE_ID} now egresses through ${GE_AGENT_GATEWAY}"
}

do_unbind() {
  read_engine

  local current
  current=$(bound_gateway)

  if [[ -z $current ]]; then
    note "${GE_ENGINE_ID} is not bound to a gateway -- nothing to do"
    return 0
  fi

  # On a shared app the binding may belong to someone else. Only clear it when
  # it is ours (GE_AGENT_GATEWAY matches) or the caller forces it.
  if [[ -n ${GE_AGENT_GATEWAY:-} && $current != "$GE_AGENT_GATEWAY" && ${GE_FORCE_REBIND:-} != "1" ]]; then
    die "${GE_ENGINE_ID} is bound to a different gateway (${current}), not ${GE_AGENT_GATEWAY}. Refusing to unbind; set GE_FORCE_REBIND=1 to override."
  fi

  note "clearing the egress gateway on ${GE_ENGINE_ID}"
  req PATCH "${ENGINE_NAME}?updateMask=agentGatewaySetting" '{}'
  [[ $REQ_CODE == 200 ]] || die "unbind failed (HTTP ${REQ_CODE}): $REQ_BODY"

  note "ok: ${GE_ENGINE_ID} no longer routes through an Agent Gateway"
}

case "$action" in
status) do_status ;;
bind) do_bind ;;
unbind) do_unbind ;;
esac
