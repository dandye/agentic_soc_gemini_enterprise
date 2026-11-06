#!/usr/bin/env bash
#
# Gemini Enterprise observability shim — enable or disable prompt and response
# logging on a Gemini Enterprise app via Discovery Engine UpdateEngine REST API.
# Driven by terraform/57-ge-observability.tf.
#
#   ge_observability.sh status     print current observabilityConfig
#   ge_observability.sh enable     turn prompt and response logging on
#   ge_observability.sh disable    turn sensitiveLoggingEnabled off

set -euo pipefail

note() { printf 'ge_observability.sh: %s\n' "$*" >&2; }
die() {
  printf 'ge_observability.sh: %s\n' "$*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

require_env() {
  local var=$1
  [[ -n ${!var:-} ]] || die "$var must be set"
}

action=${1:-status}
case "$action" in
status | enable | disable) ;;
*) die "usage: ge_observability.sh status|enable|disable" ;;
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

flag_on() {
  jq -r --arg f "$1" 'if .observabilityConfig[$f] == true then "true" else "false" end' <<<"$ENGINE_BODY"
}

do_status() {
  read_engine
  local parent sensitive
  parent=$(flag_on observabilityEnabled)
  sensitive=$(flag_on sensitiveLoggingEnabled)

  if [[ $sensitive == "true" && $parent == "true" ]]; then
    note "${GE_ENGINE_ID} logs prompt inputs and response outputs"
  elif [[ $parent == "true" ]]; then
    note "${GE_ENGINE_ID} has observability on but sensitiveLoggingEnabled off"
  else
    note "${GE_ENGINE_ID} has observability off"
  fi
  jq '{name, displayName, observabilityConfig}' <<<"$ENGINE_BODY"
}

do_enable() {
  read_engine

  if [[ $(flag_on observabilityEnabled) == "true" && $(flag_on sensitiveLoggingEnabled) == "true" ]]; then
    note "already enabled on ${GE_ENGINE_ID} -- nothing to do"
    return 0
  fi

  note "enabling prompt and response logging on ${GE_ENGINE_ID}"
  req PATCH "${ENGINE_NAME}?updateMask=observabilityConfig" \
    '{"observabilityConfig":{"observabilityEnabled":true,"sensitiveLoggingEnabled":true}}'
  [[ $REQ_CODE == 200 ]] || die "enable failed (HTTP ${REQ_CODE}): $REQ_BODY"

  ENGINE_BODY=$REQ_BODY
  [[ $(flag_on sensitiveLoggingEnabled) == "true" ]] ||
    die "PATCH returned 200 but sensitiveLoggingEnabled did not persist: $REQ_BODY"

  note "ok: prompts and responses for ${GE_ENGINE_ID} now stream to Cloud Logging"
}

do_disable() {
  read_engine

  if [[ $(flag_on sensitiveLoggingEnabled) == "false" ]]; then
    note "already disabled on ${GE_ENGINE_ID} -- nothing to do"
    return 0
  fi

  local body
  body=$(jq -n --argjson parent "$(flag_on observabilityEnabled)" \
    '{observabilityConfig: {observabilityEnabled: $parent, sensitiveLoggingEnabled: false}}')

  note "disabling prompt and response logging on ${GE_ENGINE_ID}"
  req PATCH "${ENGINE_NAME}?updateMask=observabilityConfig" "$body"
  [[ $REQ_CODE == 200 ]] || die "disable failed (HTTP ${REQ_CODE}): $REQ_BODY"

  note "ok: ${GE_ENGINE_ID} no longer logs prompts or responses"
}

case "$action" in
status) do_status ;;
enable) do_enable ;;
disable) do_disable ;;
esac
