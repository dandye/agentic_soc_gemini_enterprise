#!/usr/bin/env bash
#
# Gemini Enterprise agent shim — publish, inspect, update icon, or remove the
# Governed SecOps Orchestrator on a Gemini Enterprise app via Discovery Engine
# v1alpha Agents REST API.
# Driven by terraform/56-ge-agent.tf.
#
#   ge_agent.sh status    print the agent pointing at $GE_REASONING_ENGINE
#   ge_agent.sh create    adopt existing registration or create a new one
#   ge_agent.sh icon      update icon.uri on an existing registration
#   ge_agent.sh delete    remove the registration matching $GE_REASONING_ENGINE

set -euo pipefail

note() { printf 'ge_agent.sh: %s\n' "$*" >&2; }
die() {
  printf 'ge_agent.sh: %s\n' "$*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

require_env() {
  local var=$1
  [[ -n ${!var:-} ]] || die "$var must be set"
}

action=${1:-status}
case "$action" in
status | create | icon | delete) ;;
*) die "usage: ge_agent.sh status|create|icon|delete" ;;
esac

need curl
need jq
need base64

require_env GE_PROJECT_ID
require_env GE_PROJECT_NUMBER
require_env GE_LOCATION
require_env GE_ENGINE_ID
require_env GE_REASONING_ENGINE

GE_COLLECTION_ID=${GE_COLLECTION_ID:-default_collection}
GE_ASSISTANT_ID=${GE_ASSISTANT_ID:-default_assistant}
GE_AGENT_DISPLAY_NAME="${GE_AGENT_DISPLAY_NAME:-Governed SecOps Orchestrator}"
GE_AGENT_DESCRIPTION=${GE_AGENT_DESCRIPTION:-}
GE_AGENT_SHARING_SCOPE=${GE_AGENT_SHARING_SCOPE:-ALL_USERS}

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
GE_AGENT_ICON_PATH=${GE_AGENT_ICON_PATH-}
if [[ -n $GE_AGENT_ICON_PATH && $GE_AGENT_ICON_PATH != /* ]]; then
  GE_AGENT_ICON_PATH="${REPO_ROOT}/${GE_AGENT_ICON_PATH}"
fi

case "$GE_AGENT_SHARING_SCOPE" in
ALL_USERS | RESTRICTED) ;;
*) die "GE_AGENT_SHARING_SCOPE must be ALL_USERS or RESTRICTED, got '${GE_AGENT_SHARING_SCOPE}'" ;;
esac

readonly PARENT="projects/${GE_PROJECT_NUMBER}/locations/${GE_LOCATION}/collections/${GE_COLLECTION_ID}/engines/${GE_ENGINE_ID}/assistants/${GE_ASSISTANT_ID}"

if [[ $GE_LOCATION == "global" ]]; then
  readonly API_BASE="https://discoveryengine.googleapis.com/v1alpha"
else
  readonly API_BASE="https://${GE_LOCATION}-discoveryengine.googleapis.com/v1alpha"
fi

if [[ -z ${GOOGLE_OAUTH_ACCESS_TOKEN:-} ]]; then
  need gcloud
  GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth application-default print-access-token 2>/dev/null) ||
    die "could not obtain an ADC access token. Run 'gcloud auth login <ACCOUNT> --update-adc' or set GOOGLE_OAUTH_ACCESS_TOKEN."
fi
readonly ACCESS_TOKEN="$GOOGLE_OAUTH_ACCESS_TOKEN"

engine_key() {
  sed -E 's#^.*/(locations/[^/]+/reasoningEngines/[^/]+)$#\1#' <<<"$1"
}

WANT_ENGINE_KEY="$(engine_key "$GE_REASONING_ENGINE")"
readonly WANT_ENGINE_KEY
[[ $WANT_ENGINE_KEY == locations/*/reasoningEngines/* ]] ||
  die "GE_REASONING_ENGINE must be a full resource name like projects/<p>/locations/<r>/reasoningEngines/<id>, got '${GE_REASONING_ENGINE}'"

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

icon_data_uri() {
  [[ -n $GE_AGENT_ICON_PATH ]] || return 0
  [[ -f $GE_AGENT_ICON_PATH ]] ||
    die "GE_AGENT_ICON_PATH points at no file: ${GE_AGENT_ICON_PATH}"

  local lower mime
  lower=$(printf '%s' "$GE_AGENT_ICON_PATH" | tr '[:upper:]' '[:lower:]')
  case "$lower" in
  *.png) mime="image/png" ;;
  *.jpg | *.jpeg) mime="image/jpeg" ;;
  *.gif) mime="image/gif" ;;
  *.webp) mime="image/webp" ;;
  *.svg) mime="image/svg+xml" ;;
  *) die "unsupported icon extension for ${GE_AGENT_ICON_PATH}; use .png, .jpg, .gif, .webp, or .svg" ;;
  esac

  printf 'data:%s;base64,%s' "$mime" "$(base64 <"$GE_AGENT_ICON_PATH" | tr -d '\n')"
}

patch_icon() {
  local name=$1 uri=$2 body
  if [[ -z $uri ]]; then
    note "no icon configured (GE_AGENT_ICON_PATH is empty) -- leaving icon unchanged"
    return 0
  fi

  body=$(jq -n --arg u "$uri" '{icon: {uri: $u}}')
  note "setting icon from ${GE_AGENT_ICON_PATH} on ${name##*/}"
  req PATCH "${name}?updateMask=icon" "$body"
  if [[ $REQ_CODE != 200 ]]; then
    note "WARNING: icon patch failed (HTTP ${REQ_CODE}): $REQ_BODY"
    return 1
  fi
  note "ok: icon set on ${name##*/}"
}

AGENTS_JSON=""
list_agents() {
  req GET "${PARENT}/agents"
  case "$REQ_CODE" in
  200) AGENTS_JSON=$REQ_BODY ;;
  403) die "HTTP 403 listing agents on ${PARENT}: $REQ_BODY" ;;
  404) die "no assistant at ${PARENT}: $REQ_BODY" ;;
  *) die "unexpected HTTP ${REQ_CODE} listing agents on ${PARENT}: $REQ_BODY" ;;
  esac
}

find_agent() {
  jq -r --arg want "$WANT_ENGINE_KEY" '
    [ .agents[]?
      | select(
          (.adkAgentDefinition.provisionedReasoningEngine.reasoningEngine // "")
          | sub("^.*/(?<k>locations/[^/]+/reasoningEngines/[^/]+)$"; "\(.k)")
          | . == $want
        )
    ] | first | .name // ""
  ' <<<"$AGENTS_JSON"
}

do_status() {
  list_agents
  local name
  name=$(find_agent)
  if [[ -z $name ]]; then
    note "no agent on ${GE_ENGINE_ID} points at ${WANT_ENGINE_KEY}"
    jq -n --arg engine "$GE_REASONING_ENGINE" '{exists: false, reasoningEngine: $engine}'
    return 0
  fi
  note "${GE_ENGINE_ID} has an agent for this engine: ${name##*/}"
  jq --arg n "$name" '
    .agents[] | select(.name == $n)
    | {name, displayName, state, sharingConfig, adkAgentDefinition}
      + {hasIcon: (.icon != null)}
  ' <<<"$AGENTS_JSON"
}

do_create() {
  list_agents

  local body existing icon_uri
  icon_uri=$(icon_data_uri)

  existing=$(find_agent)
  if [[ -n $existing ]]; then
    note "already present as ${existing##*/} -- adopting"
    patch_icon "$existing" "$icon_uri" || true
    printf '%s\n' "$existing"
    return 0
  fi

  body=$(jq -n \
    --arg dn "$GE_AGENT_DISPLAY_NAME" \
    --arg desc "$GE_AGENT_DESCRIPTION" \
    --arg engine "$GE_REASONING_ENGINE" \
    --arg scope "$GE_AGENT_SHARING_SCOPE" \
    --arg icon "$icon_uri" \
    '{
      displayName: $dn,
      adkAgentDefinition: {provisionedReasoningEngine: {reasoningEngine: $engine}},
      sharingConfig: {scope: $scope}
    }
    + (if $desc == "" then {} else {description: $desc} end)
    + (if $icon == "" then {} else {icon: {uri: $icon}} end)')

  note "creating agent ${GE_AGENT_DISPLAY_NAME} on ${GE_ENGINE_ID} for ${WANT_ENGINE_KEY}"
  req POST "${PARENT}/agents" "$body"
  [[ $REQ_CODE == 200 ]] || die "create failed (HTTP ${REQ_CODE}): $REQ_BODY"

  local name state
  name=$(jq -r '.name // ""' <<<"$REQ_BODY")
  state=$(jq -r '.state // "UNKNOWN"' <<<"$REQ_BODY")
  [[ -n $name ]] || die "create returned no resource name: $REQ_BODY"

  case "$state" in
  ENABLED | CONFIGURED | PRIVATE | CREATING | DEPLOYING) ;;
  *)
    note "WARNING: created, but state is ${state}:"
    jq -r '{state, creationFailureReason, deploymentFailureReason, rejectionReason}' <<<"$REQ_BODY" >&2
    ;;
  esac

  note "ok: ${name##*/} is ${state}, shared ${GE_AGENT_SHARING_SCOPE}"
  printf '%s\n' "$name"
}

do_icon() {
  list_agents

  local existing icon_uri
  icon_uri=$(icon_data_uri)

  existing=$(find_agent)
  [[ -n $existing ]] ||
    die "no agent on ${GE_ENGINE_ID} points at ${WANT_ENGINE_KEY} -- run 'ge_agent.sh create' first"

  patch_icon "$existing" "$icon_uri"
}

do_delete() {
  list_agents

  local existing
  existing=$(find_agent)
  if [[ -z $existing ]]; then
    note "no agent on ${GE_ENGINE_ID} points at ${WANT_ENGINE_KEY} -- nothing to do"
    return 0
  fi

  note "deleting ${existing##*/} from ${GE_ENGINE_ID}"
  req DELETE "$existing"
  [[ $REQ_CODE == 200 ]] || die "delete failed (HTTP ${REQ_CODE}): $REQ_BODY"

  local op op_done
  op=$(jq -r '.name // ""' <<<"$REQ_BODY")
  op_done=$(jq -r '.done // false' <<<"$REQ_BODY")
  note "ok: delete accepted (operation ${op##*/}, done=${op_done})"
}

case "$action" in
status) do_status ;;
create) do_create ;;
icon) do_icon ;;
delete) do_delete ;;
esac
