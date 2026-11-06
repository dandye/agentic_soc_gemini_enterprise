#!/usr/bin/env bash
#
# Offline branch tests for scripts/governance/ge_agent.sh.
#
# Stubs curl (and gcloud) on PATH, so this makes no network calls and never
# touches a real Gemini Enterprise app. Every canned API response is replayed
# from a per-case fixture directory; every curl invocation is logged so the
# tests can assert exactly which methods and URLs were issued.
#
#     bash scripts/governance/tests/ge_agent_test.sh
#
# The cases that matter most, because the shim runs against a SHARED Gemini
# Enterprise app that also hosts other teams' registrations:
#   - ADOPT rather than duplicate when a registration already points at
#     $GE_REASONING_ENGINE, including when the caller passes projects/<ID> and
#     the server returns projects/<NUMBER>.
#   - Never match, patch, or delete `deep_research` (the Google built-in) or
#     any registration that points at a different reasoning engine.
#   - delete issues exactly one DELETE and it names only our agent id.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly SCRIPT_DIR
readonly TARGET="${SCRIPT_DIR}/ge_agent.sh"
REPO_ROOT="${SCRIPT_DIR%/scripts/governance}"
readonly REPO_ROOT

# The caller-side form: project ID, as `terraform output` emits it.
readonly ENGINE_ID_FORM="projects/example-project/locations/us-central1/reasoningEngines/1111111111111111111"
# The server-side form: project NUMBER, as the API stores and returns it.
readonly ENGINE_NUM_FORM="projects/123456789012/locations/us-central1/reasoningEngines/1111111111111111111"
# Two different engines entirely: must never be adopted, patched, or deleted.
readonly ENGINE_OTHER_A="projects/123456789012/locations/us-central1/reasoningEngines/2222222222222222222"
readonly ENGINE_OTHER_B="projects/123456789012/locations/us-central1/reasoningEngines/3333333333333333333"

readonly PARENT_PATH="projects/123456789012/locations/us/collections/default_collection/engines/fake-gw/assistants/default_assistant"
readonly PARENT_URL="https://us-discoveryengine.googleapis.com/v1alpha/${PARENT_PATH}"
readonly OUR_AGENT_ID="7000000000000000001"
readonly OTHER_AGENT_A_ID="7000000000000000002"
readonly OTHER_AGENT_B_ID="7000000000000000003"
readonly AGENT_NAME="${PARENT_PATH}/agents/${OUR_AGENT_ID}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# --- stubs -----------------------------------------------------------------

cat >"$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Replays $STUB_DIR/<n> ("code\nbody") in call order. Logs method + URL to
# calls.log, Authorization / X-Goog-User-Project headers to headers.log, and
# any --data-binary payload (read from stdin) to bodies.log.
[[ "$*" == *"--data-binary"* ]] && cat >>"$STUB_DIR/bodies.log"
echo "$*" | grep -oE '(-X [A-Z]+|https://[^ ]+)' | tr '\n' ' ' >>"$STUB_DIR/calls.log"
echo >>"$STUB_DIR/calls.log"
printf '%s\n' "$@" | grep -E '^(Authorization|X-Goog-User-Project):' >>"$STUB_DIR/headers.log" || true
n=$(cat "$STUB_DIR/n" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$STUB_DIR/n"
if [[ ! -f "$STUB_DIR/$n" ]]; then
  echo "curl stub: no fixture staged for call $n" >&2
  exit 7
fi
code=$(head -1 "$STUB_DIR/$n")
printf '%s\n%s' "$(tail -n +2 "$STUB_DIR/$n")" "$code"
STUB
# gcloud must never be consulted when GOOGLE_OAUTH_ACCESS_TOKEN is set; the
# stub fails loudly so a regression there shows up as a nonzero exit.
printf '#!/usr/bin/env bash\necho "gcloud stub: should not be called" >&2\nexit 9\n' >"$WORK/bin/gcloud"
chmod +x "$WORK/bin"/*

# A tiny fake PNG for the icon cases (content is irrelevant; extension is not).
printf 'PNG-BYTES-%s' "$RANDOM" >"$WORK/icon.png"
ICON_B64=$(base64 <"$WORK/icon.png" | tr -d '\n')
readonly ICON_B64

# --- harness ---------------------------------------------------------------

PASS=0
FAIL=0
CASE=0

# stage CODE BODY... -- queue canned responses for the next case
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

# invoke ACTION [VAR=value ...] -- run the shim; sets OUT, RC, CALLS, BODIES,
# HEADERS. Extra "VAR=value" arguments are exported for that run only.
invoke() {
  local action=$1
  shift
  set +e
  OUT=$(
    for kv in "$@"; do export "${kv?}"; done
    PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" \
      GOOGLE_OAUTH_ACCESS_TOKEN=fake \
      GE_PROJECT_ID=example-project \
      GE_PROJECT_NUMBER=123456789012 \
      GE_LOCATION="${GE_LOCATION:-us}" \
      GE_ENGINE_ID=fake-gw \
      GE_REASONING_ENGINE="${GE_REASONING_ENGINE:-$ENGINE_ID_FORM}" \
      bash "$TARGET" "$action" 2>&1
  )
  RC=$?
  set -e
  CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
  BODIES=$(cat "$STUB_DIR/bodies.log" 2>/dev/null || true)
  HEADERS=$(cat "$STUB_DIR/headers.log" 2>/dev/null || true)
}

# stdout_only -- the JSON the shim prints, with its stderr notes stripped.
stdout_only() { grep -v '^ge_agent.sh:' <<<"$OUT" || true; }

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

OK='200'

# The Google built-in that is ALWAYS on the app. No provisionedReasoningEngine.
DEEP_RESEARCH='{"name":"'"${PARENT_PATH}"'/agents/deep_research","displayName":"Deep Research","managedAgentDefinition":{},"state":"ENABLED"}'
agent_json() { # agent_json AGENT_ID ENGINE_NAME -> an ADK agent pointing at it
  printf '{"name":"%s/agents/%s","displayName":"agent-%s","state":"ENABLED","sharingConfig":{"scope":"ALL_USERS"},"adkAgentDefinition":{"provisionedReasoningEngine":{"reasoningEngine":"%s"}}}' \
    "$PARENT_PATH" "$1" "$1" "$2"
}
OURS=$(agent_json "$OUR_AGENT_ID" "$ENGINE_NUM_FORM")
OTHER_A=$(agent_json "$OTHER_AGENT_A_ID" "$ENGINE_OTHER_A")
OTHER_B=$(agent_json "$OTHER_AGENT_B_ID" "$ENGINE_OTHER_B")
EMPTY_LIST='{}'
ONLY_BUILTIN="{\"agents\":[${DEEP_RESEARCH}]}"
BUILTIN_PLUS_OURS="{\"agents\":[${DEEP_RESEARCH},${OURS}]}"
BUILTIN_PLUS_OTHERS="{\"agents\":[${DEEP_RESEARCH},${OTHER_A},${OTHER_B}]}"
# The realistic shared-app list: built-in, another team's agent, ours, another.
MIXED="{\"agents\":[${DEEP_RESEARCH},${OTHER_A},${OURS},${OTHER_B}]}"
CREATED="$OURS"
DELETE_LRO='{"name":"projects/123456789012/locations/us/operations/op-1","done":true}'

# --- cases: status ---------------------------------------------------------

echo "status finds OUR registration among several"
stage "$OK" "$MIXED"
invoke status
check "exits 0" "$RC" "0"
check "lists the assistant's agents" "$CALLS" "-X GET ${PARENT_URL}/agents"
check "reports our agent id" "$OUT" "has an agent for this engine: ${OUR_AGENT_ID}"
equal "stdout JSON names exactly our agent" "$(stdout_only | jq -r '.name')" "$AGENT_NAME"
equal "stdout JSON carries the server-side engine" \
  "$(stdout_only | jq -r '.adkAgentDefinition.provisionedReasoningEngine.reasoningEngine')" "$ENGINE_NUM_FORM"
equal "hasIcon is false when no icon is set" "$(stdout_only | jq -r '.hasIcon')" "false"
refute "does not name the other team's agent A" "$OUT" "$OTHER_AGENT_A_ID"
refute "does not name the other team's agent B" "$OUT" "$OTHER_AGENT_B_ID"
refute "reads only (no POST)" "$CALLS" "-X POST"
refute "reads only (no PATCH)" "$CALLS" "-X PATCH"
refute "reads only (no DELETE)" "$CALLS" "-X DELETE"
equal "exactly one request" "$(grep -c 'https://' <<<"$CALLS")" "1"

echo "status when absent -> exists:false, no writes"
stage "$OK" "$BUILTIN_PLUS_OTHERS"
invoke status
check "exits 0" "$RC" "0"
check "says no agent points at the engine" "$OUT" "no agent on fake-gw points at locations/us-central1/reasoningEngines/1111111111111111111"
equal "reports exists false" "$(stdout_only | jq -r '.exists')" "false"
equal "echoes the requested engine" "$(stdout_only | jq -r '.reasoningEngine')" "$ENGINE_ID_FORM"
refute "never adopts a different engine's agent" "$OUT" "$OTHER_AGENT_A_ID"

echo "status when the list is empty"
stage "$OK" "$EMPTY_LIST"
invoke status
check "exits 0" "$RC" "0"
equal "reports exists false" "$(stdout_only | jq -r '.exists')" "false"

# --- cases: create ---------------------------------------------------------

echo "no agents at all -> create"
stage "$OK" "$EMPTY_LIST" "$OK" "$CREATED"
invoke create
check "exits 0" "$RC" "0"
check "lists first" "$CALLS" "-X GET ${PARENT_URL}/agents"
check "POSTs to the assistant's agents collection" "$CALLS" "-X POST ${PARENT_URL}/agents"
check "uses v1alpha" "$CALLS" "/v1alpha/"
equal "body carries the engine the caller asked for" \
  "$(jq -r '.adkAgentDefinition.provisionedReasoningEngine.reasoningEngine' <<<"$BODIES")" "$ENGINE_ID_FORM"
equal "body publishes ALL_USERS by default" "$(jq -r '.sharingConfig.scope' <<<"$BODIES")" "ALL_USERS"
equal "body carries the default display name" "$(jq -r '.displayName' <<<"$BODIES")" "Governed SecOps Orchestrator"
equal "no description key when unset" "$(jq -r 'has("description")' <<<"$BODIES")" "false"
equal "no icon key when unset" "$(jq -r 'has("icon")' <<<"$BODIES")" "false"
check "says it is creating" "$OUT" "creating agent Governed SecOps Orchestrator on fake-gw"
check "reports the state and scope" "$OUT" "ok: ${OUR_AGENT_ID} is ENABLED, shared ALL_USERS"
check "prints the created resource name" "$(stdout_only)" "$AGENT_NAME"
check "sends the bearer token" "$HEADERS" "Authorization: Bearer fake"
check "sends the quota project header" "$HEADERS" "X-Goog-User-Project: example-project"
refute "never consults gcloud when a token is set" "$OUT" "gcloud stub"

echo "already present, ID form in / NUMBER form out -> ADOPT, no second agent"
stage "$OK" "$BUILTIN_PLUS_OURS"
invoke create
check "exits 0" "$RC" "0"
check "says it adopted" "$OUT" "already present as ${OUR_AGENT_ID} -- adopting"
refute "creates nothing" "$CALLS" "-X POST"
refute "patches nothing when no icon is configured" "$CALLS" "-X PATCH"
check "leaves icon unchanged" "$OUT" "leaving icon unchanged"
equal "prints the existing name" "$(stdout_only)" "$AGENT_NAME"
equal "exactly one request" "$(grep -c 'https://' <<<"$CALLS")" "1"

echo "already present among other teams' registrations -> adopts OURS only"
stage "$OK" "$MIXED"
invoke create
check "exits 0" "$RC" "0"
check "adopts our id" "$OUT" "already present as ${OUR_AGENT_ID}"
refute "creates nothing" "$CALLS" "-X POST"
equal "prints our name" "$(stdout_only)" "$AGENT_NAME"
refute "does not touch agent A" "$CALLS" "$OTHER_AGENT_A_ID"
refute "does not touch agent B" "$CALLS" "$OTHER_AGENT_B_ID"

echo "already present and the caller uses the NUMBER form too -> still adopts"
stage "$OK" "$BUILTIN_PLUS_OURS"
invoke create GE_REASONING_ENGINE="$ENGINE_NUM_FORM"
check "exits 0" "$RC" "0"
refute "creates nothing" "$CALLS" "-X POST"

echo "only the built-in is present -> does NOT adopt deep_research"
stage "$OK" "$ONLY_BUILTIN" "$OK" "$CREATED"
invoke create
check "creates ours" "$CALLS" "-X POST"
refute "never claims to adopt" "$OUT" "adopting"
refute "never names deep_research" "$CALLS" "deep_research"

echo "only other engines' agents are present -> not ours, creates"
stage "$OK" "$BUILTIN_PLUS_OTHERS" "$OK" "$CREATED"
invoke create
check "exits 0" "$RC" "0"
check "creates ours" "$CALLS" "-X POST ${PARENT_URL}/agents"
refute "never claims to adopt" "$OUT" "adopting"
refute "does not patch another engine's agent" "$CALLS" "-X PATCH"

echo "create with an icon -> icon rides in the POST body as a data URI"
stage "$OK" "$EMPTY_LIST" "$OK" "$CREATED"
invoke create GE_AGENT_ICON_PATH="$WORK/icon.png"
check "exits 0" "$RC" "0"
equal "icon uri is a png data URI with the file's base64" \
  "$(jq -r '.icon.uri' <<<"$BODIES")" "data:image/png;base64,${ICON_B64}"
refute "no separate PATCH on a fresh create" "$CALLS" "-X PATCH"

echo "adopt with an icon -> PATCHes icon on OUR registration only"
stage "$OK" "$MIXED" "$OK" '{"name":"'"$AGENT_NAME"'","icon":{"uri":"data:..."}}'
invoke create GE_AGENT_ICON_PATH="$WORK/icon.png"
check "exits 0" "$RC" "0"
check "says it adopted" "$OUT" "adopting"
check "PATCHes our agent with updateMask=icon" "$CALLS" "-X PATCH https://us-discoveryengine.googleapis.com/v1alpha/${AGENT_NAME}?updateMask=icon"
equal "PATCH body is only the icon" "$(jq -c 'keys' <<<"$BODIES")" '["icon"]'
check "reports success" "$OUT" "ok: icon set on ${OUR_AGENT_ID}"
refute "creates nothing" "$CALLS" "-X POST"
refute "does not patch agent A" "$CALLS" "$OTHER_AGENT_A_ID"
refute "does not patch agent B" "$CALLS" "$OTHER_AGENT_B_ID"
refute "does not patch deep_research" "$CALLS" "deep_research"
equal "exactly one PATCH" "$(grep -c -- '-X PATCH' <<<"$CALLS")" "1"

echo "adopt with an icon whose PATCH fails -> warns, still exits 0"
stage "$OK" "$BUILTIN_PLUS_OURS" 400 '{"error":{"message":"bad icon"}}'
invoke create GE_AGENT_ICON_PATH="$WORK/icon.png"
check "exits 0" "$RC" "0"
check "warns about the patch" "$OUT" "WARNING: icon patch failed (HTTP 400)"
check "surfaces the server message" "$OUT" "bad icon"
equal "still prints the adopted name" "$(stdout_only)" "$AGENT_NAME"

echo "RESTRICTED scope is honoured"
stage "$OK" "$EMPTY_LIST" "$OK" "$CREATED"
invoke create GE_AGENT_SHARING_SCOPE=RESTRICTED
equal "body carries RESTRICTED" "$(jq -r '.sharingConfig.scope' <<<"$BODIES")" "RESTRICTED"
check "reports the scope" "$OUT" "shared RESTRICTED"

echo "an invalid sharing scope is refused before any call"
stage "$OK" "$EMPTY_LIST"
invoke create GE_AGENT_SHARING_SCOPE=EVERYONE
check "exits 1" "$RC" "1"
check "names the allowed values" "$OUT" "GE_AGENT_SHARING_SCOPE must be ALL_USERS or RESTRICTED, got 'EVERYONE'"
refute "makes no request" "$CALLS" "https://"

echo "description is included when set"
stage "$OK" "$EMPTY_LIST" "$OK" "$CREATED"
invoke create GE_AGENT_DESCRIPTION="Governed SOC orchestration"
equal "description present" "$(jq -r '.description' <<<"$BODIES")" "Governed SOC orchestration"

echo "a display name with spaces survives into the request body"
stage "$OK" "$EMPTY_LIST" "$OK" "$CREATED"
invoke create "GE_AGENT_DISPLAY_NAME=Some Other Name"
equal "an override with spaces is not split or truncated" "$(jq -r '.displayName' <<<"$BODIES")" "Some Other Name"

echo "create rejected -> surfaces the status and body"
stage "$OK" "$EMPTY_LIST" 400 '{"error":{"message":"bad engine"}}'
invoke create
check "exits 1" "$RC" "1"
check "reports the HTTP code" "$OUT" "create failed (HTTP 400)"
check "includes the server message" "$OUT" "bad engine"

echo "create returned no name -> fatal"
stage "$OK" "$EMPTY_LIST" "$OK" '{"state":"ENABLED"}'
invoke create
check "exits 1" "$RC" "1"
check "explains" "$OUT" "create returned no resource name"

echo "a bad create state is surfaced but not fatal"
stage "$OK" "$EMPTY_LIST" "$OK" '{"name":"'"$AGENT_NAME"'","state":"CREATION_FAILED","creationFailureReason":"quota"}'
invoke create
check "exits 0" "$RC" "0"
check "warns about the state" "$OUT" "WARNING: created, but state is CREATION_FAILED"
check "surfaces the reason" "$OUT" "quota"

echo "403 on list -> fatal, no write attempted"
stage 403 '{"error":{"code":403}}'
invoke create
check "exits 1" "$RC" "1"
check "names the parent" "$OUT" "HTTP 403 listing agents on ${PARENT_PATH}"
refute "attempts no write" "$CALLS" "-X POST"

echo "404 on list -> fatal, names the assistant parent"
stage 404 '{"error":{"code":404}}'
invoke create
check "exits 1" "$RC" "1"
check "says no assistant" "$OUT" "no assistant at ${PARENT_PATH}"
refute "attempts no write" "$CALLS" "-X POST"

echo "other HTTP error on list -> fatal"
stage 500 '{"error":{"code":500}}'
invoke status
check "exits 1" "$RC" "1"
check "reports the code" "$OUT" "unexpected HTTP 500 listing agents"

echo "collection and assistant overrides are honoured"
stage "$OK" "$EMPTY_LIST" "$OK" "$CREATED"
invoke create GE_COLLECTION_ID=custom_collection GE_ASSISTANT_ID=custom_assistant
check "uses both in the path" "$CALLS" "/collections/custom_collection/engines/fake-gw/assistants/custom_assistant/agents"

# --- cases: icon -----------------------------------------------------------

echo "icon when present -> PATCHes our registration only"
stage "$OK" "$MIXED" "$OK" '{"name":"'"$AGENT_NAME"'"}'
invoke icon GE_AGENT_ICON_PATH="$WORK/icon.png"
check "exits 0" "$RC" "0"
check "says what it is doing" "$OUT" "setting icon from ${WORK}/icon.png on ${OUR_AGENT_ID}"
check "PATCHes our agent" "$CALLS" "-X PATCH https://us-discoveryengine.googleapis.com/v1alpha/${AGENT_NAME}?updateMask=icon"
equal "body is the png data URI" "$(jq -r '.icon.uri' <<<"$BODIES")" "data:image/png;base64,${ICON_B64}"
refute "does not touch agent A" "$CALLS" "$OTHER_AGENT_A_ID"
refute "does not touch agent B" "$CALLS" "$OTHER_AGENT_B_ID"
refute "no POST" "$CALLS" "-X POST"
refute "no DELETE" "$CALLS" "-X DELETE"

echo "icon when PATCH fails -> exits 1"
stage "$OK" "$BUILTIN_PLUS_OURS" 403 '{"error":{"message":"denied"}}'
invoke icon GE_AGENT_ICON_PATH="$WORK/icon.png"
check "exits 1" "$RC" "1"
check "warns" "$OUT" "icon patch failed (HTTP 403)"

echo "icon when absent -> fatal, points at create"
stage "$OK" "$BUILTIN_PLUS_OTHERS"
invoke icon GE_AGENT_ICON_PATH="$WORK/icon.png"
check "exits 1" "$RC" "1"
check "tells the operator to create first" "$OUT" "run 'ge_agent.sh create' first"
refute "no PATCH" "$CALLS" "-X PATCH"

echo "icon with a missing file -> fatal, no write"
stage "$OK" "$BUILTIN_PLUS_OURS"
invoke icon GE_AGENT_ICON_PATH="$WORK/does-not-exist.png"
check "exits 1" "$RC" "1"
check "names the missing path" "$OUT" "GE_AGENT_ICON_PATH points at no file: ${WORK}/does-not-exist.png"
refute "no PATCH" "$CALLS" "-X PATCH"

echo "a relative icon path is resolved against the repo root"
stage "$OK" "$BUILTIN_PLUS_OURS"
invoke icon GE_AGENT_ICON_PATH="governed_agents/soc_orchestrator/no-such-icon.png"
check "exits 1" "$RC" "1"
check "resolved under REPO_ROOT" "$OUT" "points at no file: ${REPO_ROOT}/governed_agents/soc_orchestrator/no-such-icon.png"

echo "an unsupported icon extension is refused"
printf 'x' >"$WORK/icon.bmp"
stage "$OK" "$BUILTIN_PLUS_OURS"
invoke icon GE_AGENT_ICON_PATH="$WORK/icon.bmp"
check "exits 1" "$RC" "1"
check "names the allowed extensions" "$OUT" "use .png, .jpg, .gif, .webp, or .svg"
refute "no PATCH" "$CALLS" "-X PATCH"

echo "create with a missing icon file -> fatal before POST"
stage "$OK" "$EMPTY_LIST"
invoke create GE_AGENT_ICON_PATH="$WORK/does-not-exist.png"
check "exits 1" "$RC" "1"
check "names the missing path" "$OUT" "points at no file"
refute "no POST" "$CALLS" "-X POST"

echo "icon with no GE_AGENT_ICON_PATH -> no-op, exits 0"
stage "$OK" "$BUILTIN_PLUS_OURS"
invoke icon
check "exits 0" "$RC" "0"
check "says it left the icon alone" "$OUT" "leaving icon unchanged"
refute "no PATCH" "$CALLS" "-X PATCH"

# --- cases: delete ---------------------------------------------------------

echo "delete when present among others -> DELETEs ONLY our agent id"
stage "$OK" "$MIXED" "$OK" "$DELETE_LRO"
invoke delete
check "exits 0" "$RC" "0"
check "says which id it deletes" "$OUT" "deleting ${OUR_AGENT_ID} from fake-gw"
check "DELETEs our agent by full name" "$CALLS" "-X DELETE https://us-discoveryengine.googleapis.com/v1alpha/${AGENT_NAME}"
equal "exactly one DELETE" "$(grep -c -- '-X DELETE' <<<"$CALLS")" "1"
equal "exactly two requests (GET then DELETE)" "$(grep -c 'https://' <<<"$CALLS")" "2"
equal "the DELETE URL ends in our agent id" \
  "$(grep -- '-X DELETE' <<<"$CALLS" | grep -oE 'agents/[^ ?]+')" "agents/${OUR_AGENT_ID}"
refute "does not name agent A anywhere" "$CALLS" "$OTHER_AGENT_A_ID"
refute "does not name agent B anywhere" "$CALLS" "$OTHER_AGENT_B_ID"
refute "does not name deep_research" "$CALLS" "deep_research"
check "reports the operation" "$OUT" "ok: delete accepted (operation op-1, done=true)"

echo "delete when absent -> no write"
stage "$OK" "$ONLY_BUILTIN"
invoke delete
check "exits 0" "$RC" "0"
check "says nothing to do" "$OUT" "nothing to do"
refute "issues no DELETE" "$CALLS" "-X DELETE"
equal "exactly one request" "$(grep -c 'https://' <<<"$CALLS")" "1"

echo "delete never touches the built-in or other engines' agents"
stage "$OK" "$BUILTIN_PLUS_OTHERS"
invoke delete
check "exits 0" "$RC" "0"
check "says nothing to do" "$OUT" "nothing to do"
refute "issues no DELETE" "$CALLS" "-X DELETE"
refute "does not name deep_research" "$CALLS" "deep_research"
refute "does not name agent A" "$CALLS" "$OTHER_AGENT_A_ID"
refute "does not name agent B" "$CALLS" "$OTHER_AGENT_B_ID"

echo "delete on an empty list -> no write"
stage "$OK" "$EMPTY_LIST"
invoke delete
check "exits 0" "$RC" "0"
refute "issues no DELETE" "$CALLS" "-X DELETE"

echo "delete rejected -> surfaces the status"
stage "$OK" "$BUILTIN_PLUS_OURS" 409 '{"error":{"message":"in use"}}'
invoke delete
check "exits 1" "$RC" "1"
check "reports the code" "$OUT" "delete failed (HTTP 409)"
check "includes the server message" "$OUT" "in use"

# --- cases: host, version, env, usage --------------------------------------

echo "the API host is derived from GE_LOCATION, and the version is always v1alpha"
stage "$OK" "$ONLY_BUILTIN"
invoke status
check "us is prefixed" "$CALLS" "https://us-discoveryengine.googleapis.com/v1alpha/projects/123456789012/locations/us/"
refute "us does not fall back to the global host" "$CALLS" "https://discoveryengine.googleapis.com/"
stage "$OK" "$ONLY_BUILTIN"
invoke status GE_LOCATION=eu
check "eu is prefixed" "$CALLS" "https://eu-discoveryengine.googleapis.com/v1alpha/projects/123456789012/locations/eu/"
stage "$OK" "$ONLY_BUILTIN"
invoke status GE_LOCATION=global
check "global is the one unprefixed host" "$CALLS" "https://discoveryengine.googleapis.com/v1alpha/projects/123456789012/locations/global/"
refute "global is not itself prefixed" "$CALLS" "global-discoveryengine.googleapis.com"
refute "never uses v1" "$CALLS" "/v1/"
refute "never uses v1beta" "$CALLS" "/v1beta/"

echo "a bare engine id is refused before any call"
stage "$OK" "$EMPTY_LIST"
invoke create GE_REASONING_ENGINE=1111111111111111111
check "exits 1" "$RC" "1"
check "explains the expected form" "$OUT" "GE_REASONING_ENGINE must be a full resource name"
refute "makes no request" "$CALLS" "https://"

echo "an unknown action is refused before any call"
stage "$OK" "$EMPTY_LIST"
invoke frobnicate
check "exits 1" "$RC" "1"
check "prints usage" "$OUT" "usage: ge_agent.sh status|create|icon|delete"
refute "makes no request" "$CALLS" "https://"

echo "no action defaults to status"
stage "$OK" "$BUILTIN_PLUS_OURS"
set +e
OUT=$(PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" GOOGLE_OAUTH_ACCESS_TOKEN=fake \
  GE_PROJECT_ID=example-project GE_PROJECT_NUMBER=123456789012 \
  GE_LOCATION=us GE_ENGINE_ID=fake-gw GE_REASONING_ENGINE="$ENGINE_ID_FORM" \
  bash "$TARGET" 2>&1)
RC=$?
set -e
CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
check "exits 0" "$RC" "0"
check "lists" "$CALLS" "-X GET ${PARENT_URL}/agents"
refute "writes nothing" "$CALLS" "-X POST"

echo "missing required env -> refuses before any call"
run_bare() { # run_bare ACTION [VAR=value ...] -- no defaults injected
  set +e
  OUT=$(env -i PATH="$WORK/bin:$PATH" HOME="$HOME" STUB_DIR="$STUB_DIR" \
    GOOGLE_OAUTH_ACCESS_TOKEN=fake "${@:2}" bash "$TARGET" "$1" 2>&1)
  RC=$?
  set -e
  CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
}
stage "$OK" "$EMPTY_LIST"
run_bare create
check "exits 1" "$RC" "1"
check "GE_PROJECT_ID first" "$OUT" "GE_PROJECT_ID must be set"
run_bare create GE_PROJECT_ID=example-project
check "then GE_PROJECT_NUMBER" "$OUT" "GE_PROJECT_NUMBER must be set"
run_bare create GE_PROJECT_ID=example-project GE_PROJECT_NUMBER=123456789012
check "then GE_LOCATION" "$OUT" "GE_LOCATION must be set"
run_bare create GE_PROJECT_ID=example-project GE_PROJECT_NUMBER=123456789012 GE_LOCATION=us
check "then GE_ENGINE_ID" "$OUT" "GE_ENGINE_ID must be set"
run_bare create GE_PROJECT_ID=example-project GE_PROJECT_NUMBER=123456789012 GE_LOCATION=us GE_ENGINE_ID=fake-gw
check "then GE_REASONING_ENGINE" "$OUT" "GE_REASONING_ENGINE must be set"
refute "none of those made a request" "$CALLS" "https://"

echo "no token and gcloud cannot mint one -> fatal before any call"
stage "$OK" "$EMPTY_LIST"
set +e
OUT=$(PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" GOOGLE_OAUTH_ACCESS_TOKEN='' \
  GE_PROJECT_ID=example-project GE_PROJECT_NUMBER=123456789012 \
  GE_LOCATION=us GE_ENGINE_ID=fake-gw GE_REASONING_ENGINE="$ENGINE_ID_FORM" \
  bash "$TARGET" status 2>&1)
RC=$?
set -e
CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
check "exits 1" "$RC" "1"
check "explains how to authenticate" "$OUT" "could not obtain an ADC access token"
refute "makes no request" "$CALLS" "https://"

# --- result ----------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
