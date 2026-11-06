#!/usr/bin/env bash
#
# Offline branch tests for scripts/governance/auth_provider.sh, the Auth
# Manager shim that holds the Google Threat Intelligence API key for
# cti_researcher on agentidentity.googleapis.com/v1 (terraform/20-authmanager.tf).
#
# Stubs curl, gcloud and sleep on PATH, so this makes no network calls and
# never touches a real AuthProvider. GOOGLE_OAUTH_ACCESS_TOKEN is set to a
# fake value so the shim never shells out to gcloud; the gcloud stub exists
# only to prove that (and to exercise the one case where it is needed).
#
#     bash scripts/governance/tests/auth_provider_test.sh
#
# The property that matters most: the key value must never reach stdout,
# stderr or a curl argv. Every case feeds its combined output into one
# accumulator that is checked at the end, on top of the per-case refutes.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly SCRIPT_DIR
readonly TARGET="${SCRIPT_DIR}/auth_provider.sh"

readonly PROJECT_ID="example-project"
readonly LOCATION="us-central1"
readonly PROVIDER_ID="agw-secops-gti-api-key"
readonly FAKE_KEY='FAKE-GTI-KEY-0001' # gitleaks:allow
readonly OTHER_KEY='FAKE-GTI-KEY-0002' # gitleaks:allow
readonly BASE="https://agentidentity.googleapis.com/v1"
readonly PARENT="projects/${PROJECT_ID}/locations/${LOCATION}"
readonly NAME="${PARENT}/authProviders/${PROVIDER_ID}"
readonly MEMBER="principal://agents.global.org-1.system.id.goog/resources/fake-cti-researcher"
readonly OTHER_MEMBER="principal://agents.global.org-1.system.id.goog/resources/fake-threat-hunter"

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
# gcloud must never run while GOOGLE_OAUTH_ACCESS_TOKEN is set. The stub
# records any call so the harness can prove that, and fails loudly.
cat >"$WORK/bin/gcloud" <<'STUB'
#!/usr/bin/env bash
printf 'gcloud %s\n' "$*" >>"$STUB_DIR/gcloud.log"
exit 1
STUB
# The shim sleeps 5s after every write ("settle"). Skip it, but record it.
cat >"$WORK/bin/sleep" <<'STUB'
#!/usr/bin/env bash
printf 'sleep %s\n' "$*" >>"$STUB_DIR/sleep.log"
exit 0
STUB
chmod +x "$WORK/bin"/*

# --- harness ---------------------------------------------------------------

PASS=0
FAIL=0
CASE=0
ALL_OUT=""

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
# ARGV, GCLOUD_CALLS, SLEEPS. Extra "VAR=value" arguments are exported for
# that run only and override the defaults below; "VAR=" clears one.
invoke() {
  local action=$1
  shift
  set +e
  OUT=$(
    export GOOGLE_OAUTH_ACCESS_TOKEN="fake-token"
    export AUTH_PROVIDER_PROJECT="$PROJECT_ID"
    export AUTH_PROVIDER_LOCATION="$LOCATION"
    export AUTH_PROVIDER_ID="$PROVIDER_ID"
    export AUTH_PROVIDER_DESCRIPTION="GTI key"
    export AUTH_PROVIDER_WORKLOAD_IDS="[]"
    export AUTH_PROVIDER_MEMBER="$MEMBER"
    export GTI_API_KEY="$FAKE_KEY"
    for kv in "$@"; do export "${kv?}"; done
    PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" bash "$TARGET" "$action" 2>&1
  )
  RC=$?
  set -e
  ALL_OUT+="$OUT"$'\n'
  CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
  BODIES=$(cat "$STUB_DIR/bodies.log" 2>/dev/null || true)
  ARGV=$(cat "$STUB_DIR/argv.log" 2>/dev/null || true)
  GCLOUD_CALLS=$(cat "$STUB_DIR/gcloud.log" 2>/dev/null || true)
  SLEEPS=$(cat "$STUB_DIR/sleep.log" 2>/dev/null || true)
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

# key_leaks DESCRIPTION : the key must not be in output or on any curl argv.
# Its only legal channel is the request body on curl's stdin.
key_leaks() {
  refute "$1: key not in stdout/stderr" "$OUT" "$FAKE_KEY"
  refute "$1: key not on any curl argv" "$ARGV" "$FAKE_KEY"
}

readonly OK='200'
readonly BODY_LIVE="{\"name\":\"${NAME}\",\"deleted\":false}"
readonly BODY_SOFT_DELETED="{\"name\":\"${NAME}\",\"deleted\":true}"
readonly NOT_FOUND='{"error":{"code":404,"status":"NOT_FOUND"}}'
readonly FORBIDDEN='{"error":{"code":403,"status":"PERMISSION_DENIED"}}'

# --- upsert ----------------------------------------------------------------

echo "upsert: absent -> create"
stage 404 "$NOT_FOUND" "$OK" "$BODY_LIVE"
invoke upsert
equal "exits 0" "$RC" "0"
check "reads the resource first with GET" "$CALLS" "-X GET ${BASE}/${NAME}"
check "POSTs to the collection with authProviderId" "$CALLS" \
  "-X POST ${BASE}/${PARENT}/authProviders?authProviderId=${PROVIDER_ID}"
refute "does not PATCH" "$CALLS" "-X PATCH"
equal "exactly two HTTP calls" "$(grep -c 'https://' <<<"$CALLS")" "2"
# Assert on the parsed value: jq -n pretty-prints, so raw text has whitespace.
equal "sends the key at authProviderTypeParams.apiKey.apiKey (stdin only)" \
  "$(jq -r '.authProviderTypeParams.apiKey.apiKey' <<<"$BODIES")" "$FAKE_KEY"
equal "sends the description" "$(jq -r '.description' <<<"$BODIES")" "GTI key"
refute "omits workloadIds when the list is empty" "$BODIES" '"workloadIds"'
refute "does not send labels" "$BODIES" '"labels"'
check "sends the bearer token" "$ARGV" "Authorization: Bearer fake-token"
check "sets the quota project header" "$ARGV" "X-Goog-User-Project: ${PROJECT_ID}"
check "says it is creating" "$OUT" "creating ${NAME}"
check "ends with ok" "$OUT" "ok: ${NAME}"
refute "never calls gcloud when a token is set" "$GCLOUD_CALLS" "gcloud"
check "settles after the write" "$SLEEPS" "sleep 5"
key_leaks "create"

echo "upsert: present -> PATCH in place (the version-bump rotation path)"
# terraform_data replaces on var.gti_api_key_version, which re-runs upsert
# against a live provider; that is a PATCH of the key, not a delete+create.
stage "$OK" "$BODY_LIVE" "$OK" "$BODY_LIVE"
invoke upsert
equal "exits 0" "$RC" "0"
check "PATCHes the resource with the two-field mask" "$CALLS" \
  "-X PATCH ${BASE}/${NAME}?updateMask=authProviderTypeParams,description"
refute "does not create" "$CALLS" "-X POST"
refute "does not delete" "$CALLS" "-X DELETE"
refute "does not undelete a live provider" "$CALLS" ":undelete"
equal "PATCH body carries the new key" \
  "$(jq -r '.authProviderTypeParams.apiKey.apiKey' <<<"$BODIES")" "$FAKE_KEY"
check "says it is updating" "$OUT" "updating ${NAME}"
key_leaks "update"

echo "upsert: present and unchanged -> still a single idempotent PATCH"
# The shim cannot read the stored key back, so it cannot diff; a re-run with
# the same key is one PATCH with identical content and no other side effect.
stage "$OK" "$BODY_LIVE" "$OK" "$BODY_LIVE"
invoke upsert
equal "exits 0" "$RC" "0"
equal "exactly two HTTP calls (GET, PATCH)" "$(grep -c 'https://' <<<"$CALLS")" "2"
equal "exactly one PATCH" "$(grep -c -- '-X PATCH' <<<"$CALLS")" "1"
refute "no create" "$CALLS" "-X POST"
check "reports ok" "$OUT" "ok: ${NAME}"
key_leaks "unchanged"

echo "upsert: soft-deleted -> :undelete, then PATCH"
stage "$OK" "$BODY_SOFT_DELETED" "$OK" "$BODY_LIVE" "$OK" "$BODY_LIVE"
invoke upsert
equal "exits 0" "$RC" "0"
check "says it is undeleting" "$OUT" "soft-deleted -- undeleting"
check "POSTs :undelete" "$CALLS" "-X POST ${BASE}/${NAME}:undelete"
check "then PATCHes" "$CALLS" "-X PATCH ${BASE}/${NAME}?updateMask="
refute "does not try to create over a soft-deleted ID" "$CALLS" "authProviderId="
equal "undelete precedes PATCH" \
  "$(grep -oE -- '-X (POST|PATCH)' <<<"$CALLS" | tr '\n' ' ')" "-X POST -X PATCH "
key_leaks "undelete"

echo "upsert: :undelete fails -> loud, no PATCH over an unrestored record"
stage "$OK" "$BODY_SOFT_DELETED" 500 '{"error":{"code":500}}'
invoke upsert
equal "exits 1" "$RC" "1"
check "names the failed step and code" "$OUT" "undelete failed (HTTP 500)"
refute "does not PATCH" "$CALLS" "-X PATCH"
key_leaks "undelete failure"

echo "upsert: workloadIds set -> field sent and mask extended"
stage "$OK" "$BODY_LIVE" "$OK" "$BODY_LIVE"
invoke upsert "AUTH_PROVIDER_WORKLOAD_IDS=[\"${MEMBER}\"]"
equal "exits 0" "$RC" "0"
check "mask includes workloadIds" "$CALLS" \
  "updateMask=authProviderTypeParams,description,workloadIds"
equal "body carries exactly the listed workload identity" \
  "$(jq -r '.workloadIds | join(",")' <<<"$BODIES")" "$MEMBER"
key_leaks "workloadIds"

echo "upsert: workloadIds empty -> omitted from mask (an empty list would clear it)"
stage "$OK" "$BODY_LIVE" "$OK" "$BODY_LIVE"
invoke upsert "AUTH_PROVIDER_WORKLOAD_IDS=[]"
equal "exits 0" "$RC" "0"
refute "mask omits workloadIds" "$CALLS" "workloadIds"
refute "body omits workloadIds" "$BODIES" '"workloadIds"'

echo "upsert: TF_VAR_gti_api_key is accepted when GTI_API_KEY is unset"
stage 404 "$NOT_FOUND" "$OK" "$BODY_LIVE"
invoke upsert "GTI_API_KEY=" "TF_VAR_gti_api_key=${FAKE_KEY}"
equal "exits 0" "$RC" "0"
equal "the TF_VAR key is what gets sent" \
  "$(jq -r '.authProviderTypeParams.apiKey.apiKey' <<<"$BODIES")" "$FAKE_KEY"
key_leaks "TF_VAR fallback"

echo "upsert: GTI_API_KEY wins over TF_VAR_gti_api_key when both are set"
stage 404 "$NOT_FOUND" "$OK" "$BODY_LIVE"
invoke upsert "TF_VAR_gti_api_key=${OTHER_KEY}"
equal "exits 0" "$RC" "0"
equal "sends GTI_API_KEY" \
  "$(jq -r '.authProviderTypeParams.apiKey.apiKey' <<<"$BODIES")" "$FAKE_KEY"
refute "does not send the TF_VAR value" "$BODIES" "$OTHER_KEY"

echo "upsert: no key at all -> refused before any HTTP call"
stage
invoke upsert "GTI_API_KEY=" "TF_VAR_gti_api_key="
equal "exits 1" "$RC" "1"
check "names both accepted variables" "$OUT" "Set GTI_API_KEY or TF_VAR_gti_api_key"
refute "makes no HTTP call" "$CALLS" "https://"

echo "upsert: 403 on read -> names the API to enable, no write attempted"
stage 403 "$FORBIDDEN"
invoke upsert
equal "exits 1" "$RC" "1"
check "names the API and project" "$OUT" \
  "agentidentity.googleapis.com is enabled in ${PROJECT_ID}"
refute "attempts no write" "$CALLS" "-X POST"
refute "attempts no PATCH" "$CALLS" "-X PATCH"
key_leaks "403"

echo "upsert: unexpected code on read -> loud, no write"
stage 500 '{"error":{"code":500,"status":"INTERNAL"}}'
invoke upsert
equal "exits 1" "$RC" "1"
check "reports the code" "$OUT" "unexpected HTTP 500 reading ${NAME}"
refute "attempts no write" "$CALLS" "-X POST"

echo "upsert: create rejected -> non-zero, code surfaced"
stage 404 "$NOT_FOUND" 409 '{"error":{"code":409,"status":"ALREADY_EXISTS"}}'
invoke upsert
equal "exits 1" "$RC" "1"
check "names the failed step and code" "$OUT" "create failed (HTTP 409)"
check "passes the server status through" "$OUT" "ALREADY_EXISTS"
refute "does not claim ok" "$OUT" "ok: ${NAME}"

echo "upsert: PATCH rejected -> non-zero, code surfaced"
stage "$OK" "$BODY_LIVE" 400 '{"error":{"code":400,"status":"INVALID_ARGUMENT"}}'
invoke upsert
equal "exits 1" "$RC" "1"
check "names the failed step and code" "$OUT" "update failed (HTTP 400)"
refute "does not claim ok" "$OUT" "ok: ${NAME}"

echo "upsert: server echoes the key back in an error -> redacted"
stage 404 "$NOT_FOUND" 400 "{\"error\":{\"message\":\"bad key ${FAKE_KEY} rejected\"}}"
invoke upsert
equal "exits 1" "$RC" "1"
check "shows the redaction marker" "$OUT" "bad key [REDACTED] rejected"
key_leaks "echoed key"

echo "upsert: server echoes the TF_VAR-supplied key back -> also redacted"
stage 404 "$NOT_FOUND" 400 "{\"error\":{\"message\":\"bad key ${FAKE_KEY} rejected\"}}"
invoke upsert "GTI_API_KEY=" "TF_VAR_gti_api_key=${FAKE_KEY}"
equal "exits 1" "$RC" "1"
check "shows the redaction marker" "$OUT" "[REDACTED]"
key_leaks "echoed TF_VAR key"

# --- grant -----------------------------------------------------------------

echo "grant: empty policy -> one binding for exactly the one member"
stage "$OK" '{"etag":"ACAB"}' "$OK" '{"etag":"BQDE"}'
invoke grant
equal "exits 0" "$RC" "0"
check "reads the policy with GET, not POST" "$CALLS" "-X GET ${BASE}/${NAME}:getIamPolicy"
refute "never POSTs :getIamPolicy" "$CALLS" "-X POST ${BASE}/${NAME}:getIamPolicy"
check "writes with POST :setIamPolicy" "$CALLS" "-X POST ${BASE}/${NAME}:setIamPolicy"
equal "one binding" "$(jq -r '.policy.bindings | length' <<<"$BODIES")" "1"
equal "role defaults to roles/agentidentity.user" \
  "$(jq -r '.policy.bindings[0].role' <<<"$BODIES")" "roles/agentidentity.user"
equal "members are exactly the requested principal" \
  "$(jq -r '.policy.bindings[0].members | join(",")' <<<"$BODIES")" "$MEMBER"
equal "sends the etag back" "$(jq -r '.policy.etag' <<<"$BODIES")" "ACAB"
refute "does not send the key during grant" "$BODIES" "apiKey"
check "reports the grant" "$OUT" "ok: roles/agentidentity.user -> ${MEMBER} on ${NAME}"
key_leaks "grant"

echo "grant: existing binding for another principal -> appended, not replaced"
stage "$OK" "{\"etag\":\"ACAB\",\"bindings\":[{\"role\":\"roles/agentidentity.user\",\"members\":[\"${OTHER_MEMBER}\"]},{\"role\":\"roles/viewer\",\"members\":[\"group:fake-soc@example.com\"]}]}" \
  "$OK" '{}'
invoke grant
equal "exits 0" "$RC" "0"
equal "still two bindings" "$(jq -r '.policy.bindings | length' <<<"$BODIES")" "2"
equal "the role binding now holds both principals, sorted" \
  "$(jq -r '.policy.bindings[] | select(.role=="roles/agentidentity.user") | .members | join(",")' <<<"$BODIES")" \
  "${MEMBER},${OTHER_MEMBER}"
equal "the unrelated binding is untouched" \
  "$(jq -r '.policy.bindings[] | select(.role=="roles/viewer") | .members | join(",")' <<<"$BODIES")" \
  "group:fake-soc@example.com"

echo "grant: member already bound -> no write"
stage "$OK" "{\"etag\":\"ACAB\",\"bindings\":[{\"role\":\"roles/agentidentity.user\",\"members\":[\"${MEMBER}\"]}]}"
invoke grant
equal "exits 0" "$RC" "0"
check "says it is already granted" "$OUT" "already has roles/agentidentity.user"
refute "does not call setIamPolicy" "$CALLS" "setIamPolicy"
refute "does not settle when nothing changed" "$SLEEPS" "sleep"

echo "grant: AUTH_PROVIDER_ROLE overrides the default role"
stage "$OK" '{"etag":"ACAB"}' "$OK" '{}'
invoke grant "AUTH_PROVIDER_ROLE=roles/agentidentity.viewer"
equal "exits 0" "$RC" "0"
equal "writes the requested role" \
  "$(jq -r '.policy.bindings[0].role' <<<"$BODIES")" "roles/agentidentity.viewer"

echo "grant: malformed member -> refused before any HTTP call"
stage
invoke grant "AUTH_PROVIDER_MEMBER=fake-cti-researcher"
equal "exits 1" "$RC" "1"
check "explains the required shape" "$OUT" "must be a fully-qualified IAM member, got: fake-cti-researcher"
refute "makes no HTTP call" "$CALLS" "https://"

echo "grant: missing AUTH_PROVIDER_MEMBER -> refused"
stage
invoke grant "AUTH_PROVIDER_MEMBER="
equal "exits 1" "$RC" "1"
check "names the variable" "$OUT" "AUTH_PROVIDER_MEMBER must be set"
refute "makes no HTTP call" "$CALLS" "https://"

echo "grant: getIamPolicy non-2xx -> loud, no write"
stage 403 "$FORBIDDEN"
invoke grant
equal "exits 1" "$RC" "1"
check "names the step and code" "$OUT" "reading IAM policy on ${NAME} failed (HTTP 403)"
refute "does not call setIamPolicy" "$CALLS" "setIamPolicy"

echo "grant: setIamPolicy non-2xx -> loud"
stage "$OK" '{"etag":"ACAB"}' 409 '{"error":{"code":409,"status":"ABORTED"}}'
invoke grant
equal "exits 1" "$RC" "1"
check "names the step and code" "$OUT" "setIamPolicy on ${NAME} failed (HTTP 409)"
refute "does not claim ok" "$OUT" "ok: roles/"

# --- delete ----------------------------------------------------------------

echo "delete"
stage "$OK" '{}'
invoke delete
equal "exits 0" "$RC" "0"
check "issues DELETE on the resource" "$CALLS" "-X DELETE ${BASE}/${NAME}"
equal "exactly one HTTP call" "$(grep -c 'https://' <<<"$CALLS")" "1"
check "reports soft-deletion" "$OUT" "soft-deleted ${NAME}"
refute "sends no body" "$ARGV" "--data-binary"

echo "delete returns 404 -> success, but flags the ambiguity"
stage 404 "$NOT_FOUND"
invoke delete
equal "exits 0" "$RC" "0"
check "names both possibilities" "$OUT" "already absent or soft-deleted"
check "points at the recovery path" "$OUT" "upsert will :undelete if needed"

echo "delete returns another non-2xx -> non-zero"
stage 403 "$FORBIDDEN"
invoke delete
equal "exits 1" "$RC" "1"
check "names the step and code" "$OUT" "delete failed (HTTP 403)"

echo "delete does not need a key in the environment (destroy-time provisioner)"
stage "$OK" '{}'
invoke delete "GTI_API_KEY=" "TF_VAR_gti_api_key="
equal "exits 0" "$RC" "0"

# --- preconditions ---------------------------------------------------------

echo "unknown action -> usage"
stage
invoke status
equal "exits 1" "$RC" "1"
check "prints usage" "$OUT" "usage: auth_provider.sh upsert|grant|delete"
refute "makes no HTTP call" "$CALLS" "https://"

echo "no action -> usage"
stage
invoke ""
equal "exits 1" "$RC" "1"
check "prints usage" "$OUT" "usage: auth_provider.sh"

for var in AUTH_PROVIDER_PROJECT AUTH_PROVIDER_LOCATION AUTH_PROVIDER_ID; do
  echo "missing ${var} -> refused before any HTTP call"
  stage
  invoke upsert "${var}="
  equal "exits 1" "$RC" "1"
  check "names the variable" "$OUT" "${var} must be set"
  refute "makes no HTTP call" "$CALLS" "https://"
  refute "does not call gcloud" "$GCLOUD_CALLS" "gcloud"
done

echo "no token -> asks gcloud for ADC, and fails clearly when it cannot"
stage
invoke upsert "GOOGLE_OAUTH_ACCESS_TOKEN="
equal "exits 1" "$RC" "1"
check "asks for an ADC token" "$GCLOUD_CALLS" "gcloud auth application-default print-access-token"
check "explains how to recover" "$OUT" "could not obtain an ADC access token"
refute "makes no HTTP call" "$CALLS" "https://"
key_leaks "no token"

# --- the invariant, across every case --------------------------------------

echo "key never appears in any case's combined stdout+stderr"
refute "fake key absent from all output" "$ALL_OUT" "$FAKE_KEY"
refute "the TF_VAR decoy is absent too" "$ALL_OUT" "$OTHER_KEY"
equal "key never appears on any curl argv in any case" \
  "$(grep -l -- "$FAKE_KEY" "$WORK"/case-*/argv.log 2>/dev/null | wc -l | tr -d ' ')" "0"
# Staged fixtures (case-*/<n>) legitimately contain the key for the echo
# cases; only the stub logs record what the shim actually emitted.
equal "key never lands in a stub log other than bodies.log" \
  "$(grep -l -- "$FAKE_KEY" "$WORK"/case-*/*.log 2>/dev/null | grep -vc '/bodies.log$' || true)" "0"

# --- result ----------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
