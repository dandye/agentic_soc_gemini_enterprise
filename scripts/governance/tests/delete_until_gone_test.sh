#!/usr/bin/env bash
#
# Offline branch tests for scripts/governance/delete_until_gone.sh.
# Stubs curl, gcloud and sleep on PATH; no network calls, no credentials.
#
#     bash scripts/governance/tests/delete_until_gone_test.sh

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly SCRIPT_DIR
readonly DUG="${SCRIPT_DIR}/delete_until_gone.sh"

readonly PROJECT="example-project"
readonly URL_A="https://iam.googleapis.com/v3/projects/${PROJECT}/locations/global/policyBindings/agw-secops-cti-researcher"
readonly URL_B="https://iam.googleapis.com/v3/projects/${PROJECT}/locations/global/policyBindings/agw-secops-threat-hunter"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# --- stubs -----------------------------------------------------------------

cat >"$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Replays $STUB_DIR/<n> ("code\nbody") in call order; logs method+URL and the
# raw arguments (for header checks) separately. Mimics curl -w '\n%{http_code}'.
echo "$*" | grep -oE '(-X [A-Z]+|https://[^ ]+)' | tr '\n' ' ' >>"$STUB_DIR/calls.log"
echo >>"$STUB_DIR/calls.log"
echo "$*" >>"$STUB_DIR/args.log"
n=$(cat "$STUB_DIR/n" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$STUB_DIR/n"
if [[ ! -f "$STUB_DIR/$n" ]]; then
  echo "curl stub: no staged response #$n" >&2
  exit 7
fi
code=$(head -1 "$STUB_DIR/$n")
printf '%s\n%s' "$(tail -n +2 "$STUB_DIR/$n")" "$code"
STUB

cat >"$WORK/bin/gcloud" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$STUB_DIR/gcloud.log"
if [[ -n ${GCLOUD_STUB_FAIL:-} ]]; then
  echo "ERROR: no credentials" >&2
  exit 1
fi
echo stub-access-token
STUB

cat >"$WORK/bin/sleep" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$STUB_DIR/sleep.log"
exit 0
STUB
chmod +x "$WORK/bin"/*

# --- harness ---------------------------------------------------------------

PASS=0
FAIL=0
CASE=0

# stage CODE BODY... - queue canned curl responses for the next case
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

# invoke ARG... - sets OUT, RC, CALLS, ARGS, GCLOUD, SLEEPS
invoke() {
  set +e
  OUT=$(
    PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" DG_POLL_SECONDS=1 \
      bash "$DUG" "$@" 2>&1
  )
  RC=$?
  set -e
  CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
  ARGS=$(cat "$STUB_DIR/args.log" 2>/dev/null || true)
  GCLOUD=$(cat "$STUB_DIR/gcloud.log" 2>/dev/null || true)
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

echo "delete_until_gone.sh"

echo "  DELETE 200, then GET 200, then GET 404 -> success, polled twice"
stage 200 '' 200 '{}' 404 '{"error":{"code":404}}'
invoke "$PROJECT" "$URL_A"
equal "exits 0" "$RC" "0"
check "deletes it" "$CALLS" "-X DELETE ${URL_A}"
check "reports delete accepted" "$OUT" "delete accepted (HTTP 200): ${URL_A}"
check "reports still present with elapsed time" "$OUT" "still present (0s/300s): ${URL_A}"
check "confirms gone" "$OUT" "confirmed gone: ${URL_A}"
equal "polled GET twice" "$(grep -c -- "-X GET ${URL_A}" <<<"$CALLS")" "2"
equal "slept once between polls with DG_POLL_SECONDS" "$SLEEPS" "1"
equal "made exactly three requests" "$(grep -c . <<<"$CALLS")" "3"

echo "  DELETE 200, GET 200 x3, then GET 404 -> retries until gone"
stage 200 '' 200 '{}' 200 '{}' 200 '{}' 404 '{}'
invoke "$PROJECT" "$URL_A"
equal "exits 0" "$RC" "0"
equal "polled GET four times" "$(grep -c -- "-X GET ${URL_A}" <<<"$CALLS")" "4"
equal "slept three times" "$(grep -c . <<<"$SLEEPS")" "3"
check "counts elapsed time across polls" "$OUT" "still present (2s/300s)"
check "confirms gone" "$OUT" "confirmed gone: ${URL_A}"

echo "  DELETE 404 -> already gone, still confirms via GET 404"
stage 404 '{"error":{"code":404}}' 404 '{"error":{"code":404}}'
invoke "$PROJECT" "$URL_A"
equal "exits 0" "$RC" "0"
check "treats 404 as already gone" "$OUT" "already gone: ${URL_A}"
check "still polls to confirm" "$CALLS" "-X GET ${URL_A}"
refute "does not report delete accepted" "$OUT" "delete accepted"
equal "no sleep needed" "$SLEEPS" ""

echo "  DELETE 403 -> fails, naming the code and body"
stage 403 '{"error":{"message":"forbidden"}}'
invoke "$PROJECT" "$URL_A"
equal "exits 1" "$RC" "1"
check "names the HTTP code" "$OUT" "delete failed (HTTP 403) for ${URL_A}"
check "echoes the response body" "$OUT" "forbidden"
refute "never polls after a hard failure" "$CALLS" "-X GET"

echo "  DELETE 200, then GET 500, then GET 404 -> transient poll fault is retried"
stage 200 '' 500 '{"error":{"message":"backend"}}' 404 '{}'
invoke "$PROJECT" "$URL_A"
equal "exits 0" "$RC" "0"
check "reports the retry" "$OUT" "poll got HTTP 500, retrying (0s/300s): ${URL_A}"
check "confirms gone after the retry" "$OUT" "confirmed gone: ${URL_A}"
equal "polled GET twice" "$(grep -c -- "-X GET ${URL_A}" <<<"$CALLS")" "2"

echo "  DELETE 200, then GET 401 -> fails on a non-retryable poll status"
stage 200 '' 401 '{"error":{"message":"expired"}}'
invoke "$PROJECT" "$URL_A"
equal "exits 1" "$RC" "1"
check "names the unexpected code" "$OUT" "unexpected HTTP 401 polling ${URL_A}"
check "echoes the response body" "$OUT" "expired"
equal "polled GET once" "$(grep -c -- "-X GET ${URL_A}" <<<"$CALLS")" "1"
equal "no sleep after a hard failure" "$SLEEPS" ""

echo "  DELETE 202 (async accepted), then GET 404 -> success"
stage 202 '{"name":"operations/1"}' 404 '{}'
invoke "$PROJECT" "$URL_A"
equal "exits 0" "$RC" "0"
check "treats 202 as accepted" "$OUT" "delete accepted (HTTP 202): ${URL_A}"

echo "  DELETE 429 then DELETE 200, then GET 404 -> rate-limited delete is retried"
stage 429 '{"error":{"message":"rate"}}' 200 '' 404 '{}'
invoke "$PROJECT" "$URL_A"
equal "exits 0" "$RC" "0"
check "reports the delete retry" "$OUT" "delete got HTTP 429, retrying (0s/300s): ${URL_A}"
equal "sent DELETE twice" "$(grep -c -- "-X DELETE ${URL_A}" <<<"$CALLS")" "2"
check "confirms gone" "$OUT" "confirmed gone: ${URL_A}"

echo "  DELETE 503 forever with a 2s budget -> bounded, then hard failure"
stage 503 '{}' 503 '{}' 503 '{}' 503 '{}'
DG_WAIT_SECONDS=2 invoke "$PROJECT" "$URL_A"
equal "exits 1" "$RC" "1"
check "fails with the last code" "$OUT" "delete failed (HTTP 503) for ${URL_A}"
equal "sent DELETE three times (0s, 1s, then budget exhausted)" "$(grep -c -- "-X DELETE ${URL_A}" <<<"$CALLS")" "3"

echo "  every request carries a curl --max-time"
stage 200 '' 404 '{}'
invoke "$PROJECT" "$URL_A"
equal "max-time on each call" "$(grep -c -- "--max-time 60" <<<"$ARGS")" "2"
DG_CURL_MAX_TIME=7 invoke "$PROJECT" "$URL_A" >/dev/null 2>&1 || true
stage 200 '' 404 '{}'
DG_CURL_MAX_TIME=7 invoke "$PROJECT" "$URL_A"
check "max-time is overridable" "$ARGS" "--max-time 7"

echo "  GET never 404s -> bounded attempts, then timeout failure"
# DG_WAIT_SECONDS=2 with DG_POLL_SECONDS=1 allows exactly two GET polls.
stage 200 '' 200 '{}' 200 '{}' 200 '{}' 200 '{}'
set +e
OUT=$(PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" DG_POLL_SECONDS=1 DG_WAIT_SECONDS=2 \
  bash "$DUG" "$PROJECT" "$URL_A" 2>&1)
RC=$?
set -e
CALLS=$(cat "$STUB_DIR/calls.log")
equal "exits 1" "$RC" "1"
check "reports a timeout" "$OUT" "timed out after 2s waiting for ${URL_A} to be gone"
equal "polled GET exactly twice" "$(grep -c -- "-X GET ${URL_A}" <<<"$CALLS")" "2"
check "reports progress against the override" "$OUT" "still present (1s/2s)"
equal "stopped after DELETE plus two GETs, leaving staged responses unused" "$(cat "$STUB_DIR/n")" "3"

echo "  two URLs are both deleted and confirmed, in order"
stage 200 '' 404 '{}' 200 '' 404 '{}'
invoke "$PROJECT" "$URL_A" "$URL_B"
equal "exits 0" "$RC" "0"
check "deletes the first" "$CALLS" "-X DELETE ${URL_A}"
check "deletes the second" "$CALLS" "-X DELETE ${URL_B}"
equal "confirms the first gone" "$(grep -c -- "-X GET ${URL_A}" <<<"$CALLS")" "1"
equal "confirms the second gone" "$(grep -c -- "-X GET ${URL_B}" <<<"$CALLS")" "1"
equal "first URL fully handled before the second" \
  "$(sed -n '1p;2p' <<<"$CALLS" | grep -c -- "${URL_A}")" "2"
check "reports both confirmed" "$OUT" "confirmed gone: ${URL_B}"

echo "  second URL failing aborts after the first succeeded"
stage 200 '' 404 '{}' 409 '{"error":{"message":"conflict"}}'
invoke "$PROJECT" "$URL_A" "$URL_B"
equal "exits 1" "$RC" "1"
check "first confirmed gone" "$OUT" "confirmed gone: ${URL_A}"
check "second delete fails with its code" "$OUT" "delete failed (HTTP 409) for ${URL_B}"
refute "second URL never polled" "$CALLS" "-X GET ${URL_B}"

echo "  request headers"
stage 404 '{}' 404 '{}'
invoke "$PROJECT" "$URL_A"
check "sends X-Goog-User-Project" "$ARGS" "X-Goog-User-Project: ${PROJECT}"
check "sends bearer token from gcloud ADC" "$ARGS" "Authorization: Bearer stub-access-token"
check "uses ADC print-access-token" "$GCLOUD" "auth application-default print-access-token"
check "uses -sS" "$ARGS" "-sS"
check "appends the http code via -w" "$ARGS" "-w \\n%{http_code}"

echo "  GOOGLE_OAUTH_ACCESS_TOKEN set -> gcloud is skipped"
stage 404 '{}' 404 '{}'
set +e
OUT=$(PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" DG_POLL_SECONDS=1 \
  GOOGLE_OAUTH_ACCESS_TOKEN=preset-token \
  bash "$DUG" "$PROJECT" "$URL_A" 2>&1)
RC=$?
set -e
ARGS=$(cat "$STUB_DIR/args.log")
equal "exits 0" "$RC" "0"
check "uses the preset token" "$ARGS" "Authorization: Bearer preset-token"
refute "does not send the gcloud token" "$ARGS" "stub-access-token"
equal "never calls gcloud" "$(cat "$STUB_DIR/gcloud.log" 2>/dev/null || true)" ""

echo "  gcloud cannot mint a token -> fails before any request"
stage 404 '{}' 404 '{}'
set +e
OUT=$(PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" GCLOUD_STUB_FAIL=1 \
  bash "$DUG" "$PROJECT" "$URL_A" 2>&1)
RC=$?
set -e
equal "exits 1" "$RC" "1"
check "explains the ADC failure" "$OUT" "could not obtain an ADC access token"
check "points at --update-adc" "$OUT" "gcloud auth login <ACCOUNT> --update-adc"
check "mentions the env override" "$OUT" "GOOGLE_OAUTH_ACCESS_TOKEN"
equal "no curl calls" "$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)" ""

echo "  curl missing from PATH -> fails with required command"
stage
set +e
OUT=$(PATH="$WORK/nobin" STUB_DIR="$STUB_DIR" \
  "$BASH" "$DUG" "$PROJECT" "$URL_A" 2>&1)
RC=$?
set -e
equal "exits 1" "$RC" "1"
check "names curl" "$OUT" "required command not found: curl"

echo "  gcloud missing from PATH and no token -> fails with required command"
stage
mkdir -p "$WORK/curlonly"
cp "$WORK/bin/curl" "$WORK/curlonly/curl"
set +e
OUT=$(PATH="$WORK/curlonly" STUB_DIR="$STUB_DIR" \
  "$BASH" "$DUG" "$PROJECT" "$URL_A" 2>&1)
RC=$?
set -e
equal "exits 1" "$RC" "1"
check "names gcloud" "$OUT" "required command not found: gcloud"

echo "  missing args -> usage"
set +e
OUT=$(PATH="$WORK/bin:$PATH" bash "$DUG" 2>&1)
RC=$?
set -e
equal "exits 1" "$RC" "1"
check "prints usage" "$OUT" "usage: delete_until_gone.sh PROJECT_ID URL [URL...]"
check "prefixes with script name" "$OUT" "delete_until_gone.sh: usage:"

set +e
OUT=$(PATH="$WORK/bin:$PATH" bash "$DUG" "$PROJECT" 2>&1)
RC=$?
set -e
equal "exits 1 with only a project id" "$RC" "1"
check "prints usage" "$OUT" "usage: delete_until_gone.sh"

# --- result ----------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
