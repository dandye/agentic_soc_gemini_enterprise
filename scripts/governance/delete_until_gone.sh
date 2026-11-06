#!/usr/bin/env bash
#
# Deletes one or more REST objects and polls GET until each returns 404.
# Called by terraform_data destroy provisioners in 52-policies-access.tf and
# 65-semantic-governance.tf so recreated bindings/policies do not race async
# deletion.
#
#   delete_until_gone.sh PROJECT_ID URL [URL...]

set -euo pipefail

note() { printf 'delete_until_gone.sh: %s\n' "$*" >&2; }
die() {
  printf 'delete_until_gone.sh: %s\n' "$*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

[[ $# -ge 2 ]] || die "usage: delete_until_gone.sh PROJECT_ID URL [URL...]"

need curl

readonly PROJECT_ID=$1
shift
readonly URLS=("$@")

DG_POLL_SECONDS=${DG_POLL_SECONDS:-5}
DG_WAIT_SECONDS=${DG_WAIT_SECONDS:-300}

if [[ -z ${GOOGLE_OAUTH_ACCESS_TOKEN:-} ]]; then
  need gcloud
  GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth application-default print-access-token 2>/dev/null) ||
    die "could not obtain an ADC access token. Run 'gcloud auth login <ACCOUNT> --update-adc' or set GOOGLE_OAUTH_ACCESS_TOKEN."
fi
readonly ACCESS_TOKEN="$GOOGLE_OAUTH_ACCESS_TOKEN"

REQ_CODE=""
REQ_BODY=""
DG_CURL_MAX_TIME=${DG_CURL_MAX_TIME:-60}

req() {
  local method=$1 url=$2 out
  if ! out=$(curl -sS -X "$method" \
    --max-time "$DG_CURL_MAX_TIME" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    -w '\n%{http_code}' "$url"); then
    die "curl ${method} ${url} failed (network error or exceeded ${DG_CURL_MAX_TIME}s)"
  fi
  REQ_CODE=${out##*$'\n'}
  REQ_BODY=${out%$'\n'*}
}

# HTTP codes that mean "not an answer yet, ask again": rate limiting and
# transient upstream faults. Anything else that is not 200/404 is a real error.
retryable() {
  case "$1" in
  429 | 500 | 502 | 503 | 504) return 0 ;;
  *) return 1 ;;
  esac
}

delete_until_gone() {
  local url=$1

  local waited=0
  while :; do
    req DELETE "$url"
    case "$REQ_CODE" in
    200 | 202 | 204)
      note "delete accepted (HTTP ${REQ_CODE}): ${url}"
      break
      ;;
    404)
      note "already gone: ${url}"
      break
      ;;
    *)
      if retryable "$REQ_CODE" && ((waited < DG_WAIT_SECONDS)); then
        note "delete got HTTP ${REQ_CODE}, retrying (${waited}s/${DG_WAIT_SECONDS}s): ${url}"
        sleep "$DG_POLL_SECONDS"
        waited=$((waited + DG_POLL_SECONDS))
        continue
      fi
      die "delete failed (HTTP ${REQ_CODE}) for ${url}: $REQ_BODY"
      ;;
    esac
  done

  while ((waited < DG_WAIT_SECONDS)); do
    req GET "$url"
    case "$REQ_CODE" in
    404)
      note "confirmed gone: ${url}"
      return 0
      ;;
    200)
      note "still present (${waited}s/${DG_WAIT_SECONDS}s): ${url}"
      ;;
    *)
      if retryable "$REQ_CODE"; then
        note "poll got HTTP ${REQ_CODE}, retrying (${waited}s/${DG_WAIT_SECONDS}s): ${url}"
      else
        die "unexpected HTTP ${REQ_CODE} polling ${url}: $REQ_BODY"
      fi
      ;;
    esac
    sleep "$DG_POLL_SECONDS"
    waited=$((waited + DG_POLL_SECONDS))
  done
  die "timed out after ${DG_WAIT_SECONDS}s waiting for ${url} to be gone"
}

for url in "${URLS[@]}"; do
  delete_until_gone "$url"
done
