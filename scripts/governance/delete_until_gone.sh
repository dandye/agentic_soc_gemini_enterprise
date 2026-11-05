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
req() {
  local method=$1 url=$2 out
  out=$(curl -sS -X "$method" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    -w '\n%{http_code}' "$url")
  REQ_CODE=${out##*$'\n'}
  REQ_BODY=${out%$'\n'*}
}

delete_until_gone() {
  local url=$1

  req DELETE "$url"
  case "$REQ_CODE" in
  200) note "delete accepted: ${url}" ;;
  404) note "already gone: ${url}" ;;
  *) die "delete failed (HTTP ${REQ_CODE}) for ${url}: $REQ_BODY" ;;
  esac

  local waited=0
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
    *) die "unexpected HTTP ${REQ_CODE} polling ${url}: $REQ_BODY" ;;
    esac
    sleep "$DG_POLL_SECONDS"
    waited=$((waited + DG_POLL_SECONDS))
  done
  die "timed out after ${DG_WAIT_SECONDS}s waiting for ${url} to be gone"
}

for url in "${URLS[@]}"; do
  delete_until_gone "$url"
done
