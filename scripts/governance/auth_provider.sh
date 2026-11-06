#!/usr/bin/env bash
#
# Auth Manager shim — create, update, grant, or soft-delete an Agent Identity
# AuthProvider for the Google Threat Intelligence (VirusTotal v3) API key.
#
# Stands in for google_agent_identity_auth_provider so the secret never enters
# Terraform state and soft-deleted providers can be restored via :undelete.
# Driven by terraform/20-authmanager.tf.
#
#   auth_provider.sh upsert    create or update the AuthProvider
#   auth_provider.sh grant     grant resource-scoped IAM to one agent principal
#   auth_provider.sh delete    soft-delete the AuthProvider
#
# Required env:
#   AUTH_PROVIDER_PROJECT, AUTH_PROVIDER_LOCATION, AUTH_PROVIDER_ID
#   AUTH_PROVIDER_MEMBER (for grant)
#   GTI_API_KEY or TF_VAR_gti_api_key (for upsert)
#
# Credential handling: the API key is never passed via CLI arguments, temporary
# files, or stdout. Request bodies go to curl on stdin and error bodies pass
# through redact(). Never invoke under `bash -x`.

set -euo pipefail

readonly AGENTIDENTITY_BASE="https://agentidentity.googleapis.com/v1"

note() { printf 'auth_provider.sh: %s\n' "$*" >&2; }
die() {
  printf 'auth_provider.sh: %s\n' "$*" >&2
  exit 1
}

redact() {
  local text=$1
  if [[ -n ${GTI_API_KEY:-} ]]; then
    text="${text//"$GTI_API_KEY"/[REDACTED]}"
  fi
  if [[ -n ${TF_VAR_gti_api_key:-} ]]; then
    text="${text//"$TF_VAR_gti_api_key"/[REDACTED]}"
  fi
  printf '%s' "$text"
}

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

require_env() {
  local var=$1
  [[ -n ${!var:-} ]] || die "$var must be set"
}

action=${1:-}
case "$action" in
upsert | grant | delete) ;;
*) die "usage: auth_provider.sh upsert|grant|delete" ;;
esac

need curl
need jq

require_env AUTH_PROVIDER_PROJECT
require_env AUTH_PROVIDER_LOCATION
require_env AUTH_PROVIDER_ID

readonly PARENT="projects/${AUTH_PROVIDER_PROJECT}/locations/${AUTH_PROVIDER_LOCATION}"
readonly NAME="${PARENT}/authProviders/${AUTH_PROVIDER_ID}"

if [[ -z ${GOOGLE_OAUTH_ACCESS_TOKEN:-} ]]; then
  need gcloud
  GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth application-default print-access-token 2>/dev/null) ||
    die "could not obtain an ADC access token. Run 'gcloud auth login <ACCOUNT> --update-adc' or set GOOGLE_OAUTH_ACCESS_TOKEN."
fi
readonly ACCESS_TOKEN="$GOOGLE_OAUTH_ACCESS_TOKEN"

REQ_CODE=""
REQ_BODY=""
req() {
  local method=$1 url=$2 body=${3-} out
  local -a args=(
    -sS -X "$method"
    -H "Authorization: Bearer ${ACCESS_TOKEN}"
    -H "X-Goog-User-Project: ${AUTH_PROVIDER_PROJECT}"
    -H "Content-Type: application/json"
    -w '\n%{http_code}'
  )
  if [[ -n $body ]]; then
    out=$(printf '%s' "$body" | curl "${args[@]}" --data-binary @- "$url")
  else
    out=$(curl "${args[@]}" "$url")
  fi
  REQ_CODE=${out##*$'\n'}
  REQ_BODY=${out%$'\n'*}
}

req_ai() { req "$1" "${AGENTIDENTITY_BASE}/$2" "${3-}"; }

settle() { sleep 5; }

do_upsert() {
  if [[ -z ${GTI_API_KEY:-} ]]; then
    GTI_API_KEY=${TF_VAR_gti_api_key:-}
  fi
  [[ -n ${GTI_API_KEY:-} ]] ||
    die "no GTI API key supplied. Set GTI_API_KEY or TF_VAR_gti_api_key in the environment."

  local workload_ids=${AUTH_PROVIDER_WORKLOAD_IDS:-'[]'}
  local mask="authProviderTypeParams,description"
  if [[ $(jq 'length' <<<"$workload_ids") -gt 0 ]]; then
    mask="${mask},workloadIds"
  fi

  local body
  body=$(jq -n \
    --arg key "$GTI_API_KEY" \
    --arg desc "${AUTH_PROVIDER_DESCRIPTION:-}" \
    --argjson workloadIds "$workload_ids" \
    '{
       authProviderTypeParams: { apiKey: { apiKey: $key } },
       description: $desc
     }
     + (if ($workloadIds | length) > 0 then { workloadIds: $workloadIds } else {} end)')

  req_ai GET "$NAME"

  case "$REQ_CODE" in
  200)
    if [[ $(jq -r '.deleted // false' <<<"$REQ_BODY") == "true" ]]; then
      note "$NAME is soft-deleted -- undeleting"
      req_ai POST "${NAME}:undelete" '{}'
      [[ $REQ_CODE == 200 ]] || die "undelete failed (HTTP $REQ_CODE): $(redact "$REQ_BODY")"
      settle
    fi
    note "updating $NAME"
    req_ai PATCH "${NAME}?updateMask=${mask}" "$body"
    [[ $REQ_CODE == 200 ]] || die "update failed (HTTP $REQ_CODE): $(redact "$REQ_BODY")"
    ;;
  404)
    note "creating $NAME"
    req_ai POST "${PARENT}/authProviders?authProviderId=${AUTH_PROVIDER_ID}" "$body"
    [[ $REQ_CODE == 200 ]] || die "create failed (HTTP $REQ_CODE): $(redact "$REQ_BODY")"
    ;;
  403)
    die "HTTP 403 reading $NAME. Verify agentidentity.googleapis.com is enabled in ${AUTH_PROVIDER_PROJECT}: $(redact "$REQ_BODY")"
    ;;
  *)
    die "unexpected HTTP $REQ_CODE reading $NAME: $(redact "$REQ_BODY")"
    ;;
  esac

  settle
  note "ok: $NAME"
}

do_grant() {
  require_env AUTH_PROVIDER_MEMBER

  local role=${AUTH_PROVIDER_ROLE:-roles/agentidentity.user}
  local member=$AUTH_PROVIDER_MEMBER

  case "$member" in
  principal://* | principalSet://* | serviceAccount:* | user:* | group:*) ;;
  *) die "AUTH_PROVIDER_MEMBER must be a fully-qualified IAM member, got: ${member}" ;;
  esac

  req GET "${AGENTIDENTITY_BASE}/${NAME}:getIamPolicy"
  [[ $REQ_CODE == 200 ]] ||
    die "reading IAM policy on $NAME failed (HTTP $REQ_CODE): $(redact "$REQ_BODY")"

  if jq -e --arg r "$role" --arg m "$member" \
    '(.bindings // []) | any(.role == $r and ((.members // []) | index($m)))' \
    <<<"$REQ_BODY" >/dev/null; then
    note "ok: ${member} already has ${role} on $NAME"
    return
  fi

  local policy
  policy=$(jq --arg r "$role" --arg m "$member" '
      .bindings = (
        (.bindings // []) as $b
        | if ($b | any(.role == $r))
          then ($b | map(if .role == $r
                         then .members = ((.members // []) + [$m] | unique)
                         else . end))
          else ($b + [{role: $r, members: [$m]}])
          end
      )
      | {version, bindings, etag}
      | with_entries(select(.value != null))
    ' <<<"$REQ_BODY")

  note "granting ${role} to ${member} on $NAME"
  req POST "${AGENTIDENTITY_BASE}/${NAME}:setIamPolicy" "$(jq -n --argjson p "$policy" '{policy: $p}')"
  [[ $REQ_CODE == 200 ]] ||
    die "setIamPolicy on $NAME failed (HTTP $REQ_CODE): $(redact "$REQ_BODY")"

  settle
  note "ok: ${role} -> ${member} on ${NAME}"
}

do_delete() {
  req_ai DELETE "$NAME"
  case "$REQ_CODE" in
  200) note "soft-deleted $NAME" ;;
  404) note "$NAME is already absent or soft-deleted (upsert will :undelete if needed)" ;;
  *) die "delete failed (HTTP $REQ_CODE): $(redact "$REQ_BODY")" ;;
  esac
  settle
}

case "$action" in
upsert) do_upsert ;;
grant) do_grant ;;
delete) do_delete ;;
esac
