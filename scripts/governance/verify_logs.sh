#!/usr/bin/env bash
#
# Read Agent Gateway, IAP, and Agent Engine telemetry status from Cloud Logging
# and Vertex AI REST APIs.
#
#   verify_logs.sh mcp                  MCP traffic: method, tool name, result
#   verify_logs.sh all                  every gateway request entry
#   verify_logs.sh audit                every IAP AuthorizeUser decision (allow + deny)
#   verify_logs.sh denied               IAP denials only
#   verify_logs.sh model-armor          every Model Armor SanitizeOperation verdict (alias: armor)
#   verify_logs.sh model-armor-blocked  Model Armor BLOCK verdicts only (alias: armor-blocked)
#   verify_logs.sh who                  distinct SPIFFE agent identities observed
#   verify_logs.sh types                diagnostic: resource.type carrying gateway logs
#   verify_logs.sh telemetry            verify GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY
#   verify_logs.sh unregistered         observed SNI hosts minus Agent Registry hosts
#
# Flags:
#   --limit N        entries to return (default 20; 1000 for unregistered)
#
# Exit codes for `unregistered`: 0 checked and no gaps (or gaps printed),
# 1 fatal, 2 empty observation window (nothing verified), 3 sample truncated.
#   --freshness D    lookback window (default 1h; e.g. 10m, 24h)
#   --project P      GCP project ID (defaults to terraform output project_id)
#   --raw            output raw JSON

set -euo pipefail

readonly SELF="verify_logs.sh"
TF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../terraform" && pwd)"
readonly TF_DIR

RESOURCE_TYPE="${AGW_LOG_RESOURCE_TYPE:-networkservices.googleapis.com/Gateway}"

note() { printf '%s: %s\n' "$SELF" "$*" >&2; }
die() {
  printf '%s: %s\n' "$SELF" "$*" >&2
  exit 1
}

action=""
limit=20
limit_explicit=false
freshness="1h"
project=""
raw=false

while [[ $# -gt 0 ]]; do
  case "$1" in
  mcp | all | audit | denied | who | types | unregistered | telemetry) action="$1" ;;
  model-armor | armor) action="model-armor" ;;
  model-armor-blocked | armor-blocked) action="model-armor-blocked" ;;
  --limit)
    limit="${2:-}"
    limit_explicit=true
    shift
    ;;
  --limit=*)
    limit="${1#*=}"
    limit_explicit=true
    ;;
  --freshness)
    freshness="${2:-}"
    shift
    ;;
  --freshness=*) freshness="${1#*=}" ;;
  --project)
    project="${2:-}"
    shift
    ;;
  --project=*) project="${1#*=}" ;;
  --raw) raw=true ;;
  -h | --help)
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"
    exit 0
    ;;
  *) die "unknown argument '$1'. Actions: mcp | all | audit | denied | model-armor | model-armor-blocked | who | types | unregistered | telemetry." ;;
  esac
  shift
done

[[ -n $action ]] || die "no action given. Expected: mcp | all | audit | denied | model-armor | model-armor-blocked | who | types | unregistered | telemetry."
[[ $limit =~ ^[1-9][0-9]*$ ]] || die "--limit must be a positive integer, got '$limit'"
[[ $freshness =~ ^[0-9]+[smhd]$ ]] || die "--freshness must look like 30m, 2h, or 7d, got '$freshness'"

command -v gcloud >/dev/null 2>&1 || die "gcloud not found on PATH"

if [[ $action == unregistered ]] && ! $limit_explicit; then
  limit=1000
fi

if [[ -z $project ]]; then
  project="$(terraform -chdir="$TF_DIR" output -raw project_id 2>/dev/null || true)"
fi
if [[ -z $project ]]; then
  project="$(gcloud config get-value project 2>/dev/null || true)"
  [[ -n $project && $project != "(unset)" ]] ||
    die "could not determine project. Pass --project or initialize terraform state in ${TF_DIR}."
  note "falling back to gcloud configured project '${project}'"
fi

readonly GATEWAY_SCOPE="resource.type=\"${RESOURCE_TYPE}\""
readonly AUDIT_SCOPE="logName=\"projects/${project}/logs/cloudaudit.googleapis.com%2Fdata_access\"
  AND protoPayload.serviceName=\"iap.googleapis.com\"
  AND protoPayload.methodName=\"GatekeeperAuthorizer.AuthorizeUser\""
readonly MODEL_ARMOR_SCOPE='resource.type="modelarmor.googleapis.com/SanitizeOperation"'

run_read() {
  local filter="$1"
  shift
  local out status=0

  out="$(gcloud logging read "$filter" \
    --project="$project" \
    --limit="$limit" \
    --freshness="$freshness" \
    --quiet \
    "$@" 2>&1)" || status=$?

  if ((status != 0)); then
    printf '%s\n' "$out" >&2
    die "gcloud logging read failed (exit ${status}) on project '${project}'."
  fi

  if [[ -n $out ]]; then
    printf '%s\n' "$out"
  fi
}

readonly MCP_TABLE='table(
  timestamp.date(tz=LOCAL),
  httpRequest.status,
  jsonPayload.authzPolicyInfo.result,
  jsonPayload.agentGatewayInfo.mcpInfo.method,
  jsonPayload.agentGatewayInfo.mcpInfo.parameter,
  httpRequest.requestUrl
)'

readonly ALL_TABLE='table(
  timestamp.date(tz=LOCAL),
  httpRequest.status,
  jsonPayload.authzPolicyInfo.result.yesno(no="<no authz>"),
  jsonPayload.agentGatewayInfo.mcpInfo.method.yesno(no="<no mcpInfo>"),
  jsonPayload.agentGatewayInfo.mcpInfo.parameter.yesno(no="-"),
  httpRequest.requestUrl
)'

readonly AUDIT_TABLE='table(
  timestamp.date(tz=LOCAL),
  protoPayload.authorizationInfo[0].granted.yesno(yes="ALLOW", no="DENY"):label=VERDICT,
  protoPayload.metadata.dryRun.yesno(yes="DRY_RUN", no="-"),
  protoPayload.metadata.mcp_attributes.mcp_method.yesno(no="-"),
  protoPayload.metadata.mcp_attributes.mcp_tool_name.yesno(no="-"),
  protoPayload.authenticationInfo.principalSubject.basename():label=AGENT,
  protoPayload.requestMetadata.requestAttributes.host.yesno(no="-")
)'

readonly MODEL_ARMOR_TABLE='table(
  timestamp.date(tz=LOCAL),
  jsonPayload.sanitizationResult.sanitizationVerdict.yesno(no="-"):label=VERDICT,
  resource.labels.template_id.yesno(no="-"):label=TEMPLATE,
  jsonPayload.operationType.yesno(no="-"):label=OPERATION,
  jsonPayload.sanitizationResult.filterMatchState.yesno(no="-"):label=MATCH,
  jsonPayload.sanitizationResult.filterResults.pi_and_jailbreak.piAndJailbreakFilterResult.matchState.yesno(no="-"):label=PI_JAILBREAK,
  jsonPayload.sanitizationResult.filterResults.rai.raiFilterResult.matchState.yesno(no="-"):label=RAI
)'

# Mirrors local.api_id in 10-registry-endpoints.tf for *.googleapis.com hosts
# only. Third-party hosts are registered under hand-chosen ids (for example
# `<prefix>-virustotal`), so no derivation applies to them; callers must not
# use this for a host that does not end in .googleapis.com.
derive_service_id() {
  local region=$1 host=$2 base
  base="${host%.googleapis.com}"
  base="${base//./-}"
  if [[ -n $region && $base == "${region}-"* ]]; then
    :
  else
    base="${region:-us-central1}-g-${base}"
  fi
  ((${#base} >= 6)) || base="${base}-api"
  printf '%s' "$base"
}

case "$action" in
mcp)
  filter="${GATEWAY_SCOPE} AND jsonPayload.agentGatewayInfo.mcpInfo.method:*"
  note "MCP traffic in the last ${freshness}, project ${project}"
  if $raw; then
    run_read "$filter" --format=json
  else
    run_read "$filter" --format="$MCP_TABLE"
  fi
  ;;

all)
  filter="${GATEWAY_SCOPE}"
  note "ALL gateway entries in the last ${freshness}, project ${project}"
  if $raw; then
    run_read "$filter" --format=json
  else
    run_read "$filter" --format="$ALL_TABLE"
  fi
  ;;

audit)
  filter="${AUDIT_SCOPE}"
  note "IAP authorization decisions in the last ${freshness}, project ${project}"
  if $raw; then
    run_read "$filter" --format=json
  else
    rows="$(run_read "$filter" --format="$AUDIT_TABLE")"
    if [[ -n $rows ]]; then
      printf '%s\n' "$rows"
    else
      note "no IAP decisions recorded in the last ${freshness}."
    fi
  fi
  ;;

denied)
  filter="${AUDIT_SCOPE} AND protoPayload.authorizationInfo.granted=false"
  note "IAP denials in the last ${freshness}, project ${project}"
  if $raw; then
    run_read "$filter" --format=json
  else
    rows="$(run_read "$filter" --format="$AUDIT_TABLE")"
    if [[ -n $rows ]]; then
      printf '%s\n' "$rows"
    else
      note "no IAP denials recorded in the last ${freshness}."
    fi
  fi
  ;;

model-armor)
  filter="${MODEL_ARMOR_SCOPE}"
  note "Model Armor sanitize verdicts in the last ${freshness}, project ${project}"
  if $raw; then
    run_read "$filter" --format=json
  else
    rows="$(run_read "$filter" --format="$MODEL_ARMOR_TABLE")"
    if [[ -n $rows ]]; then
      printf '%s\n' "$rows"
    else
      note "no Model Armor sanitize verdicts recorded in the last ${freshness}."
    fi
  fi
  ;;

model-armor-blocked)
  filter="${MODEL_ARMOR_SCOPE} AND jsonPayload.sanitizationResult.sanitizationVerdict=\"MODEL_ARMOR_SANITIZATION_VERDICT_BLOCK\""
  note "Model Armor blocks in the last ${freshness}, project ${project}"
  if $raw; then
    run_read "$filter" --format=json
  else
    rows="$(run_read "$filter" --format="$MODEL_ARMOR_TABLE")"
    if [[ -n $rows ]]; then
      printf '%s\n' "$rows"
    else
      note "no Model Armor blocks recorded in the last ${freshness}."
    fi
  fi
  ;;

who)
  filter="${AUDIT_SCOPE}"
  note "identities seen in the last ${freshness}, project ${project}"
  if $raw; then
    run_read "$filter" --format=json
    exit 0
  fi

  found="$(run_read "$filter" --format='value(protoPayload.authenticationInfo.principalSubject)' |
    sort | uniq -c | sort -rn)"
  if [[ -z $found ]]; then
    note "no authorization decisions in the last ${freshness}."
    exit 0
  fi
  printf 'COUNT  PRINCIPAL\n%s\n' "$found"
  ;;

types)
  found="$(run_read 'jsonPayload.agentGatewayInfo:*' --format='value(resource.type)' | sort | uniq -c | sort -rn)"
  if [[ -n $found ]]; then
    printf 'COUNT  RESOURCE.TYPE\n%s\n' "$found"
  else
    note "no gateway log entries found in the last ${freshness}."
  fi
  ;;

unregistered)
  command -v jq >/dev/null 2>&1 || die "jq not found on PATH"

  state_json="$(terraform -chdir="$TF_DIR" show -json 2>/dev/null || true)"
  [[ -n $state_json ]] || die "terraform show -json in ${TF_DIR} returned empty output"

  registered="$(printf '%s' "$state_json" | jq -r '
    [ .values.root_module | recurse(.child_modules[]?) | .resources[]?
      | select(.type | test("^google_agent_registry_(service|mcp_server)$"))
      | .values.interfaces[]?.url // empty
    ]
    | map(sub("^[a-z]+://"; "") | split("/")[0])
    | unique[]' 2>/dev/null || true)"

  [[ -n $registered ]] || die "no Agent Registry resources in terraform state (${TF_DIR})"

  # service_id -> host pairs as actually registered, so the collision check
  # compares against real ids rather than re-deriving them.
  registered_ids="$(printf '%s' "$state_json" | jq -r '
    [ .values.root_module | recurse(.child_modules[]?) | .resources[]?
      | select(.type | test("^google_agent_registry_(service|mcp_server)$"))
      | . as $r
      | ($r.values.interfaces[]?.url // empty)
      | [($r.values.service_id // $r.values.mcp_server_id // "?"),
         (sub("^[a-z]+://"; "") | split("/")[0])]
      | @tsv
    ] | unique[]' 2>/dev/null || true)"

  region="$(printf '%s' "$state_json" | jq -r '
    [ .values.root_module | recurse(.child_modules[]?) | .resources[]?
      | select(.type == "google_agent_registry_service")
      | .values.location // empty
    ] | unique | first // empty' 2>/dev/null || true)"

  observed_raw="$(run_read "${GATEWAY_SCOPE} AND jsonPayload.tlsSniHostname:*" \
    --format='value(jsonPayload.tlsSniHostname)')"
  observed="$(printf '%s\n' "$observed_raw" | sed '/^$/d' | LC_ALL=C sort -u)"
  registered="$(printf '%s\n' "$registered" | sed '/^$/d' | LC_ALL=C sort -u)"

  if [[ -z $observed ]]; then
    # Exit 2 keeps "nothing to check" distinct from exit 0 "checked, no gaps":
    # an empty window is not a clean bill of health.
    note "no gateway SNI entries observed in the last ${freshness}; nothing to verify (not a clean result)."
    exit 2
  fi

  entries_read="$(printf '%s\n' "$observed_raw" | sed '/^$/d' | wc -l | tr -d ' ')"
  missing="$(LC_ALL=C comm -23 <(printf '%s\n' "$observed") <(printf '%s\n' "$registered"))"

  if [[ -z $missing ]]; then
    printf 'no gaps: every observed host is registered\n'
  else
    printf 'UNREGISTERED HOSTS SEEN AT THE GATEWAY\n\n'
    printf '%-52s %s\n' "HOST" "ADD TO (terraform/10-registry-endpoints.tf)"
    while IFS= read -r host; do
      [[ -n $host ]] || continue
      if [[ $host != *.googleapis.com ]]; then
        target="dedicated google_agent_registry_service scoped to one agent"
      elif [[ -n $region && $host == "${region}-"* ]]; then
        target="local.google_api_hosts_regional"
      else
        target="local.google_api_hosts_global"
      fi
      printf '%-52s %s\n' "$host" "$target"

      # Only *.googleapis.com hosts share the derived-id namespace of the
      # google_apis for_each; a third-party host gets its own hand-named
      # resource and cannot collide with it.
      if [[ $host == *.googleapis.com ]]; then
        base="$(derive_service_id "$region" "$host")"
        while IFS=$'\t' read -r rid rhost; do
          [[ -n $rid ]] || continue
          if [[ $rid == "$base" ]]; then
            printf '%-52s WARNING: service_id "%s" is already registered for %s; adding this host to the list would be a silent no-op (for_each key already taken). Register it under a distinct id.\n' "" "$base" "$rhost"
          fi
        done <<<"$registered_ids"
      fi
    done <<<"$missing"
  fi

  if ((entries_read >= limit)); then
    note "WARNING: sample truncated at --limit ${limit}; rerun with higher --limit"
    exit 3
  fi
  ;;

telemetry)
  command -v jq >/dev/null 2>&1 || die "jq not found on PATH"
  command -v curl >/dev/null 2>&1 || die "curl not found on PATH"

  region="$(terraform -chdir="$TF_DIR" output -raw region 2>/dev/null || true)"
  region="${region:-us-central1}"
  api="https://${region}-aiplatform.googleapis.com/v1beta1/projects/${project}/locations/${region}/reasoningEngines"

  token="${GOOGLE_OAUTH_ACCESS_TOKEN:-}"
  if [[ -z $token ]]; then
    token="$(gcloud auth application-default print-access-token 2>/dev/null || true)"
  fi
  [[ -n $token ]] || die "could not obtain an ADC access token."

  listing="$(curl -sS -H "Authorization: Bearer ${token}" \
    -H "X-Goog-User-Project: ${project}" "$api" 2>/dev/null || true)"
  managed_ids="$(terraform -chdir="$TF_DIR" output -json agent_engines 2>/dev/null |
    jq -r 'to_entries[]? | .value.engine_id // empty' 2>/dev/null || true)"
  engines="$(printf '%s' "$listing" |
    jq -r --arg managed "$managed_ids" '
      ($managed | split("\n") | map(select(length > 0))) as $ids
      | .reasoningEngines[]?
      | (.name | split("/") | last) as $eid
      | select(($ids | length == 0) or ($ids | index($eid) != null))
      | [.name, (.displayName // "?")] | @tsv' 2>/dev/null || true)"
  [[ -n $engines ]] || die "no reasoning engines found in ${project}/${region}"

  printf '%-34s %-9s %-9s %s\n' AGENT TELEMETRY CONTENT ENGINE
  missing=0
  while IFS=$'\t' read -r res display; do
    [[ -n $res ]] || continue
    engine_json="$(curl -sS -H "Authorization: Bearer ${token}" \
      -H "X-Goog-User-Project: ${project}" "${api}/${res##*/}" 2>/dev/null || echo '{}')"

    if printf '%s' "$engine_json" | jq -e '
      [ .spec.deploymentSpec.env[]?
        | select(.name == "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY")
        | select((.value // "") | ascii_downcase == "true")
      ] | length > 0' >/dev/null 2>&1; then
      tel="on"
    else
      tel="OFF"
      missing=$((missing + 1))
    fi

    if printf '%s' "$engine_json" | jq -e '
      [ .spec.deploymentSpec.env[]?
        | select(.name == "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT")
      ] | length > 0' >/dev/null 2>&1; then
      content="on"
    else
      content="off"
    fi

    printf '%-34s %-9s %-9s %s\n' "${display:-?}" "$tel" "$content" "${res##*/}"
  done <<<"$engines"

  if ((missing > 0)); then
    die "ERROR: ${missing} engine(s) have telemetry OFF."
  fi
  ;;
esac
