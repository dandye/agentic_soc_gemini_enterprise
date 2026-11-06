#!/usr/bin/env bash
#
# Offline tests for `scripts/governance/verify_logs.sh unregistered`.
#
# Same harness idea as bind_ge_app_test.sh: stubs gcloud and terraform on
# PATH, so this makes no network calls and reads no real state.
#
#     bash scripts/governance/tests/verify_logs_test.sh
#
# Only `unregistered` has real logic: a set difference between the SNI hosts
# the gateway logged and the hosts registered in Agent Registry (read from
# `terraform show -json`), a service_id derivation that mirrors
# terraform/10-registry-endpoints.tf, and four guards against a confident
# wrong answer:
#
#   * an empty registered set must be FATAL, not an empty diff
#   * a truncated sample must WARN; a short read gives a falsely clean result
#   * a service_id collision must WARN; adding the host would be a no-op
#   * an empty observation window must not be reported as "no gaps"
#
# The terraform stub ignores -chdir and replays $STUB_DIR/state.json; its
# `output` subcommand always fails, which exercises the fallback to the
# gcloud-configured project. The gcloud stub replays $STUB_DIR/hosts.txt for
# `logging read` and records the argv so the harness can prove which filter,
# --limit, --freshness, and --project reached the API.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly SCRIPT_DIR
readonly TARGET="${SCRIPT_DIR}/verify_logs.sh"

readonly PROJECT_ID="example-project"
readonly REGION="us-central1"
readonly CHRONICLE_REGION="us"
readonly PREFIX="agw-secops"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# --- stubs -----------------------------------------------------------------

cat >"$WORK/bin/terraform" <<'STUB'
#!/usr/bin/env bash
# `show -json` replays $STUB_DIR/state.json; everything else (notably
# `output -raw project_id`) fails so the script falls back to gcloud.
printf 'terraform %s\n' "$*" >>"$STUB_DIR/terraform.log"
for a in "$@"; do
  [[ $a == show ]] && { cat "$STUB_DIR/state.json"; exit 0; }
done
exit 1
STUB

cat >"$WORK/bin/gcloud" <<'STUB'
#!/usr/bin/env bash
# `logging read` replays $STUB_DIR/hosts.txt (one tlsSniHostname per line,
# exactly what --format='value(jsonPayload.tlsSniHostname)' prints) and logs
# its argv to read.log. `config get-value project` answers the fallback.
printf 'gcloud %s\n' "$*" >>"$STUB_DIR/gcloud.log"
if [[ ${1:-} == logging && ${2:-} == read ]]; then
  printf '%s\n' "$*" >>"$STUB_DIR/read.log"
  cat "$STUB_DIR/hosts.txt"
  exit 0
fi
if [[ ${1:-} == config && ${2:-} == get-value ]]; then
  echo "example-project"
  exit 0
fi
echo "gcloud stub: unexpected call: $*" >&2
exit 1
STUB
chmod +x "$WORK/bin"/*

# --- harness ---------------------------------------------------------------

PASS=0
FAIL=0
CASE=0

# resource TYPE ADDRESS URL [PROTOCOL] [SERVICE_ID] : one terraform state
# resource, shaped like the google-beta provider's state for
# google_agent_registry_service in terraform/10-registry-endpoints.tf and
# 11-registry-mcp.tf. Addresses such as google_apis["id"] carry double
# quotes, which are escaped for JSON.
resource() {
  local type=$1 address=$2 url=$3 protocol=${4:-JSONRPC} service_id=${5:-}
  local host=${url#https://}
  host=${host%%/*}
  local name=${address#*.}
  printf '{"address":"%s","type":"%s","name":"%s","provider_name":"registry.terraform.io/hashicorp/google-beta","values":{"project":"%s","location":"%s","service_id":"%s","display_name":"%s","interfaces":[{"url":"%s","protocol_binding":"%s"}],"endpoint_spec":[{"type":"NO_SPEC"}]}}' \
    "${address//\"/\\\"}" "$type" "${name//\"/\\\"}" "$PROJECT_ID" "$REGION" \
    "${service_id:-${host//./-}}" "$host" "$url" "$protocol"
}

# write_state RESOURCE_JSON... : assemble `terraform show -json` output
write_state() {
  local joined
  joined=$(
    IFS=,
    echo "$*"
  )
  printf '{"format_version":"1.0","terraform_version":"1.9.0","values":{"root_module":{"resources":[%s]}}}' \
    "$joined" >"$STUB_DIR/state.json"
  # A malformed fixture would surface as "no Agent Registry resources" and
  # make the FATAL case pass for the wrong reason; fail the harness instead.
  jq -e . "$STUB_DIR/state.json" >/dev/null || {
    echo "harness bug: state.json is not valid JSON" >&2
    exit 2
  }
}

# state HOST... : register each host as google_agent_registry_service.google_apis["<id>"]
state() {
  local res=() h
  for h in "$@"; do
    res+=("$(resource google_agent_registry_service \
      "google_agent_registry_service.google_apis[\"${h//./-}\"]" "https://${h}")")
  done
  write_state "${res[@]}"
}

# secops_state : the real registry shape, abbreviated. Infrastructure hosts
# from 10-registry-endpoints.tf, the GTI endpoint (HTTP_JSON) and the
# Chronicle OneMCP server (JSONRPC, URL carries a /mcp path) from
# 11-registry-mcp.tf.
secops_state() {
  local res=() h
  for h in "${REGION}-aiplatform.googleapis.com" \
    "${REGION}-discoveryengine.googleapis.com" \
    "modelarmor.${REGION}.rep.googleapis.com" \
    "aiplatform.googleapis.com" \
    "aiplatform.us.rep.googleapis.com" \
    "iap.googleapis.com" \
    "oauth2.googleapis.com" \
    "logging.googleapis.com"; do
    res+=("$(resource google_agent_registry_service \
      "google_agent_registry_service.google_apis[\"${h//./-}\"]" "https://${h}")")
  done
  res+=("$(resource google_agent_registry_service \
    "google_agent_registry_service.gti_api" "https://www.virustotal.com" HTTP_JSON \
    "${PREFIX}-virustotal")")
  res+=("$(resource google_agent_registry_service \
    "google_agent_registry_service.chronicle_mcp" \
    "https://chronicle.${CHRONICLE_REGION}.rep.googleapis.com/mcp" JSONRPC \
    "${PREFIX}-chronicle-mcp")")
  write_state "${res[@]}"
}

# empty_state : valid JSON, no resources, which is what `terraform show -json`
# returns with no state in the directory.
empty_state() { printf '{"format_version":"1.0"}' >"$STUB_DIR/state.json"; }

# observed HOST... : what the gateway log returns
observed() {
  : >"$STUB_DIR/hosts.txt"
  (($# == 0)) || printf '%s\n' "$@" >"$STUB_DIR/hosts.txt"
}

new_case() {
  STUB_DIR="$WORK/case-$((++CASE))"
  mkdir -p "$STUB_DIR"
  : >"$STUB_DIR/hosts.txt"
  empty_state
}

# invoke [args...] : run `verify_logs.sh unregistered`; sets OUT, RC, READ
invoke() {
  set +e
  OUT=$(PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" bash "$TARGET" unregistered "$@" 2>&1)
  RC=$?
  set -e
  READ=$(cat "$STUB_DIR/read.log" 2>/dev/null || true)
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

# --- 1. a clean run against the real SecOps registry shape -----------------

echo "a fully registered set is clean"

new_case
secops_state
observed "${REGION}-aiplatform.googleapis.com" "iap.googleapis.com" \
  "chronicle.${CHRONICLE_REGION}.rep.googleapis.com" "www.virustotal.com"
invoke
check "clean run reports no gaps" "$OUT" "no gaps: every observed host is registered"
equal "clean run exits 0" "$RC" 0
check "terraform output failure falls back to the gcloud project" "$OUT" \
  "falling back to gcloud configured project '${PROJECT_ID}'"
check "the gateway filter scopes to the Gateway resource type" "$READ" \
  'resource.type="networkservices.googleapis.com/Gateway" AND jsonPayload.tlsSniHostname:*'
check "the fallback project reaches the logging read" "$READ" "--project=${PROJECT_ID}"
check "unregistered defaults to --limit 1000" "$READ" "--limit=1000"
check "the default freshness is 1h" "$READ" "--freshness=1h"
refute "a clean run does not list gaps" "$OUT" "UNREGISTERED HOSTS SEEN"
refute "a clean run does not warn about truncation" "$OUT" "truncated"

# The Chronicle MCP interface URL is https://chronicle.us.rep.googleapis.com/mcp;
# the registered set must be the host, not the host plus path.
new_case
secops_state
observed "chronicle.${CHRONICLE_REGION}.rep.googleapis.com"
invoke
check "a registered URL with a path still registers its host" "$OUT" "no gaps"

# --- 2. a gap, and which list it belongs in --------------------------------

echo "a host seen at the gateway but not registered is listed"

new_case
state "iap.googleapis.com"
observed "iap.googleapis.com" "storage.googleapis.com"
invoke
check "gap is reported" "$OUT" "UNREGISTERED HOSTS SEEN AT THE GATEWAY"
check "the fix points at the SecOps registry file" "$OUT" "ADD TO (terraform/10-registry-endpoints.tf)"
check "the missing host is named" "$OUT" "storage.googleapis.com"
check "a global host routes to the global list" "$OUT" "local.google_api_hosts_global"
refute "a registered host is not reported" "$OUT" "iap.googleapis.com"
equal "a gap is reported but is not an error exit" "$RC" 0

# --- 3. a regionalized host goes in the regional list ----------------------
#
# Not cosmetic: 10-registry-endpoints.tf keeps "<region>-" ids as-is and
# gives everything else a "<region>-g-" infix, so a regional host dropped in
# the global list would be registered under the wrong id.

new_case
state "iap.googleapis.com"
observed "${REGION}-agentregistry.googleapis.com"
invoke
check "a regionalized host routes to the regional list" "$OUT" "local.google_api_hosts_regional"
refute "a regionalized host avoids the global list" "$OUT" "local.google_api_hosts_global"

# The region comes from the registered resources' location, not a flag: a
# host prefixed with some other region is global from this registry's view.
new_case
state "iap.googleapis.com"
observed "europe-west1-aiplatform.googleapis.com"
invoke
check "a foreign-region host is treated as global" "$OUT" "local.google_api_hosts_global"

# --- 3b. a non-Google host does NOT go in either shared list ---------------
#
# Both shared lists are granted to all five agents; a third-party backend
# dropped there is handed to cti_researcher, threat_hunter,
# detection_engineer, tier2_responder, and soc_orchestrator alike. GTI is
# scoped to cti_researcher alone, so the advice is a dedicated resource.

new_case
state "iap.googleapis.com"
observed "api.some-vendor.example"
invoke
check "a non-Google host gets its own resource" "$OUT" \
  "dedicated google_agent_registry_service scoped to one agent"
refute "a non-Google host avoids the global list" "$OUT" "local.google_api_hosts_global"
refute "a non-Google host avoids the regional list" "$OUT" "local.google_api_hosts_regional"

# --- 4. the service_id collision --------------------------------------------
#
# service_id is derived as replace(trimsuffix(h, ".googleapis.com"), ".", "-"),
# so a dotted and a dashed host can derive the same id. Registering the second
# one is a no-op: for_each keys by id and keeps the first host, so the 403 at
# the gateway continues.

echo "a service_id collision warns"

new_case
state "aiplatform.us.rep.googleapis.com"
observed "aiplatform-us-rep.googleapis.com"
invoke
check "a colliding service_id is flagged" "$OUT" "WARNING: service_id"
check "the collision names the derived id" "$OUT" "\"${REGION}-g-aiplatform-us-rep\""
check "the collision names the registered host that owns the id" "$OUT" \
  "collides with aiplatform.us.rep.googleapis.com"

# The upstream reference collided aiplatform.googleapis.com with
# <region>-aiplatform.googleapis.com. The SecOps derivation adds a "-g-"
# infix to non-regional ids precisely so both can coexist; a WARNING here
# would mean the script drifted from 10-registry-endpoints.tf.
new_case
state "${REGION}-aiplatform.googleapis.com"
observed "aiplatform.googleapis.com"
invoke
check "global aiplatform is still reported as a gap" "$OUT" "aiplatform.googleapis.com"
refute "global and regional aiplatform no longer collide" "$OUT" "WARNING: service_id"

# --- 5. empty registered set is FATAL ----------------------------------------

echo "an empty registered set is fatal"

new_case
empty_state
observed "storage.googleapis.com" "iap.googleapis.com"
invoke
equal "an empty registry is fatal" "$RC" 1
check "an empty registry explains itself" "$OUT" "no Agent Registry resources in terraform state"
refute "an empty registry reports no gap list" "$OUT" "UNREGISTERED HOSTS SEEN"
refute "an empty registry is not called clean" "$OUT" "no gaps"
equal "the diff is refused before any logs are read" "$READ" ""

# Resources of other types do not count as a registry.
new_case
write_state "$(resource google_compute_network "google_compute_network.vpc" "https://unused.example")"
observed "iap.googleapis.com"
invoke
equal "a state with no registry resources is fatal" "$RC" 1
check "the non-registry state explains itself" "$OUT" "no Agent Registry resources in terraform state"

# `terraform show -json` producing nothing at all is a distinct failure.
new_case
: >"$STUB_DIR/state.json"
observed "iap.googleapis.com"
invoke
equal "empty terraform output is fatal" "$RC" 1
check "empty terraform output explains itself" "$OUT" "terraform show -json"
check "empty terraform output names the cause" "$OUT" "returned empty output"

# --- 6. empty observation window is not a clean result -----------------------

echo "an empty observation window is not reported as clean"

new_case
state "iap.googleapis.com"
observed
invoke
check "an empty window is called out" "$OUT" "no gateway SNI entries observed in the last 1h"
refute "an empty window does not claim no gaps" "$OUT" "no gaps"
refute "an empty window does not list gaps" "$OUT" "UNREGISTERED HOSTS SEEN"
equal "an empty window is not an error exit" "$RC" 0

# --- 7. a truncated sample warns -------------------------------------------
#
# entries read == --limit means the window was cut short, so a clean result
# is optimistic.

echo "a truncated sample warns"

new_case
state "iap.googleapis.com" "storage.googleapis.com" "oauth2.googleapis.com"
observed "iap.googleapis.com" "storage.googleapis.com" "oauth2.googleapis.com"
invoke --limit 3
check "a truncated sample warns" "$OUT" "WARNING: sample truncated at --limit 3"
check "the warning says what to do" "$OUT" "rerun with higher --limit"
check "the explicit limit reaches the logging read" "$READ" "--limit=3"
check "a truncated clean sample still prints the diff" "$OUT" "no gaps"

new_case
state "iap.googleapis.com" "storage.googleapis.com" "oauth2.googleapis.com"
observed "iap.googleapis.com" "storage.googleapis.com"
invoke --limit 50
refute "an untruncated sample does not warn" "$OUT" "truncated"

# Truncation counts raw entries, not distinct hosts: three log lines for one
# host still fill a --limit 3 window.
new_case
state "iap.googleapis.com"
observed "iap.googleapis.com" "iap.googleapis.com" "iap.googleapis.com"
invoke --limit=3
check "truncation counts raw entries, not distinct hosts" "$OUT" "WARNING: sample truncated at --limit 3"

# --- 8. duplicates in the log collapse --------------------------------------

new_case
state "iap.googleapis.com"
observed "storage.googleapis.com" "storage.googleapis.com" "storage.googleapis.com"
invoke
equal "repeated hosts collapse to one gap row" \
  "$(printf '%s\n' "$OUT" | grep -c '^storage.googleapis.com')" 1

# --- 9. flags reach the logging read ------------------------------------------

echo "flags are passed through to the logging filter"

new_case
state "iap.googleapis.com"
observed "iap.googleapis.com"
invoke --freshness 24h
check "--freshness is passed through" "$READ" "--freshness=24h"
refute "the default freshness is replaced, not appended" "$READ" "--freshness=1h"

new_case
state "iap.googleapis.com"
observed
invoke --freshness=10m
check "--freshness=VALUE is passed through" "$READ" "--freshness=10m"
check "the empty-window note quotes the requested window" "$OUT" "in the last 10m"

new_case
state "iap.googleapis.com"
observed "iap.googleapis.com"
invoke --freshness 2weeks
equal "a malformed --freshness is rejected" "$RC" 1
check "the rejection explains the shape" "$OUT" "--freshness must look like 30m, 2h, or 7d"
equal "a malformed --freshness never reaches gcloud" "$READ" ""

new_case
state "iap.googleapis.com"
observed "iap.googleapis.com"
invoke --project other-project
check "--project overrides the fallback" "$READ" "--project=other-project"
refute "--project skips the fallback note" "$OUT" "falling back to gcloud configured project"

new_case
state "iap.googleapis.com"
observed "iap.googleapis.com"
invoke --limit abc
equal "a non-numeric --limit is rejected" "$RC" 1
check "the limit rejection explains itself" "$OUT" "--limit must be a positive integer"

# --- result ----------------------------------------------------------------

printf '\n%d passed, %d failed (%d cases)\n' "$PASS" "$FAIL" "$CASE"
[[ $FAIL -eq 0 ]]
