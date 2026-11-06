#!/usr/bin/env bash
#
# Offline branch tests for scripts/governance/sgp_gateway_config.sh.
#
# Stubs curl, gcloud and sleep on PATH, so this makes no network calls and
# provisions nothing. The script under test is the shim that
# terraform/65-semantic-governance.tf runs from terraform_data.sgp_gateway_config
# (attach on create, detach on destroy) with SGP_PROJECT_ID, SGP_REGION,
# SGP_GATEWAY_KEY (= resource_prefix, agw-secops), SGP_NETWORK, SGP_SUBNETWORK
# and SGP_DNS_ZONE_FQDN in the environment.
#
#     bash scripts/governance/tests/sgp_test.sh
#
# Scope note: the shim only manages the engine's gatewayConfigs map. The
# CONTENT_AUTHZ callout timeout (var.sgp_timeout), the DRY_RUN/ENFORCED toggle
# (sgpEnforcementMode metadata on the authz extension) and the per-agent
# policy attachment (google_vertex_ai_semantic_governance_policy) are plain
# Terraform resources in 65-semantic-governance.tf, not script output, so
# there is nothing for this harness to assert about them.
#
# gatewayConfigs is a whole-map replace: a PATCH that forgets someone else's
# key deletes their PSC endpoint. Several cases exist only to catch that.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly SCRIPT_DIR
readonly GWCFG="${SCRIPT_DIR}/sgp_gateway_config.sh"

readonly PROJECT_ID="example-project"
readonly REGION="us-central1"
readonly KEY="agw-secops"

readonly ENGINE_URL="https://${REGION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT_ID}/locations/${REGION}/semanticGovernancePolicyEngine"
readonly RULE_URL="https://compute.googleapis.com/compute/v1/projects/${PROJECT_ID}/regions/${REGION}/forwardingRules/sgpe-psce-${KEY}"

readonly NETWORK="projects/${PROJECT_ID}/global/networks/${KEY}-sgp"
readonly SUBNET="projects/${PROJECT_ID}/regions/${REGION}/subnetworks/${KEY}-sgp"
readonly ZONE="sgp.example.internal"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# --- stubs -----------------------------------------------------------------

cat >"$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Replays $STUB_DIR/<n> ("code\nbody") in call order; logs method+URL, the
# full argv, and any request bodies.
[[ "$*" == *"--data-binary"* ]] && { cat >>"$STUB_DIR/bodies.log"; echo >>"$STUB_DIR/bodies.log"; }
echo "$*" | grep -oE '(-X [A-Z]+|https://[^ ]+)' | tr '\n' ' ' >>"$STUB_DIR/calls.log"
echo >>"$STUB_DIR/calls.log"
printf '%s\n' "$*" >>"$STUB_DIR/args.log"
n=$(cat "$STUB_DIR/n" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$STUB_DIR/n"
code=$(head -1 "$STUB_DIR/$n")
printf '%s\n%s' "$(tail -n +2 "$STUB_DIR/$n")" "$code"
STUB

cat >"$WORK/bin/gcloud" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_DIR/gcloud.log"
[[ -n ${GCLOUD_FAIL:-} ]] && exit 1
echo stub-access-token
STUB

printf '#!/usr/bin/env bash\nexit 0\n' >"$WORK/bin/sleep"
chmod +x "$WORK/bin"/*

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

# invoke SCRIPT ACTION [VAR=value ...] -- sets OUT, RC, CALLS, BODIES, ARGS, GCLOUD
invoke() {
  local script=$1 action=$2
  shift 2
  set +e
  OUT=$(
    for kv in "$@"; do export "${kv?}"; done
    PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" \
      SGP_PROJECT_ID="$PROJECT_ID" \
      SGP_REGION="$REGION" \
      SGP_GATEWAY_KEY="$KEY" \
      SGP_POLL_SECONDS=1 \
      bash "$script" "$action" 2>&1
  )
  RC=$?
  set -e
  CALLS=$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)
  BODIES=$(cat "$STUB_DIR/bodies.log" 2>/dev/null || true)
  ARGS=$(cat "$STUB_DIR/args.log" 2>/dev/null || true)
  GCLOUD=$(cat "$STUB_DIR/gcloud.log" 2>/dev/null || true)
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

count_patches() { grep -c -- '-X PATCH' <<<"$CALLS" || true; }
count_gets() { grep -c -- '-X GET' <<<"$CALLS" || true; }

OK='200'

# An ACTIVE engine with no gateway configs at all.
EMPTY='{"name":"engines/x","state":"ACTIVE"}'

# ours [STATE] [ZONE] -- our key, provisioned. Carries the output-only fields
# the shim must strip before echoing the map back.
ours() {
  cat <<EOF
{"name":"e","state":"ACTIVE","gatewayConfigs":{"${KEY}":{"network":"${NETWORK}","subnetwork":"${SUBNET}","dnsZoneName":"${2:-$ZONE}","state":"${1:-ACTIVE}","ipAddress":"10.60.0.9","pscEndpoint":"projects/${PROJECT_ID}/regions/${REGION}/forwardingRules/f","dnsRecord":"${REGION}.${2:-$ZONE}."}}}
EOF
}

# Someone else's gateway config, which must survive both attach and detach.
OTHER="{\"name\":\"e\",\"state\":\"ACTIVE\",\"gatewayConfigs\":{\"someone-else\":{\"network\":\"projects/${PROJECT_ID}/global/networks/theirs\",\"subnetwork\":\"projects/${PROJECT_ID}/regions/${REGION}/subnetworks/theirs\",\"dnsZoneName\":\"theirs.internal\",\"state\":\"ACTIVE\",\"ipAddress\":\"10.9.9.9\"}}}"

# both [STATE] -- ours merged with OTHER
both() {
  jq -sc '.[0].gatewayConfigs += .[1].gatewayConfigs | .[0]' <(ours "${1:-ACTIVE}") <(echo "$OTHER")
}

ACCEPTED='{"pscConnectionStatus":"ACCEPTED","IPAddress":"10.60.0.5"}'
PENDING='{"pscConnectionStatus":"PENDING","IPAddress":"10.60.0.5"}'
NOT_FOUND='{"error":{"code":404}}'

ATTACH_ENV=(SGP_NETWORK="$NETWORK" SGP_SUBNETWORK="$SUBNET" SGP_DNS_ZONE_FQDN="$ZONE")

echo "sgp_gateway_config.sh"

echo "  attach onto an empty engine"
stage "$OK" "$EMPTY" "$OK" "$(ours)" "$OK" "$(ours)"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 0" "$RC" "0"
check "reads the engine first" "$CALLS" "-X GET ${ENGINE_URL}"
check "PATCHes with updateMask=gatewayConfigs" "$CALLS" "-X PATCH ${ENGINE_URL}?updateMask=gatewayConfigs"
# The host is regional; the global aiplatform host does not serve this resource.
check "uses the regional host" "$CALLS" "https://${REGION}-aiplatform.googleapis.com/"
check "singleton path has no id segment" "$CALLS" "/locations/${REGION}/semanticGovernancePolicyEngine "
check "sends the bearer token from gcloud" "$ARGS" "Authorization: Bearer stub-access-token"
check "bills the project via X-Goog-User-Project" "$ARGS" "X-Goog-User-Project: ${PROJECT_ID}"
check "token comes from ADC, not the gcloud user login" "$GCLOUD" "auth application-default print-access-token"
check "sends our key" "$(jq -r --arg k "$KEY" '.gatewayConfigs[$k].network' <<<"$BODIES")" "$NETWORK"
check "sends the subnetwork" "$(jq -r --arg k "$KEY" '.gatewayConfigs[$k].subnetwork' <<<"$BODIES")" "$SUBNET"
check "sends the dns zone" "$(jq -r --arg k "$KEY" '.gatewayConfigs[$k].dnsZoneName' <<<"$BODIES")" "$ZONE"
equal "body carries only the three writable fields" \
  "$(jq -c --arg k "$KEY" '.gatewayConfigs[$k] | keys' <<<"$BODIES")" '["dnsZoneName","network","subnetwork"]'
check "announces the attach" "$OUT" "attaching '${KEY}' to ${NETWORK} (${SUBNET}), zone ${ZONE}"
check "waits for ACTIVE" "$OUT" "gateway config '${KEY}' is ACTIVE"
check "reports the endpoint address" "$OUT" "endpoint IP: 10.60.0.9"
check "reports the DNS record" "$OUT" "DNS record:  ${REGION}.${ZONE}."
equal "exactly one PATCH" "$(count_patches)" "1"

echo "  attach preserves another gateway's config"
stage "$OK" "$OTHER" "$OK" "$(both)" "$OK" "$(both)"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 0" "$RC" "0"
# gatewayConfigs is a whole-map replace. Dropping this key would delete a PSC
# endpoint belonging to someone else.
check "keeps someone-else" "$(jq -r '.gatewayConfigs["someone-else"].dnsZoneName' <<<"$BODIES")" "theirs.internal"
check "adds ours alongside" "$(jq -r --arg k "$KEY" '.gatewayConfigs[$k].network' <<<"$BODIES")" "$NETWORK"
equal "sends both keys" "$(jq -r '.gatewayConfigs | keys | join(",")' <<<"$BODIES")" "${KEY},someone-else"

echo "  attach strips output-only fields from the echoed-back map"
stage "$OK" "$(both PROVISIONING)" "$OK" "$(both)" "$OK" "$(both)" "$OK" "$(both)" "$OK" "$(both)"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
# Sending state/ipAddress/pscEndpoint/dnsRecord back is a 400.
refute "no state in the body" "$BODIES" '"state"'
refute "no ipAddress in the body" "$BODIES" '"ipAddress"'
refute "no pscEndpoint in the body" "$BODIES" '"pscEndpoint"'
refute "no dnsRecord in the body" "$BODIES" '"dnsRecord"'

echo "  attach is idempotent when already ACTIVE with the same settings"
stage "$OK" "$(ours)"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 0" "$RC" "0"
check "says it already matches" "$OUT" "gateway config '${KEY}' is already ACTIVE with matching settings"
refute "issues no PATCH" "$CALLS" "-X PATCH"
equal "a single GET is the only call" "$(count_gets)" "1"
refute "does not consult Compute" "$CALLS" "compute.googleapis.com"

echo "  attach re-PATCHes in place when ACTIVE but the settings drifted"
# An ACTIVE key is never cleared first; the merged map just overwrites it.
stage "$OK" "$(ours ACTIVE old.example.internal)" "$OK" "$(ours)" "$OK" "$(ours)"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 0" "$RC" "0"
refute "does not clear" "$OUT" "clearing before retry"
equal "exactly one PATCH" "$(count_patches)" "1"
check "sends the new zone" "$(jq -r --arg k "$KEY" '.gatewayConfigs[$k].dnsZoneName' <<<"$BODIES")" "$ZONE"
refute "old zone is gone from the body" "$BODIES" "old.example.internal"

echo "  attach waits while the engine is still PROVISIONING"
# Differs from the reference shim, which refused outright: ours polls the
# engine state until ACTIVE, then proceeds with the normal attach.
stage "$OK" '{"name":"e","state":"PROVISIONING"}' "$OK" "$EMPTY" "$OK" "$(ours)" "$OK" "$(ours)"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 0" "$RC" "0"
check "reports the wait" "$OUT" "policy engine state=PROVISIONING; waiting (0s/"
check "then attaches" "$OUT" "attaching '${KEY}'"
equal "GET, GET, PATCH, GET in that order" \
  "$(grep -oE -- '-X [A-Z]+' <<<"$CALLS" | tr '\n' ' ')" "-X GET -X GET -X PATCH -X GET "

echo "  attach gives up when the engine stays INACTIVE past SGP_WAIT_SECONDS"
stage "$OK" '{"name":"e","state":"INACTIVE"}' "$OK" '{"name":"e","state":"INACTIVE"}'
invoke "$GWCFG" attach "${ATTACH_ENV[@]}" SGP_WAIT_SECONDS=2
equal "exits 1" "$RC" "1"
check "polls INACTIVE too" "$OUT" "policy engine state=INACTIVE; waiting"
check "names the final state and the budget" "$OUT" "policy engine remained in state INACTIVE after 2s"
refute "mutates nothing" "$CALLS" "-X PATCH"
equal "polled exactly twice" "$(count_gets)" "2"

echo "  attach refuses an engine in an unexpected state"
stage "$OK" '{"name":"e","state":"FAILED"}'
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 1" "$RC" "1"
check "names the state" "$OUT" "policy engine is in state FAILED, expected ACTIVE"
refute "mutates nothing" "$CALLS" "-X PATCH"

echo "  attach fails on FAILED when the endpoint is NOT up"
# Fourth response is the Compute lookup endpoint_ok() makes: a 404 means the
# engine genuinely failed, which must still stop the apply.
stage "$OK" "$EMPTY" "$OK" "$(ours)" "$OK" "$(ours FAILED)" 404 "$NOT_FOUND"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 1" "$RC" "1"
check "looks up the forwarding rule by its engine-assigned name" "$CALLS" "-X GET ${RULE_URL}"
check "reports FAILED" "$OUT" "gateway config '${KEY}' reached state FAILED"
check "names the missing endpoint" "$OUT" "PSC endpoint sgpe-psce-${KEY} is missing or not ACCEPTED"

echo "  attach tolerates FAILED when the PSC endpoint is ACCEPTED"
# The engine can mark a config FAILED despite a working endpoint; failing the
# apply here strands a deployment.
stage "$OK" "$EMPTY" "$OK" "$(ours)" "$OK" "$(ours FAILED)" "$OK" "$ACCEPTED"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 0" "$RC" "0"
check "warns rather than dying" "$OUT" "WARNING: gateway config '${KEY}' reports state FAILED, but"
check "names the endpoint address" "$OUT" "sgpe-psce-${KEY} exists at 10.60.0.5"
check "points at the Terraform-owned A record" "$OUT" "65-semantic-governance.tf"

echo "  attach does NOT tolerate a PENDING endpoint"
# A forwarding rule that exists proves nothing: PSC connections sit PENDING
# until the producer accepts them, and a PENDING rule routes nowhere.
stage "$OK" "$EMPTY" "$OK" "$(ours)" "$OK" "$(ours FAILED)" "$OK" "$PENDING"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 1" "$RC" "1"
check "treats PENDING as not up" "$OUT" "is missing or not ACCEPTED"

echo "  attach times out when the key never leaves PROVISIONING"
stage "$OK" "$EMPTY" "$OK" "$(ours PROVISIONING)" "$OK" "$(ours PROVISIONING)"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}" SGP_WAIT_SECONDS=1
equal "exits 1" "$RC" "1"
check "reports the interim state" "$OUT" "state=PROVISIONING; waiting (0s/1s)"
check "names the timeout" "$OUT" "timed out after 1s waiting for '${KEY}' to become ACTIVE"

echo "  attach refuses to exceed the five-config limit"
FIVE=$(jq -nc '{name:"e",state:"ACTIVE",gatewayConfigs:
  ([range(5)] | map({key:("gw-"+tostring), value:{network:"n",subnetwork:"s",dnsZoneName:"z"}}) | from_entries)}')
stage "$OK" "$FIVE"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 1" "$RC" "1"
check "names the limit and the would-be count" "$OUT" "attaching '${KEY}' would exceed the 5-config limit (6)"
refute "mutates nothing" "$CALLS" "-X PATCH"

echo "  attach dies on a non-2xx PATCH"
stage "$OK" "$EMPTY" 409 '{"error":{"code":409,"message":"conflict"}}'
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 1" "$RC" "1"
check "names the HTTP code" "$OUT" "gatewayConfigs update failed (HTTP 409)"
check "echoes the response body" "$OUT" "conflict"
equal "does not poll after the failed write" "$(count_gets)" "1"

echo "  404 -> names the Terraform resource that creates the engine"
stage 404 "$NOT_FOUND"
invoke "$GWCFG" status
equal "exits 1" "$RC" "1"
check "names the engine path" "$OUT" "no policy engine at projects/${PROJECT_ID}/locations/${REGION}/semanticGovernancePolicyEngine"
check "names the resource that creates it" "$OUT" "Apply google_vertex_ai_semantic_governance_policy_engine first"

echo "  403 -> reports the denial"
stage 403 '{"error":{"code":403,"message":"denied"}}'
invoke "$GWCFG" status
equal "exits 1" "$RC" "1"
check "names the code" "$OUT" "HTTP 403 reading policy engine at"
check "echoes the body" "$OUT" "denied"

echo "  other non-2xx -> unexpected"
stage 500 '{"error":{"code":500}}'
invoke "$GWCFG" status
equal "exits 1" "$RC" "1"
check "names the code" "$OUT" "unexpected HTTP 500 reading"

echo "  status prints state and the config map"
stage "$OK" "$(ours)"
invoke "$GWCFG" status
equal "exits 0" "$RC" "0"
check "reports the engine state" "$OUT" "engine state: ACTIVE"
check "prints our key" "$OUT" "\"${KEY}\""
check "prints the endpoint" "$OUT" "10.60.0.9"
refute "issues no PATCH" "$CALLS" "-X PATCH"

echo "  detach removes only our key"
# Three responses, not two: detach polls until the key is gone, so the PATCH
# reply is followed by a wait_gone GET.
stage "$OK" "$(both)" "$OK" "$OTHER" "$OK" "$OTHER"
invoke "$GWCFG" detach
equal "exits 0" "$RC" "0"
check "announces it" "$OUT" "detaching '${KEY}'"
check "PATCHes" "$CALLS" "-X PATCH ${ENGINE_URL}?updateMask=gatewayConfigs"
check "someone-else survives" "$(jq -r '.gatewayConfigs["someone-else"].dnsZoneName' <<<"$BODIES")" "theirs.internal"
refute "our key is gone" "$(jq -r '.gatewayConfigs | keys | join(",")' <<<"$BODIES")" "$KEY"
refute "someone-else is sent without output-only fields" "$BODIES" '"ipAddress"'
check "reports it gone" "$OUT" "gateway config '${KEY}' is gone"
check "ends with ok" "$OUT" "ok"

echo "  detach of the last key sends an empty map, not a missing field"
stage "$OK" "$(ours)" "$OK" "$EMPTY" "$OK" "$EMPTY"
invoke "$GWCFG" detach
equal "exits 0" "$RC" "0"
equal "body is {\"gatewayConfigs\":{}}" "$(jq -c . <<<"$BODIES")" '{"gatewayConfigs":{}}'

echo "  detach waits for the teardown, not just the 200"
stage "$OK" "$(both)" "$OK" "$OTHER" "$OK" "$(both)" "$OK" "$OTHER"
invoke "$GWCFG" detach
equal "exits 0" "$RC" "0"
check "polls while the key is still present" "$OUT" "teardown state=ACTIVE; waiting"
check "reports it gone" "$OUT" "is gone"
equal "three GETs" "$(count_gets)" "3"

echo "  detach warns but exits 0 when the key never disappears"
# Terraform runs detach with on_failure = continue; the shim itself also does
# not fail a destroy over a slow teardown.
stage "$OK" "$(both)" "$OK" "$OTHER" "$OK" "$(both)" "$OK" "$(both)"
invoke "$GWCFG" detach SGP_WAIT_SECONDS=2
equal "exits 0" "$RC" "0"
check "warns" "$OUT" "WARNING: '${KEY}' still present after 2s. Continuing anyway."

echo "  attach clears a FAILED config instead of re-PATCHing an identical map"
# Without the clearing branch the merged map is byte-identical, the PATCH is
# a no-op, and every retry dies on the same stale FAILED read. Second response
# is the Compute lookup (404): endpoint genuinely gone, so clearing is right.
stage "$OK" "$(ours FAILED)" 404 "$NOT_FOUND" \
  "$OK" "$EMPTY" "$OK" "$EMPTY" "$OK" "$EMPTY" \
  "$OK" "$(ours)" "$OK" "$(ours)"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 0" "$RC" "0"
check "says it is clearing" "$OUT" "gateway config '${KEY}' is in state FAILED; clearing before retry"
check "waits for the clear" "$OUT" "is gone"
check "ends ACTIVE" "$OUT" "is ACTIVE"
# Two PATCHes: one to delete the FAILED key, one to write it back.
equal "deletes then recreates" "$(count_patches)" "2"
equal "first PATCH drops our key" "$(head -1 <<<"$BODIES" | jq -c '.gatewayConfigs')" "{}"

echo "  attach leaves a FAILED-but-working config alone when the settings match"
# The regression this catches: clearing a live endpoint reserves a new
# address on rebuild, so the A record stays stale from the next apply on.
stage "$OK" "$(ours FAILED)" "$OK" "$ACCEPTED"
invoke "$GWCFG" attach "${ATTACH_ENV[@]}"
equal "exits 0" "$RC" "0"
check "says why it is leaving it" "$OUT" "reports FAILED, but endpoint 10.60.0.5 is ACCEPTED with matching settings"
refute "issues no PATCH" "$CALLS" "-X PATCH"

echo "  detach when nothing is attached -> no write"
stage "$OK" "$EMPTY"
invoke "$GWCFG" detach
equal "exits 0" "$RC" "0"
check "says nothing to do" "$OUT" "no gateway config '${KEY}' -- nothing to do"
refute "issues no PATCH" "$CALLS" "-X PATCH"

echo "  GOOGLE_OAUTH_ACCESS_TOKEN short-circuits gcloud"
stage "$OK" "$EMPTY"
invoke "$GWCFG" detach GOOGLE_OAUTH_ACCESS_TOKEN=preset-token
equal "exits 0" "$RC" "0"
equal "gcloud never runs" "$GCLOUD" ""
check "uses the preset token" "$ARGS" "Authorization: Bearer preset-token"

echo "  gcloud failure -> actionable message, no calls"
stage "$OK" "$EMPTY"
invoke "$GWCFG" status GCLOUD_FAIL=1
equal "exits 1" "$RC" "1"
check "names the fix" "$OUT" "could not obtain an ADC access token"
check "mentions --update-adc" "$OUT" "--update-adc"
equal "no curl calls" "$CALLS" ""

echo "  missing required env -> refuses before any call"
stage "$OK" "$EMPTY"
set +e
OUT=$(PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" SGP_PROJECT_ID="$PROJECT_ID" SGP_REGION="$REGION" \
  bash "$GWCFG" attach 2>&1)
RC=$?
set -e
equal "exits 1" "$RC" "1"
check "names the missing variable" "$OUT" "SGP_GATEWAY_KEY must be set"
equal "no curl calls" "$(cat "$STUB_DIR/calls.log" 2>/dev/null || true)" ""

echo "  attach without its network env -> refuses before any call"
stage "$OK" "$EMPTY"
invoke "$GWCFG" attach SGP_NETWORK="$NETWORK" SGP_SUBNETWORK="$SUBNET"
equal "exits 1" "$RC" "1"
check "names the missing variable" "$OUT" "SGP_DNS_ZONE_FQDN must be set"
equal "no curl calls" "$CALLS" ""

echo "  detach does not need the attach-only env"
stage "$OK" "$EMPTY"
invoke "$GWCFG" detach
equal "exits 0" "$RC" "0"
refute "no env complaint" "$OUT" "must be set"

echo "  unknown action -> usage"
stage "$OK" "$EMPTY"
invoke "$GWCFG" bogus
equal "exits 1" "$RC" "1"
check "prints usage" "$OUT" "usage: sgp_gateway_config.sh status|attach|detach"
equal "no curl calls" "$CALLS" ""

# --- result ----------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
