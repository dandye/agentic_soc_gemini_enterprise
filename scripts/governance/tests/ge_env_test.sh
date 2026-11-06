#!/usr/bin/env bash
#
# Offline branch tests for scripts/governance/ge_env.sh, which derives GE_*
# variables for bind_ge_app.sh and ge_agent.sh from `terraform output -json`.
#
# Stubs `terraform` on PATH so no state file or network access is required.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly SCRIPT_DIR
readonly TARGET="${SCRIPT_DIR}/ge_env.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

cat >"$WORK/bin/terraform" <<'STUB'
#!/usr/bin/env bash
printf 'terraform %s\n' "$*" >>"$STUB_DIR/terraform.log"
for a in "$@"; do
  if [[ $a == output ]]; then
    if [[ -f "$STUB_DIR/fail" ]]; then
      exit 1
    fi
    cat "$STUB_DIR/outputs.json"
    exit 0
  fi
done
exit 1
STUB
chmod +x "$WORK/bin/terraform"

PASS=0
FAIL=0
CASE=0

new_case() {
  STUB_DIR="$WORK/case-$((++CASE))"
  mkdir -p "$STUB_DIR"
  printf '{}' >"$STUB_DIR/outputs.json"
}

check() {
  if [[ "$2" == *"$3"* ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       expected to find: %s\n       in: %s\n' "$1" "$3" "$2"
    FAIL=$((FAIL + 1))
  fi
}

refute() {
  if [[ "$2" != *"$3"* ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       did NOT expect: %s\n       in: %s\n' "$1" "$3" "$2"
    FAIL=$((FAIL + 1))
  fi
}

equal() {
  if [[ "$2" == "$3" ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$3" "$2"
    FAIL=$((FAIL + 1))
  fi
}

readonly FULL_OUTPUTS='{
  "project_id": { "value": "example-secops-proj" },
  "ge_binding": {
    "value": {
      "bound": true,
      "published": true,
      "engine": "projects/123456789012/locations/global/collections/default_collection/engines/example-ge-app_100",
      "gateway": "projects/example-secops-proj/locations/us-central1/agentGateways/agw-secops-egress",
      "service_agent": "service-123456789012@gcp-sa-discoveryengine.iam.gserviceaccount.com",
      "custom_role": "projects/example-secops-proj/roles/agw_secops_ge_agent_gateway"
    }
  },
  "agent_engines": {
    "value": {
      "soc_orchestrator": {
        "engine_id": "9876543210",
        "path": "projects/example-secops-proj/locations/us-central1/reasoningEngines/9876543210",
        "a2a_url": "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/example-secops-proj/locations/us-central1/reasoningEngines/9876543210/a2a"
      }
    }
  }
}'

readonly UNBOUND_OUTPUTS='{
  "project_id": { "value": "example-secops-proj" },
  "ge_binding": {
    "value": {
      "bound": false,
      "published": false,
      "engine": null,
      "gateway": "projects/example-secops-proj/locations/us-central1/agentGateways/agw-secops-egress",
      "service_agent": "service-123456789012@gcp-sa-discoveryengine.iam.gserviceaccount.com",
      "custom_role": "projects/example-secops-proj/roles/agw_secops_ge_agent_gateway"
    }
  },
  "agent_engines": {
    "value": {
      "soc_orchestrator": {
        "engine_id": "9876543210",
        "path": "projects/example-secops-proj/locations/us-central1/reasoningEngines/9876543210"
      }
    }
  }
}'

invoke_env() {
  set +e
  OUT=$(
    unset GE_PROJECT_ID GE_PROJECT_NUMBER GE_LOCATION GE_COLLECTION_ID GE_ENGINE_ID GE_AGENT_GATEWAY GE_REASONING_ENGINE
    for kv in "$@"; do
      if [[ $kv == *=* ]]; then
        export "${kv?}"
      fi
    done
    local_args=()
    for kv in "$@"; do
      if [[ $kv != *=* ]]; then
        local_args+=("$kv")
      fi
    done
    PATH="$WORK/bin:$PATH" STUB_DIR="$STUB_DIR" bash "$TARGET" "${local_args[@]}" 2>"$STUB_DIR/stderr.log"
  )
  RC=$?
  set -e
  ERR=$(cat "$STUB_DIR/stderr.log" 2>/dev/null || true)
}

echo "full outputs -> derives all seven GE_* exports and evals cleanly"
new_case
printf '%s\n' "$FULL_OUTPUTS" >"$STUB_DIR/outputs.json"
invoke_env
equal "exits 0" "$RC" "0"
equal "no stderr" "$ERR" ""
eval_summary=$(
  unset GE_PROJECT_ID GE_PROJECT_NUMBER GE_LOCATION GE_COLLECTION_ID GE_ENGINE_ID GE_AGENT_GATEWAY GE_REASONING_ENGINE
  eval "$OUT"
  printf '%s|%s|%s|%s|%s|%s|%s' \
    "$GE_PROJECT_ID" "$GE_PROJECT_NUMBER" "$GE_LOCATION" "$GE_COLLECTION_ID" \
    "$GE_ENGINE_ID" "$GE_AGENT_GATEWAY" "$GE_REASONING_ENGINE"
)
equal "all seven variables match terraform outputs" "$eval_summary" \
  "example-secops-proj|123456789012|global|default_collection|example-ge-app_100|projects/example-secops-proj/locations/us-central1/agentGateways/agw-secops-egress|projects/example-secops-proj/locations/us-central1/reasoningEngines/9876543210"

echo "caller environment overrides win unless --force is passed"
new_case
printf '%s\n' "$FULL_OUTPUTS" >"$STUB_DIR/outputs.json"
invoke_env "GE_ENGINE_ID=caller-app_999" "GE_LOCATION=us"
equal "exits 0" "$RC" "0"
override_summary=$(
  unset GE_PROJECT_ID GE_PROJECT_NUMBER GE_LOCATION GE_COLLECTION_ID GE_ENGINE_ID GE_AGENT_GATEWAY GE_REASONING_ENGINE
  eval "$OUT"
  printf '%s|%s|%s' "$GE_ENGINE_ID" "$GE_LOCATION" "$GE_PROJECT_ID"
)
equal "caller GE_ENGINE_ID and GE_LOCATION win" "$override_summary" "caller-app_999|us|example-secops-proj"

new_case
printf '%s\n' "$FULL_OUTPUTS" >"$STUB_DIR/outputs.json"
invoke_env "GE_ENGINE_ID=caller-app_999" --force
equal "--force exits 0" "$RC" "0"
force_engine=$(
  unset GE_ENGINE_ID
  eval "$OUT"
  printf '%s' "$GE_ENGINE_ID"
)
equal "--force prefers terraform output over caller env" "$force_engine" "example-ge-app_100"

echo "unbound state (ge_binding.engine = null) -> fails loudly without GE_ENGINE_ID, succeeds with override"
new_case
printf '%s\n' "$UNBOUND_OUTPUTS" >"$STUB_DIR/outputs.json"
invoke_env
equal "exits 1 when ge_engine_id is unset everywhere" "$RC" "1"
equal "prints no partial exports on failure" "$OUT" ""
check "stderr names GE_ENGINE_ID" "$ERR" "GE_ENGINE_ID"

new_case
printf '%s\n' "$UNBOUND_OUTPUTS" >"$STUB_DIR/outputs.json"
invoke_env "GE_ENGINE_ID=manual-app_42"
equal "exits 0 when GE_ENGINE_ID is supplied in env" "$RC" "0"
fallback_pnum=$(
  unset GE_PROJECT_NUMBER GE_ENGINE_ID GE_LOCATION GE_COLLECTION_ID
  eval "$OUT"
  printf '%s|%s|%s|%s' "$GE_PROJECT_NUMBER" "$GE_ENGINE_ID" "$GE_LOCATION" "$GE_COLLECTION_ID"
)
equal "derives project_number from service_agent and defaults location/collection" \
  "$fallback_pnum" "123456789012|manual-app_42|global|default_collection"

echo "shell metacharacters in caller override are safely quoted for eval"
new_case
printf '%s\n' "$FULL_OUTPUTS" >"$STUB_DIR/outputs.json"
invoke_env 'GE_ENGINE_ID=app with spaces; touch /tmp/should-not-run $(false)'
equal "exits 0" "$RC" "0"
quoted_val=$(
  unset GE_ENGINE_ID
  eval "$OUT"
  printf '%s' "$GE_ENGINE_ID"
)
equal "eval preserves literal value without executing metacharacters" \
  "$quoted_val" 'app with spaces; touch /tmp/should-not-run $(false)'
refute "sentinel file was never created" "$(ls /tmp/should-not-run 2>/dev/null || true)" "should-not-run"

echo "empty or failed terraform output -> exits 1 with no stdout"
new_case
invoke_env
equal "empty {} output exits 1" "$RC" "1"
equal "no stdout on empty output" "$OUT" ""
check "mentions terraform apply" "$ERR" "returned no outputs"

new_case
touch "$STUB_DIR/fail"
invoke_env
equal "terraform exit 1 fails cleanly" "$RC" "1"
equal "no stdout on failed terraform" "$OUT" ""

echo "unknown flag -> usage error"
new_case
invoke_env --bogus
equal "exits 1" "$RC" "1"
check "names the unknown flag" "$ERR" "unknown argument '--bogus'"

printf '\n%d passed, %d failed (%d cases)\n' "$PASS" "$FAIL" "$CASE"
[[ $FAIL -eq 0 ]]
