#!/usr/bin/env bash
#
# Derive GE_* environment variables for bind_ge_app.sh and ge_agent.sh from
# `terraform output -json` (`project_id`, `ge_binding`, and `agent_engines`).
#
#   eval "$(bash scripts/governance/ge_env.sh)"
#   eval "$(bash scripts/governance/ge_env.sh --force)"
#
# Existing GE_* variables in the caller's environment win over Terraform outputs
# unless `--force` is passed. Exits non-zero without printing partial exports if
# any required variable cannot be resolved.

set -euo pipefail

readonly SELF="ge_env.sh"
TF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../terraform" && pwd)"
force=false

die() {
  printf '%s: %s\n' "$SELF" "$*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
  --force) force=true ;;
  --tf-dir)
    TF_DIR="${2:-}"
    [[ -n $TF_DIR ]] || die "--tf-dir requires a directory path"
    shift
    ;;
  --tf-dir=*)
    TF_DIR="${1#*=}"
    [[ -n $TF_DIR ]] || die "--tf-dir requires a directory path"
    ;;
  -h | --help)
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"
    exit 0
    ;;
  *) die "unknown argument '$1'. Usage: ge_env.sh [--force] [--tf-dir DIR]" ;;
  esac
  shift
done

need terraform
need jq

tf_json="$(terraform -chdir="$TF_DIR" output -json 2>/dev/null || true)"
[[ -n $tf_json && $tf_json != "{}" ]] ||
  die "terraform -chdir=${TF_DIR} output -json returned no outputs. Run terraform apply first or export GE_* explicitly."

jq -e . >/dev/null 2>&1 <<<"$tf_json" ||
  die "terraform -chdir=${TF_DIR} output -json did not return valid JSON."

parsed="$(jq -r '
  (.project_id.value // "") as $project_id
  | (.ge_binding.value // {}) as $ge
  | ($ge.engine // "") as $engine_res
  | (if ($engine_res | test("^projects/[^/]+/locations/[^/]+/collections/[^/]+/engines/[^/]+$"))
     then ($engine_res | capture("^projects/(?<pnum>[^/]+)/locations/(?<loc>[^/]+)/collections/(?<col>[^/]+)/engines/(?<eid>[^/]+)$"))
     else {pnum: "", loc: "", col: "", eid: ""}
     end) as $eng
  | (if $eng.pnum != "" then $eng.pnum
     elif (($ge.service_agent // "") | test("^service-[0-9]+@"))
     then (($ge.service_agent | sub("^service-"; "") | split("@")[0]))
     else ""
     end) as $project_number
  | [
      $project_id,
      $project_number,
      $eng.loc,
      $eng.col,
      $eng.eid,
      ($ge.gateway // ""),
      (.agent_engines.value.soc_orchestrator.path // "")
    ]
  | join("\u001f")
' <<<"$tf_json")"

IFS=$'\x1f' read -r tf_project_id tf_project_number tf_location tf_collection tf_engine_id tf_gateway tf_reasoning_engine <<<"$parsed"

pick() {
  local current=$1 derived=$2 fallback=${3:-}
  if ! $force && [[ -n $current ]]; then
    printf '%s' "$current"
  elif [[ -n $derived ]]; then
    printf '%s' "$derived"
  else
    printf '%s' "$fallback"
  fi
}

ge_project_id="$(pick "${GE_PROJECT_ID:-}" "$tf_project_id")"
ge_project_number="$(pick "${GE_PROJECT_NUMBER:-}" "$tf_project_number")"
ge_location="$(pick "${GE_LOCATION:-}" "$tf_location" "global")"
ge_collection_id="$(pick "${GE_COLLECTION_ID:-}" "$tf_collection" "default_collection")"
ge_engine_id="$(pick "${GE_ENGINE_ID:-}" "$tf_engine_id")"
ge_agent_gateway="$(pick "${GE_AGENT_GATEWAY:-}" "$tf_gateway")"
ge_reasoning_engine="$(pick "${GE_REASONING_ENGINE:-}" "$tf_reasoning_engine")"

[[ -n $ge_project_id ]] || die "could not derive GE_PROJECT_ID from terraform output project_id (export GE_PROJECT_ID to override)."
[[ -n $ge_project_number ]] || die "could not derive GE_PROJECT_NUMBER from terraform output ge_binding (export GE_PROJECT_NUMBER to override)."
[[ -n $ge_engine_id ]] || die "could not derive GE_ENGINE_ID from terraform output ge_binding.engine (set ge_engine_id in terraform.tfvars and apply, or export GE_ENGINE_ID)."
[[ -n $ge_agent_gateway ]] || die "could not derive GE_AGENT_GATEWAY from terraform output ge_binding.gateway (export GE_AGENT_GATEWAY to override)."
[[ -n $ge_reasoning_engine ]] || die "could not derive GE_REASONING_ENGINE from terraform output agent_engines.soc_orchestrator.path (export GE_REASONING_ENGINE to override)."

printf 'export GE_PROJECT_ID=%q\n' "$ge_project_id"
printf 'export GE_PROJECT_NUMBER=%q\n' "$ge_project_number"
printf 'export GE_LOCATION=%q\n' "$ge_location"
printf 'export GE_COLLECTION_ID=%q\n' "$ge_collection_id"
printf 'export GE_ENGINE_ID=%q\n' "$ge_engine_id"
printf 'export GE_AGENT_GATEWAY=%q\n' "$ge_agent_gateway"
printf 'export GE_REASONING_ENGINE=%q\n' "$ge_reasoning_engine"
