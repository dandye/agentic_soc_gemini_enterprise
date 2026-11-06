#!/usr/bin/env bash
#
# Flip the IAP authorization extension between DRY_RUN and ENFORCED.
#
#   enforce.sh              switch to ENFORCED (denials return HTTP 403)
#   enforce.sh dry-run      switch to DRY_RUN (denials logged only)
#   enforce.sh --plan       show planned diff without applying
#   enforce.sh status       print the current mode from terraform output

set -euo pipefail

TF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../terraform" && pwd)"
readonly TF_DIR

note() { printf 'enforce.sh: %s\n' "$*" >&2; }
die() {
  printf 'enforce.sh: %s\n' "$*" >&2
  exit 1
}

mode="ENFORCED"
plan_only=false
status_only=false
args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
  dry-run | dryrun | DRY_RUN) mode="DRY_RUN" ;;
  enforce | enforced | ENFORCED) mode="ENFORCED" ;;
  --plan) plan_only=true ;;
  status | --status) status_only=true ;;
  -h | --help)
    sed -n '2,9p' "${BASH_SOURCE[0]}"
    exit 0
    ;;
  *) args+=("$1") ;;
  esac
  shift
done

command -v terraform >/dev/null 2>&1 || die "terraform not found on PATH"

if $status_only; then
  cd "$TF_DIR"
  exec terraform output authz_enforcement
fi

if [[ -z ${TF_VAR_gti_api_key:-} ]] &&
  ! grep -rqsE '^[[:space:]]*gti_api_key[[:space:]]*=' "$TF_DIR"/*.tfvars 2>/dev/null; then
  die "TF_VAR_gti_api_key is unset and no *.tfvars in terraform/ defines gti_api_key. Set TF_VAR_gti_api_key before running enforce.sh."
fi

verb="apply"
$plan_only && verb="plan"

note "running terraform ${verb} with authz_enforcement_mode=${mode} in ${TF_DIR}"

cd "$TF_DIR"
terraform "$verb" -var "authz_enforcement_mode=${mode}" "${args[@]}"

if ! $plan_only; then
  cat >&2 <<EOT

enforce.sh: authz_enforcement_mode is now ${mode}.
Allow roughly 60 seconds for the Agent Gateway to pick up the updated metadata.
Verify with:
  terraform -chdir=terraform output authz_enforcement
EOT
fi
