#!/usr/bin/env bash
#
# Offline verification for multi-environment Terraform templates, gitignore rules,
# and `just governance-init` / `just governance-plan` arguments when `just` is
# installed on PATH.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
readonly REPO_ROOT

PASS=0
FAIL=0

check() {
  if [[ "$2" == *"$3"* ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       expected to find: %s\n       in: %s\n' "$1" "$3" "$2"
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

echo "gitignore protects backend.tf and environment tfvars while tracking examples"
set +e
git -C "$REPO_ROOT" check-ignore -q terraform/backend.tf
rc_backend=$?
git -C "$REPO_ROOT" check-ignore -q terraform/environments/demo.tfvars
rc_demo=$?
git -C "$REPO_ROOT" check-ignore -q terraform/backend.tf.example
rc_backend_ex=$?
git -C "$REPO_ROOT" check-ignore -q terraform/environments/example.tfvars.example
rc_env_ex=$?
set -e

equal "terraform/backend.tf is git-ignored" "$rc_backend" "0"
equal "terraform/environments/demo.tfvars is git-ignored" "$rc_demo" "0"
equal "terraform/backend.tf.example is tracked" "$rc_backend_ex" "1"
equal "terraform/environments/example.tfvars.example is tracked" "$rc_env_ex" "1"

if command -v just >/dev/null 2>&1; then
  echo "just governance-init writes backend.tf and passes -migrate-state"
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  mkdir -p "$WORK/bin" "$WORK/terraform/environments"

  cat >"$WORK/bin/terraform" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_LOG"
STUB
  chmod +x "$WORK/bin/terraform"

  set +e
  OUT=$(
    PATH="$WORK/bin:$PATH" STUB_LOG="$WORK/tf.log" \
      just --justfile "$REPO_ROOT/justfile" --working-directory "$WORK" \
      governance-init bucket=example-tfstate-bucket prefix=agentic-soc-governance/demo migrate=true 2>&1
  )
  rc=$?
  set -e
  equal "governance-init exits 0" "$rc" "0"
  check "announces backend.tf write" "$OUT" "Wrote terraform/backend.tf"
  backend_body=$(cat "$WORK/terraform/backend.tf")
  check "backend.tf carries bucket" "$backend_body" 'bucket = "example-tfstate-bucket"'
  check "backend.tf carries prefix" "$backend_body" 'prefix = "agentic-soc-governance/demo"'
  check "calls terraform init -migrate-state" "$(cat "$WORK/tf.log")" "-chdir=terraform init -migrate-state"

  set +e
  BAD_OUT=$(
    PATH="$WORK/bin:$PATH" STUB_LOG="$WORK/tf.log" \
      just --justfile "$REPO_ROOT/justfile" --working-directory "$WORK" \
      governance-init bucket="BAD BUCKET!" 2>&1
  )
  bad_rc=$?
  set -e
  equal "rejects malformed bucket name" "$bad_rc" "1"
  check "names invalid bucket" "$BAD_OUT" "invalid GCS bucket name"

  : >"$WORK/tf.log"
  set +e
  PRE_OUT=$(
    PATH="$WORK/bin:$PATH" STUB_LOG="$WORK/tf.log" \
      just --justfile "$REPO_ROOT/justfile" --working-directory "$WORK" \
      bucket=second-tfstate-bucket governance-init 2>&1
  )
  pre_rc=$?
  set -e
  equal "just bucket=... governance-init also exits 0" "$pre_rc" "0"
  check "updates backend.tf with default prefix" "$PRE_OUT" "prefix=agentic-soc-governance/default"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
