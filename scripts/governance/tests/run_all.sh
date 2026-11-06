#!/usr/bin/env bash
#
# Run every offline governance harness. No network, no credentials: each
# harness stubs gcloud/terraform/curl on PATH. Ported from the reference
# agent-governance repository's scripts/tests/, adapted to the five SecOps
# agents. The reference prompt_probe.py (a live A2A probe) is intentionally
# not ported; use scripts/governance/smoke_test.py for live verification.
#
#     bash scripts/governance/tests/run_all.sh
#
# Prints "ALL GREEN: <n> harnesses, <m> checks" and exits 0 on success,
# "FAILED: <k> of <n> harnesses" and exits 1 otherwise.

set -euo pipefail
shopt -s nullglob

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly HERE

harnesses=0
failures=0
checks=0

for t in "$HERE"/*_test.sh; do
  harnesses=$((harnesses + 1))
  printf '== %s\n' "$(basename "$t")"
  if out=$(bash "$t" 2>&1); then
    printf '%s\n' "$out"
  else
    printf '%s\n' "$out"
    failures=$((failures + 1))
  fi
  ok_count=$(printf '%s\n' "$out" | grep -c '^  ok ' || true)
  checks=$((checks + ok_count))
done

if ((failures > 0)); then
  printf 'FAILED: %d of %d harnesses\n' "$failures" "$harnesses"
  exit 1
fi

printf 'ALL GREEN: %d harnesses, %d checks\n' "$harnesses" "$checks"
