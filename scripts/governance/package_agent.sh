#!/usr/bin/env bash
#
# Package governed SecOps agents into deterministic tarballs for Agent Runtime.
#
#   package_agent.sh all
#   package_agent.sh cti_researcher threat_hunter
#
# Produces, for each agent name:
#   terraform/dist/<name>.tar.gz    archive, base64-encoded into
#                                   spec.source_code_spec.inline_source
#   terraform/dist/<name>.sha256    hash of the source tree (see source_hash())
#
# Must stay byte-identical for identical input and place agent.py and
# requirements.txt at the archive root. The .sha256 formula must match
# terraform/40-package.tf exactly so stale archives fail at plan time.

set -euo pipefail

readonly SELF="package_agent.sh"
readonly AGENTS=(
  cti_researcher
  threat_hunter
  detection_engineer
  tier2_responder
  soc_orchestrator
)

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
readonly ROOT
readonly SRC_ROOT="$ROOT/governed_agents"
readonly DIST="$ROOT/terraform/dist"

note() { printf '%s: %s\n' "$SELF" "$*" >&2; }
die() {
  printf '%s: %s\n' "$SELF" "$*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

usage() {
  printf 'usage: %s all | <agent> [<agent>...]   (agents: %s)\n' \
    "$SELF" "${AGENTS[*]}" >&2
  exit 2
}

# Lists archive files, sorted bytewise (LC_ALL=C matches Terraform's sort()).
# Exclusions must match terraform/40-package.tf: __pycache__, *.pyc, *.pyo.
source_files() {
  local dir=$1
  (
    cd -- "$dir" || exit 1
    find . -type f \
      ! -path '*/__pycache__/*' \
      ! -name '*.pyc' \
      ! -name '*.pyo' \
      -print |
      sed 's|^\./||' |
      LC_ALL=C sort
  )
}

# Hash formula must match terraform/40-package.tf exactly.
source_hash() {
  local dir=$1 file
  {
    while IFS= read -r file; do
      printf '%s\n%s\n' "$file" "$(sha256sum -- "$dir/$file" | cut -d' ' -f1)"
    done
  } < <(source_files "$dir") | sha256sum | cut -d' ' -f1
}

package_one() {
  local name=$1
  local dir="$SRC_ROOT/$name"
  local out="$DIST/$name.tar.gz"

  [[ -d $dir ]] || die "no such agent directory: $dir"

  local files=()
  local f
  while IFS= read -r f; do files+=("$f"); done < <(source_files "$dir")
  ((${#files[@]} > 0)) || die "$name: no source files found in $dir"

  printf '%s\n' "${files[@]}" | grep -qx 'agent.py' ||
    die "$name: agent.py is missing from $dir (entrypoint_module = \"agent\")"
  printf '%s\n' "${files[@]}" | grep -qx 'requirements.txt' ||
    die "$name: requirements.txt is missing from $dir"

  mkdir -p -- "$DIST"

  tar \
    --create \
    --file - \
    --directory "$dir" \
    --no-recursion \
    --sort=name \
    --format=gnu \
    --mtime=@0 \
    --mode=0644 \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -- "${files[@]}" |
    gzip -9 -n >"$out.tmp"

  local entry
  local listing=""
  while IFS= read -r entry; do
    case "$entry" in
      /* | ./* | ../* | */../*)
        rm -f -- "$out.tmp"
        die "$name: archive entry '$entry' is not a plain path under the archive root"
        ;;
    esac
    listing+="$entry"$'\n'
  done < <(tar --list --file "$out.tmp" --gzip)

  grep -qx 'agent.py' <<<"$listing" || {
    rm -f -- "$out.tmp"
    die "$name: agent.py is not at the archive root"
  }
  grep -qx 'requirements.txt' <<<"$listing" || {
    rm -f -- "$out.tmp"
    die "$name: requirements.txt is not at the archive root"
  }

  mv -- "$out.tmp" "$out"
  source_hash "$dir" >"$DIST/$name.sha256"

  note "$name: $(printf '%s' "${#files[@]}") files -> $(realpath --relative-to="$ROOT" -- "$out" 2>/dev/null || printf '%s' "$out")"
}

main() {
  need tar
  need gzip
  need sha256sum
  need find

  (($# > 0)) || usage

  local requested=()
  if [[ $1 == all ]]; then
    (($# == 1)) || usage
    requested=("${AGENTS[@]}")
  else
    local arg known name
    for arg in "$@"; do
      known=false
      for name in "${AGENTS[@]}"; do
        [[ $arg == "$name" ]] && known=true
      done
      $known || die "unknown agent '$arg' (known: ${AGENTS[*]})"
      requested+=("$arg")
    done
  fi

  local name
  for name in "${requested[@]}"; do
    package_one "$name"
  done
}

main "$@"
