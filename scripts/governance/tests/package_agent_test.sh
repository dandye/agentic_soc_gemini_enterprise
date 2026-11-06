#!/usr/bin/env bash
#
# Offline tests for scripts/governance/package_agent.sh. Guards the two
# properties it exists to guarantee: files at the archive root, and
# byte-identical output for identical input.
#
# Makes no network calls and needs no credentials. Run from anywhere:
#
#     bash scripts/governance/tests/package_agent_test.sh
#
# Most cases run against a synthetic tree in a tempdir. package_agent.sh
# derives its root from its own location two levels up, so copying it into
# $WORK/root/scripts/governance/ gives it a fake repo whose agents live in
# $WORK/root/governed_agents/. The last block runs against the real
# governed_agents/ tree and regenerates terraform/dist/ (gitignored).

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly SCRIPT_DIR
readonly TARGET="$SCRIPT_DIR/package_agent.sh"
readonly REPO_ROOT="${SCRIPT_DIR%/scripts/governance}"
readonly AGENTS=(cti_researcher threat_hunter detection_engineer tier2_responder soc_orchestrator)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

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

differs() { # differs DESCRIPTION ACTUAL UNEXPECTED
  if [[ "$2" != "$3" ]]; then
    printf '  ok   %s\n' "$1"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n       expected a value other than: %s\n' "$1" "$3"
    FAIL=$((FAIL + 1))
  fi
}

# --- synthetic repo --------------------------------------------------------
#
# Same five agent names the script knows about; content is chosen to exercise
# the exclusion rules: a nested package, __pycache__, a stray .pyc, an exec bit.

fixture() {
  rm -rf "$WORK/root"
  mkdir -p "$WORK/root/scripts/governance"
  cp "$TARGET" "$WORK/root/scripts/governance/"

  local a
  for a in "${AGENTS[@]}"; do
    mkdir -p "$WORK/root/governed_agents/$a/__pycache__" "$WORK/root/governed_agents/$a/sub"
    printf 'root_agent = "%s"\n' "$a" >"$WORK/root/governed_agents/$a/agent.py"
    printf 'pinned==1.0\n' >"$WORK/root/governed_agents/$a/requirements.txt"
    printf 'VALUE = 1\n' >"$WORK/root/governed_agents/$a/sub/helper.py"
    printf 'garbage\n' >"$WORK/root/governed_agents/$a/__pycache__/agent.cpython-313.pyc"
    printf 'garbage\n' >"$WORK/root/governed_agents/$a/stray.pyc"
  done
  chmod 0777 "$WORK/root/governed_agents/cti_researcher/agent.py"
}

run() { # run ARGS... -- sets OUT and RC
  set +e
  OUT=$(bash "$WORK/root/scripts/governance/package_agent.sh" "$@" 2>&1)
  RC=$?
  set -e
}

entries() { tar --list --file "$1" --gzip | LC_ALL=C sort | tr '\n' ' '; }

# Independent reimplementation of the hash in package_agent.sh (a here-doc
# pipeline, not the function under test), so a typo in one isn't mirrored.
expected_hash() { # expected_hash DIR
  local dir=$1 f
  (
    cd "$dir" || exit 1
    find . -type f ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name '*.pyo' |
      sed 's|^\./||' | LC_ALL=C sort |
      while IFS= read -r f; do
        printf '%s\n' "$f"
        sha256sum "$f" | cut -c1-64
      done
  ) | sha256sum | cut -c1-64
}

DIST="$WORK/root/terraform/dist"

echo "packages every agent from 'all'"
fixture
run all
equal "exits 0" "$RC" "0"
for a in "${AGENTS[@]}"; do
  check "built $a.tar.gz" "$(ls "$DIST")" "$a.tar.gz"
  check "wrote $a.sha256" "$(ls "$DIST")" "$a.sha256"
  check "reports $a file count and relative path" "$OUT" "$a: 3 files -> terraform/dist/$a.tar.gz"
done
refute "leaves no .tmp behind" "$(ls "$DIST")" ".tmp"

echo "archive layout"
equal "entries are at the archive root, nested package kept as a path" \
  "$(entries "$DIST/cti_researcher.tar.gz")" \
  "agent.py requirements.txt sub/helper.py "
refute "no __pycache__ entries" "$(entries "$DIST/cti_researcher.tar.gz")" "__pycache__"
refute "no stray .pyc" "$(entries "$DIST/cti_researcher.tar.gz")" "stray.pyc"
refute "no leading ./" "$(entries "$DIST/cti_researcher.tar.gz")" "./"

echo "archive metadata is normalized"
LISTING=$(tar --list --verbose --numeric-owner --file "$DIST/cti_researcher.tar.gz" --gzip)
check "owner and group are 0/0" "$LISTING" "0/0"
check "mtime is the epoch" "$LISTING" "1970-01-01"
check "mode is normalized despite the 0777 source file" "$LISTING" "-rw-r--r--"
refute "no file keeps its exec bit" "$LISTING" "rwxr"

echo "determinism"
FIRST=$(sha256sum <"$DIST/cti_researcher.tar.gz")
sleep 1 # a timestamp leak would only show up across a clock tick
run all
SECOND=$(sha256sum <"$DIST/cti_researcher.tar.gz")
equal "same input produces byte-identical output" "$SECOND" "$FIRST"

echo "source hash"
equal "matches the documented formula" \
  "$(cat "$DIST/cti_researcher.sha256")" \
  "$(expected_hash "$WORK/root/governed_agents/cti_researcher")"
BEFORE=$(cat "$DIST/cti_researcher.sha256")
printf 'garbage\n' >"$WORK/root/governed_agents/cti_researcher/__pycache__/new.pyc"
printf 'garbage\n' >"$WORK/root/governed_agents/cti_researcher/another.pyc"
printf 'garbage\n' >"$WORK/root/governed_agents/cti_researcher/legacy.pyo"
run cti_researcher
equal "ignores added .pyc, .pyo and __pycache__ files" "$(cat "$DIST/cti_researcher.sha256")" "$BEFORE"
printf '# edit\n' >>"$WORK/root/governed_agents/cti_researcher/agent.py"
run cti_researcher
differs "changes when a source file changes" "$(cat "$DIST/cti_researcher.sha256")" "$BEFORE"

echo "a rename is not invisible to the hash"
fixture
run cti_researcher
BEFORE=$(cat "$DIST/cti_researcher.sha256")
mv "$WORK/root/governed_agents/cti_researcher/sub/helper.py" "$WORK/root/governed_agents/cti_researcher/sub/helper2.py"
run cti_researcher
differs "path is hashed, not just content" "$(cat "$DIST/cti_researcher.sha256")" "$BEFORE"

echo "a subset only touches the named agents"
fixture
run threat_hunter soc_orchestrator
equal "exits 0" "$RC" "0"
equal "only the two requested archives and hashes exist" \
  "$(ls "$DIST" | LC_ALL=C sort | tr '\n' ' ')" \
  "soc_orchestrator.sha256 soc_orchestrator.tar.gz threat_hunter.sha256 threat_hunter.tar.gz "

echo "refuses to build something the runtime cannot load"
fixture
rm "$WORK/root/governed_agents/threat_hunter/agent.py"
run threat_hunter
equal "exits 1 when agent.py is missing" "$RC" "1"
check "names entrypoint_module" "$OUT" 'entrypoint_module = "agent"'
refute "writes no archive" "$(ls "$DIST" 2>/dev/null || true)" "threat_hunter.tar.gz"

fixture
rm "$WORK/root/governed_agents/threat_hunter/requirements.txt"
run threat_hunter
equal "exits 1 when requirements.txt is missing" "$RC" "1"
check "says which file" "$OUT" "requirements.txt is missing"

fixture
rm -rf "$WORK/root/governed_agents/tier2_responder"
run tier2_responder
equal "exits 1 when the agent directory is absent" "$RC" "1"
check "names the missing directory" "$OUT" "no such agent directory"

fixture
rm -rf "$WORK/root/governed_agents/detection_engineer"
mkdir -p "$WORK/root/governed_agents/detection_engineer/__pycache__"
printf 'garbage\n' >"$WORK/root/governed_agents/detection_engineer/__pycache__/x.pyc"
run detection_engineer
equal "exits 1 when only excluded files remain" "$RC" "1"
check "says no source files found" "$OUT" "no source files found"

echo "argument handling"
fixture
run
equal "no arguments is a usage error" "$RC" "2"
check "prints usage" "$OUT" "usage:"
check "usage lists the five agents" "$OUT" "agents: ${AGENTS[*]}"
run nosuchagent
equal "unknown agent exits 1" "$RC" "1"
check "lists the known agents" "$OUT" "known: ${AGENTS[*]}"
refute "unknown agent writes nothing" "$(ls "$DIST" 2>/dev/null || true)" ".tar.gz"
run all cti_researcher
equal "'all' takes no other arguments" "$RC" "2"
run cti_researcher nosuchagent
equal "one unknown name in a list fails the whole run" "$RC" "1"
refute "and nothing is packaged before the check" "$(ls "$DIST" 2>/dev/null || true)" "cti_researcher.tar.gz"

echo "missing tool is reported, not silently skipped"
fixture
mkdir -p "$WORK/bin"
for t in bash dirname find sort sed cut grep mkdir ls cat tr mv rm realpath; do
  p=$(command -v "$t") && ln -sf "$p" "$WORK/bin/$t"
done
set +e
OUT=$(PATH="$WORK/bin" bash "$WORK/root/scripts/governance/package_agent.sh" all 2>&1)
RC=$?
set -e
equal "exits 1 without tar/gzip/sha256sum on PATH" "$RC" "1"
check "names the missing command" "$OUT" "required command not found:"

echo "against the real governed_agents/ tree"
REAL_DIST="$REPO_ROOT/terraform/dist"
run_real() { # run_real -- sets OUT and RC using the real script
  set +e
  OUT=$(bash "$TARGET" all 2>&1)
  RC=$?
  set -e
}
run_real
equal "real tree: 'all' exits 0" "$RC" "0"
declare -A FIRST_REAL=()
for a in "${AGENTS[@]}"; do
  ARCHIVE="$REAL_DIST/$a.tar.gz"
  HASHFILE="$REAL_DIST/$a.sha256"
  check "$a: archive exists" "$(ls "$REAL_DIST")" "$a.tar.gz"
  if [[ -s $HASHFILE ]]; then
    printf '  ok   %s\n' "$a: .sha256 exists and is non-empty"
    PASS=$((PASS + 1))
  else
    printf '  FAIL %s\n' "$a: .sha256 exists and is non-empty"
    FAIL=$((FAIL + 1))
    continue
  fi
  check "$a: .sha256 is a 64-hex digest" \
    "$(grep -cEx '[0-9a-f]{64}' "$HASHFILE")" "1"
  refute "$a: nothing nested under a directory named after the agent" \
    "$(entries "$ARCHIVE")" "$a/"
  check "$a: agent.py is at the root" "$(entries "$ARCHIVE")" "agent.py"
  check "$a: requirements.txt is at the root" "$(entries "$ARCHIVE")" "requirements.txt"
  refute "$a: no __pycache__ shipped" "$(entries "$ARCHIVE")" "__pycache__"
  equal "$a: source hash matches the formula" \
    "$(cat "$HASHFILE")" \
    "$(expected_hash "$REPO_ROOT/governed_agents/$a")"
  FIRST_REAL[$a]=$(sha256sum <"$ARCHIVE")
done
sleep 1
run_real
equal "real tree: second 'all' exits 0" "$RC" "0"
for a in "${AGENTS[@]}"; do
  [[ -n ${FIRST_REAL[$a]:-} ]] || continue
  equal "$a: second run reproduces a byte-identical tar.gz" \
    "$(sha256sum <"$REAL_DIST/$a.tar.gz")" "${FIRST_REAL[$a]}"
done

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
