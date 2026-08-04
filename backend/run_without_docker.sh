#!/usr/bin/env sh
# Run named backend test files with DOCKER REMOVED FROM PATH — the CI environment.
#
# WHY THIS EXISTS. CI has twice caught a test in this repo that passed locally and failed
# there, for the same reason both times: the test reached a real `docker` binary that CI
# does not have. A green local run is not evidence about CI unless the thing CI lacks is
# actually absent while it runs.
#
# WHY IT STRIPS ONE DIRECTORY, NOT THE WHOLE PATH. Blanking PATH also removes git, and the
# KB ingester's recovery path shells out to git — so a blanked-PATH run does not simulate
# CI, it simulates a different broken machine, and it has previously mutated the live KB
# while pretending to be a safety check. Only the directory holding `docker` is removed.
#
# THE STRIP IS VERIFIED TO BITE before any test runs. A strip that silently failed to
# remove docker would make every run below meaningless while still printing PASS — the
# exact failure mode this script exists to prevent, so it is checked rather than assumed.
#
# Usage:  sh backend/run_without_docker.sh test_foo.py [test_bar.py ...]
set -e

cd "$(dirname "$0")"

PY="${PY:-.venv/Scripts/python.exe}"
[ -x "$PY" ] || PY="$(command -v python3 || command -v python)"

[ "$#" -gt 0 ] || { echo "usage: sh run_without_docker.sh <test-file> [...]" >&2; exit 2; }

DOCKER_BIN="$(command -v docker || true)"
if [ -z "$DOCKER_BIN" ]; then
  echo "docker is not on PATH here — this run proves nothing about a docker-free CI." >&2
  echo "Run it on a machine that HAS docker, so removing it is a real change." >&2
  exit 2
fi
DOCKER_DIR="$(dirname "$DOCKER_BIN")"

# Rebuild PATH without that one directory. Everything else — git, python, coreutils — stays.
NEW_PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -vxF "$DOCKER_DIR" | paste -sd: -)"

# THE STRIP MUST BITE. If docker is still reachable the rest of this script is theatre.
if PATH="$NEW_PATH" command -v docker >/dev/null 2>&1; then
  echo "STRIP DID NOT BITE — docker is still on PATH after removing $DOCKER_DIR." >&2
  echo "Reachable at: $(PATH="$NEW_PATH" command -v docker)" >&2
  exit 1
fi
echo "docker removed from PATH (was $DOCKER_BIN) — strip verified to bite."
# ...and git must have SURVIVED it, or we are testing the wrong absence.
PATH="$NEW_PATH" command -v git >/dev/null 2>&1 || {
  echo "git disappeared too — that is not the CI environment, it is a broken PATH." >&2
  exit 1
}
echo "git still present — the strip removed docker and nothing else that matters."
echo

FAILED=0
for f in "$@"; do
  echo "== $f (no docker) =="
  # Exit code captured EXPLICITLY. `cmd | tail` and `cmd && echo ok` do not gate — that
  # has shipped broken work in this repo before.
  if PATH="$NEW_PATH" "$PY" "$f"; then
    echo "-- $f: PASS (without docker)"
  else
    echo "-- $f: FAIL (without docker)" >&2
    FAILED=1
  fi
  echo
done

if [ "$FAILED" -ne 0 ]; then
  echo "AT LEAST ONE FILE FAILED WITHOUT DOCKER — it would fail in CI." >&2
  exit 1
fi
echo "All $# file(s) passed with docker absent."
