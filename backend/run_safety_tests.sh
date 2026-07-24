#!/usr/bin/env sh
# Re-verify the Cockpit SAFETY INVARIANTS in one command.
#
# Runs the hermetic safety-layer + composer regression tests (no Docker needed).
# Pass --with-proof to also run the live Docker isolation PROOF (needs the stack up:
#   docker compose -f docker/docker-compose.yml up -d).
#
# Invariants guarded (docs/cockpit-plan.md §c):
#   allowlist (recon-only, no metachars) -> target-lock (lab only) -> approval
#   (explicit) -> isolation (sandbox on internal-only networks). See test_cockpit.py.
#
# Usage:
#   sh backend/run_safety_tests.sh              # hermetic tests only
#   sh backend/run_safety_tests.sh --with-proof # + live isolation proof
set -e

cd "$(dirname "$0")"

# Prefer the backend venv interpreter; fall back to PATH python.
PY="${PY:-.venv/Scripts/python.exe}"
[ -x "$PY" ] || PY="$(command -v python3 || command -v python)"

echo "== attack-path composer regressions =="
"$PY" test_attack_path.py

echo "== cockpit safety-layer tests (allowlist / target / approval / isolation / order) =="
"$PY" test_cockpit.py

echo "== :kali containment tests (isolation-refusal / hardcoded container / audit) =="
"$PY" test_kali.py

echo "== engagement/report path tests (run recorded + report evidence + scope) =="
"$PY" test_engagement.py

if [ "$1" = "--with-proof" ]; then
  echo
  echo "== live Docker isolation PROOF (must exit 0) =="
  sh ../docker/proof/isolation_proof.sh
else
  echo
  echo "Hermetic safety tests passed."
  echo "To also run the live isolation proof (needs the stack up):"
  echo "  sh backend/run_safety_tests.sh --with-proof"
fi
