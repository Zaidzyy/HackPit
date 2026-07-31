#!/usr/bin/env sh
# HackPit — shared plumbing for the build #10 Windows/AD C2 proofs.
#
# The four C2 proof scripts (c2_01..c2_04) are thin: each collects the operator's [[PASTE]]
# command(s), calls one driver phase, and tallies. This file is the plumbing they share —
# the same shape as live_fire_proof.sh's helpers (pass/fail/notrun, a `drive` that folds the
# driver's RESULT/VALUE lines into the tally, teardown-safe summary), factored out so four
# scripts do not each carry a copy that can drift.
#
# IT DOES NOT, AND MUST NOT, BRING THE EXPOSURE UP. The opt-in UDP/53 publish
# (docker/proof/c2-lab.yml) is composed in exactly ONE reviewable place —
# docker/proof/c2_lab_proof.sh — and nowhere else, by design (test_exposure_safety.py invariant
# 2: the exposure is typed on purpose, every time). These scripts REQUIRE it already up and
# refuse to run otherwise, pointing you at that one script. Nothing here runs `docker compose`.
#
# Sourced, not executed:  . "$(dirname "$0")/c2_lib.sh"

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DRIVER="$ROOT/docker/proof/c2_winrm_driver.py"
ENGAGE="${HACKPIT_ENGAGE_CONTAINER:-hackpit-engage-sandbox}"
# The single host interface the lab DC's NAT subnet can reach — the VMnet8 address the opt-in
# override binds UDP/53 to. Keep in step with docker/proof/c2-lab.yml and fix-vmnet8.ps1.
VMNET8_HOST="${HACKPIT_VMNET8_HOST:-192.168.13.1}"

PY="$ROOT/backend/.venv/Scripts/python.exe"
[ -x "$PY" ] || PY="$ROOT/backend/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3 || command -v python)"

# A per-run scratch dir for the operator [[PASTE]] files the driver reads. Cleaned on summary.
C2_SCRATCH="${TMPDIR:-/tmp}/hackpit-c2.$$"
mkdir -p "$C2_SCRATCH"

ok=0; bad=0; skipped=0
NOTES_FILE="$C2_SCRATCH/notes"
: > "$NOTES_FILE"
DRIVER_OUT="$C2_SCRATCH/driver.out"
: > "$DRIVER_OUT.values"

pass()   { echo "  [PASS]   $1"; ok=$((ok + 1)); }
fail()   { echo "  [FAIL]   $1"; bad=$((bad + 1)); }
notrun() { echo "  [NOTRUN] $1"; skipped=$((skipped + 1)); echo "$1" >> "$NOTES_FILE"; }
head2()  { echo; echo "== $1 =="; }

# Run the driver and fold its RESULT lines into this script's tally; VALUE lines are captured
# for getval; everything else is echoed as indented transcript detail. Identical protocol to
# live_fire_proof.sh's `drive`.
drive() {
  "$PY" "$DRIVER" "$@" > "$DRIVER_OUT" 2>&1
  rc=$?
  while IFS= read -r line; do
    case "$line" in
      "RESULT "*)
        name=$(echo "$line" | awk '{print $2}')
        st=$(echo "$line" | awk '{print $3}')
        detail=$(echo "$line" | cut -d' ' -f4-)
        case "$st" in
          PASS)   pass "$name — $detail" ;;
          FAIL)   fail "$name — $detail" ;;
          NOTRUN) notrun "$name — $detail" ;;
        esac ;;
      "VALUE "*) echo "$line" >> "$DRIVER_OUT.values" ;;
      *) [ -n "$line" ] && echo "      | $line" ;;
    esac
  done < "$DRIVER_OUT"
  return $rc
}
getval() { grep "^VALUE $1 " "$DRIVER_OUT.values" 2>/dev/null | tail -1 | cut -d' ' -f3-; }

# Write an operator paste (the value of a shell variable) to a scratch file and echo its path.
# The offensive command string never touches argv or this harness's source — it lives in the
# proof script's [[PASTE]] variable and is handed to the driver by file path only.
paste_file() {
  _name="$1"; _content="$2"
  _path="$C2_SCRATCH/$_name"
  printf '%s\n' "$_content" > "$_path"
  echo "$_path"
}

# Preflight shared by every C2 proof: the engage sandbox is up AND the opt-in UDP/53 exposure
# is active on the VMnet8 host address. Neither is brought up here — that is c2_lab_proof.sh's
# single job. Exits the caller (via `return 2`) when the exposure is not present.
c2_require_exposure() {
  echo "== HackPit build #10 C2 proof =="
  echo "engage sandbox = $ENGAGE"
  echo "exposure       = UDP/53 on $VMNET8_HOST (opt-in; docker/proof/c2-lab.yml)"
  echo

  head2 "0. preflight"
  if ! docker inspect -f '{{.State.Running}}' "$ENGAGE" 2>/dev/null | grep -q true; then
    echo "  [ERROR] engage sandbox '$ENGAGE' is not running, and the opt-in C2 exposure is not up."
    echo "          Bring the whole C2 lab up in the one reviewable place:"
    echo "              sh docker/proof/c2_lab_proof.sh --up"
    return 2
  fi
  pass "engage sandbox is running"

  # The published UDP/53 must be bound to the VMnet8 host address specifically — a wildcard
  # bind is exactly what test_exposure_safety.py forbids, so a wildcard here is a lab-wiring
  # error worth stopping on, not a pass.
  PORTS=$(docker inspect -f '{{json .NetworkSettings.Ports}}' "$ENGAGE" 2>/dev/null)
  if echo "$PORTS" | grep -q "\"53/udp\"" && echo "$PORTS" | grep -q "$VMNET8_HOST"; then
    pass "opt-in UDP/53 is published on $VMNET8_HOST (the DC's only route to the listener)"
  else
    echo "  [ERROR] UDP/53 is not published on $VMNET8_HOST. The DC's callback has nowhere to land."
    echo "          Bring the opt-in exposure up:"
    echo "              sh docker/proof/c2_lab_proof.sh --up"
    echo "          (ports seen: ${PORTS:-<none>})"
    return 2
  fi
  return 0
}

# The Windows-target profile the DC is reached through. A saved WinRM profile is a build #9
# prerequisite; the proofs never hardcode the DC address, they resolve it from the profile.
c2_resolve_profile() {
  C2_PROFILE="${HACKPIT_WIN_PROFILE:-$1}"
  if [ -z "$C2_PROFILE" ]; then
    echo "  [ERROR] no Windows profile id. Pass one, or set HACKPIT_WIN_PROFILE."
    echo "          List them: $PY $ROOT/backend/cockpit/winprofiles.py  (or the cockpit UI)"
    return 2
  fi
  C2_SESSION="${HACKPIT_C2_SESSION:-build10-c2}"
  return 0
}

c2_summary() {
  head2 "result"
  rm -f "$DRIVER_OUT" "$DRIVER_OUT.values"
  echo
  echo "=========================================================================="
  echo "== $1: $ok passed, $bad failed, $skipped not-run =="
  echo "=========================================================================="
  if [ "$skipped" -gt 0 ]; then
    echo
    echo "NOT RUN (reported as not-run, never as passed):"
    sed 's/^/  * /' "$NOTES_FILE"
  fi
  rm -rf "$C2_SCRATCH"
  echo
  if [ "$bad" -eq 0 ]; then
    echo "No assertion FAILED. Any not-run above is a gap in the DEMONSTRATION (an unfilled"
    echo "[[PASTE]] or missing operator infra), not a passed check."
    return 0
  fi
  echo "FAILURES PRESENT — investigate before relying on this surface."
  return 1
}
