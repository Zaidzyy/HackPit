#!/usr/bin/env sh
# HackPit — BUILD #10 C2 LAB: the one opt-in bring-up + orchestrator (tickets 2614-2617).
#
# THIS IS THE ONLY PLACE THE EXPOSURE IS COMPOSED. The opt-in UDP/53 publish lives in
# docker/listener-profile.yml (generated) and is applied by exactly one command, in exactly one reviewable file —
# this one. test_exposure_safety.py invariant 2 enforces that: any OTHER script that composed the
# override in would be an offender, so the four proof scripts (c2_01..c2_04) never do — they
# REQUIRE the exposure already up and defer here. Exposure is typed on purpose, every time.
#
# WHAT IT DOES:
#   --up      compose the main stack + the opt-in override up, and verify UDP/53 is published on
#             the VMnet8 host address (and nowhere else).
#   --down    compose it back down — the exposure is gone.
#   (default) --up, run the four C2 proofs in order, then --down (unless --keep).
#   --keep    leave the exposure up after the run for inspection.
#
# The offensive command strings the four proofs need are [[PASTE]] placeholders inside each
# script; fill them in before a live run (see docs/proof/build10-c2-windows.md). With them empty,
# this still runs end to end and reports each unfilled step as NOT-RUN — never as a pass.
#
# Usage:
#   sh docker/proof/c2_lab_proof.sh --up          # bring the opt-in exposure up
#   sh docker/proof/c2_lab_proof.sh               # up, run all four proofs, tear down
#   sh docker/proof/c2_lab_proof.sh --keep        # ...but leave the exposure up
#   sh docker/proof/c2_lab_proof.sh --down        # tear the exposure down
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BASE_YML="$ROOT/docker/docker-compose.yml"
# Build #13: the exposure is GENERATED from the vmnet8-dns preset rather than checked in, so
# a profile on a client engagement never reaches this public repo. The generated file is
# gitignored; `gen_profile` below writes it before the first compose call has anything to merge.
C2_YML="$ROOT/docker/listener-profile.yml"
PY="${PY:-$ROOT/backend/.venv/Scripts/python.exe}"
ENGAGE="${HACKPIT_ENGAGE_CONTAINER:-hackpit-engage-sandbox}"
VMNET8_HOST="${HACKPIT_VMNET8_HOST:-192.168.13.1}"

gen_profile() {
  echo "== generating the exposure from the vmnet8-dns preset =="
  # The preset is locked against the file build #10 hand-wrote (test_exposure), so this
  # generates the identical exposure — UDP/53 on the VMnet8 host address, nothing else.
  ( cd "$ROOT/backend" && "$PY" -c "
from datetime import datetime, timezone
from cockpit import exposure
p = exposure.write(exposure.PRESETS['vmnet8-dns'],
                   at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'))
print('  wrote', p)
" ) || { echo "  [ERROR] could not generate the listener profile"; return 2; }
}

up() {
  echo "== bringing the opt-in C2 exposure up (UDP/53 on $VMNET8_HOST) =="
  gen_profile || return 2
  # THE ONE opt-in compose line — the whole exposure surface, in one place a reviewer can read.
  docker compose -f "$BASE_YML" -f "$C2_YML" up -d || {
    echo "  [ERROR] could not bring the C2 lab up"; return 2; }
  sleep 3
  PORTS=$(docker inspect -f '{{json .NetworkSettings.Ports}}' "$ENGAGE" 2>/dev/null)
  if echo "$PORTS" | grep -q "\"53/udp\"" && echo "$PORTS" | grep -q "$VMNET8_HOST"; then
    echo "  UDP/53 published on $VMNET8_HOST — the DC's only route to the listener. Exposure up."
    return 0
  fi
  echo "  [ERROR] UDP/53 is not published on $VMNET8_HOST after up (ports: ${PORTS:-<none>})."
  echo "          Check docker/listener-profile.yml and the VMnet8 address (fix-vmnet8.ps1)."
  return 2
}

down() {
  echo "== tearing the opt-in C2 exposure down =="
  # Compose needs BOTH -f flags on teardown or it does not know about the service it is
  # tearing down. The profile is gitignored, so on a fresh checkout — or after someone deleted
  # it — the file is absent and the merge would fail silently into /dev/null, leaving the
  # exposure UP while this printed success. Regenerate it first; it is deterministic.
  [ -f "$C2_YML" ] || gen_profile >/dev/null 2>&1
  docker compose -f "$BASE_YML" -f "$C2_YML" down >/dev/null 2>&1
  echo "  exposure down — UDP/53 no longer published."
}

case "${1:-run}" in
  --up)   up; exit $? ;;
  --down) down; exit 0 ;;
esac

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

up || exit 2

rc=0
for s in c2_01_dc_prereq_stage.sh c2_02_iodine_tunnel.sh c2_03_sliver_beacon.sh c2_04_dcsync_defender_excl.sh; do
  echo
  echo "############################################################################"
  echo "## $s"
  echo "############################################################################"
  sh "$ROOT/docker/proof/$s" || rc=1
done

echo
if [ "$KEEP" = "1" ]; then
  echo "--keep: exposure left up. Tear down with:  sh docker/proof/c2_lab_proof.sh --down"
else
  down
fi
exit $rc
