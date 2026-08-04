#!/bin/sh
# Build #17 — the last three steps, in the only order that works.
#
# Run from the repo root, AFTER `docker compose -f docker/docker-compose.yml build engage-sandbox`
# has succeeded:   sh docs/proof/build17_finish.sh
#
# WHY THIS IS LAST. Recreating the container kills the ZAP daemon and the ~1,300 captured
# messages with it. Items 2 and 4 both needed that capture, so the rebuild could not happen
# until they had run. They have.
#
# 1. recreate the engage sandbox on the NEW image, KEEPING the listener profile — the proof
#    checks that the port is published and dies if it is not, so teardown cannot come first
# 2. run the browser-interception proof (it starts its own daemon and reaps it)
# 3. runbook §5 teardown: remove the profile and recreate WITHOUT it
#
# Deleting the profile alone does NOT close the port. A published port is fixed when the
# container is created, which is why `exposure.observe()` reports that state as `drifted` and
# never as `none`.
set -u
export MSYS_NO_PATHCONV=1

COMPOSE="docker/docker-compose.yml"
PROFILE="docker/listener-profile.yml"
ENGAGE=hackpit-engage-sandbox
PORT=8090

step() { printf '\n############################################################\n# %s\n############################################################\n' "$1"; }

step "1. recreate $ENGAGE on the rebuilt image, port still published"
if [ ! -f "$PROFILE" ]; then
  echo "FATAL: $PROFILE is gone. The proof needs the published port; re-apply the profile"
  echo "       (POST /cockpit/exposure/profile + /apply, or the zap-proxy preset on :exposure)."
  exit 2
fi
docker compose -f "$COMPOSE" -f "$PROFILE" up -d --force-recreate "$ENGAGE" > /tmp/b17_recreate.log 2>&1
RC=$?
echo "RECREATE_EXIT=$RC"
[ "$RC" -eq 0 ] || { tail -20 /tmp/b17_recreate.log; exit 1; }

# The image the container RUNS is not necessarily the image just built — that is a recorded
# trap ("the container is not the image"). Compare them before believing anything below.
BUILT=$(docker image inspect hackpit/kali-sandbox:m1 --format '{{.Id}}' 2>/dev/null)
RUNNING=$(docker inspect "$ENGAGE" --format '{{.Image}}' 2>/dev/null)
echo "built  =$BUILT"
echo "running=$RUNNING"
[ "$BUILT" = "$RUNNING" ] || { echo "FATAL: the container runs a DIFFERENT image than the one built"; exit 1; }

echo "-- xvfb present in the new image? --"
docker exec "$ENGAGE" sh -c 'command -v Xvfb || echo MISSING; getcap /usr/bin/Xvfb 2>/dev/null || true'

step "2. the browser-interception proof"
sh docker/proof/browser_intercept_proof.sh > docs/proof/build17-proof.log 2>&1
PROOF=$?
echo "PROOF_EXIT=$PROOF"
tail -40 docs/proof/build17-proof.log
grep -E '^=== .* passed' docs/proof/build17-proof.log || true
if [ "$PROOF" -ne 0 ]; then
  echo
  echo "The proof FAILED. Teardown is NOT run — leaving the port up so the failure can be"
  echo "investigated against a live daemon. Full log: docs/proof/build17-proof.log"
  exit 1
fi

step "3. runbook 5 — teardown"
docker exec "$ENGAGE" sh -c "pkill -f \"[z]aproxy.*-daemon.*-port $PORT\" 2>/dev/null; sleep 2" >/dev/null 2>&1
rm -f "$PROFILE"
docker compose -f "$COMPOSE" up -d --force-recreate "$ENGAGE" > /tmp/b17_teardown.log 2>&1
RC=$?
echo "TEARDOWN_RECREATE_EXIT=$RC"
[ "$RC" -eq 0 ] || { tail -20 /tmp/b17_teardown.log; exit 1; }

echo "-- the container must now publish NOTHING --"
PORTS=$(docker inspect "$ENGAGE" --format '{{json .NetworkSettings.Ports}}' 2>/dev/null)
echo "ports=$PORTS"
case "$PORTS" in
  *"\"$PORT/tcp\":null"*|*"{}"*) echo "TEARDOWN=OK (no published $PORT)" ;;
  *"HostPort"*)                  echo "TEARDOWN=FAILED — a host port is still published"; exit 1 ;;
  *)                             echo "TEARDOWN=OK (no host binding reported)" ;;
esac

echo
echo "Remember to put the browser's proxy setting back."
