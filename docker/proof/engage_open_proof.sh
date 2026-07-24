#!/usr/bin/env sh
# HackPit engagement mode — FULLY-OPEN sandbox proof (Wall A DOWN).
#
# Wall A is intentionally removed (Zaid's informed decision): the engagement sandbox
# (hackpit-engage-sandbox) is a normal NAT-bridge container with FULL network reach —
# internet + LAN + host + metadata. Nothing bounds WHERE it can reach; the only guard on a
# real-target run is human-approval-of-every-command (never hands-off). This proof asserts
# the intended OPEN behaviour (it is the counterpart to the isolated lab's isolation_proof).
#
# Exits 0 ONLY if, from INSIDE the engagement sandbox (the exact box the executor runs in):
#   1. a basic shell works                       (id, ls)
#   2. the sandbox CAN reach the internet        (curl https://example.com + a public IP)
#   3. the sandbox is on a NON-internal network  (structural: NAT egress, not egress-less)
# It also REPORTS (informational, now intended, not a failure) whether the operator's host is
# reachable — a reminder that this box can turn inward, and only human approval stands in the way.
#
# Run:  sh docker/proof/engage_open_proof.sh
set -u

SBX="${HACKPIT_ENGAGE_CONTAINER:-hackpit-engage-sandbox}"
TIMEOUT=10

ok=0
bad=0
pass() { echo "  [PASS] $1"; ok=$((ok + 1)); }
fail() { echo "  [FAIL] $1"; bad=$((bad + 1)); }

# The SAME exec shape the engagement executor uses: docker exec into the hardcoded sandbox.
xin() { docker exec "$SBX" "$@"; }

echo "== HackPit engagement-mode FULLY-OPEN proof (Wall A DOWN) =="
echo "sandbox=$SBX  $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
echo

if ! docker inspect -f '{{.State.Running}}' "$SBX" 2>/dev/null | grep -q true; then
  echo "  [ERROR] engagement sandbox '$SBX' is not running. Bring the stack up first:"
  echo "          docker compose -f docker/docker-compose.yml up -d --build"
  exit 2
fi

echo "-- 1. a free shell works inside the engagement sandbox  (MUST succeed) --"
if xin sh -c 'id && ls -1 / >/dev/null' >/dev/null 2>&1; then
  pass "a basic shell runs inside the engagement sandbox"
else
  fail "could not run a basic shell inside the engagement sandbox"
fi
echo

echo "-- 2. the engagement sandbox CAN reach the internet  (MUST succeed — the intent) --"
code="$(xin curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" https://example.com/ 2>/dev/null)"
echo "     HTTP status from example.com: ${code:-<none>}"
case "$code" in
  2*|3*) pass "engagement sandbox reached https://example.com (HTTP $code) — full network reach";;
  *)     fail "engagement sandbox could NOT reach the internet (status='${code:-none}')";;
esac
if xin curl -s -o /dev/null --max-time "$TIMEOUT" http://1.1.1.1/ 2>/dev/null; then
  pass "engagement sandbox reached public IP 1.1.1.1 — internet routing OK"
else
  fail "engagement sandbox could NOT reach public IP 1.1.1.1"
fi
echo

echo "-- 3. the engagement sandbox is on a NON-internal network  (structural: NAT egress) --"
nets="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$SBX" 2>/dev/null)"
all_open=1
for n in $nets; do
  internal="$(docker network inspect -f '{{.Internal}}' "$n" 2>/dev/null)"
  echo "     network $n internal=$internal"
  [ "$internal" = "true" ] && all_open=0
done
if [ "$all_open" -eq 1 ] && [ -n "$nets" ]; then
  pass "engagement sandbox is on non-internal network(s) only (NAT egress — no isolation floor)"
else
  fail "engagement sandbox is (partly) on an internal network — that is not the open model"
fi
echo

echo "-- (informational) the sandbox CAN now turn inward — Wall A is down, by design --"
if xin curl -s -o /dev/null --max-time "$TIMEOUT" http://host.docker.internal/ 2>/dev/null; then
  echo "     [note] host.docker.internal reachable — intended (only human approval guards this)."
else
  echo "     [note] host.docker.internal not answering on :80 (no service there); LAN/host reach"
  echo "            is nonetheless unrestricted — Wall A is down. Human approval is the only guard."
fi
echo

echo "== result: $ok passed, $bad failed =="
if [ "$bad" -eq 0 ] && [ "$ok" -ge 3 ]; then
  echo "FULLY OPEN CONFIRMED — engagement sandbox has full network reach (Wall A down)."
  echo "The ONLY guard on a real-target run is human-approval-of-every-command (never hands-off)."
  exit 0
fi
echo "OPEN REACH NOT CONFIRMED — check the compose network config."
exit 1
