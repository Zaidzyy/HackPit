#!/usr/bin/env sh
# HackPit :kali — OPEN-sandbox egress proof.
#
# :kali runs ARBITRARY commands as `docker exec <KALI_OPEN_CONTAINER> sh -c "<cmd>"` inside a
# SEPARATE, intentionally NON-isolated container (hackpit-kali-open). This proves that model
# holds — the OPEN sandbox has full network reach — WITHOUT touching the isolated cockpit
# sandbox (which docker/proof/isolation_proof.sh separately proves is still egress-less).
# Exercises the EXACT exec path the :kali endpoint uses. Exits 0 ONLY if:
#   1. a basic shell works inside the open sandbox        (id, ls)
#   2. the open sandbox CAN reach the internet            (curl https://example.com succeeds)
#   3. the open sandbox is on a NON-internal network      (structural: NAT egress)
#
# It is deliberately NOT isolated — that is Zaid's informed decision, and this proof asserts
# the intended (open) behaviour, not containment. The safety of :kali rests on it being
# human-only (no agent path — see backend/test_kali.py), not on network isolation.
#
# Run:  sh docker/proof/kali_open_egress_proof.sh
set -u

OPEN="${HACKPIT_KALI_OPEN_CONTAINER:-hackpit-kali-open}"
ISO="${HACKPIT_SANDBOX_CONTAINER:-hackpit-kali-sandbox}"
TIMEOUT=10

ok=0
bad=0
pass() { echo "  [PASS] $1"; ok=$((ok + 1)); }
fail() { echo "  [FAIL] $1"; bad=$((bad + 1)); }

# The SAME invocation shape the :kali endpoint uses: sh -c into the hardcoded OPEN sandbox.
kali() { docker exec "$OPEN" sh -c "$1"; }

echo "== HackPit :kali OPEN-sandbox egress proof =="
echo "open=$OPEN  (isolated cockpit sandbox=$ISO, unaffected)  $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
echo

if ! docker inspect -f '{{.State.Running}}' "$OPEN" 2>/dev/null | grep -q true; then
  echo "  [ERROR] open sandbox container '$OPEN' is not running. Bring the stack up first:"
  echo "          docker compose -f docker/docker-compose.yml up -d"
  exit 2
fi

echo "-- 1. a free shell works inside the open sandbox  (MUST succeed) --"
if kali 'id && ls -1 / >/dev/null' >/dev/null 2>&1; then
  pass "sh -c 'id && ls' ran inside the open sandbox"
else
  fail "could not run a basic shell inside the open sandbox"
fi
echo

echo "-- 2. the open sandbox CAN reach the internet  (MUST succeed — the intent) --"
code="$(kali "curl -s -o /dev/null -w '%{http_code}' --max-time ${TIMEOUT} https://example.com/" 2>/dev/null)"
echo "     HTTP status from example.com: ${code:-<none>}"
case "$code" in
  2*|3*) pass "open sandbox reached https://example.com (HTTP $code) — full network reach";;
  *)     fail "open sandbox could NOT reach the internet (status='${code:-none}')";;
esac
echo

echo "-- 3. the open sandbox is on a NON-internal network  (structural) --"
nets="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$OPEN" 2>/dev/null)"
all_open=1
for n in $nets; do
  internal="$(docker network inspect -f '{{.Internal}}' "$n" 2>/dev/null)"
  echo "     network $n internal=$internal"
  [ "$internal" = "true" ] && all_open=0
done
if [ "$all_open" -eq 1 ] && [ -n "$nets" ]; then
  pass "open sandbox is on non-internal network(s) only (NAT egress)"
else
  fail "open sandbox is (partly) on an internal network — egress would be blocked"
fi
echo

echo "== result: $ok passed, $bad failed =="
if [ "$bad" -eq 0 ] && [ "$ok" -ge 3 ]; then
  echo "OPEN EGRESS CONFIRMED — :kali's open sandbox has full network reach (by design)."
  echo "(The isolated cockpit sandbox is unaffected — see docker/proof/isolation_proof.sh.)"
  exit 0
fi
echo "OPEN EGRESS NOT CONFIRMED — check the compose network config."
exit 1
