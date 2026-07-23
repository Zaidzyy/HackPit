#!/usr/bin/env sh
# HackPit Cockpit — isolation proof (M1.2 hard gate).
#
# Exits 0 ONLY if ALL of the following hold for the running sandbox:
#   1. sandbox CAN reach the lab target      (curl http://lab:3000 -> HTTP status)
#   2. sandbox CANNOT reach the internet     (curl to a public IP + host both fail)
#   3. sandbox CANNOT reach the host         (host.docker.internal unreachable)
#
# Run:  sh docker/proof/isolation_proof.sh
# A non-zero exit means DO NOT wire execution (docs/cockpit-plan.md §c Layer 1).
set -u

SANDBOX="${HACKPIT_SANDBOX_CONTAINER:-hackpit-kali-sandbox}"
LAB_HOST="${HACKPIT_LAB_TARGET:-hackpit-lab-target}"
LAB_PORT="${HACKPIT_LAB_PORT:-3000}"
TIMEOUT=8

ok=0
bad=0

pass() { echo "  [PASS] $1"; ok=$((ok + 1)); }
fail() { echo "  [FAIL] $1"; bad=$((bad + 1)); }

xin() { docker exec "$SANDBOX" "$@"; }

echo "== HackPit Cockpit isolation proof =="
echo "sandbox=$SANDBOX  lab=$LAB_HOST:$LAB_PORT  $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
echo

# Precondition: sandbox is running.
if ! docker inspect -f '{{.State.Running}}' "$SANDBOX" 2>/dev/null | grep -q true; then
  echo "  [ERROR] sandbox container '$SANDBOX' is not running. Bring the stack up first."
  exit 2
fi

echo "-- 1. sandbox -> lab  (MUST succeed) --"
code="$(xin curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" \
        "http://${LAB_HOST}:${LAB_PORT}/" 2>/dev/null)"
echo "     HTTP status from lab: ${code:-<none>}"
case "$code" in
  2*|3*) pass "sandbox reached the lab (HTTP $code)";;
  *)     fail "sandbox could NOT reach the lab (status='${code:-none}')";;
esac
echo

echo "-- 2. sandbox -> internet  (MUST fail) --"
# 2a: public IP by number (bypasses DNS entirely — pure routing test).
if xin curl -s -o /dev/null --max-time "$TIMEOUT" http://1.1.1.1/ 2>/dev/null; then
  fail "sandbox reached public IP 1.1.1.1 (egress NOT blocked!)"
else
  pass "sandbox could not reach public IP 1.1.1.1"
fi
# 2b: public hostname over HTTPS (DNS + routing).
if xin curl -s -o /dev/null --max-time "$TIMEOUT" https://example.com/ 2>/dev/null; then
  fail "sandbox reached https://example.com (egress NOT blocked!)"
else
  pass "sandbox could not reach https://example.com"
fi
# 2c: external DNS resolution (informational — should also fail).
if xin getent hosts example.com >/dev/null 2>&1; then
  echo "     [note] external DNS resolved (no route still blocks traffic above)"
else
  echo "     [note] external DNS did not resolve"
fi
echo

echo "-- 3. sandbox -> host  (MUST fail) --"
if xin curl -s -o /dev/null --max-time "$TIMEOUT" http://host.docker.internal/ 2>/dev/null; then
  fail "sandbox reached host.docker.internal (host NOT isolated!)"
else
  pass "sandbox could not reach host.docker.internal"
fi
echo

echo "== result: $ok passed, $bad failed =="
if [ "$bad" -eq 0 ] && [ "$ok" -ge 4 ]; then
  echo "ISOLATION PROVEN — safe to wire execution (M1.3)."
  exit 0
fi
echo "ISOLATION NOT PROVEN — DO NOT wire execution."
exit 1
