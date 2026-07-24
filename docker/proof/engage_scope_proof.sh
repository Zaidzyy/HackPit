#!/bin/sh
# engage_scope_proof.sh — prove the engagement SCOPE-LOCK contains egress to the AUTHORIZED
# SCOPE ONLY. Applies a single-host scope (scanme.nmap.org) to the firewall sidecar, then from
# the engagement sandbox verifies:
#   1. the scope IS reachable (in scope),
#   2. the operator's host + host-gateway are NOT,
#   3. an out-of-scope LAN IP is NOT,
#   4. cloud metadata 169.254.169.254 is NOT,
#   5. an unrelated public host is NOT.
# Prints "N passed, 0 failed"; exit 0 iff everything holds. Resets the firewall to default-DENY
# at the end. This is the engagement analog of isolation_proof.sh (the lab isolation proof).
#
# MSYS_NO_PATHCONV keeps Git-Bash on Windows from rewriting the in-container script path.
export MSYS_NO_PATHCONV=1
set -u

FW=hackpit-engage-firewall
SB=hackpit-engage-sandbox
SCOPE_HOST=scanme.nmap.org
OUT_LAN=192.168.255.254        # an out-of-scope RFC1918 host
METADATA=169.254.169.254       # cloud metadata / link-local
OUT_PUBLIC=8.8.8.8             # unrelated public host (out of scope)

pass=0; fail=0
ok()  { echo "  [PASS] $1"; pass=$((pass + 1)); }
bad() { echo "  [FAIL] $1"; fail=$((fail + 1)); }

# reachable() -> true iff the sandbox gets at least one ICMP reply from $1 (the firewall allows
# ALL protocols to an in-scope destination, so ICMP is a protocol-agnostic reachability signal).
reachable() { docker exec "$SB" ping -c 2 -W 3 "$1" 2>/dev/null | grep -q '[1-9][0-9]* received'; }

echo "== HackPit engagement SCOPE-LOCK proof =="
if [ "$(docker inspect -f '{{.State.Running}}' "$FW" 2>/dev/null)" != "true" ] \
   || [ "$(docker inspect -f '{{.State.Running}}' "$SB" 2>/dev/null)" != "true" ]; then
  echo "engagement pair not running — bring it up: docker compose -f docker/docker-compose.yml up -d"
  exit 2
fi

SCOPE_IP=$(docker exec "$FW" getent ahostsv4 "$SCOPE_HOST" 2>/dev/null | awk 'NR==1{print $1}')
[ -n "$SCOPE_IP" ] || { echo "could not resolve scope host $SCOPE_HOST"; exit 2; }
GW=$(docker exec "$FW" sh -c "ip route 2>/dev/null | awk '/default/{print \$3; exit}'")
docker exec "$FW" /usr/local/bin/scope_lock.sh apply "$SCOPE_IP" >/dev/null 2>&1
echo "scope=$SCOPE_HOST ($SCOPE_IP)  gateway=$GW  $(date -u +%FT%TZ)"
echo

echo "-- 1. scope IS reachable (MUST succeed) --"
if reachable "$SCOPE_IP"; then ok "scope $SCOPE_IP reachable (in scope)"; else bad "scope $SCOPE_IP NOT reachable"; fi

echo "-- 2. operator host / gateway NOT reachable (MUST fail) --"
if [ -n "$GW" ]; then
  if reachable "$GW"; then bad "host gateway $GW IS reachable"; else ok "host gateway $GW not reachable"; fi
else
  echo "  [note] no default gateway found to test"
fi
if docker exec "$SB" sh -c 'curl -s -m 5 -o /dev/null http://host.docker.internal/' 2>/dev/null; then
  bad "host.docker.internal IS reachable"
else
  ok "host.docker.internal not reachable"
fi

echo "-- 3. out-of-scope LAN NOT reachable (MUST fail) --"
if reachable "$OUT_LAN"; then bad "out-of-scope LAN $OUT_LAN IS reachable"; else ok "out-of-scope LAN $OUT_LAN not reachable"; fi

echo "-- 4. cloud metadata NOT reachable (MUST fail) --"
if reachable "$METADATA"; then bad "metadata $METADATA IS reachable"; else ok "metadata $METADATA not reachable"; fi

echo "-- 5. unrelated public host NOT reachable (MUST fail) --"
if reachable "$OUT_PUBLIC"; then bad "public $OUT_PUBLIC IS reachable"; else ok "public $OUT_PUBLIC not reachable"; fi

# reset to default-DENY so the sidecar is left fail-closed (no lingering scope).
docker exec "$FW" /usr/local/bin/scope_lock.sh deny >/dev/null 2>&1

echo
echo "== result: $pass passed, $fail failed =="
if [ "$fail" -eq 0 ]; then
  echo "SCOPE-LOCK PROVEN — egress reaches the authorized scope ONLY (host/LAN/metadata/off-scope dropped)."
  exit 0
fi
echo "SCOPE-LOCK PROOF FAILED — do NOT run real-target commands."
exit 1
