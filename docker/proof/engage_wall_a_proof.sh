#!/usr/bin/env sh
# HackPit engagement mode — WALL-A INVERTED proof.
#
# The engagement sandbox (hackpit-engage-sandbox) has NO isolation floor — it reaches the
# PUBLIC INTERNET. What contains it is Wall A: it must NOT be able to turn inward on the
# operator's host, the LAN (RFC1918), or link-local/cloud-metadata (169.254/16). This proof
# is INVERTED vs the lab isolation proof: internet MUST work; host/LAN/metadata MUST fail.
#
# Exits 0 ONLY if ALL hold, exercised from INSIDE the engagement sandbox (the exact box the
# executor runs engagement commands in):
#   1. a public host IS reachable            (curl https://example.com + a public IP succeed)
#   2. the metadata IP is NOT reachable      (169.254.169.254 fails)
#   3. an RFC1918 LAN host is NOT reachable  (10.x / 192.168.x fail)
#   4. the operator's host is NOT reachable  (the bridge gateway + host.docker.internal fail)
#
# Run:  sh docker/proof/engage_wall_a_proof.sh
# A non-zero exit means Wall A is NOT holding — DO NOT run engagement mode.
set -u

SBX="${HACKPIT_ENGAGE_CONTAINER:-hackpit-engage-sandbox}"
FW="${HACKPIT_ENGAGE_FIREWALL:-hackpit-engage-firewall}"
TIMEOUT=8

ok=0
bad=0
pass() { echo "  [PASS] $1"; ok=$((ok + 1)); }
fail() { echo "  [FAIL] $1"; bad=$((bad + 1)); }

# The SAME exec shape the engagement executor uses: docker exec into the hardcoded sandbox.
xin() { docker exec "$SBX" "$@"; }

echo "== HackPit engagement-mode WALL-A inverted proof =="
echo "sandbox=$SBX  firewall=$FW  $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
echo

if ! docker inspect -f '{{.State.Running}}' "$SBX" 2>/dev/null | grep -q true; then
  echo "  [ERROR] engagement sandbox '$SBX' is not running. Bring the stack up first:"
  echo "          docker compose -f docker/docker-compose.yml up -d --build"
  exit 2
fi
if ! docker inspect -f '{{.State.Running}}' "$FW" 2>/dev/null | grep -q true; then
  echo "  [ERROR] firewall sidecar '$FW' is not running — the sandbox has no Wall-A owner."
  exit 2
fi

# Structural: the sandbox must SHARE the firewall's netns (that is what applies Wall A).
mode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$SBX" 2>/dev/null)"
fwid="$(docker inspect -f '{{.Id}}' "$FW" 2>/dev/null)"
echo "-- 0. sandbox shares the firewall netns  (structural) --"
case "$mode" in
  container:"$fwid"*) pass "sandbox NetworkMode=$mode → shares the firewall netns";;
  *) fail "sandbox NetworkMode='$mode' does NOT share the firewall netns (Wall-A would not apply)";;
esac
echo

echo "-- 1. engagement sandbox -> internet  (MUST succeed — the intent) --"
code="$(xin curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" https://example.com/ 2>/dev/null)"
echo "     HTTP status from example.com: ${code:-<none>}"
case "$code" in
  2*|3*) pass "sandbox reached https://example.com (HTTP $code) — internet OK";;
  *)     fail "sandbox could NOT reach the internet (status='${code:-none}') — Wall-A too strict / DNS?";;
esac
# public IP by number (no DNS) — pure routing to the internet.
if xin curl -s -o /dev/null --max-time "$TIMEOUT" http://1.1.1.1/ 2>/dev/null; then
  pass "sandbox reached public IP 1.1.1.1 — internet routing OK"
else
  fail "sandbox could NOT reach public IP 1.1.1.1 (egress broken)"
fi
echo

echo "-- 2. sandbox -> cloud metadata 169.254.169.254  (MUST fail) --"
if xin curl -s -o /dev/null --max-time "$TIMEOUT" http://169.254.169.254/latest/meta-data/ 2>/dev/null; then
  fail "sandbox reached 169.254.169.254 (metadata NOT blocked!)"
else
  pass "sandbox could not reach cloud metadata 169.254.169.254"
fi
echo

echo "-- 3. sandbox -> RFC1918 LAN  (MUST fail) --"
for lan in http://10.0.0.1/ http://192.168.0.1/ http://172.16.0.1/; do
  if xin curl -s -o /dev/null --max-time "$TIMEOUT" "$lan" 2>/dev/null; then
    fail "sandbox reached LAN host $lan (RFC1918 NOT blocked!)"
  else
    pass "sandbox could not reach LAN host $lan"
  fi
done
echo

echo "-- 4. sandbox -> operator host  (MUST fail) --"
# host.docker.internal (Docker Desktop maps this to an RFC1918 host addr → dropped by Wall A).
if xin curl -s -o /dev/null --max-time "$TIMEOUT" http://host.docker.internal/ 2>/dev/null; then
  fail "sandbox reached host.docker.internal (operator host NOT isolated!)"
else
  pass "sandbox could not reach host.docker.internal"
fi
# the bridge gateway = the host's address on this network.
gw="$(docker exec "$FW" sh -c "ip route | awk '/default/{print \$3; exit}'" 2>/dev/null)"
if [ -n "$gw" ]; then
  if xin curl -s -o /dev/null --max-time "$TIMEOUT" "http://${gw}/" 2>/dev/null; then
    fail "sandbox reached the bridge gateway $gw (host NOT blocked!)"
  else
    pass "sandbox could not reach the bridge gateway $gw (host)"
  fi
else
  echo "     [note] could not determine the bridge gateway (skipped)"
fi
echo

echo "== result: $ok passed, $bad failed =="
# 1 structural + 2 internet + 1 metadata + 3 LAN + 2 host = up to 9 checks.
if [ "$bad" -eq 0 ] && [ "$ok" -ge 8 ]; then
  echo "WALL A HOLDS — engagement sandbox reaches the internet but not host/LAN/metadata."
  exit 0
fi
echo "WALL A NOT PROVEN — DO NOT run engagement mode."
exit 1
