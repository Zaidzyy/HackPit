#!/usr/bin/env sh
# HackPit :kali — free-shell CONTAINMENT proof (K4 e2e).
#
# :kali runs ARBITRARY commands as `docker exec <sandbox> sh -c "<cmd>"`. This proves the
# containment holds even for a free shell — i.e. that arbitrary shell is safe because of
# the sandbox, not because of input filtering. Exercises the EXACT exec path the endpoint
# uses. Exits 0 ONLY if:
#   1. a basic shell works inside the sandbox   (id, ls)
#   2. the sandbox can reach the lab target     (nmap hackpit-lab-target)
#   3. the sandbox CANNOT reach the internet    (curl https://example.com FAILS)
#
# (3) is the whole point: a free shell that still cannot egress = contained. If (3) ever
# succeeds, the shell is NOT contained — DO NOT expose :kali.
#
# Run:  sh docker/proof/kali_containment_proof.sh
set -u

SANDBOX="${HACKPIT_SANDBOX_CONTAINER:-hackpit-kali-sandbox}"
LAB_HOST="${HACKPIT_LAB_TARGET:-hackpit-lab-target}"
TIMEOUT=10

ok=0
bad=0
pass() { echo "  [PASS] $1"; ok=$((ok + 1)); }
fail() { echo "  [FAIL] $1"; bad=$((bad + 1)); }

# The SAME invocation shape the :kali endpoint uses: sh -c into the hardcoded sandbox.
kali() { docker exec "$SANDBOX" sh -c "$1"; }

echo "== HackPit :kali containment proof =="
echo "sandbox=$SANDBOX  lab=$LAB_HOST  $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
echo

if ! docker inspect -f '{{.State.Running}}' "$SANDBOX" 2>/dev/null | grep -q true; then
  echo "  [ERROR] sandbox container '$SANDBOX' is not running. Bring the stack up first:"
  echo "          docker compose -f docker/docker-compose.yml up -d"
  exit 2
fi

echo "-- 1. a free shell works inside the sandbox  (MUST succeed) --"
if kali 'id && ls -1 / >/dev/null' >/dev/null 2>&1; then
  pass "sh -c 'id && ls' ran inside the sandbox"
else
  fail "could not run a basic shell inside the sandbox"
fi
echo

echo "-- 2. the shell can reach the lab target  (MUST succeed) --"
# nmap the lab from inside the sandbox (unprivileged connect scan — caps are dropped).
if kali "nmap -sT -Pn --max-retries 1 --host-timeout ${TIMEOUT}s -p 3000 ${LAB_HOST}" \
     2>/dev/null | grep -qi 'open\|3000/tcp'; then
  pass "nmap reached the lab ($LAB_HOST)"
else
  # Fall back to a plain TCP check in case nmap output formatting differs.
  if kali "curl -s -o /dev/null --max-time ${TIMEOUT} http://${LAB_HOST}:3000/"; then
    pass "sandbox reached the lab ($LAB_HOST:3000)"
  else
    fail "sandbox could NOT reach the lab ($LAB_HOST)"
  fi
fi
echo

echo "-- 3. the shell CANNOT reach the internet  (MUST fail) --"
if kali "curl -s -o /dev/null --max-time ${TIMEOUT} https://example.com/" 2>/dev/null; then
  fail "free shell reached https://example.com — EGRESS NOT BLOCKED, shell NOT contained!"
else
  pass "free shell could not reach https://example.com (egress blocked — contained)"
fi
# Also test a raw public IP (bypasses DNS — pure routing).
if kali "curl -s -o /dev/null --max-time ${TIMEOUT} http://1.1.1.1/" 2>/dev/null; then
  fail "free shell reached public IP 1.1.1.1 — EGRESS NOT BLOCKED!"
else
  pass "free shell could not reach public IP 1.1.1.1 (contained)"
fi
echo

echo "== result: $ok passed, $bad failed =="
if [ "$bad" -eq 0 ] && [ "$ok" -ge 4 ]; then
  echo "CONTAINMENT PROVEN — the free :kali shell is contained to the isolated sandbox."
  exit 0
fi
echo "CONTAINMENT NOT PROVEN — DO NOT expose :kali."
exit 1
