#!/bin/sh
# ZAP active-scan proof (build #14 part 3) — the checks a hermetic test CANNOT make.
#
# Part 2's proof answered "can the daemon be reached only through docker exec?". This one answers
# the two questions that only exist once the daemon can ATTACK:
#
#   CHECK 4  ZAP REFUSES A URL IT HAS NEVER SEEN.  ascan/action/scan on an unproxied URL returns
#            {"code":"url_not_found"}. That is what bounds the active scanner to traffic the proxy
#            already captured — a host never proxied cannot be attacked through this path even if
#            every HackPit gate were bypassed. It is a BOUND, not a control (the gates are the
#            control), and it is a property of ZAP's Sites tree, so no unit test can assert it.
#
#   CHECK 6  THE REAL ALERT RESPONSE MAPS TO FINDINGS WITH THE REAL MAPPER.  test_zap_scan.py is
#            hermetic and runs against a committed fixture — but a fixture is only as true as the
#            day it was captured. This re-reads ZAP live and maps it with the same code, so the
#            fixture and reality are forced to agree. Part 1's headline defect (a parser written
#            against key names that existed nowhere) survived a green suite precisely because
#            nothing ever compared the two.
#
# Check 3 (host-unreachability) is inherited from part 2 and re-run deliberately: this build puts
# the first ACTION urls behind that boundary, so if it ever fails, an unauthenticated caller on
# the host could launch a real active scan. That is the measured finding recorded in
# zap-api-unauthenticated-finding.md — `-config api.key=...` enforces NOTHING.
#
# Conventions paid for in parts 1-2 and not decoration:
#   * compare the running container's image id against the built image BEFORE exec'ing into it
#   * MSYS_NO_PATHCONV=1 on container paths (Git Bash rewrites them in transit)
#   * pipe into python; never stage through a host /tmp file
#   * print the exit code, but decide pass/fail on the ARTEFACT — an exit code is not a result
#
# Usage:  sh docker/proof/zap_scan_proof.sh
set -eu

IMAGE="hackpit/kali-sandbox:m1"
SANDBOX="hackpit-kali-sandbox"
LAB="hackpit-lab-target"
PORT=8093
TARGET_PATH="/rest/products/search?q=proof"
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die() { printf '\nABORT: %s\n' "$1"; exit 2; }

# Every API read goes through here so the transport is stated once: docker exec, loopback inside
# the container, never a socket from this host.
api() {
  MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" \
    curl -s --max-time 25 "http://127.0.0.1:$PORT$1" 2>/dev/null || true
}

printf '\n=== ZAP active-scan proof (build #14 part 3) ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build kali-sandbox"
docker ps --format '{{.Names}}' | grep -qx "$SANDBOX" \
  || die "$SANDBOX is not running. Run: docker compose -f docker/docker-compose.yml up -d"
docker ps --format '{{.Names}}' | grep -qx "$LAB" \
  || die "$LAB is not running — there is nothing to scan. Run: docker compose -f docker/docker-compose.yml up -d"

# --- 0. the container IS the image ----------------------------------------------------------
IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null || echo unknown)"
CONTAINER_IMAGE_ID="$(docker inspect "$SANDBOX" --format '{{.Image}}' 2>/dev/null || echo unknown)"
if [ "$IMAGE_ID" = "$CONTAINER_IMAGE_ID" ]; then
  ok "the running sandbox is the image that was built"
else
  die "$SANDBOX runs a DIFFERENT image than the one built — every check below would be about
        the wrong container. Recreate it:
          docker compose -f docker/docker-compose.yml up -d --force-recreate kali-sandbox"
fi

# --- 1. the daemon starts and answers, INSIDE the container ---------------------------------
# *** KILL EVERY ZAP DAEMON IN THE CONTAINER, NOT JUST ONE ON THIS PORT. ***
# ZAP takes an exclusive lock on its HOME DIRECTORY ($HOME/.ZAP), not on its port, so a daemon
# left running on ANY other port makes this one die at startup with:
#   "The home directory is already in use. Ensure no other ZAP instances are running"
# Found by this proof on its first run, against a daemon left over on another port. Part 2's
# teardown pattern is port-scoped on purpose (it must not reap a proxy on another port); a proof
# that wants a clean box has the opposite requirement, so the pattern here is deliberately wider.
MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" \
  sh -c "pkill -f \"[z]aproxy.*-daemon\" 2>/dev/null; sleep 3" >/dev/null 2>&1 || true
MSYS_NO_PATHCONV=1 docker exec -d "$SANDBOX" sh -c \
  "zaproxy -daemon -host 127.0.0.1 -port $PORT -config api.disablekey=true >/tmp/zapscan.log 2>&1"

READY=no
i=0
while [ "$i" -lt 90 ]; do
  if api "/JSON/core/view/version/" | grep -q '"version"'; then READY=yes; break; fi
  i=$((i+1)); sleep 1
done
if [ "$READY" = yes ]; then
  ok "the daemon answers its API via docker exec (after ${i}s)"
else
  die "the daemon never answered within 90s — see: docker exec $SANDBOX cat /tmp/zapscan.log"
fi

# --- 2. a request through the proxy puts the endpoint in the Sites tree ----------------------
MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" sh -c \
  "curl -s -o /dev/null -x http://127.0.0.1:$PORT --max-time 20 'http://$LAB:3000$TARGET_PATH'" \
  >/dev/null 2>&1
printf '        (proxied request exit=%s — an exit code is not a result; the tree below is)\n' "$?"
sleep 2
if api "/JSON/core/view/sites/" | grep -q "$LAB"; then
  ok "a proxied request put $LAB in ZAP's Sites tree"
else
  bad "the proxied request did not reach the Sites tree — nothing below can scan"
fi

# --- 3. *** INHERITED LOAD-BEARING CHECK *** the API is UNREACHABLE FROM THIS HOST -----------
# It matters MORE now than in part 2: behind this boundary there are now ACTION urls, and
# `-config api.key=...` was MEASURED to enforce nothing. If this fails, anything on this host can
# launch a real active scan with no key and no approval.
if curl -s --max-time 5 "http://127.0.0.1:$PORT/JSON/core/view/version/" >/dev/null 2>&1; then
  bad "THE ZAP API IS REACHABLE FROM THIS HOST, and it now exposes ascan/action/scan. An
        unauthenticated caller on this machine could start a real active scan — the api.key
        config does NOT stop it (measured). STOP and fix this before anything else."
else
  ok "the ZAP API is UNREACHABLE from this host (and it now carries action URLs)"
fi

# --- 4. *** ZAP REFUSES TO SCAN A URL IT HAS NEVER SEEN *** ---------------------------------
UNSEEN="$(api "/JSON/ascan/action/scan/?url=http%3A%2F%2F$LAB%3A3000%2Fnever-proxied-$$&recurse=false")"
if printf '%s' "$UNSEEN" | grep -q 'url_not_found'; then
  ok "ZAP refuses to scan a URL that never went through the proxy (url_not_found)"
else
  bad "ZAP ACCEPTED a scan of a URL it has never seen: $UNSEEN
        The containment bound in the spec (§2.2) does not hold on this version — the active
        scanner is not limited to captured traffic. Re-measure before relying on that claim."
fi

# --- 5. the captured endpoint scans for real -------------------------------------------------
ENCODED="http%3A%2F%2F$LAB%3A3000%2Frest%2Fproducts%2Fsearch%3Fq%3Dproof"
LAUNCH="$(api "/JSON/ascan/action/scan/?url=$ENCODED&recurse=false&inScopeOnly=false")"
SCAN_ID="$(printf '%s' "$LAUNCH" | tr -dc '0-9')"
if [ -z "$SCAN_ID" ]; then
  bad "the scan did not launch: $LAUNCH"
else
  i=0
  PROGRESS=0
  while [ "$i" -lt 180 ]; do
    PROGRESS="$(api "/JSON/ascan/view/status/?scanId=$SCAN_ID" | tr -dc '0-9')"
    [ "${PROGRESS:-0}" -ge 100 ] && break
    i=$((i+3)); sleep 3
  done
  REQS="$(api "/JSON/ascan/view/scans/" | tr ',' '\n' | grep -m1 reqCount | tr -dc '0-9')"
  if [ "${PROGRESS:-0}" -ge 100 ] && [ "${REQS:-0}" -gt 0 ]; then
    ok "the captured endpoint scanned to completion (${REQS} attack requests sent, ${i}s)"
  else
    bad "the scan did not complete: progress=${PROGRESS:-?}% requests=${REQS:-?}"
  fi
fi

# --- 6. the REAL alert response maps with the REAL mapper ------------------------------------
cd "$(dirname "$0")/../../backend" || die "cannot find backend/"
PY=".venv/Scripts/python.exe"
[ -x "$PY" ] || PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"

# Piped, not staged: on a Windows host, bash's /tmp and Windows Python's /tmp are different
# directories, so a redirect here and an open() there disagree silently.
if api "/JSON/core/view/alerts/?start=0&count=99" | MSYS_NO_PATHCONV=1 "$PY" -c "
import json, sys
from cockpit import proxy
rows = json.loads(sys.stdin.read()).get('alerts') or []
alerts = [a for a in (proxy.parse_alert(r) for r in rows) if a]
findings = proxy.findings_from(alerts, session_id='s-proof', run_id='r-proof')
eps = proxy.alert_endpoints_from(alerts, session_id='s-proof', run_id='r-proof')
print(f'      {len(rows)} raw alert(s) -> {len(alerts)} parsed, {len(findings)} finding(s), {len(eps)} endpoint(s)')
for f in sorted(findings, key=lambda f: f.severity)[:6]:
    print(f'        {f.severity:8} {f.title[:38]:40} {f.reference}')
# The fixture and reality must agree on SHAPE: every raw row that has a name must survive, and
# no finding may fall back to 'info' when ZAP gave it a real risk.
risks = {(r.get('risk') or '').lower() for r in rows if isinstance(r, dict)}
lost = [r for r in rows if isinstance(r, dict) and (r.get('name') or r.get('alert')) ]
sys.exit(0 if alerts and len(alerts) == len(lost) and risks - {''} else 1)
"; then
  ok "the REAL alert response maps to Findings with the real mapper"
else
  bad "the live alert response did not map — the committed fixture and reality disagree, which
        is the part-1 defect class (a parser matched against a string nobody re-measured)"
fi

# --- 7. teardown leaves nothing listening ----------------------------------------------------
# THE WRAPPER EXEC'S THE JVM, so the spawned argv is NOT the running command line, and the [z]
# is load-bearing: pkill -f matches its own command line. Both found by part 2's proof.
MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" \
  sh -c "pkill -f \"[z]aproxy.*-daemon.*-port $PORT\" 2>/dev/null; sleep 3" >/dev/null 2>&1 || true
STILL="$(MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" sh -c "ss -lntH 2>/dev/null | grep ':$PORT ' || true")"
if [ -z "$STILL" ]; then
  ok "teardown released the port — nothing left listening"
else
  bad "the port is still bound after teardown: $STILL"
fi

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
