#!/bin/sh
# ZAP recording-proxy proof — the checks a hermetic test CANNOT make.
#
# THE LOAD-BEARING ONE IS #3: the ZAP API must be UNREACHABLE FROM THIS HOST. That single fact
# is the entire reason build #14 part 2 is allowed to run a daemon that part 1 refused. Part 1's
# objection was to an HTTP control channel that bypasses executor.validate_request, and to
# opening the `internal: true` network that assert_isolation_proven() exists to deny. Neither
# happens as long as the daemon binds 127.0.0.1 INSIDE the container and no port is published —
# and no unit test can assert that, because it is a property of the network, not the code.
#
# If check 3 ever reports REACHABLE, stop. Nothing else in this build matters until it is
# understood: it would mean the backend has a socket to an ungated control surface.
#
# Conventions here were paid for in part 1 and are not decoration:
#   * compare the running container's image id against the built image BEFORE exec'ing into it
#     (six name checks once passed against a new image while the container ran the old one)
#   * MSYS_NO_PATHCONV=1 on container paths (Git Bash rewrites them into host paths in transit)
#   * pipe into python; never stage through a host /tmp file (bash's /tmp and Windows Python's
#     /tmp are different directories)
#   * print the exit code, but decide pass/fail on the ARTEFACT — an exit code is not a result
#
# Usage:  sh docker/proof/zap_proxy_proof.sh
set -eu

IMAGE="hackpit/kali-sandbox:m1"
SANDBOX="hackpit-kali-sandbox"
LAB="hackpit-lab-target"
PORT=8090
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die() { printf '\nABORT: %s\n' "$1"; exit 2; }

printf '\n=== ZAP recording-proxy proof ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build kali-sandbox"
docker ps --format '{{.Names}}' | grep -qx "$SANDBOX" \
  || die "$SANDBOX is not running. Run: docker compose -f docker/docker-compose.yml up -d"

# --- 0. the container IS the image ---------------------------------------------------------
IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null || echo unknown)"
CONTAINER_IMAGE_ID="$(docker inspect "$SANDBOX" --format '{{.Image}}' 2>/dev/null || echo unknown)"
if [ "$IMAGE_ID" = "$CONTAINER_IMAGE_ID" ]; then
  ok "the running sandbox is the image that was built"
else
  die "$SANDBOX runs a DIFFERENT image than the one built — every check below would be about
        the wrong container. Recreate it:
          docker compose -f docker/docker-compose.yml up -d --force-recreate kali-sandbox"
fi

# --- 1. the daemon starts and answers, INSIDE the container --------------------------------
MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" sh -c "pkill -f \"[z]aproxy.*-daemon.*-port $PORT\" 2>/dev/null; sleep 1" \
  >/dev/null 2>&1 || true
MSYS_NO_PATHCONV=1 docker exec -d "$SANDBOX" sh -c \
  "zaproxy -daemon -host 127.0.0.1 -port $PORT -config api.disablekey=true >/tmp/zapd.log 2>&1"

READY=no
i=0
while [ "$i" -lt 60 ]; do
  if MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" \
       curl -s --max-time 2 "http://127.0.0.1:$PORT/JSON/core/view/version/" 2>/dev/null \
       | grep -q '"version"'; then
    READY=yes
    break
  fi
  i=$((i+1))
  sleep 1
done
if [ "$READY" = yes ]; then
  ok "the daemon answers its API via docker exec (after ${i}s)"
else
  bad "the daemon never answered within 60s — see: docker exec $SANDBOX cat /tmp/zapd.log"
fi

# --- 2. it is bound to LOOPBACK, not 0.0.0.0 -----------------------------------------------
BIND="$(MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" sh -c "ss -lntH 2>/dev/null | grep ':$PORT ' || true")"
if printf '%s' "$BIND" | grep -q '127\.0\.0\.1'; then
  ok "the listener is bound to 127.0.0.1 inside the container"
elif [ -z "$BIND" ]; then
  bad "no listener on :$PORT inside the container"
else
  bad "the listener is NOT loopback-bound — this is the isolation property: $BIND"
fi

# --- 3. *** THE LOAD-BEARING CHECK *** the API is UNREACHABLE FROM THIS HOST ----------------
if curl -s --max-time 5 "http://127.0.0.1:$PORT/JSON/core/view/version/" >/dev/null 2>&1; then
  bad "THE ZAP API IS REACHABLE FROM THIS HOST. That is an ungated control channel with a
        socket straight to it — exactly what build #14 part 1 refused. Something published the
        port or widened the bind. STOP and fix this before anything else."
else
  ok "the ZAP API is UNREACHABLE from this host (the whole safety argument)"
fi

# --- 4. a real request proxied from inside is captured --------------------------------------
BEFORE="$(MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" \
  curl -s --max-time 10 "http://127.0.0.1:$PORT/JSON/core/view/numberOfMessages/" 2>/dev/null || echo '')"
MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" sh -c \
  "curl -s -o /dev/null -x http://127.0.0.1:$PORT --max-time 20 'http://$LAB:3000/rest/products/search?q=proof'" \
  >/dev/null 2>&1
printf '        (proxied request exit=%s — an exit code is not a result; the count below is)\n' "$?"
sleep 2
AFTER="$(MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" \
  curl -s --max-time 10 "http://127.0.0.1:$PORT/JSON/core/view/numberOfMessages/" 2>/dev/null || echo '')"
B="$(printf '%s' "$BEFORE" | tr -dc '0-9')"
A="$(printf '%s' "$AFTER" | tr -dc '0-9')"
if [ -n "$A" ] && [ "${A:-0}" -gt "${B:-0}" ]; then
  ok "a request proxied from inside the sandbox was captured (${B:-0} -> ${A})"
else
  bad "the capture count did not increase (${B:-?} -> ${A:-?}) — the proxy recorded nothing"
fi

# --- 5. the captured message parses with the REAL parser ------------------------------------
cd "$(dirname "$0")/../../backend" || die "cannot find backend/"
PY=".venv/Scripts/python.exe"
[ -x "$PY" ] || PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"

# Piped, not staged: on a Windows host, bash's /tmp and Windows Python's /tmp are different
# directories, so a redirect here and an open() there disagree silently.
if MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" \
     curl -s --max-time 10 "http://127.0.0.1:$PORT/JSON/core/view/messages/?start=0&count=5" \
     2>/dev/null | "$PY" -c "
import json, sys
from cockpit import proxy
msgs = json.loads(sys.stdin.read()).get('messages') or []
exchanges = [e for e in (proxy.parse_message(m, 'proof') for m in msgs) if e]
eps = proxy.endpoints_from(exchanges, session_id='s-proof', run_id='r-proof')
print(f'      parsed {len(exchanges)} exchange(s), {len(eps)} endpoint(s)')
for e in exchanges[:4]:
    print(f'        {e.request.method:5} {e.request.url[:58]} -> {e.response.status}')
sys.exit(0 if exchanges else 1)
"; then
  ok "the REAL captured traffic parses into exchanges and endpoints"
else
  bad "captured traffic did not parse — the hand-written fixture and reality disagree"
fi

# --- 6. teardown leaves nothing listening ---------------------------------------------------
# THE WRAPPER EXEC'S THE JVM, so the literal spawned argv is NOT the running command line:
#   java -Xmx… -jar /usr/share/zaproxy/zap-2.17.0.jar -daemon -host 127.0.0.1 -port 8090
# "zaproxy -daemon" appears nowhere in that, so the obvious pkill matched nothing and the daemon
# survived every stop. THIS CHECK is what found it — no unit test can, because a hermetic test
# has no process to fail to kill. Same pattern as cockpit/proxy.py::kill_pattern_for: match the
# install path and the PORT, so it is version-agnostic and cannot reap a proxy on another port.
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
