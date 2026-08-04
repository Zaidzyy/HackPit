#!/bin/sh
# Browser-interception proof (build #15) — the checks no hermetic test CAN make.
#
# THE LOAD-BEARING ONE IS #4: an API call from the host WITHOUT the key must be REFUSED.
#
# Build #14 part 2's safety argument was "no port is published, so the API is unreachable, so the
# only channel is `docker exec`, which the gates classify". This build makes half of that
# deliberately false: the engage sandbox's proxy port IS published, because nine of eleven assets
# in a live bug bounty program refused a bare HTTP client outright (h2 stream reset, h1.1
# timeout) and only a real browser gets through. What REPLACES the missing half is the API key.
#
# So the property being proven changes from "nothing can reach the control channel" to "the
# control channel refuses everyone who does" — and the second needs MORE assertions, not fewer:
#
#     4. host -> API, no key      MUST be refused     <- the whole build rests on this
#     5. host -> API, with key    MUST answer         <- or the refusal above proves nothing
#     6. host -> proxy            MUST serve          <- or the feature does not exist
#     7. the LAB sandbox's API    STILL unreachable   <- part 2's check, unweakened
#
# If check 4 ever reports ANSWERED, stop. It would mean scan control is exposed on the host —
# and on a wildcard bind, to whatever network the laptop is on.
#
# Conventions paid for in parts 1-3 and not decoration:
#   * compare the running container's image id against the built image BEFORE exec'ing into it
#   * MSYS_NO_PATHCONV=1 on container paths (Git Bash rewrites them in transit)
#   * pipe into python; never stage through a host /tmp file (bash's /tmp and Windows Python's
#     /tmp are different directories)
#   * print the exit code, but decide pass/fail on the ARTEFACT — an exit code is not a result
#
# Usage:  sh docker/proof/browser_intercept_proof.sh
set -u

IMAGE="hackpit/kali-sandbox:m1"
ENGAGE="hackpit-engage-sandbox"
LAB="hackpit-kali-sandbox"
LAB_TARGET="hackpit-lab-target"
PORT="${HACKPIT_PROXY_PORT:-8090}"
BIND="${HACKPIT_PROXY_BIND:-127.0.0.1}"
KEY=""
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die()  { printf '\nABORT: %s\n' "$1"; exit 2; }
note() { printf '        %s\n' "$1"; }

cleanup() {
  printf '\n-- teardown --\n'
  MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
    sh -c "pkill -f \"[z]aproxy.*-daemon.*-port $PORT\" 2>/dev/null; sleep 3" >/dev/null 2>&1
  # The proof's own crawl target. `[h]ttp.server` for the same reason the ZAP pattern uses
  # `[z]`: without it, pkill -f matches its own command line and kills itself instead.
  MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
    sh -c "pkill -f '[h]ttp.server' 2>/dev/null; rm -rf /tmp/crawlsite" >/dev/null 2>&1
  # The published port belongs to the container, not to the daemon: removing the profile does
  # NOT close it (exposure.observe() reports that state as `drifted`, never as `none`). Say so
  # rather than implying teardown undid the exposure.
  if [ -f docker/listener-profile.yml ]; then
    note "docker/listener-profile.yml still on disk — the container keeps its published port"
    note "until it is recreated:  docker compose -f docker/docker-compose.yml up -d $ENGAGE"
  fi
}

printf '\n=== browser-interception proof (build #15) ===\n\n'

cd "$(dirname "$0")/../.." || die "cannot find the repo root"

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build kali-sandbox"
docker ps --format '{{.Names}}' | grep -qx "$ENGAGE" \
  || die "$ENGAGE is not running. Run: docker compose -f docker/docker-compose.yml up -d"

trap cleanup EXIT

# --- 0. the container IS the image ----------------------------------------------------------
IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null || echo unknown)"
RUNNING_ID="$(docker inspect "$ENGAGE" --format '{{.Image}}' 2>/dev/null || echo unknown)"
if [ "$IMAGE_ID" = "$RUNNING_ID" ]; then
  ok "the running engage sandbox is the image that was built"
else
  die "$ENGAGE runs a DIFFERENT image than the one built — every check below would be about the
        wrong container. Recreate it:
          docker compose -f docker/docker-compose.yml up -d --force-recreate $ENGAGE"
fi

# --- 1. the webdriver and the browser are actually in the image ------------------------------
# UNVERIFIED when the Dockerfile layer was written: the container has zero apt list files, so
# `apt-cache` inside it can see no uninstalled package. The image build is the only thing that
# can answer, which is precisely how build #14 part 1's `zap-baseline.py` was caught.
DRV="$(MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" sh -c 'chromedriver --version 2>/dev/null' || true)"
if [ -n "$DRV" ]; then
  ok "chromedriver is present and runs: $DRV"
else
  bad "chromedriver is absent or will not run — the package name in Dockerfile.sandbox is wrong,
        and the AJAX spider cannot launch a browser without it"
fi
BROWSER="$(MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
  sh -c 'chromium --version 2>/dev/null || chromium-browser --version 2>/dev/null' || true)"
if [ -n "$BROWSER" ]; then
  ok "a browser is present: $BROWSER"
else
  bad "no chromium in the image — a driver with no browser is inert"
fi

# *** THE TWO DEFECTS THE FIRST RUN OF THIS PROOF FOUND. ***
# Both produced the SAME symptom — the spider answering OK and crawling nothing — and neither
# is visible to any hermetic test. They are checked separately here because they fail
# separately, and because a version drift in a future image would otherwise reappear as an
# unexplained empty crawl.
#
# 1. driver/browser MAJOR versions must match. ZAP bundles a chromedriver for a different Chrome
#    than Kali ships; proving the driver RUNS proves nothing about whether it can drive THIS
#    browser. cockpit/proxy.py pins ZAP to the system driver, and this is what makes that pin
#    meaningful.
DRV_MAJOR="$(printf '%s' "$DRV" | sed -E 's/^ChromeDriver ([0-9]+)\..*/\1/')"
BRW_MAJOR="$(printf '%s' "$BROWSER" | sed -E 's/^Chromium ([0-9]+)\..*/\1/')"
if [ -n "$DRV_MAJOR" ] && [ "$DRV_MAJOR" = "$BRW_MAJOR" ]; then
  ok "chromedriver and chromium are the same major version ($DRV_MAJOR)"
else
  bad "chromedriver major '$DRV_MAJOR' != chromium major '$BRW_MAJOR'. Selenium refuses the
        session with 'only supports Chrome version $DRV_MAJOR' and the crawl below will return
        OK while finding nothing."
fi

# 2. chromium must be able to start AS THE USER THIS CONTAINER RUNS AS. The engage sandbox runs
#    as root, and Chromium refuses to run as root without --no-sandbox — every Crawljax browser
#    died at creation. The Dockerfile drops the flag into /etc/chromium.d/, Debian's own
#    launcher extension point. This runs the launcher rather than reading the file, because the
#    file existing is not the same as the flag reaching the browser.
# The STDERR text is the evidence, matched directly. An earlier version piped into `grep -c`,
# which prints "0" and EXITS 1 when it finds nothing — so the `|| echo 1` fallback fired on the
# success case and appended a second line, and the comparison could never match. The check
# failed while the thing it tests was working perfectly. A check whose own plumbing decides the
# verdict is worse than no check; read the output, do not infer it from an exit code.
LAUNCH_ERR="$(MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
  sh -c 'chromium --headless=new --dump-dom about:blank 2>&1 >/dev/null' 2>/dev/null || true)"
case "$LAUNCH_ERR" in
  *"without --no-sandbox"*)
    bad "chromium refuses to start as this container's user — /etc/chromium.d/hackpit-container
        is missing or not being sourced, so every browser the crawl launches dies at creation" ;;
  *)
    ok "chromium starts as $(docker exec "$ENGAGE" whoami 2>/dev/null | tr -d '\r') (the --no-sandbox drop-in is in force)" ;;
esac

# --- 2. the port is PUBLISHED, and bound where the profile said ------------------------------
PUBLISHED="$(docker inspect "$ENGAGE" \
  --format "{{json .NetworkSettings.Ports}}" 2>/dev/null || echo '{}')"
if printf '%s' "$PUBLISHED" | grep -q "\"$PORT/tcp\""; then
  ok "the engage sandbox publishes $PORT/tcp"
  note "$PUBLISHED"
else
  die "the engage sandbox publishes no $PORT/tcp. Write and APPLY the profile first:
          POST /cockpit/exposure/profile  {ip: \"$BIND\", container: \"engage-sandbox\",
                                           extra: [[$PORT, \"tcp\"]]}
          POST /cockpit/exposure/apply    {approved: true}
        (or use the zap-proxy preset on the :exposure screen)"
fi

# THE DEFAULT PROFILE BINDS NARROW. A wildcard here is not a failure — it is a red-confirm the
# operator may legitimately have given for a phone or a second machine — but it must be VISIBLE
# in the proof output, because it is the difference between "a privacy annoyance on one machine"
# and "an open proxy on the café wifi".
if printf '%s' "$PUBLISHED" | grep -q '"HostIp":"0.0.0.0"'; then
  note "*** WIDE BIND: this port is on EVERY interface. With the engage sandbox's full egress"
  note "    behind it that is an OPEN PROXY to anyone who can reach this machine. Intended for a"
  note "    phone or a second box; on shared wifi, scanners find it quickly."
else
  ok "the published bind is narrow (not 0.0.0.0)"
fi

# --- 3. start the daemon the way cockpit/proxy.py does ---------------------------------------
# THE FLAGS ARE STATED EXPLICITLY, AND THAT IS THE POINT OF THIS WHOLE BUILD. ZAP PERSISTS
# `-config` values into $HOME/.ZAP/config.xml, so an unstated flag inherits whatever a previous
# run wrote — and a previous HackPit run wrote `api.disablekey=true`. The original "the ZAP API
# key enforces NOTHING" finding was produced exactly that way and was WRONG. A daemon that
# persists its configuration makes every measurement conditional on what a previous run wrote.
KEY="$(od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n')"
[ -n "$KEY" ] || KEY="proofkey$(date +%s)0123456789abcdef"
MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
  sh -c "pkill -f \"[z]aproxy.*-daemon.*-port $PORT\" 2>/dev/null; sleep 1" >/dev/null 2>&1
# `selenium.chromeDriver` pins ZAP to the SYSTEM driver instead of its bundled one — the same
# flag cockpit/proxy.py::server_argv_for passes, for the same measured reason. Kept in step with
# that function: a proof that starts the daemon differently from the product is measuring a
# configuration nobody ships.
MSYS_NO_PATHCONV=1 docker exec -d "$ENGAGE" sh -c \
  "zaproxy -daemon -host 0.0.0.0 -port $PORT \
     -config api.disablekey=false -config api.key=$KEY \
     -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
     -config selenium.chromeDriver=/usr/bin/chromedriver \
     >/tmp/zapd.log 2>&1"

READY=no
i=0
while [ "$i" -lt 90 ]; do
  if MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
       curl -s --max-time 2 -H "X-ZAP-API-Key: $KEY" \
       "http://127.0.0.1:$PORT/JSON/core/view/version/" 2>/dev/null | grep -q '"version"'; then
    READY=yes
    break
  fi
  i=$((i+1))
  sleep 1
done
if [ "$READY" = yes ]; then
  ok "the daemon answers its API from inside the container (after ${i}s)"
else
  bad "the daemon never answered within 90s — see: docker exec $ENGAGE cat /tmp/zapd.log"
  printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
  exit 1
fi

# It must be bound WIDE inside the container, or the published port forwards to nothing. This is
# the fact the design spec did not state and the implementation had to answer.
BIND_SEEN="$(MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
  sh -c "ss -lntH 2>/dev/null | grep ':$PORT ' || true")"
if printf '%s' "$BIND_SEEN" | grep -qE '0\.0\.0\.0|\*:'; then
  ok "the daemon is bound wide INSIDE the container, so the published port reaches it"
else
  bad "the daemon is loopback-bound inside the container: $BIND_SEEN
        `docker -p` forwards to the bridge interface, so the host port would be open and
        nothing would be listening behind it — the feature would be silently inert"
fi

# --- 4. *** THE LOAD-BEARING CHECK *** host -> API WITHOUT the key must be REFUSED -----------
NOKEY="$(curl -s --max-time 5 "http://$BIND:$PORT/JSON/core/view/version/" 2>/dev/null || true)"
if printf '%s' "$NOKEY" | grep -q '"version"'; then
  bad "THE ZAP API ANSWERED FROM THE HOST WITHOUT A KEY. That is ungated scan control exposed on
        this machine — and on a wildcard bind, to whatever network it is on. STOP and fix this
        before anything else. Got: $NOKEY"
else
  ok "the API REFUSES a call from the host with no key (the whole safety argument)"
  note "raw: '$NOKEY'"
fi

# And an ACTION, not just a view — the original finding was wrong specifically about actions.
NOKEY_ACT="$(curl -s --max-time 5 \
  "http://$BIND:$PORT/JSON/ascan/action/stop/?scanId=0" 2>/dev/null || true)"
if printf '%s' "$NOKEY_ACT" | grep -qi '"Result"'; then
  bad "an ACTION was accepted from the host with no key: $NOKEY_ACT"
else
  ok "an unauthenticated ACTION is refused too, not only a view"
fi

WRONGKEY="$(curl -s --max-time 5 -H "X-ZAP-API-Key: not-the-key" \
  "http://$BIND:$PORT/JSON/core/view/version/" 2>/dev/null || true)"
if printf '%s' "$WRONGKEY" | grep -q '"version"'; then
  bad "a WRONG key was accepted: $WRONGKEY"
else
  ok "a wrong key is refused"
fi

# --- 5. the CONTROL: with the key it answers -------------------------------------------------
# Without this, check 4 would pass just as happily against a port with nothing behind it.
WITHKEY="$(curl -s --max-time 5 -H "X-ZAP-API-Key: $KEY" \
  "http://$BIND:$PORT/JSON/core/view/version/" 2>/dev/null || true)"
if printf '%s' "$WITHKEY" | grep -q '"version"'; then
  ok "the same call WITH the key answers: $WITHKEY"
else
  bad "the API does not answer even with the key — check 4 above is therefore proving nothing
        about enforcement, only that the port is dead. Got: '$WITHKEY'"
fi

# --- 6. the PROXY serves the host, and what it serves lands in the history -------------------
BEFORE="$(curl -s --max-time 10 -H "X-ZAP-API-Key: $KEY" \
  "http://$BIND:$PORT/JSON/core/view/numberOfMessages/" 2>/dev/null || echo '')"
PROXIED_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 25 \
  -x "http://$BIND:$PORT" "http://$LAB_TARGET:3000/" 2>/dev/null || true)"
note "(a request proxied FROM THE HOST returned HTTP '$PROXIED_CODE' — the count below decides)"
sleep 2
AFTER="$(curl -s --max-time 10 -H "X-ZAP-API-Key: $KEY" \
  "http://$BIND:$PORT/JSON/core/view/numberOfMessages/" 2>/dev/null || echo '')"
B="$(printf '%s' "$BEFORE" | tr -dc '0-9')"
A="$(printf '%s' "$AFTER" | tr -dc '0-9')"
if [ -n "$A" ] && [ "${A:-0}" -gt "${B:-0}" ]; then
  ok "a request from the HOST went through the proxy and was captured (${B:-0} -> ${A})"
else
  bad "the capture count did not increase (${B:-?} -> ${A:-?}). The proxy did not serve the host,
        which is the one thing this build exists to make possible.
        NOTE: the engage sandbox reaches the internet but NOT the isolated lab network, so a
        failure here against $LAB_TARGET may mean the target is unroutable rather than that the
        proxy is broken — retry with an internet host to tell the two apart."
fi

# --- 7. the LAB sandbox's API is STILL unreachable from the host -----------------------------
# Part 2's check, unweakened. The lab half of the isolation argument does not move: only the
# ENGAGE sandbox becomes reachable, and only when a profile publishes it.
if docker ps --format '{{.Names}}' | grep -qx "$LAB"; then
  LAB_PUBLISHED="$(docker inspect "$LAB" --format '{{json .NetworkSettings.Ports}}' 2>/dev/null)"
  if printf '%s' "$LAB_PUBLISHED" | grep -q 'HostPort'; then
    bad "THE LAB SANDBOX PUBLISHES A PORT: $LAB_PUBLISHED
          Its network is `internal: true` and exposure.py refuses that container by construction.
          Something bypassed the profile path."
  else
    ok "the lab sandbox publishes nothing (its half of the isolation argument is untouched)"
  fi
else
  note "the lab sandbox is not running — its published-port check was SKIPPED, not passed"
fi

# --- 8. the AJAX spider LAUNCHES A BROWSER and captures — not merely that the option was set --
# *** AN OK IS NOT A RESULT. *** setOptionBrowserId accepted `not-a-browser` and answered
# {"Result":"OK"} (measured 2026-08-04), so the only evidence worth having is a browser process
# and a rising message count. This is the check that separates "configured" from "works".
zapi() {
  MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
    curl -s --max-time 20 -H "X-ZAP-API-Key: $KEY" "http://127.0.0.1:$PORT$1" 2>/dev/null
}

zapi "/JSON/ajaxSpider/action/setOptionBrowserId/?String=chrome-headless" >/dev/null
BROWSER_SET="$(zapi "/JSON/ajaxSpider/view/optionBrowserId/")"
if printf '%s' "$BROWSER_SET" | grep -q 'chrome-headless'; then
  ok "ZAP reports browser id chrome-headless (read BACK, not assumed from the OK)"
else
  bad "ZAP reports $BROWSER_SET after being set to chrome-headless — the option did not take"
fi

# *** THE CRAWL TARGET IS SERVED FROM INSIDE THE ENGAGE SANDBOX, AND THAT IS DELIBERATE. ***
# The first run of this proof aimed the crawl at the lab target and failed with 0 URLs — because
# the LAB lives on `hackpit-isolated` and the ENGAGE sandbox is on `hackpit-engage`. They cannot
# reach each other, which is the whole point of the two-network design; the same run's proxied
# fetch returned 502 for exactly that reason. Aiming at an internet host would have worked (this
# sandbox has full egress) but would put third-party traffic into a proof that does not need it.
#
# So the proof brings its own site: two linked pages on loopback INSIDE the container, which the
# headless browser ZAP launches can reach and nothing outside can. A crawler proves itself by
# following a link, so there are two pages rather than one.
CRAWL_PORT=8099
MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" sh -c "
  mkdir -p /tmp/crawlsite &&
  printf '%s' '<html><body><h1>proof</h1><a href=\"/second.html\">second</a></body></html>' \
    > /tmp/crawlsite/index.html &&
  printf '%s' '<html><body><h1>second page</h1></body></html>' \
    > /tmp/crawlsite/second.html &&
  (cd /tmp/crawlsite && nohup python3 -m http.server $CRAWL_PORT --bind 127.0.0.1 \
     >/tmp/crawlsite.log 2>&1 &) ; sleep 2" >/dev/null 2>&1
SITE_CODE="$(MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  "http://127.0.0.1:$CRAWL_PORT/" 2>/dev/null || true)"
if [ "$SITE_CODE" = "200" ]; then
  ok "the proof's own two-page site is serving inside the container on :$CRAWL_PORT"
else
  bad "the proof's crawl target did not come up (HTTP '$SITE_CODE') — the crawl check below
        would fail for a reason that has nothing to do with the browser"
fi

# REAP STRAY BROWSERS BEFORE STARTING, so the process check below cannot pass on residue. On an
# earlier run it reported success "after 0s" against a leftover chrome from a previous attempt
# while the crawl itself found nothing — a check that passes on another run's leavings is worse
# than no check at all. Deliberately here, BEFORE the crawl: doing it after would kill the very
# browser the evidence depends on.
#
# *** `pkill -x`, MATCHING THE PROCESS NAME — NOT `pkill -f "[c]hrome"`. ***
# The first version used `-f`, which matches the FULL COMMAND LINE, and it killed the ZAP DAEMON:
# its argv now contains `-config selenium.chromeDriver=/usr/bin/chromedriver`, so the daemon's
# own command line contains the string "chrome". Every API call after this point then returned
# empty and three checks failed for a reason that had nothing to do with what they test.
#
# This is the `[z]aproxy` lesson arriving from the other direction. There, `-f` matched too
# LITTLE (the wrapper exec'd the JVM, so the spawned argv was not the running one). Here it
# matched too MUCH — and it started matching only because a fix earlier in this same build put
# a new word on the daemon's command line. A `pkill -f` pattern is a claim about every argv on
# the box, and it silently stops being true when an unrelated argv changes.
MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
  sh -c 'pkill -x chromedriver 2>/dev/null; pkill -x chromium 2>/dev/null; sleep 1; true' \
  >/dev/null 2>&1

SPIDER_BEFORE="$(zapi "/JSON/core/view/numberOfMessages/" | tr -dc '0-9')"
zapi "/JSON/ajaxSpider/action/setOptionMaxCrawlDepth/?Integer=2" >/dev/null
zapi "/JSON/ajaxSpider/action/setOptionMaxDuration/?Integer=1" >/dev/null
CRAWL_TARGET="${HACKPIT_CRAWL_TARGET:-http://127.0.0.1:$CRAWL_PORT/}"
STARTED="$(zapi "/JSON/ajaxSpider/action/scan/?url=$(printf '%s' "$CRAWL_TARGET" | sed 's|:|%3A|g; s|/|%2F|g')&inScope=false&subtreeOnly=false")"
note "spider start said: $STARTED  (target $CRAWL_TARGET)"

# A browser PROCESS is the direct evidence. Poll for it while the crawl runs.
SAW_BROWSER=no
j=0
while [ "$j" -lt 40 ]; do
  if MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
       sh -c 'ps -eo comm 2>/dev/null | grep -qiE "chrome|chromedriver"'; then
    SAW_BROWSER=yes
    break
  fi
  j=$((j+1))
  sleep 1
done
if [ "$SAW_BROWSER" = yes ]; then
  ok "a real browser process was observed running during the crawl (after ${j}s)"
else
  bad "no chrome/chromedriver process ever appeared — the spider returned OK and launched
        nothing, which is exactly what setOptionBrowserId's unvalidated OK would look like.
        See: docker exec $ENGAGE cat /tmp/zapd.log"
fi

# Let it crawl, then stop it and decide on the ARTEFACT.
sleep 25
zapi "/JSON/ajaxSpider/action/stop/" >/dev/null
SPIDER_RESULTS="$(zapi "/JSON/ajaxSpider/view/numberOfResults/" | tr -dc '0-9')"
SPIDER_AFTER="$(zapi "/JSON/core/view/numberOfMessages/" | tr -dc '0-9')"
if [ -n "${SPIDER_AFTER:-}" ] && [ "${SPIDER_AFTER:-0}" -gt "${SPIDER_BEFORE:-0}" ]; then
  ok "the crawl captured traffic (${SPIDER_BEFORE:-0} -> ${SPIDER_AFTER}, ${SPIDER_RESULTS:-0} URLs found)"
else
  bad "the crawl captured nothing (${SPIDER_BEFORE:-?} -> ${SPIDER_AFTER:-?}, ${SPIDER_RESULTS:-0} URLs).
        A browser that starts and finds nothing is a browser that could not REACH the target.
        Check $CRAWL_TARGET is routable from the ENGAGE sandbox — note the lab target is NOT
        (different network, by design). Override with HACKPIT_CRAWL_TARGET."
fi

# --- 9. the captured traffic parses with the REAL parser -------------------------------------
cd backend || die "cannot find backend/"
PY=".venv/Scripts/python.exe"
[ -x "$PY" ] || PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"

# Piped, not staged: on a Windows host, bash's /tmp and Windows Python's /tmp are different
# directories, so a redirect here and an open() there disagree silently.
if MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
     curl -s --max-time 15 -H "X-ZAP-API-Key: $KEY" \
     "http://127.0.0.1:$PORT/JSON/core/view/messages/?start=0&count=10" 2>/dev/null \
   | "$PY" -c "
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
  bad "captured traffic did not parse — the fixture and reality disagree"
fi
cd .. || true

# --- 10. teardown leaves nothing listening ---------------------------------------------------
# THE WRAPPER EXEC'S THE JVM, so the spawned argv is NOT the running command line and the obvious
# pkill matches nothing. The `[z]` is load-bearing: without it, pkill -f matches its own command
# line and SIGTERMs itself. Both were found by a proof's teardown check, not by a unit test.
MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
  sh -c "pkill -f \"[z]aproxy.*-daemon.*-port $PORT\" 2>/dev/null; sleep 3" >/dev/null 2>&1
STILL="$(MSYS_NO_PATHCONV=1 docker exec "$ENGAGE" \
  sh -c "ss -lntH 2>/dev/null | grep ':$PORT ' || true")"
if [ -z "$STILL" ]; then
  ok "teardown released the port — nothing left listening inside the container"
else
  bad "the port is still bound after teardown: $STILL"
fi
LEFT="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
  "http://$BIND:$PORT/JSON/core/view/version/" 2>/dev/null || true)"
if [ "$LEFT" = "000" ] || [ -z "$LEFT" ]; then
  ok "and nothing answers on the host side either"
else
  bad "something still answers on $BIND:$PORT (HTTP $LEFT) after teardown"
fi

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
