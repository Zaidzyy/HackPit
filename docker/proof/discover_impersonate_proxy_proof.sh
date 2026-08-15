#!/usr/bin/env bash
# Proof for the :discover JA3 MITM proxy (impersonate-proxy).
#
# ffuf/feroxbuster/arjun speak their own TLS, so a JA3-fingerprinting WAF 403s them. The fix routes
# them through impersonate-proxy: mitmproxy terminates the tool's TLS and re-issues via curl_cffi
# with Chrome's JA3. This rebuilds the image (build-time gate: mitmproxy+curl_cffi venv + addon
# parses), starts the proxy in the sandbox, and compares a PLAIN request (bot fingerprint) with one
# THROUGH the proxy (browser fingerprint) against the in-scope Fishbowl host, plus an ffuf run
# through the proxy. Proxied status 2xx/3xx/404 == the WAF was cleared. Read-only, in-scope recon.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; cd "$here" || { echo "cannot cd to docker/"; exit 1; }

echo "== 1/2  rebuild hackpit/kali-sandbox:m1 (build-time impersonate-proxy venv gate) =="
docker compose -f docker-compose.yml build engage-sandbox || { echo ">> BUILD FAILED"; exit 1; }

echo ""
echo "== 2/2  plain vs proxied against the in-scope Fishbowl host =="
out=$(docker run --rm hackpit/kali-sandbox:m1 bash -lc '
  set -e
  impersonate-proxy >/tmp/px.log 2>&1 &
  for i in $(seq 1 30); do ss -ltn 2>/dev/null | grep -q ":8899" && break; sleep 0.5; done
  ss -ltn 2>/dev/null | grep -q ":8899" && echo "PROXY_UP" || { echo "PROXY_DOWN"; tail -5 /tmp/px.log; }
  P=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 20 https://www.fishbowlapp.com/faq || echo 000)
  echo "PLAIN_STATUS=$P"
  X=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 25 -x http://127.0.0.1:8899 -k https://www.fishbowlapp.com/faq || echo 000)
  echo "PROXY_STATUS=$X"
  echo "-- ffuf THROUGH the proxy (tiny list; expect varied real statuses, not blanket 403) --"
  printf "%s\n" faq terms privacy robots.txt careers > /tmp/w.txt
  ffuf -u https://www.fishbowlapp.com/FUZZ -w /tmp/w.txt -mc all -x http://127.0.0.1:8899 -s 2>/dev/null | head -12 || true
' 2>&1)
echo "$out"
echo "---"
if echo "$out" | grep -q PROXY_DOWN; then
  echo ">> RESULT: FAIL — impersonate-proxy never bound 8899 (see the px.log tail above)"; exit 1
fi
ps=$(echo "$out" | sed -n "s/PROXY_STATUS=//p" | tr -dc "0-9")
pl=$(echo "$out" | sed -n "s/PLAIN_STATUS=//p" | tr -dc "0-9")
case "$ps" in
  2*|3*|404) echo ">> RESULT: PASS — proxy cleared the WAF (proxied=$ps, plain=$pl)"; exit 0;;
  *) echo ">> RESULT: FAIL — proxied request still blocked (proxied=$ps, plain=$pl)"; exit 1;;
esac
