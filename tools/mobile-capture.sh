#!/usr/bin/env bash
# HackPit mobile-capture harness — turnkey Part B of the authenticated-testing flow.
#
# Runs on YOUR HOST (where the Android emulator/device + adb + mitmproxy + frida live), NOT in the
# sandbox — the emulator needs KVM the sandbox doesn't have. It does the fiddly plumbing (start
# mitmproxy, install its CA as a SYSTEM cert, launch a Frida SSL-unpinning) so the only thing left
# for you is: OPEN THE APP AND LOG IN. Then paste the captured request into HackPit :repeater →
# "import a captured request", which flags the app-key vs session-token headers.
#
# Host prereqs: adb (platform-tools), mitmproxy (mitmweb), frida + frida-tools, openssl. A rooted
# emulator ("Google APIs" AVD, not "Google Play") or a rooted device on adb. Drop the community
# frida-multiple-unpinning.js next to this script if the app is cert-pinned.
#
# Env: MITM_PORT (default 8080). APP_MATCH (default 'fishbowl') to match the package name.
set -uo pipefail

PORT="${MITM_PORT:-8080}"
APP_MATCH="${APP_MATCH:-fishbowl}"
CERT="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
HERE="$(cd "$(dirname "$0")" && pwd)"
UNPIN="${HERE}/frida-multiple-unpinning.js"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
die() { printf '\033[1;31m!! %s\033[0m\n' "$*"; exit 1; }

command -v adb     >/dev/null || die "adb not found (install Android platform-tools)"
command -v openssl >/dev/null || die "openssl not found"

say "0. device"
adb get-state >/dev/null 2>&1 || die "no device on adb — start your emulator / plug in a rooted device"
adb devices | sed '1d;/^$/d'

say "1. mitmproxy"
if [ ! -f "$CERT" ]; then
  echo "   generating the mitmproxy CA (a one-off headless run)…"
  timeout 5 mitmdump >/dev/null 2>&1 || true
fi
[ -f "$CERT" ] || die "mitmproxy CA not found at $CERT — run 'mitmweb' once by hand, then re-run this"
if ! pgrep -f "mitmweb|mitmdump" >/dev/null 2>&1; then
  echo "   starting mitmweb on :$PORT (flows UI at http://127.0.0.1:8081)…"
  nohup mitmweb --listen-port "$PORT" >/tmp/hackpit-mitmweb.log 2>&1 &
  sleep 2
fi
echo "   mitmweb log: /tmp/hackpit-mitmweb.log  ·  flows UI: http://127.0.0.1:8081"

say "2. point the device proxy at the host"
echo "   emulator: Settings → Wi-Fi → (long-press network) → proxy Manual → 10.0.2.2:$PORT"
echo "   physical device: use your host's LAN IP:$PORT"

say "3. install the mitmproxy CA as a SYSTEM cert (Android 7+ ignores user certs for apps)"
HASH="$(openssl x509 -inform PEM -subject_hash_old -in "$CERT" 2>/dev/null | head -1)"
[ -n "$HASH" ] || die "could not hash the CA cert"
openssl x509 -inform PEM -in "$CERT" > "/tmp/${HASH}.0"
if adb root >/dev/null 2>&1 && adb remount >/dev/null 2>&1; then
  if adb push "/tmp/${HASH}.0" "/system/etc/security/cacerts/${HASH}.0" >/dev/null 2>&1 \
     && adb shell chmod 644 "/system/etc/security/cacerts/${HASH}.0" >/dev/null 2>&1; then
    echo "   pushed ${HASH}.0 to the system store. If the app still rejects the cert: adb reboot"
  else
    echo "   push failed even after remount — try 'adb reboot' then re-run, or a Magisk cert module."
  fi
else
  echo "   adb root/remount failed (Play image or non-rooted device). Fixes:"
  echo "     - use a 'Google APIs' AVD (rootable), a rooted device, or a Magisk 'MoveCert'/'CA cert' module"
  echo "     - the cert is staged at /tmp/${HASH}.0 for a manual move"
fi

say "4. app + SSL-unpinning"
PKG="$(adb shell pm list packages 2>/dev/null | tr -d '\r' | grep -i "$APP_MATCH" | sed 's/package://' | head -1)"
if [ -z "$PKG" ]; then
  echo "   no package matching '$APP_MATCH' installed — install the app, then re-run."
  echo "   (list: adb shell pm list packages | grep -i $APP_MATCH)"
elif command -v frida >/dev/null && [ -f "$UNPIN" ]; then
  echo "   package: $PKG"
  echo "   >>> now OPEN THE APP and LOG IN as your test account <<<"
  echo "   launching Frida multiple-unpinning (Ctrl-C to stop)…"
  frida -U -f "$PKG" -l "$UNPIN" 2>/tmp/hackpit-frida.log \
    || echo "   frida failed (see /tmp/hackpit-frida.log) — if the app isn't pinned, just open it manually."
else
  echo "   package: $PKG"
  [ -f "$UNPIN" ] || echo "   (no frida-multiple-unpinning.js next to this script — grab one from"
  [ -f "$UNPIN" ] || echo "    https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/ if the app is pinned)"
  command -v frida >/dev/null || echo "   (frida not installed — 'pip install frida-tools' + a matching frida-server if pinned)"
  echo "   if the app is NOT pinned, just open it and log in — traffic will already decrypt."
fi

say "next — bring the capture into HackPit"
cat <<'NEXT'
  1. In the app: log in as your test account and open a bowl / a DM.
  2. In mitmweb (http://127.0.0.1:8081): click a request to api.fishbowlapp.com (e.g. /bowl/list)
     → right-click → "Copy as raw" (or "Copy as curl").
  3. HackPit :repeater → "import a captured request" → paste → "parse & fill". Send it; a 200
     (not 401) means the key + token work.
  4. Repeat the login+capture for a SECOND account. Then compare the two: a credential header that
     is IDENTICAL across both accounts is the shared app key; one that DIFFERS is the per-user
     session token an IDOR test swaps. (HackPit's import-diff does this for you.)
NEXT
