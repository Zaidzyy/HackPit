#!/usr/bin/env bash
# ONE-COMMAND mobile-capture bench. Auto-fires the mechanical setup, then PAUSES for a human login.
#
#   capture-bench.sh [--avd NAME] [--apk PATH] [--pkg PACKAGE_OR_MATCH] [--frida] [--port 8080]
#
# What it automates (host plumbing only): boot the emulator if needed -> install the app bundle ->
# (optional) push+start frida-server -> install the mitmproxy CA as a system cert -> point the
# device proxy at mitmproxy -> force-stop the app -> tell YOU to log in.
#
# What stays human, by design:
#   * LOGIN — your credentials + the app's ToS. The bench prints "log in now" and waits on you.
#   * TESTING — the HackPit :repeater IDOR loop still needs per-command approval. This automates
#     the capture BENCH, never the attacks.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/_bench-env.sh"
[ -n "${ADB:-}" ] || die "adb not found (set ANDROID_SDK_ROOT, or put adb on PATH)"

AVD=""; APK=""; PKG="${APP_MATCH:-}"; USE_FRIDA=0; PORT="${MITM_PORT:-8080}"
while [ $# -gt 0 ]; do
  case "$1" in
    --avd)  AVD="$2";  shift 2;;
    --apk)  APK="$2";  shift 2;;
    --pkg)  PKG="$2";  shift 2;;
    --port) PORT="$2"; shift 2;;
    --frida) USE_FRIDA=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) die "unknown arg: $1";;
  esac
done

_port_up() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; }; return 1; }

# 1) device online? boot the AVD if not.
if ! "$ADB" get-state >/dev/null 2>&1; then
  EMU="$SDK/emulator/emulator.exe"; [ -x "$EMU" ] || EMU="$SDK/emulator/emulator"
  [ -x "$EMU" ] || die "emulator binary not found under $SDK/emulator"
  [ -n "$AVD" ] || AVD="$("$EMU" -list-avds 2>/dev/null | head -1)"
  [ -n "$AVD" ] || die "no AVD to boot (create one, or pass --avd NAME)"
  say "== booting emulator '$AVD' (writable-system) =="
  "$EMU" -avd "$AVD" -writable-system >/dev/null 2>&1 &
  "$ADB" wait-for-device
fi
say "== waiting for boot to complete =="
until [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
say "device booted."

# 2) install the app bundle if given
if [ -n "$APK" ]; then
  say "== installing app from $APK =="
  APP_MATCH="$PKG" bash "$HERE/install-fishbowl.sh" "$APK" || die "app install failed"
fi

# 3) mitmproxy CA + mitmweb on $PORT
[ -f "$MITM_CA" ] || die "mitmproxy CA not at $MITM_CA — run mitmweb once so it generates the CA (or set MITMPROXY_HOME)"
if ! _port_up "$PORT"; then
  MITMWEB="$(_resolve_bin mitmweb || true)"
  [ -n "$MITMWEB" ] || die "mitmweb not found (pip install mitmproxy) and nothing is on :$PORT"
  say "== starting mitmweb on :$PORT (flows UI http://127.0.0.1:8081) =="
  nohup "$MITMWEB" --listen-port "$PORT" >"$STAGE/mitmweb.log" 2>&1 &
  sleep 2
fi

# 4) frida-server (optional) + system cert
[ "$USE_FRIDA" = "1" ] && { say "== frida-server =="; bash "$HERE/setup-frida-server.sh" || die "frida-server setup failed"; }
say "== installing mitmproxy CA as a system cert =="
bash "$HERE/install-system-cert.sh" || die "system cert install failed"

# 5) proxy on
say "== pointing device proxy at 10.0.2.2:$PORT =="
"$ADB" shell settings put global http_proxy "10.0.2.2:$PORT"

# 6) fresh app + the ONE human step
if [ -n "$PKG" ]; then
  FULLPKG="$("$ADB" shell pm list packages 2>/dev/null | tr -d '\r' | sed 's/package://' | grep -iE "$PKG" | head -1)"
  [ -n "$FULLPKG" ] && "$ADB" shell am force-stop "$FULLPKG" 2>/dev/null || true
fi
say ""
say "== BENCH READY — now the ONE human step =="
cat <<EOF
  1. Open the app in the emulator and LOG IN as your test account.
  2. Watch mitmweb:  http://127.0.0.1:8081
  3. Right-click the request you want (e.g. /thread/{id}/messages) -> Copy as raw.
  4. Repeat for a SECOND account, then paste both into HackPit :repeater -> import + import-diff.

Flows RED / TLS-failed => the app pins: re-run with --frida (needs an anti-tamper bypass), or
capture the web app instead.  Undo the proxy later:  adb shell settings put global http_proxy :0
EOF
