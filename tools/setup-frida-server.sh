#!/usr/bin/env bash
# Push + start frida-server on the connected device so `frida -U -f` works in rooted mode.
# Portable: version/arch/paths auto-detected via _bench-env.sh. Override with FRIDA_VERSION.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/_bench-env.sh"

[ -n "${ADB:-}" ]      || die "adb not found (set ANDROID_SDK_ROOT, or put adb on PATH)"
[ -n "${FRIDA_PS:-}" ] || die "frida-ps not found (pip install frida-tools)"
[ -n "${FRIDA_VER:-}" ] || die "could not determine frida version (set FRIDA_VERSION)"
[ -n "${PY:-}" ]       || die "python not found (needed to decompress the .xz)"

ABI="$("$ADB" shell getprop ro.product.cpu.abi | tr -d '\r')"
case "$ABI" in
  x86_64) FA=x86_64;; x86) FA=x86;; arm64-v8a) FA=arm64;; armeabi-v7a) FA=arm;;
  *) die "unknown device abi '$ABI'";;
esac
say "frida-server $FRIDA_VER for device abi=$ABI (arch=$FA)"

URL="https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-${FA}.xz"
XZ="$STAGE/frida-server.xz"; BIN="$STAGE/frida-server"
echo "downloading $URL"
curl -sSL -o "$XZ" "$URL" || die "download failed"
"$PY" -c "import lzma,shutil; shutil.copyfileobj(lzma.open(r'$(winpath "$XZ")'), open(r'$(winpath "$BIN")','wb'))" \
  || die "xz decompress failed"

"$ADB" root >/dev/null 2>&1
"$ADB" push "$(winpath "$BIN")" /data/local/tmp/frida-server >/dev/null || die "push failed"
"$ADB" shell chmod 755 /data/local/tmp/frida-server
"$ADB" shell "pkill -f frida-server" >/dev/null 2>&1 || true
"$ADB" shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
sleep 2
if "$FRIDA_PS" -U >/dev/null 2>&1; then
  say "PASS: frida-server is up"
  "$FRIDA_PS" -U | head -3
else
  die "frida-ps could not reach frida-server (run /data/local/tmp/frida-server in the foreground to see why)"
fi
