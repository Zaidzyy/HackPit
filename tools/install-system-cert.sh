#!/usr/bin/env bash
# Install the mitmproxy CA as an Android system cert on the connected device, WITHOUT Frida.
# Handles A14: overlays BOTH /system/etc/security/cacerts and the conscrypt APEX (init namespace).
# Portable via _bench-env.sh. Root required. tmpfs overlays are per-boot — re-run after a reboot.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/_bench-env.sh"

[ -n "${ADB:-}" ] || die "adb not found (set ANDROID_SDK_ROOT, or put adb on PATH)"
command -v openssl >/dev/null 2>&1 || die "openssl not found"
[ -f "$MITM_CA" ] || die "mitmproxy CA not at $MITM_CA — run mitmweb/the harness once (it generates it), or set MITMPROXY_HOME"

HASH="$(openssl x509 -inform PEM -subject_hash_old -in "$MITM_CA" 2>/dev/null | head -1)"
[ -n "$HASH" ] || die "could not hash the CA"
say "cert hash: $HASH"

CERT0="$STAGE/${HASH}.0"
openssl x509 -inform PEM -in "$MITM_CA" > "$CERT0"

DEV="$STAGE/certinstall.sh"
cat > "$DEV" <<'DEVSCRIPT'
#!/system/bin/sh
HASH="$1"
SRC="/data/local/tmp/${HASH}.0"
[ -f "$SRC" ] || { echo "FAIL: $SRC not on device"; exit 1; }
CAD="/data/local/tmp/ca-copy"; rm -rf "$CAD"; mkdir -p "$CAD"
[ -d /apex/com.android.conscrypt/cacerts ] && cp /apex/com.android.conscrypt/cacerts/* "$CAD/" 2>/dev/null
cp /system/etc/security/cacerts/* "$CAD/" 2>/dev/null
cp "$SRC" "$CAD/${HASH}.0"; chmod 644 "$CAD"/*; chown 0:0 "$CAD"/* 2>/dev/null
mount -t tmpfs tmpfs /system/etc/security/cacerts 2>/dev/null && {
  cp "$CAD"/* /system/etc/security/cacerts/; chown 0:0 /system/etc/security/cacerts/* 2>/dev/null
  chmod 644 /system/etc/security/cacerts/*
  chcon u:object_r:system_security_cacerts_file:s0 /system/etc/security/cacerts/* 2>/dev/null
}
if [ -d /apex/com.android.conscrypt/cacerts ]; then
  if command -v nsenter >/dev/null 2>&1; then
    nsenter --mount=/proc/1/ns/mnt -- sh -c "mount -t tmpfs tmpfs /apex/com.android.conscrypt/cacerts && cp $CAD/* /apex/com.android.conscrypt/cacerts/ && chown 0:0 /apex/com.android.conscrypt/cacerts/* && chmod 644 /apex/com.android.conscrypt/cacerts/* && (chcon u:object_r:system_security_cacerts_file:s0 /apex/com.android.conscrypt/cacerts/* 2>/dev/null; true)" \
      || echo "WARN: APEX nsenter overlay failed"
  else
    echo "WARN: no nsenter on device — APEX store not overlaid (system store still done)"
  fi
fi
if [ -f /apex/com.android.conscrypt/cacerts/${HASH}.0 ] || [ -f /system/etc/security/cacerts/${HASH}.0 ]; then
  echo "PASS: mitmproxy CA installed (${HASH}.0)"
else
  echo "FAIL: cert not visible in either store"
fi
DEVSCRIPT

"$ADB" root >/dev/null 2>&1
"$ADB" push "$(winpath "$CERT0")" "/data/local/tmp/${HASH}.0" >/dev/null || die "push cert failed"
"$ADB" push "$(winpath "$DEV")"   "/data/local/tmp/certinstall.sh" >/dev/null || die "push script failed"
"$ADB" shell sh "/data/local/tmp/certinstall.sh" "$HASH"
