#!/usr/bin/env bash
# Install an app into the connected device. Portable + ABI-aware: takes an .apkm/.xapk bundle,
# a directory of split APKs, or a single .apk. Picks base + the device's ABI split + English +
# density splits (what APKMirror's own installer does). Not app-specific despite the name.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/_bench-env.sh"
[ -n "${ADB:-}" ] || die "adb not found (set ANDROID_SDK_ROOT, or put adb on PATH)"

SRC="${1:-}"; [ -n "$SRC" ] || die "usage: install-fishbowl.sh <app.apkm | dir-of-splits | app.apk>"

APKDIR=""
if [ -d "$SRC" ]; then
  APKDIR="$SRC"
elif [ -f "$SRC" ]; then
  case "$SRC" in
    *.apk)
      say "single-APK install"; "$ADB" install "$(winpath "$SRC")"; exit $? ;;
    *.apkm|*.xapk|*.zip)
      APKDIR="$STAGE/apks"; rm -rf "$APKDIR"; mkdir -p "$APKDIR"
      say "extracting bundle -> $APKDIR"; unzip -q -o "$SRC" -d "$APKDIR" || die "unzip failed" ;;
    *) die "unrecognized file type: $SRC (want .apkm/.xapk/.zip/.apk or a dir)" ;;
  esac
else
  die "not found: $SRC"
fi

ABI="$("$ADB" shell getprop ro.product.cpu.abi | tr -d '\r')"
SPLIT_ABI="${ABI//-/_}"    # arm64-v8a -> arm64_v8a
say "device abi=$ABI (split token: $SPLIT_ABI)"

[ -f "$APKDIR/base.apk" ] || die "no base.apk in $APKDIR"
sel=("$APKDIR/base.apk")
if [ -f "$APKDIR/split_config.$SPLIT_ABI.apk" ]; then
  sel+=("$APKDIR/split_config.$SPLIT_ABI.apk")
else
  echo "  (note: no ABI split for $SPLIT_ABI — app may be arm-only, relying on the emulator's native bridge)"
fi
[ -f "$APKDIR/split_config.en.apk" ] && sel+=("$APKDIR/split_config.en.apk")
for d in ldpi mdpi tvdpi hdpi xhdpi xxhdpi xxxhdpi; do
  [ -f "$APKDIR/split_config.$d.apk" ] && sel+=("$APKDIR/split_config.$d.apk")
done

args=(); for f in "${sel[@]}"; do args+=("$(winpath "$f")"); done
say "installing ${#sel[@]} APK(s)…"
"$ADB" install-multiple "${args[@]}"
rc=$?
say "installed 3rd-party packages matching '${APP_MATCH:-(any)}':"
"$ADB" shell pm list packages -3 2>/dev/null | tr -d '\r' | sed 's/package://' | grep -iE "${APP_MATCH:-.}" | head -5
exit $rc
