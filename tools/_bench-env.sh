#!/usr/bin/env bash
# Shared, PORTABLE environment detection for the HackPit mobile-capture bench scripts.
# Sourced by setup-frida-server.sh / install-system-cert.sh / install-fishbowl.sh so they
# run on any machine (Windows Git-Bash, Linux, macOS) instead of hardcoding one host's paths.
#
# Exports: ADB, FRIDA, FRIDA_PS, FRIDA_VER, MITM_CA, SDK, STAGE, and helpers winpath()/say()/die().
# Override anything via env: ANDROID_SDK_ROOT / ANDROID_HOME, MITMPROXY_HOME, FRIDA_VERSION.

# Keep ANDROID paths (/data,/system,/apex) literal for adb on MSYS (else Git rewrites them).
export MSYS_NO_PATHCONV=1

say() { printf '\033[1;36m%s\033[0m\n' "$*"; }
die() { printf '\033[1;31m!! %s\033[0m\n' "$*" >&2; exit 1; }

# winpath: a host path that a NATIVE Windows tool (adb.exe, native python) understands.
# On Git-Bash `cygpath -m` turns /c/x -> C:/x; elsewhere it is identity.
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

# --- Android SDK + adb ------------------------------------------------------ #
_find_sdk() {
  local c
  for c in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" \
           "$HOME/AppData/Local/Android/Sdk" "$HOME/Android/Sdk" \
           "$HOME/Library/Android/sdk"; do
    [ -n "$c" ] && [ -d "$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}
SDK="$(_find_sdk || true)"
if   [ -n "${SDK:-}" ] && [ -x "$SDK/platform-tools/adb.exe" ]; then ADB="$SDK/platform-tools/adb.exe"
elif [ -n "${SDK:-}" ] && [ -x "$SDK/platform-tools/adb" ];     then ADB="$SDK/platform-tools/adb"
elif command -v adb >/dev/null 2>&1;                            then ADB="$(command -v adb)"
else ADB=""; fi

# --- frida CLI (PATH, or the python user-site Scripts dir) ------------------ #
_resolve_bin() {
  local n="$1" s ext base
  command -v "$n" >/dev/null 2>&1 && { command -v "$n"; return 0; }
  base="$(python -c 'import site;print(site.getuserbase())' 2>/dev/null)"
  [ -z "$base" ] && base="$(python3 -c 'import site;print(site.getuserbase())' 2>/dev/null)"
  [ -z "$base" ] && return 1
  # Windows path -> bash path so globbing + -x work; harmless on posix.
  command -v cygpath >/dev/null 2>&1 && base="$(cygpath -u "$base" 2>/dev/null)"
  # user scripts live at <base>/Scripts, <base>/PythonXY/Scripts (Windows), or <base>/bin (posix).
  for s in "$base/Scripts" "$base"/Python*/Scripts "$base/bin"; do
    for ext in "" ".exe"; do
      [ -x "$s/$n$ext" ] && { printf '%s' "$s/$n$ext"; return 0; }
    done
  done
  return 1
}
FRIDA="$(_resolve_bin frida || true)"
FRIDA_PS="$(_resolve_bin frida-ps || true)"
FRIDA_VER="${FRIDA_VERSION:-}"
[ -z "$FRIDA_VER" ] && [ -n "${FRIDA:-}" ] && FRIDA_VER="$("$FRIDA" --version 2>/dev/null | tr -d '\r')"

# --- mitmproxy CA ----------------------------------------------------------- #
MITM_CA="${MITMPROXY_HOME:-$HOME/.mitmproxy}/mitmproxy-ca-cert.pem"

# --- a staging dir every tool (bash + native) can read --------------------- #
STAGE="$HOME/.hackpit-bench"
mkdir -p "$STAGE"

# python launcher (native)
PY="$(command -v python || command -v python3 || true)"
