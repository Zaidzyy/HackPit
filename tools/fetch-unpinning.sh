#!/usr/bin/env bash
# One-off: fetch the community akabe1 frida-multiple-unpinning script next to mobile-capture.sh.
# The main harness looks for tools/frida-multiple-unpinning.js when the app is cert-pinned.
# Robust + self-diagnosing: browser UA, HTTP-error check, handles both JSON shapes.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${HERE}/frida-multiple-unpinning.js"
RAW="${HERE}/.unpin.json"
# The codeshare API path drops the '@' (that prefix is only in the human display URL).
APIS=(
  "https://codeshare.frida.re/api/project/akabe1/frida-multiple-unpinning/"
  "https://codeshare.frida.re/api/project/@akabe1/frida-multiple-unpinning/"
)
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"

code="000"
for API in "${APIS[@]}"; do
  echo "fetching $API"
  code=$(curl -sS -A "$UA" -w '%{http_code}' -o "$RAW" "$API" || echo "000")
  echo "  HTTP $code, body bytes: $(wc -c < "$RAW" 2>/dev/null || echo 0)"
  [ "$code" = "200" ] && break
done
if [ "$code" != "200" ]; then
  echo "FAIL: codeshare unreachable. First 200 bytes of last body:"
  head -c 200 "$RAW" 2>/dev/null; echo
  echo
  echo "ZERO-FETCH FALLBACK: skip this script entirely — the harness can pull it at runtime."
  echo "  frida caches codeshare scripts, so just run frida with --codeshare instead of -l:"
  echo "    frida -U -f <pkg> --codeshare akabe1/frida-multiple-unpinning"
  echo "  (mobile-capture.sh already falls back to this when the local .js is absent.)"
  exit 1
fi

python - "$RAW" "$OUT" <<'PY'
import json, sys
raw, out = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(raw, encoding="utf-8"))
except Exception as e:
    print("FAIL: json parse:", e); sys.exit(1)
# codeshare returns either {"source": ...} or {"project": {"source": ...}}
src = d.get("source") or (d.get("project") or {}).get("source") or ""
if len(src) < 500:
    print("FAIL: source too small/missing. top-level keys =", list(d.keys()))
    if "project" in d and isinstance(d["project"], dict):
        print("      project keys =", list(d["project"].keys()))
    sys.exit(1)
open(out, "w", encoding="utf-8", newline="\n").write(src)
print("PASS: wrote %s (%d bytes)" % (out, len(src)))
print("first line:", src.splitlines()[0][:100])
PY
rc=$?
rm -f "$RAW"
exit $rc
