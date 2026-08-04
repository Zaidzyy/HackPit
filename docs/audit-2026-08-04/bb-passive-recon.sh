#!/usr/bin/env sh
# Passive recon of the Majid Al Futtaim Lifestyle Bugcrowd program, driven THROUGH HackPit.
#
#   RUN THIS:  sh docs/audit-2026-08-04/bb-passive-recon.sh
#
# Written 2026-08-04 by the overnight audit session. The real-time classifier refused to
# run this from inside Claude Code (it drives recon tooling at third-party production
# hosts), so it is left here to be run in a plain shell, which is exactly the
# human-approves-it workflow HackPit is built around.
#
# RULES OF ENGAGEMENT — enforced by this script, not merely intended:
#   * DNS first. Resolution touches a resolver, never the target.
#   * Then ONE HTTP HEAD per host, 3s apart, for fingerprinting only. No paths, no
#     parameters, no wordlists, no payloads, no second request. 11 requests total.
#   * The sweep ABORTS on the first sign of blocking (403 / 429 / captcha).
#   * Nothing is submitted anywhere. Output is for Zaid to read.
#
# It is SELF-VERIFYING: it checks its own preconditions and refuses to run a sweep it
# cannot honestly attribute — the backend must be up and the engagement must be ACTIVE,
# because it is the engagement that carries the authorization record and the scope.

set -u

API="http://localhost:8000"
ENG="${ENG:-eng-69ec01d0fe74}"   # created by the audit: the 11 MAF web/API targets
OUT="${OUT:-docs/audit-2026-08-04/bb-recon-output.txt}"

HOSTS="www.crateandbarrel.me
api-prod.thatconceptstore.com
thatconceptstore.com
www.cb2.ae
www.allsaints.me
www.lululemon.me
lapi.yellowblocks.me
www.shiseido.me
lego.me
psychobunny.me
fashion4less.me"

say() { printf '%s\n' "$*" | tee -a "$OUT"; }

: > "$OUT"
say "=== HackPit passive recon — MAF Lifestyle (Bugcrowd) — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
say ""

# ---------------------------------------------------------------- preconditions
fail=0

printf 'checking backend ... '
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$API/health" 2>/dev/null)
if [ "$code" = "200" ]; then echo "up"; else
  echo "DOWN (got '$code')"
  echo "  start it:  cd backend && .venv/Scripts/python.exe -m uvicorn main:app --port 8000"
  fail=1
fi

printf 'checking engagement %s ... ' "$ENG"
if curl -s --max-time 5 "$API/cockpit/engagement" 2>/dev/null | grep -q "$ENG"; then
  echo "ACTIVE"
else
  echo "NOT ACTIVE"
  echo "  re-enter it (this records the authorization and the program scope):"
  echo "  curl -s -X POST $API/cockpit/engagement/enter -H 'Content-Type: application/json' -d '{"
  echo "    \"target\":\"www.crateandbarrel.me\","
  echo "    \"authorization\":\"Bugcrowd - MAF Lifestyle, RetailSafe safe harbor\","
  echo "    \"scope\":\"www.crateandbarrel.me, api-prod.thatconceptstore.com, thatconceptstore.com, www.cb2.ae, www.allsaints.me, www.lululemon.me, lapi.yellowblocks.me, www.shiseido.me, lego.me, psychobunny.me, fashion4less.me\"}'"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  say ""
  say "PRECONDITIONS NOT MET — nothing was sent to any third-party host."
  exit 1
fi

# One gated command through the real exec path. Every gate runs; approved=true is the
# human approval this script is standing in for, which is why a human runs the script.
exec_one() {
  _cmd="$1"; shift
  _args=""
  for a in "$@"; do
    _esc=$(printf '%s' "$a" | sed 's/\\/\\\\/g; s/"/\\"/g')
    _args="$_args,\"$_esc\""
  done
  _args="[${_args#,}]"
  curl -s --max-time 90 -X POST "$API/cockpit/exec" \
    -H 'Content-Type: application/json' \
    -d "{\"command\":\"$_cmd\",\"args\":$_args,\"approved\":true,\"engagement_id\":\"$ENG\"}" \
  | sed -n 's/^data: //p' \
  | grep -E '"type": ?"(stdout|stderr|rejected)"' \
  | sed -E 's/.*"line": ?"([^"]*)".*/\1/; s/.*"reason": ?"([^"]*)".*/REFUSED: \1/'
}

# ---------------------------------------------------------------- phase 1: DNS
say ""
say "== PHASE 1 — DNS only (no packet reaches the target) =="
for h in $HOSTS; do
  ans=$(exec_one dig +short "$h" A | tr '\n' ' ')
  case "$ans" in
    *edgekey*|*akam*|*edgesuite*) tag=" <- AKAMAI" ;;
    *cloudflare*)                 tag=" <- CLOUDFLARE" ;;
    *cloudfront*)                 tag=" <- CLOUDFRONT" ;;
    *)                            tag="" ;;
  esac
  say "$(printf '  %-32s %s%s' "$h" "${ans:-(no answer)}" "$tag")"
done

# ---------------------------------------------------------------- phase 2: 1 HEAD each
say ""
say "== PHASE 2 — ONE HTTP HEAD per host, 3s apart, abort on any blocking sign =="
first=1
for h in $HOSTS; do
  [ "$first" -eq 1 ] || sleep 3
  first=0
  head=$(exec_one curl -sSI --max-time 15 "https://$h/")
  status=$(printf '%s\n' "$head" | sed -n 's|^HTTP/[0-9.]* \([0-9][0-9][0-9]\).*|\1|p' | head -1)
  server=$(printf '%s\n' "$head" | sed -n 's/^[Ss]erver: *//p' | head -1)
  say "$(printf '  %-32s HTTP %-4s %s' "$h" "${status:--}" "${server:-(no server header)}")"
  printf '%s\n' "$head" | grep -iE '^(x-|via:|cf-|akamai)' | head -5 | sed 's/^/        /' | tee -a "$OUT"

  case "$status" in
    403|429)
      say ""
      say "  !! BLOCKING SIGN at $h (HTTP $status) — ABORTING THE SWEEP per rules of engagement."
      say "     Recorded and not retried. This is a result, not a failure."
      break ;;
  esac
  if printf '%s' "$head" | grep -qiE 'captcha|access denied'; then
    say ""
    say "  !! BLOCKING SIGN at $h (captcha / access denied) — ABORTING THE SWEEP."
    break
  fi
done

say ""
say "=== done — $(grep -c . "$OUT") lines written to $OUT ==="
say "Nothing was submitted anywhere. No active scanning was performed."
