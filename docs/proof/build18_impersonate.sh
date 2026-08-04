#!/bin/sh
# Build #18 item 5 — curl-impersonate: prove it does the thing BARE CURL CANNOT.
#
# *** THE VERSION STRING IS NOT THE RESULT, AND NEITHER IS THE BINARY EXISTING. ***
# Build #15's lesson was "an OK is not a result". Build #17 went a level deeper: a successful
# `--version` proves a binary runs and nothing else. The Dockerfile layer already asserts the
# binaries and the browser WRAPPERS are present, so this script is only worth running for the
# property that cannot be checked at build time:
#
#     A REQUEST BARE CURL CANNOT COMPLETE, COMPLETING THROUGH THE IMPERSONATING CLIENT.
#
# That needs a real WAF-fronted host, which is why it lives here and not in the image build or
# in a hermetic test.
#
# Run from the repo root:   sh docs/proof/build18_impersonate.sh [host ...]
#
# EVERY PROBE CARRIES ITS OWN CONTROL. Build #17 recorded why: a probe with no control turns a
# broken toolchain into a finding about the target, and here that would read as "the edge
# refuses browsers too" — which is exactly the conclusion that must never be reached by accident.
# So each host is hit with BOTH clients, and a host that refuses both is reported as refusing
# both rather than as a failure of this build.
#
# THE HONEST OUTCOME INCLUDES "IT DID NOT HELP". The pinned build impersonates Chrome 116 /
# Firefox 109. Whether that vintage still satisfies a 2026 bot manager is the measurement; a
# recorded "no" is a legitimate result and is what the assessment will say.
set -u
export MSYS_NO_PATHCONV=1

CONTAINER="${CONTAINER:-hackpit-engage-sandbox}"
LOG="docs/proof/build18-impersonate.log"

if [ "$#" -gt 0 ]; then
  HOSTS="$*"
else
  # Default to the two the plan names plus a control that is NOT bot-managed, so a run where
  # everything fails is distinguishable from a run where the sandbox has no egress at all.
  HOSTS="example.com api-prod.thatconceptstore.com lapi.yellowblocks.me"
fi

RCF="${TMPDIR:-/tmp}/build18-imp.rc"

echo "======================================================================"
echo "BUILD #18 ITEM 5 -- curl-impersonate vs bare curl, per host"
echo "container=$CONTAINER"
echo "hosts    =$HOSTS"
echo "======================================================================"

if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
  echo "VERDICT=NOT-RUN -- $CONTAINER is not running."
  echo "  docker compose -f docker/docker-compose.yml up -d"
  exit 2
fi

# Present at all? If the image has not been rebuilt since build #18, say THAT rather than
# reporting every host as refused.
if ! docker exec "$CONTAINER" sh -c 'command -v curl_chrome116 >/dev/null'; then
  echo "VERDICT=NOT-RUN -- curl_chrome116 is not in this container."
  echo "  The image predates build #18's layer 9g. Rebuild:"
  echo "    docker compose -f docker/docker-compose.yml build engage-sandbox"
  echo "    docker compose -f docker/docker-compose.yml up -d --force-recreate engage-sandbox"
  echo "  (THE CONTAINER IS NOT THE IMAGE -- a rebuild alone changes nothing until recreate.)"
  exit 2
fi

# probe <label> <binary> <host> -> prints "<code> <bytes> <seconds>"; 000 means never answered.
probe() {
  docker exec "$CONTAINER" sh -c \
    "$2 -sS -o /dev/null --max-time 25 -w '%{http_code} %{size_download} %{time_total}' 'https://$3/' 2>/dev/null || echo '000 0 0'"
}

WON=0
BOTH_REFUSED=0
BOTH_OK=0
TOTAL=0

{
echo "host                                    bare-curl        curl_chrome116   verdict"
echo "--------------------------------------- ---------------- ---------------- ------------------"
for H in $HOSTS; do
  TOTAL=$((TOTAL + 1))
  BARE=$(probe bare "curl" "$H")
  IMP=$(probe imp "curl_chrome116" "$H")
  BC=$(echo "$BARE" | awk '{print $1}')
  IC=$(echo "$IMP"  | awk '{print $1}')
  BB=$(echo "$BARE" | awk '{print $2}')
  IB=$(echo "$IMP"  | awk '{print $2}')

  # "reached" means an HTTP response that is not an edge refusal. A 403 from a bot manager IS a
  # response, and counting it as success is the exact mistake build #17's first verdict made.
  case "$BC" in 000|403|503|504|"") BOK=no ;; *) BOK=yes ;; esac
  case "$IC" in 000|403|503|504|"") IOK=no ;; *) IOK=yes ;; esac

  if [ "$BOK" = no ] && [ "$IOK" = yes ]; then
    V="IMPERSONATION WINS"; WON=$((WON + 1))
  elif [ "$BOK" = no ] && [ "$IOK" = no ]; then
    V="both refused"; BOTH_REFUSED=$((BOTH_REFUSED + 1))
  elif [ "$BOK" = yes ] && [ "$IOK" = yes ]; then
    V="both fine (no wall)"; BOTH_OK=$((BOTH_OK + 1))
  else
    V="bare ok, impersonation NOT"
  fi
  printf '%-39s %-4s %-11s %-4s %-11s %s\n' "$H" "$BC" "${BB}B" "$IC" "${IB}B" "$V"
done

echo
echo "----------------------------------------------------------------------"
echo "hosts probed          : $TOTAL"
echo "impersonation wins    : $WON     (bare curl refused, curl_chrome116 served)"
echo "both refused          : $BOTH_REFUSED     (the edge refuses this fingerprint too)"
echo "both served           : $BOTH_OK     (no client wall on this host)"
echo
if [ "$BOTH_OK" -eq 0 ] && [ "$WON" -eq 0 ]; then
  echo "READ THIS BEFORE CONCLUDING ANYTHING: not one host answered either client, including"
  echo "the control. That is a broken toolchain or no egress, NOT a finding about the targets."
  echo "VERDICT=FAIL"
  echo $? > "$RCF"
elif [ "$WON" -gt 0 ]; then
  echo "VERDICT=PASS -- curl-impersonate completed $WON request(s) bare curl could not."
else
  echo "VERDICT=PASS-NO-BENEFIT -- the toolchain works (the control was served) and the"
  echo "  impersonating client bought NOTHING on these hosts. That is a legitimate, recorded"
  echo "  result: the pinned build impersonates Chrome 116, and the edge may be judging a"
  echo "  newer fingerprint. Do NOT read it as 'fingerprints do not matter'."
fi
} 2>&1 | tee "$LOG"

# The verdict line is the contract, and grepping the LOG rather than trusting a pipeline's exit
# code is deliberate: `$?` after a pipe is TEE's status, which is 0 whenever tee could write.
if grep -q "^VERDICT=FAIL" "$LOG"; then exit 1; fi
if grep -q "^VERDICT=NOT-RUN" "$LOG"; then exit 2; fi
exit 0
