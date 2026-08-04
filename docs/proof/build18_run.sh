#!/bin/sh
# Build #18 — every real-target and live-daemon verification, in one place, in order.
#
# Everything here needs either a LIVE ZAP DAEMON or a real, in-scope bug-bounty target, which is
# why it lives in a script rather than in the agent's tool calls: the real-time classifier refuses
# live-fire from inside the session, and the recorded convention is to run it in a plain shell and
# document from the log.
#
# Run from the repo root:   sh docs/proof/build18_run.sh
#
# `RC=$?` AFTER A PIPE IS TEE'S STATUS, which is 0 whenever tee could write the file. That defect
# shipped into two wrappers in build #17 before it was caught. `run()` below stashes the real
# status through the pipe, and every stage below is gated on the CAPTURED code.
#
# NOTHING HERE RECREATES A CONTAINER. Recreating the engage sandbox destroys the ZAP daemon and
# its capture. If the image needs rebuilding for item 5, that is a separate, deliberate step and
# it goes LAST — see the note at the bottom.
#
# STAGE ORDER IS DELIBERATE, cheapest and most passive first:
#   2  fronting        passive lookups + one HEAD per host. Answers what the rest is FOR.
#   1  bypass header   needs a live daemon; touches a local page, not the program.
#   4  shaping         entirely local; stands up its own signature matcher and kills it.
#   3  scan policy     LAB attack traffic. Two scans, same endpoint.
#   6/7 auth scan      LAB only. Tier 3 is UNVERIFIED against a real target — no account exists.
#   5  impersonate     the only stage that reaches the real program, and only with GET /.
set -u
export MSYS_NO_PATHCONV=1

PY=backend/.venv/Scripts/python.exe
[ -x "$PY" ] || PY=backend/.venv/bin/python
[ -x "$PY" ] || { echo "FATAL: no backend venv python found"; exit 2; }

LAB_URL="${LAB_URL:-}"
ENGAGEMENT="${ENGAGEMENT:-}"

RCF="${TMPDIR:-/tmp}/build18.rc"
run() {  # run() <log> <cmd...> — live output, tee'd, with the COMMAND's exit code returned
  LOG="$1"; shift
  { "$@"; echo $? > "$RCF"; } 2>&1 | tee "$LOG"
  read -r RC < "$RCF" || RC=99
  return "$RC"
}

banner() {
  echo
  echo "############################################################"
  echo "# $1"
  echo "############################################################"
}

banner "ITEM 2 — is each in-scope host CDN-fronted? PASSIVE ONLY."
if [ -n "$ENGAGEMENT" ]; then
  run docs/proof/build18-fronting.log "$PY" docs/proof/build18_fronting.py \
      --engagement "$ENGAGEMENT" --json docs/proof/build18-fronting.json
else
  echo "(no ENGAGEMENT= set — sweeping only the two hosts the plan names by hand)"
  run docs/proof/build18-fronting.log "$PY" docs/proof/build18_fronting.py \
      --json docs/proof/build18-fronting.json
fi
ITEM2=$?; echo "ITEM2_EXIT=$ITEM2"

banner "ITEM 1 — the bypass header, on the OUTGOING request (dummy header)"
run docs/proof/build18-bypass.log "$PY" docs/proof/build18_bypass_header.py
ITEM1=$?; echo "ITEM1_EXIT=$ITEM1"

banner "ITEM 4 — payload shaping, shaped vs unshaped (entirely local)"
run docs/proof/build18-shaping.log "$PY" docs/proof/build18_shaping.py
ITEM4=$?; echo "ITEM4_EXIT=$ITEM4"

banner "ITEM 3 — scan policy: default vs targeted-web, SAME LAB ENDPOINT"
if [ -z "$LAB_URL" ]; then
  echo "SKIPPED — set LAB_URL to a lab URL already in ZAP's Sites tree, e.g."
  echo "  LAB_URL='http://hackpit-lab-target:3000/rest/products/search?q=a' sh docs/proof/build18_run.sh"
  echo "(ZAP answers url_not_found for a URL it has never seen — a containment property of the"
  echo " whole feature, not an error. Proxy a request to it first.)"
  ITEM3=3
else
  run docs/proof/build18-scan-policy.log "$PY" docs/proof/build18_scan_policy.py --url "$LAB_URL"
  ITEM3=$?
fi
echo "ITEM3_EXIT=$ITEM3"

banner "ITEMS 6 & 7 — authenticated scanning. LAB ONLY. Tier 3 UNVERIFIED on a real target."
if [ -z "$LAB_URL" ]; then
  echo "SKIPPED — set LAB_URL (see above)."
  ITEM67=3
else
  run docs/proof/build18-auth-scan.log "$PY" docs/proof/build18_auth_scan.py --url "$LAB_URL"
  ITEM67=$?
fi
echo "ITEM67_EXIT=$ITEM67"

banner "ITEM 5 — curl-impersonate vs bare curl. THE ONLY REAL-TARGET STAGE."
echo "It sends ONE GET / per host per client. Every probe carries its own control, because a"
echo "probe with no control turns a broken toolchain into a finding about the target."
sh docs/proof/build18_impersonate.sh
ITEM5=$?; echo "ITEM5_EXIT=$ITEM5"

echo
echo "============================================================"
echo "ITEM2(fronting)=$ITEM2   ITEM1(bypass)=$ITEM1   ITEM4(shaping)=$ITEM4"
echo "ITEM3(policy)=$ITEM3     ITEM6/7(auth)=$ITEM67  ITEM5(impersonate)=$ITEM5"
echo "  0 = pass   1 = FAIL   2 = NOT-RUN (a precondition was missing)   3 = skipped (no LAB_URL)"
echo
echo "logs:"
echo "  docs/proof/build18-fronting.log      (+ build18-fronting.json)"
echo "  docs/proof/build18-bypass.log"
echo "  docs/proof/build18-shaping.log"
echo "  docs/proof/build18-scan-policy.log"
echo "  docs/proof/build18-auth-scan.log"
echo "  docs/proof/build18-impersonate.log"
echo
echo "IF ITEM 5 REPORTED NOT-RUN: the image predates build #18's layer 9g. THE REBUILD GOES"
echo "LAST, ON ITS OWN, because recreating the engage sandbox destroys the ZAP daemon and its"
echo "capture — and DOCKER COMPOSE TAKES THE SERVICE NAME while everything else takes the"
echo "container name:"
echo "    docker compose -f docker/docker-compose.yml build engage-sandbox"
echo "    docker compose -f docker/docker-compose.yml up -d --force-recreate engage-sandbox"
echo "    sh docker/proof/browser_intercept_proof.sh    # must still be 25 passed, 0 failed"
echo "    sh docs/proof/build18_impersonate.sh"
echo "============================================================"

# The runner's own exit code: FAIL if any stage genuinely failed. NOT-RUN and skipped are not
# failures — a precondition that was not there is a fact about the environment, and reporting it
# as a failure is how a harness starts lying about what it measured.
for RC in "$ITEM2" "$ITEM1" "$ITEM4" "$ITEM3" "$ITEM67" "$ITEM5"; do
  [ "$RC" = "1" ] && exit 1
done
exit 0
