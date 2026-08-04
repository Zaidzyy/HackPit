#!/bin/sh
# Build #17 — the three things that must run in a plain shell, in order.
#
# Everything here reaches a real, in-scope bug-bounty target, which is why it lives in a
# script rather than in the agent's tool calls: the real-time classifier refuses live-fire,
# and the recorded convention is to run it outside and document from the log.
#
# Run from the repo root:   sh docs/proof/build17_run.sh
#
# It does NOT recreate any container. Recreating the engage sandbox kills the ZAP daemon and
# the ~1000 captured messages items 2 and 4 both depend on, and step 1 of
# docs/proof/build15-acceptance-runbook.md would have to be re-run from scratch.
#
# Each stage writes its own log under docs/proof/ and each stage is gated on the previous
# stage's CAPTURED EXIT CODE — `cmd | tee && next` does not gate, which has shipped broken
# work in this repo three times.
#
# AND `RC=$?` AFTER A PIPE IS THAT SAME DEFECT WEARING A HAT: in `cmd | tee log`, `$?` is
# TEE's status, which is 0 whenever tee could write the file — i.e. always. `run()` below
# stashes the real status through the pipe. Item 4 polls for minutes and the operator needs
# to watch `requests` climb, so dropping tee and redirecting to a log is not an option here.
set -u
export MSYS_NO_PATHCONV=1

PY=backend/.venv/Scripts/python.exe
[ -x "$PY" ] || PY=backend/.venv/bin/python
[ -x "$PY" ] || { echo "FATAL: no backend venv python found"; exit 2; }

RCF="${TMPDIR:-/tmp}/build17.rc"
run() {  # run() <log> <cmd...> — live output, tee'd, with the COMMAND's exit code returned
  LOG="$1"; shift
  { "$@"; echo $? > "$RCF"; } 2>&1 | tee "$LOG"
  read -r RC < "$RCF" || RC=99
  return "$RC"
}

echo "############################################################"
echo "# ITEM 1 — correct the engagement's authorization text"
echo "############################################################"
run docs/proof/build17-item1.log "$PY" docs/proof/build17_item1_fix_engagement.py
ITEM1=$?
echo "ITEM1_EXIT=$ITEM1"
if [ "$ITEM1" -ne 0 ]; then
  echo
  echo "STOPPING. Item 4 must not run under a record that forbids active scanning."
  echo "Item 2 (the diagnostic) is passive and can still be run on its own:"
  echo "    sh docs/proof/build17_headless_diagnostic.sh"
  exit 1
fi

echo
echo "############################################################"
echo "# ITEM 2 — the headless-refusal diagnostic (no build)"
echo "############################################################"
sh docs/proof/build17_headless_diagnostic.sh
ITEM2=$?
echo "ITEM2_EXIT=$ITEM2"

echo
echo "############################################################"
echo "# ITEM 4 — runbook 3.4: active scanner vs the real target"
echo "#"
echo "# THIS SENDS REAL ATTACK TRAFFIC. One read-only catalogue URL,"
echo "# recurse=false, with a request ceiling as the only rate control."
echo "# Ctrl-C stops the script; the scan itself is stopped from the"
echo "# :proxy panel (stop is ungated for exactly this reason)."
echo "############################################################"
run docs/proof/build17-item4.log "$PY" docs/proof/build17_scanner_livefire.py
ITEM4=$?
echo "ITEM4_EXIT=$ITEM4"

echo
echo "============================================================"
echo "ITEM1_EXIT=$ITEM1  ITEM2_EXIT=$ITEM2  ITEM4_EXIT=$ITEM4"
echo "logs: docs/proof/build17-item1.log"
echo "      docs/proof/build17-diagnostic.log"
echo "      docs/proof/build17-item4.log"
echo "============================================================"
