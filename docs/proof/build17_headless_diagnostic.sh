#!/bin/sh
# Build #17 item 2 -- run the headless-refusal diagnostic inside the engage sandbox.
#
# Run this from the repo root. It reads ZAP's API key from the RUNNING daemon's own cmdline
# (the key is random per start, so it can never be hardcoded), copies the diagnostic into the
# container and runs it, teeing everything to docs/proof/build17-diagnostic.log.
#
# It does NOT recreate the container. Recreating it kills the daemon and the ~1000 captured
# messages the rest of build #17 depends on; step 1 of build15-acceptance-runbook.md would
# then have to be re-run from scratch.
#
# MSYS_NO_PATHCONV: Git Bash on Windows rewrites anything that looks like a unix path into a
# Windows one before docker sees it, which silently turns /tmp/x.py into C:/.../x.py inside
# the container. Recorded trap from build #14.
set -u
export MSYS_NO_PATHCONV=1

C=hackpit-engage-sandbox
LOG=docs/proof/build17-diagnostic.log

if ! docker ps --format '{{.Names}}' | grep -qx "$C"; then
  echo "FATAL: $C is not running. The daemon and its capture history are gone;"
  echo "       re-run step 1 of docs/proof/build15-acceptance-runbook.md first."
  exit 2
fi

KEY=$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do
  tr "\0" "\n" < $p/cmdline 2>/dev/null | grep -m1 "^api.key=" && break
done' | head -1 | cut -d= -f2)

if [ -z "$KEY" ]; then
  echo "FATAL: could not read api.key from the running daemon's cmdline."
  exit 2
fi
echo "ZAP api.key read from the live daemon (len=${#KEY})"

docker cp docs/proof/build17_headless_diagnostic.py "$C:/tmp/build17_diag.py" || exit 2

# `RC=$?` after a pipe is TEE's status, not the diagnostic's — tee succeeds whenever it can
# write the file, so the gate would always read 0. Stash the real one through the pipe.
RCF="${TMPDIR:-/tmp}/build17.diag.rc"
{ docker exec -e ZAP_KEY="$KEY" "$C" python3 /tmp/build17_diag.py; echo $? > "$RCF"; } \
  2>&1 | tee "$LOG"
read -r RC < "$RCF" || RC=99
echo "EXIT=$RC" | tee -a "$LOG"
echo
echo "log written to $LOG"
exit $RC
