#!/usr/bin/env sh
# HackPit — BUILD #10 C2 PROOF 3/4: Sliver beacon callback through the tunnel (ticket 2616).
#
# WHAT THIS DEMONSTRATES. The implant on the REAL domain controller calls back to the Sliver
# server in the engage sandbox THROUGH the iodine DNS tunnel, and the session registers. This is
# the whole point of build #9's task-4 gap closed: a Windows-target C2 callback with a real path
# home. The Sliver server is started through HackPit's GATED lifecycle (cockpit/sliver.py), the
# iodine tunnel is raised exactly as in proof 2, the implant is run on the DC over GATED WinRM,
# and the callback is confirmed FROM THE SERVER'S OWN SESSION LIST — not from the implant's log.
#
# ONE HELD PROCESS, again. iodined and the Sliver server are both console-lifetime listeners, so
# the whole phase — both servers up, the DC's tunnel raised, the implant run, the session list
# watched — happens inside one `beacon-phase` driver call. Both are stopped in the driver's
# finally guard: the phase leaves no listener and no C2 server behind.
#
# WHAT IS WRITTEN vs PASTED. All plumbing/gating/observe/teardown is written here and in the
# driver. THREE offensive strings are [[PASTE]]s the operator fills: the iodine client invocation
# (same as proof 2), the Sliver implant GENERATION line (run by the operator's hand in the Sliver
# console — HackPit never generates offense for you), and the implant EXECUTION line on the DC.
#
# HONESTY. Standing up the operator's own Sliver LISTENER that the implant's C2 config points at
# is operator infrastructure done in the interactive console; where it cannot be completed
# non-interactively the beacon is reported NOTRUN, never faked into a PASS — the same boundary
# live_fire_proof.sh draws for the mTLS listener.
#
# GATING. Engagement-mode (scoped to the DC) + approve-each + three-limb server/listener refusal
# proofs + the red-confirm on the implant launch. Requires the opt-in exposure up. Nothing autonomous.
#
# Usage:  sh docker/proof/c2_03_sliver_beacon.sh [<windows-profile-id>]
set -u
. "$(dirname -- "$0")/c2_lib.sh"

TUN_ZONE="${HACKPIT_TUN_ZONE:-t.hackpit.lab}"
TUN_SECRET="${HACKPIT_TUN_SECRET:-build10-iodine-lab}"
TUN_NET="${HACKPIT_TUN_NET:-10.99.53.1/24}"

# ------------------------------------------------------------------------ [[PASTE POINTS]] --
IODINE_CLIENT_CMD=''
# [[PASTE: the SAME iodine client invocation as proof 2 — run on the DC, dialling 192.168.13.1
#          over UDP/53 for topdomain "'"$TUN_ZONE"'" with password "'"$TUN_SECRET"'", forcing the
#          DNS path (-r), launched DETACHED. The beacon needs this tunnel up to have a path home.]]


SLIVER_IMPLANT_GEN='
# [[PASTE: the Sliver implant GENERATION line, run in the sandbox Sliver console (the harness runs
#          it there on your behalf — the same operator-hand boundary as the mTLS listener setup).
#          It MUST build a WINDOWS implant (--os windows) whose C2 endpoint is reachable through
#          the tunnel — i.e. the server tun endpoint '"${TUN_NET%%/*}"' (or the beacon/DNS
#          transport you have configured to ride the tunnel) — and SAVE it to a path under a
#          sandbox dir the harness can copy off, e.g. --save /tmp/beacon.exe. Non-interactive form
#          (echo '"'"'generate ...'"'"' | sliver-client) works well here.]]
'

SLIVER_IMPLANT_RUN='
# [[PASTE: the command, run ON THE DC over WinRM, that launches the built implant. Assumes the
#          artifact from the generate step has been copied to the DC (e.g. into C:\hackpit\). It
#          MUST launch DETACHED (Start-Process ...\beacon.exe) so the gated WinRM call returns and
#          the harness can watch the server session list. Success = a session/beacon appears in
#          the Sliver server below.]]
'
# --------------------------------------------------------------------------------------------

c2_require_exposure   || exit 2
c2_resolve_profile "${1:-}" || exit 2

head2 "1. the DC answers over WinRM"
drive preflight "$C2_PROFILE" "$C2_SESSION"
DC=$(getval DC_HOST)
[ "$DC" ] || { c2_summary "beacon proof aborted (no DC)"; exit 1; }

head2 "2. enter engagement mode, scoped to the DC"
drive enter-engagement "$DC" "$DC"
EID=$(getval ENGAGEMENT_ID)
if [ -z "$EID" ]; then
  notrun "no engagement id — the gated C2 server + listener require an active engagement"
  c2_summary "beacon proof aborted"; exit 1
fi
echo "      engagement_id=$EID  target=$DC"

head2 "3. iodined + Sliver server (both gated) + DC tunnel + implant + callback — one held process"
CLIENT_FILE=$(paste_file  "iodine_client.ps1" "$IODINE_CLIENT_CMD")
GEN_FILE=$(paste_file     "implant_gen.sh"    "$SLIVER_IMPLANT_GEN")
RUN_FILE=$(paste_file     "implant_run.ps1"   "$SLIVER_IMPLANT_RUN")
drive beacon-phase "$C2_PROFILE" "$C2_SESSION" "$EID" "$TUN_ZONE" "$TUN_SECRET" "$TUN_NET" \
      "$CLIENT_FILE" "$GEN_FILE" "$RUN_FILE"

c2_summary "Sliver beacon-over-tunnel proof"
exit $?
