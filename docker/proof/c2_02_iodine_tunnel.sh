#!/usr/bin/env sh
# HackPit — BUILD #10 C2 PROOF 2/4: iodine DNS tunnel, DC <-> engage sandbox (ticket 2615).
#
# WHAT THIS DEMONSTRATES. A working IP-over-DNS tunnel between the REAL domain controller and the
# engage sandbox, carried over the opt-in UDP/53 published to the VMnet8 host address — the exact
# path build #9's task 4 recorded as NOTRUN for lack of a landing spot. The iodined server is
# started through HackPit's GATED listener lifecycle (cockpit/obfuscation.py, kind=iodine), the
# DC's iodine client is launched over GATED WinRM, and the proof that traffic actually crossed is
# taken FROM THE SERVER'S OWN WIRE: a UDP/53 capture in the sandbox counting DNS queries encoded
# under the tunnel zone. Measured where the DC dialled, never asserted from the DC's own log.
#
# THE WHOLE LIVE PHASE IS ONE DRIVER PROCESS, on purpose. A console listener lives only as long
# as the process holding its stdin (cockpit/lifecycle.py); starting the server and completing the
# tunnel against it in one `iodine-phase` call is what keeps the assertions measured while the
# listener is genuinely alive. The listener is stopped in the driver's finally guard, so the
# phase leaves udp/53 released and nothing bound.
#
# WHAT IS WRITTEN vs PASTED. All plumbing, gating, settle/observe and teardown is written here and
# in c2_winrm_driver.py. The one offensive/operational string — the iodine client invocation on
# the DC — is the [[PASTE]] below, handed to the driver by file path.
#
# GATING. Engagement-mode (scoped to the DC) + approve-each + the three-limb listener refusal
# proof. Requires the opt-in exposure up (via c2_lab_proof.sh). Nothing autonomous.
#
# Usage:  sh docker/proof/c2_02_iodine_tunnel.sh [<windows-profile-id>]
set -u
. "$(dirname -- "$0")/c2_lib.sh"

# Tunnel parameters — authored, not offensive: a lab topdomain (NOT a real delegated zone), a lab
# tunnel password, and the server's tun endpoint. Keep the zone in step with the client paste.
TUN_ZONE="${HACKPIT_TUN_ZONE:-t.hackpit.lab}"
TUN_SECRET="${HACKPIT_TUN_SECRET:-build10-iodine-lab}"
TUN_NET="${HACKPIT_TUN_NET:-10.99.53.1/24}"

# ------------------------------------------------------------------------- [[PASTE POINT]] --
IODINE_CLIENT_CMD='
# [[PASTE: the iodine client invocation, run ON THE DC, that connects it to the tunnel server.
#          It MUST:
#            * dial the published listener at 192.168.13.1 over UDP/53 (the VMnet8 host address —
#              the DC has no route to the sandbox bridge, only to this),
#            * use topdomain "'"$TUN_ZONE"'" and password "'"$TUN_SECRET"'",
#            * force the DNS-encapsulated path (iodine -r) so it cannot silently fall back to raw
#              UDP and report a "tunnel" that never touched DNS,
#            * and launch DETACHED (e.g. Start-Process C:\hackpit\iodine\iodine.exe -ArgumentList
#              ...), so the gated WinRM call returns and the harness can watch the server side.
#          Success = the sandbox capture below sees DNS queries under "'"$TUN_ZONE"'" on UDP/53.]]
'
# --------------------------------------------------------------------------------------------

c2_require_exposure   || exit 2
c2_resolve_profile "${1:-}" || exit 2

head2 "1. the DC answers over WinRM"
drive preflight "$C2_PROFILE" "$C2_SESSION"
DC=$(getval DC_HOST)
[ "$DC" ] || { c2_summary "tunnel proof aborted (no DC)"; exit 1; }

head2 "2. enter engagement mode, scoped to the DC"
drive enter-engagement "$DC" "$DC"
EID=$(getval ENGAGEMENT_ID)
if [ -z "$EID" ]; then
  notrun "no engagement id — the gated listener requires an active engagement"
  c2_summary "tunnel proof aborted"; exit 1
fi
echo "      engagement_id=$EID  target=$DC"

head2 "3. iodined server (gated) + the DC's tunnel + traffic on the wire — one held process"
CLIENT_FILE=$(paste_file "iodine_client.ps1" "$IODINE_CLIENT_CMD")
drive iodine-phase "$C2_PROFILE" "$C2_SESSION" "$EID" "$TUN_ZONE" "$TUN_SECRET" "$TUN_NET" "$CLIENT_FILE"

head2 "4. delegated-zone hop (stated, not faked)"
notrun "the public-delegation hop is NOT demonstrated — the DC's client points straight at the \
published listener IP, so its queries do not walk a real DNS hierarchy through a delegated NS \
record. That hop needs a domain the operator controls with an NS record pointed at the listener \
(operator infrastructure). The IP-over-DNS channel itself IS demonstrated carrying traffic above, \
confirmed DNS-encapsulated on the sandbox's wire; what is missing is only the delegation in front."

c2_summary "iodine DNS tunnel proof"
exit $?
