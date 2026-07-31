#!/usr/bin/env sh
# HackPit — BUILD #10 C2 PROOF 1/4: DC prerequisite + staging (ticket 2614).
#
# WHAT THIS DEMONSTRATES. Before the DC can be the client end of an iodine DNS tunnel it needs
# two things it does not have on a bare Server 2022 promotion: the iodine client binary, and a
# TAP-Windows virtual adapter for iodine's IP-over-DNS interface to sit on. This script stages
# both onto the DC over WinRM, IDEMPOTENTLY (a second run is a no-op and still PASSes), and
# VERIFIES each step against the box itself — never assuming a copy worked.
#
# EVERYTHING GOES THROUGH THE GATE. Every touch of the DC — even a Test-Path — is a gated WinRM
# command through the shipped executor (cockpit/executor.py). The staging actions themselves
# carry the explicit red-confirm, because dropping tooling onto a domain controller is exactly
# the kind of action a human should have to acknowledge. The driver proves the approval refusal
# before each run, and the danger refusal before each acknowledged run when the classifier flags
# it — a proof, not a happy path.
#
# WHAT IS AND IS NOT WRITTEN HERE. The harness — the gating, the idempotency logic, the
# verification, the PASS/FAIL accounting — is written out in full. The two commands that actually
# put bytes on the DC are left as [[PASTE]] variables for the operator to fill: the exact
# mechanism for materialising iodine.exe, and the exact TAP-driver install. They are handed to
# the driver by file path, so the offensive/operational strings live only in the operator's own
# paste, never in this harness.
#
# GATING. Engagement-mode + approve-each + red-confirm, unchanged. Reachable only once the opt-in
# UDP/53 exposure is up (docker/proof/c2-lab.yml, via c2_lab_proof.sh). Nothing autonomous.
#
# Usage:  sh docker/proof/c2_01_dc_prereq_stage.sh [<windows-profile-id>]
#         (or set HACKPIT_WIN_PROFILE=<id>)
set -u
. "$(dirname -- "$0")/c2_lib.sh"

# The DC-side staging paths. Authored (not offensive): where the client tooling lives on the DC.
STAGE_DIR='C:\hackpit\iodine'
IODINE_EXE='C:\hackpit\iodine\iodine.exe'

# ------------------------------------------------------------------------ [[PASTE POINTS]] --
# Leave these EMPTY to see the harness report each as NOT-RUN with instructions. Fill the real
# command in (the comment lines are ignored by the driver, so a placeholder never runs).

IODINE_STAGE_CMD='
# [[PASTE: the exact command that materialises the iodine client binary on the DC at
#          C:\hackpit\iodine\iodine.exe. MUST be idempotent (a no-op if already present and
#          non-empty). Success = the file exists with length > 0. Shape only (you fill the real
#          source): copy from an operator-controlled SMB/HTTP share on the lab subnet, or expand
#          an archive already staged on the DC. Do NOT pull from the public internet.]]
'

TAP_INSTALL_CMD='
# [[PASTE: the exact command that installs the TAP-Windows virtual adapter driver on the DC
#          (the interface iodine brings up its IP-over-DNS tunnel on). MUST be idempotent (a
#          no-op if a TAP-Windows adapter already exists). Success = Get-NetAdapter shows an
#          adapter whose InterfaceDescription matches *TAP-Windows*. Shape only: run the bundled
#          tapinstall/OpenVPN devcon .inf from the staging dir, or pnputil /add-driver …/install.]]
'
# --------------------------------------------------------------------------------------------

# Run one authored, benign PowerShell probe on the DC and return its exit via getval <KEY>_EXIT.
probe() {  # <label> <ps>
  _f=$(paste_file "$1.ps1" "$2")
  drive winrm-probe "$C2_PROFILE" "$C2_SESSION" "$1" "$_f"
}
# Run one operator PASTE on the DC with the explicit red-confirm supplied.
stage() {  # <label> <paste-content>
  _f=$(paste_file "$1.ps1" "$2")
  drive winrm-run "$C2_PROFILE" "$C2_SESSION" 1 "$1" "$_f"
}

c2_require_exposure   || exit 2
c2_resolve_profile "${1:-}" || exit 2

head2 "1. the DC answers over WinRM (and its secret stays masked)"
drive preflight "$C2_PROFILE" "$C2_SESSION"
[ "$(getval DC_HOST)" ] || { c2_summary "staging aborted (no DC)"; exit 1; }

head2 "2. staging directory on the DC (idempotent)"
probe "stagedir" "New-Item -ItemType Directory -Force '$STAGE_DIR' | Out-Null; if (Test-Path '$STAGE_DIR') { exit 0 } else { exit 1 }"
if [ "$(getval STAGEDIR_EXIT)" = "0" ]; then
  pass "staging dir $STAGE_DIR present on the DC"
else
  notrun "could not create the staging dir $STAGE_DIR on the DC"
fi

head2 "3. iodine client binary staged on the DC (idempotent)"
probe "binbefore" "if ((Test-Path '$IODINE_EXE') -and ((Get-Item '$IODINE_EXE').Length -gt 0)) { exit 0 } else { exit 1 }"
if [ "$(getval BINBEFORE_EXIT)" = "0" ]; then
  pass "iodine.exe already staged (length > 0) — staging step is idempotent, skipped"
else
  stage "stage_iodine_bin" "$IODINE_STAGE_CMD"
  probe "binafter" "if ((Test-Path '$IODINE_EXE') -and ((Get-Item '$IODINE_EXE').Length -gt 0)) { exit 0 } else { exit 1 }"
  if [ "$(getval BINAFTER_EXIT)" = "0" ]; then
    pass "iodine.exe staged and verified on the DC (exists, length > 0)"
  else
    notrun "iodine.exe not present after the staging step — fill the [[PASTE]] IODINE_STAGE_CMD"
  fi
fi

head2 "4. TAP-Windows adapter installed on the DC (idempotent)"
TAP_CHECK="if (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { \$_.InterfaceDescription -like '*TAP-Windows*' }) { exit 0 } else { exit 1 }"
probe "tapbefore" "$TAP_CHECK"
if [ "$(getval TAPBEFORE_EXIT)" = "0" ]; then
  pass "a TAP-Windows adapter is already present — install step is idempotent, skipped"
else
  stage "stage_tap_driver" "$TAP_INSTALL_CMD"
  probe "tapafter" "$TAP_CHECK"
  if [ "$(getval TAPAFTER_EXIT)" = "0" ]; then
    pass "TAP-Windows adapter installed and verified on the DC (Get-NetAdapter matches)"
  else
    notrun "no TAP-Windows adapter after the install step — fill the [[PASTE]] TAP_INSTALL_CMD"
  fi
fi

head2 "5. prerequisite summary — is the DC ready to be the tunnel client?"
if [ "$(getval BINAFTER_EXIT)" = "0" ] || [ "$(getval BINBEFORE_EXIT)" = "0" ]; then BIN_OK=1; else BIN_OK=0; fi
if [ "$(getval TAPAFTER_EXIT)" = "0" ] || [ "$(getval TAPBEFORE_EXIT)" = "0" ]; then TAP_OK=1; else TAP_OK=0; fi
if [ "$BIN_OK" = "1" ] && [ "$TAP_OK" = "1" ]; then
  pass "DC prerequisites satisfied — proceed to c2_02_iodine_tunnel.sh"
else
  notrun "DC not yet ready (iodine.exe present=$BIN_OK, TAP adapter present=$TAP_OK) — fill the pastes and re-run"
fi

c2_summary "staging proof"
exit $?
