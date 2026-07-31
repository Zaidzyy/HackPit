# Build #10 — the Windows/AD C2 path, live-fire proofs

Build #9 drove HackPit's Windows/AD path against a real domain (corp.local, DC at
`192.168.13.140`) and closed four defects, but recorded its C2 tasks as **NOT-RUN**: the DC
sits on VMware's NAT subnet and had no route to a Docker bridge, so a beacon from it had
nowhere to land. Build #10 closes that gap. It publishes exactly the listener the DC needs on
exactly the interface the DC can see — UDP/53 bound to the VMnet8 host address `192.168.13.1`
(`docker/proof/c2-lab.yml`, guarded by `backend/test_exposure_safety.py`) — and finishes the
Windows/AD C2 path against it with four self-verifying proof scripts.

These scripts are the Windows/AD equivalent of `live_fire_proof.sh`: same honesty rule
(**PASS** ran and held, **FAIL** ran and did not hold, **NOT-RUN** could not run and is never
counted as a pass), same "prove the refusal first" discipline on every gate, same teardown
that leaves no listener bound.

## Safety posture (unchanged from build #9)

- **Nothing runs by default.** The whole surface is reachable only with the explicit opt-in
  `-f docker/proof/c2-lab.yml`, composed in exactly one reviewable place
  (`docker/proof/c2_lab_proof.sh`). The four proof scripts never compose it themselves — they
  require it already up. `test_exposure_safety.py` invariant 2 enforces that.
- **Every action stays behind the existing gates.** WinRM commands to the DC go through the
  shipped gated executor (`cockpit/executor.py`) — windows-profile host-lock + approve-each +
  the danger red-confirm; the destructive DCSync additionally carries the engagement scope-lock.
  Sandbox-side listeners (iodined, the Sliver server) go through the gated lifecycle
  (`cockpit/obfuscation.py`, `cockpit/sliver.py`) with all three refusal limbs proved first.
- **No new autonomous or hands-off path.** Approve-each is unchanged; the proposer never
  executes; a human fills every `[[PASTE]]` and approves every command.
- **Credential hygiene.** The WinRM credential is swept out of the persisted record (whole and
  in fragments — build #9's `secretargs.redact_argv`, reused, not reinvented). DCSync output is
  summarised as counts; the raw dumped hashes are never echoed into the committed transcript.

## The files

| File | Role |
|------|------|
| `docker/proof/c2-lab.yml` | The opt-in UDP/53 publish (build #9→#10 pre-work; unchanged here). |
| `docker/proof/c2_lab_proof.sh` | **The one place the exposure is composed up/down.** Also orchestrates the four proofs in order. |
| `docker/proof/c2_winrm_driver.py` | Shared gated driver — drives the real cockpit paths (WinRM exec, iodined, Sliver server) and emits `RESULT`/`VALUE` lines. |
| `docker/proof/c2_lib.sh` | Shared shell plumbing (tally, `drive`, preflight, paste-file handling). |
| `docker/proof/c2_01_dc_prereq_stage.sh` | **Proof 1 (2614)** — stage the iodine client + TAP driver onto the DC, idempotently. |
| `docker/proof/c2_02_iodine_tunnel.sh` | **Proof 2 (2615)** — iodine DNS tunnel, DC ↔ engage sandbox over the published UDP/53. |
| `docker/proof/c2_03_sliver_beacon.sh` | **Proof 3 (2616)** — Sliver beacon from the DC through the iodine tunnel; the session registers. |
| `docker/proof/c2_04_dcsync_defender_excl.sh` | **Proof 4 (2617)** — native DCSync via a scoped Defender exclusion, removed in a finally guard. |

## What each proof demonstrates

**Proof 1 — DC prerequisite + staging.** A bare Server 2022 promotion has neither the iodine
client binary nor a TAP-Windows adapter for iodine's tunnel interface. This stages both over
gated WinRM, **idempotently** (a second run is a no-op and still PASSes), and verifies each step
against the box itself. Every DC touch — even a `Test-Path` — goes through the approval gate.

**Proof 2 — iodine DNS tunnel.** Starts the gated iodined server in the sandbox, launches the
DC's iodine client over gated WinRM, and proves traffic crossed **from the server's own wire**:
a UDP/53 capture in the sandbox counting DNS queries encoded under the tunnel zone. The whole
live phase is one driver process (a console listener lives only as long as the process holding
its stdin), and the listener is stopped in a finally guard. The public-delegation hop is
reported NOT-RUN — it needs a delegated zone (operator infrastructure).

**Proof 3 — Sliver beacon callback.** iodined and the Sliver server are both held in one
process; the DC's tunnel is raised; the implant is generated (operator's own paste, in the
Sliver console) and run on the DC over gated WinRM; and the callback is confirmed **from the
Sliver server's own session list**. Both servers are torn down in the finally guard.

**Proof 4 — native DCSync via a scoped Defender exclusion.** Runs a domain-wide credential
replication on the DC over gated WinRM, made to run past Defender by a **scoped path exclusion**
(`Add-MpPreference -ExclusionPath`) rather than a real-time-protection toggle — the narrower,
reversible change. The exclusion is removed by a **trap on EXIT/INT/TERM**, guarded by a flag so
it runs exactly once and can never be left in place, even if the run dies mid-way. The danger
gate is proved to refuse first; the WinRM credential is swept out of the record; the dumped
hashes are summarised as counts only.

## The `[[PASTE]]` points Zaid must fill

The harness — gating, idempotency, settle/observe, teardown, PASS/FAIL accounting — is written
in full. The **offensive command strings are left blank** as clearly-labelled `[[PASTE]]`
variables in each script. With them empty, every script still runs end to end and reports each
unfilled step as NOT-RUN (never a pass); the driver refuses to run an empty/placeholder string.
Fill each variable **in-place** (single-quoted; avoid apostrophes — they close the shell string):

| Script | Variable | The command must… | Success signal |
|--------|----------|--------------------|----------------|
| `c2_01_dc_prereq_stage.sh` | `IODINE_STAGE_CMD` | Materialise `iodine.exe` at `C:\hackpit\iodine\iodine.exe` on the DC, idempotently, from an operator-controlled lab share (not the public internet). | `Test-Path` + length > 0 (verified by the harness). |
| `c2_01_dc_prereq_stage.sh` | `TAP_INSTALL_CMD` | Install the TAP-Windows adapter driver on the DC, idempotently (bundled `tapinstall`/`devcon` `.inf` or `pnputil`). | `Get-NetAdapter` shows a `*TAP-Windows*` adapter. |
| `c2_02_iodine_tunnel.sh` | `IODINE_CLIENT_CMD` | Run the iodine client on the DC → dial `192.168.13.1:53/udp`, topdomain + password as set, `-r` to force the DNS path, **launched detached**. | Sandbox capture sees DNS queries under the tunnel zone on UDP/53. |
| `c2_03_sliver_beacon.sh` | `IODINE_CLIENT_CMD` | Same iodine client invocation as proof 2 (the beacon needs the tunnel up). | Tunnel traffic on the wire (as proof 2). |
| `c2_03_sliver_beacon.sh` | `SLIVER_IMPLANT_GEN` | Sliver console `generate` line building a **Windows** implant whose C2 rides the tunnel (server tun endpoint), saved to a sandbox path the harness can copy off. | `generate` line exits 0; artifact written. |
| `c2_03_sliver_beacon.sh` | `SLIVER_IMPLANT_RUN` | Launch the copied implant **detached** on the DC over WinRM. | A session/beacon appears in the Sliver server. |
| `c2_04_dcsync_defender_excl.sh` | `DCSYNC_CMD` | mimikatz/DCSync one-liner on the DC, loading its tooling from the excluded `C:\hackpit\tools`, dumping credential material to stdout. | Credential-shaped lines returned, exit 0 (counts only in the transcript). |

Two authored paths you may want to align with your staging layout (not offensive, safe to edit):
`STAGE_DIR`/`IODINE_EXE` in proof 1, and `TOOL_PATH` in proof 4 (the directory the Defender
exclusion is scoped to — the DCSync tool must live here).

## Running

```sh
# 1. Bring the opt-in exposure up (the one reviewable place it is composed):
sh docker/proof/c2_lab_proof.sh --up

# 2. Fill the [[PASTE]] variables above, then run a proof (needs a saved Windows profile id,
#    or set HACKPIT_WIN_PROFILE):
sh docker/proof/c2_01_dc_prereq_stage.sh <windows-profile-id>
sh docker/proof/c2_02_iodine_tunnel.sh   <windows-profile-id>
sh docker/proof/c2_03_sliver_beacon.sh   <windows-profile-id>
sh docker/proof/c2_04_dcsync_defender_excl.sh <windows-profile-id>

# …or all four in order, with bring-up + teardown handled for you:
sh docker/proof/c2_lab_proof.sh            # add --keep to leave the exposure up

# 3. Tear the exposure back down:
sh docker/proof/c2_lab_proof.sh --down
```

The hermetic safety suite stays green with all of this in the tree
(`sh backend/run_safety_tests.sh` — verified, exit 0). These scripts are run **by hand** against
the operator's own lab; they are not part of the hermetic suite (no Docker, no VM, no pywinrm
required to run the suite).
