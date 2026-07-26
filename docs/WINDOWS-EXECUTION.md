# Windows execution backend (WinRM driver)

HackPit can drive a real **Windows / Active Directory** box over the network. This is the
thing that makes the CRTP toolset, the OSCP AD set, PNPT, CPTS, HTB Pro Labs and real
internal pentests *executable*, and — the larger payoff — it makes the existing AD
attack-path graph + gated edge-orchestrator run **live** instead of on synthetic data.

Branch: `sandbox-kali-image`. Built the same way as Phases 1–5: hermetic safety suite green
(`sh backend/run_safety_tests.sh`), tested with Ollama, committed piece by piece.

## The model: HackPit is a DRIVER, not an owner (Model A)

HackPit does **not** own the VM lifecycle. The operator runs a Windows/AD VM in VMware
Workstation themselves (start / snapshot / revert stay in VMware — see
[`WINDOWS-TARGET-SETUP.md`](WINDOWS-TARGET-SETUP.md)). HackPit connects to it over the
network, runs one command on the box, and captures the output. Rubeus, PowerView, Mimikatz
and PowerShell/.NET all run **on the Windows host**; HackPit sends the command and reads the
result.

That is the whole safety argument: this is a **new execution transport**, not a new safety
model. `docker exec` is swapped for a WinRM call; the gates, the target-lock, the approval
model and the audit trail are the ones that already governed every other command.

## The third execution mode: `windows`

The cockpit already had two modes: `lab` (isolated, egress-less sandbox) and `engagement`
(real target, fully open, human-approve-each). WinRM adds a third, `windows`, selected by a
saved **connection profile**.

- `ExecRequest` gains `windows_profile_id`. When set, the run is `windows` mode.
- The **target is the profile's host — hardcoded by the profile, resolved server-side, never
  a field on the request.** A command therefore can never reach a box the operator did not
  pick. This is the exact containment shape `:kali` gets from its hardcoded container.
- Gates (`cockpit/executor.py::_validate_windows`), in order:
  1. **windows** — the named profile exists.
  2. **target** — the profile host is the lock. If an `engagement_id` is *also* named, that
     engagement's program scope must **additionally** permit the host (belt-and-suspenders;
     never widens anything).
  3. **approval** — NEVER-AUTO-RUN. Every command needs an individual human approval. The
     orchestrator may *propose* a WinRM command; it can never fire one.
  4. **danger** — the danger heuristic red-confirm, unchanged.
- There is **no isolation gate** — the target is a real external box, exactly like
  engagement mode. Approval is the real bound.

The executor re-checks approval even on the prevalidated path for `windows` mode, the same
belt-and-suspenders engagement mode gets — never-auto-run is the sole floor on a real box.

### What executes

One **PowerShell command string** runs on the box (`command` + `args` rejoined). This is the
natural fit for Rubeus/PowerView/Mimikatz pipelines and CRTP one-liners, rather than forcing
the Linux argv shape onto PowerShell. Credentials live in the profile, never in the command,
so nothing secret can leak into the command line, the run record or the transcript.

WinRM is request/response, so the run happens on a worker thread bounded by a wall-clock
timeout, and its captured stdout/stderr are emitted line-by-line — the same event shape the
docker path produces (`start → stdout/stderr → exit`), so the UI, the run store, the state
ingest and recon expansion all work unchanged.

## Connection profiles (the "Windows targets" store)

`cockpit/winprofiles.py` — CRUD over a `windows_profiles` table in the gitignored
`sessions.db` (the same store the credential vault + engagement records use):

| field | notes |
|-------|-------|
| `name` | human label for the picker |
| `host` | the Windows box's IP/hostname |
| `transport` | `winrm` (SSH is a documented later seam, not built) |
| `port` | 5985 (WinRM over HTTP) by default |
| `username` | local or domain account |
| `auth_kind` | `password` or `ntlm-hash` (pass-the-hash) |
| `secret` | password or NT hash — **never returned in the clear** |
| `domain` | optional AD domain |

Switching which VM the cockpit drives is "pick a different profile" — a different host +
creds — and nothing else changes.

**Secrets** are stored in the gitignored `sessions.db` and masked in every public view to
`has_secret: bool`, exactly like the credential vault. The raw secret is read only by the
WinRM transport (`winprofiles.get_secret`) and is never serialised into an API response, a
run record, or a command line. A **captured vault credential can fill a new profile**, so a
`secretsdump`'d hash becomes a connection in one step.

## The transport

`cockpit/winrm_transport.py` — `run(profile, command, timeout)`:

- **Lazy-imports `pywinrm`**, so the hermetic safety suite needs no third-party WinRM
  dependency and no network. Tests monkeypatch the transport (see `test_winrm.py`).
- Auth is **NTLM/Negotiate**, so a **local** Windows account authenticates over plain
  HTTP:5985 without enabling Basic auth. `password` uses the password verbatim; `ntlm-hash`
  presents the NT hash in `LM:NT` form (pass-the-hash) so the plaintext is never needed.
- `server_cert_validation="ignore"` (HTTP), operation/read timeouts derived from the run
  timeout.

`pip install pywinrm` is required only to drive a **live** box; see
`backend/requirements-winrm.txt`.

## AD graph / orchestrator, live

The AD attack-path graph and the gated edge-orchestrator now execute against a real Windows
target. Each abusable edge offers a **native Windows variant** (Rubeus / PowerView /
PowerShell) alongside the Linux one (impacket / evil-winrm run from Kali). The walk /
orchestrator's proposed command is sent to `POST /cockpit/exec`; when a Windows profile is
selected it runs over WinRM on the box. `advance` still requires an approved + exit-0 run
verified server-side — identical to the synthetic path, now real. The orchestrator
**proposes, never auto-fires** — regression-locked for the WinRM path in
`test_winrm_safety.py`, exactly like the Linux path in `test_adorch_safety.py`.

## Per-target tool reconciliation

Windows-only tools (Rubeus/PowerView/Mimikatz/winPEAS) were marked `runs_here=false` for the
**Linux** sandbox. When a **Windows** target is selected they *do* run, so tool availability
is reconciled **per active target** (served from `main.py` so the cockpit stays
arsenal-blind): a Linux run still sees them as N/A; a Windows run sees them as runnable and
the Linux-only tools as N/A.

## Safety invariants (regression-locked)

`test_winrm_safety.py`:

1. **Locked to the profile host** — no host field on the request; a run reaches only the
   profile's host, resolved server-side.
2. **No gate bypass** — unapproved / dangerous-without-ack / unknown-profile all refuse.
3. **Secrets never leak** — absent from public views, run records, events and command lines.
4. **The orchestrator cannot auto-run WinRM** — the transport is reachable only from the
   gated executor (+ the human-initiated router probe), scanned across the source tree.

`test_winrm.py` covers the functional path with a **mocked WinRM transport**, so the suite
stays hermetic.

## Deferred to a live VM

The backend is built and unit-tested hermetically. **Live/browser verification against a
real Windows box is deferred until the operator's VM is up** — the same way tunnels and
AD-live execution were deferred. Follow [`WINDOWS-TARGET-SETUP.md`](WINDOWS-TARGET-SETUP.md)
to stand up a VM, then the live pass can confirm a real WinRM round-trip.
