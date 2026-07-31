"""Build #10 C2 driver — the Windows/AD C2 path driven through the REAL gated code.

Build #9's live-fire task 4 recorded a NOTRUN: the lab domain controller
(192.168.13.140, on VMware's NAT subnet) had no route to a Docker bridge, so a beacon
from the DC had nowhere to land. Build #10 publishes exactly the listener the DC needs
on exactly the host interface it can see (docker/proof/c2-lab.yml — UDP/53 bound to the
VMnet8 host address 192.168.13.1) and finishes the Windows/AD C2 path against it.

This driver is to the four C2 proof scripts what live_fire_driver.py is to
live_fire_proof.sh: every action goes through the SAME function the HTTP router calls, so
what the proofs demonstrate is the shipped, gated path and not a re-implementation of it.

    executor.validate_request / executor.iter_run   (cockpit/executor.py) — WinRM to the DC
    obfuscation.start_listener / stop_listener       (cockpit/obfuscation.py) — the iodined server
    sliver.start_server / stop_server                (cockpit/sliver.py) — the C2 server
    engagement.enter                                 (cockpit/engagement.py) — the scoped engagement

TWO DISCIPLINES CARRIED OVER FROM live_fire_driver.py, because they are the difference
between a proof and a happy-path demo:

  * EVERY GATED ACTION PROVES THE REFUSAL FIRST. Before an approved command runs, the same
    request is fired with the acknowledgement missing and the gate is asserted to REFUSE with
    nothing spawned. A proof that only shows the allowed path cannot tell a working gate from
    an absent one.

  * A HELD LISTENER LIVES FOR ONE PROCESS. A console listener's lifetime is tied to the
    python process holding its stdin open (cockpit/lifecycle.py). So a whole live phase —
    start the iodined server, bring the DC's tunnel up against it, observe traffic — happens
    inside ONE driver invocation; splitting it across processes would kill the listener the
    instant the first process exited and then "measure" a listener that was already gone.

WHERE THE OFFENSIVE COMMANDS COME FROM. This file authors NONE of the offensive command
strings (the iodine client invocation, the Sliver implant line, the DCSync one-liner). Each
proof script holds those as a shell variable the operator fills in, writes them to a scratch
file, and passes the FILE PATH here. This driver reads the text and runs it through the gate.
That keeps the offensive strings in exactly one place — the operator's own paste — and keeps
this harness to the plumbing, the gating, and the honest PASS/FAIL/NOTRUN accounting.

Output is one machine-readable line per assertion, parsed by the shell (same protocol as
live_fire_driver.py):
    RESULT <name> PASS|FAIL|NOTRUN <detail>
    VALUE  <key> <text>
"""
from __future__ import annotations

import subprocess
import sys
import time
import traceback
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND))

from cockpit import (  # noqa: E402
    config,
    engagement,
    executor,
    obfuscation,
    runstore,
    sliver,
    winprofiles,
)
from cockpit.models import ExecRequest  # noqa: E402

ENGAGE = config.ENGAGE_SANDBOX_CONTAINER


# --- the RESULT/VALUE protocol the shell parses ----------------------------------------- #


def result(name: str, status: str, detail: str = "") -> None:
    print(f"RESULT {name} {status} {detail}".rstrip(), flush=True)


def value(key: str, text: str) -> None:
    print(f"VALUE {key} {text}", flush=True)


def note(text: str) -> None:
    """A plain line — echoed by the shell as transcript detail, never tallied."""
    print(text, flush=True)


def _sh(*argv: str, timeout: float = 30.0) -> "subprocess.CompletedProcess[str]":
    """A docker command for the HARNESS ITSELF (observing the sandbox side). NOT a HackPit
    execution path — the equivalent of live_fire_driver.py's `_sh`, used only to look at
    what the gated code produced (packet captures, session lists), never to run offense."""
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", "timeout")


# --- credential leak sweep (reuses build #9's redaction, does not reinvent it) ----------- #
#
# The redaction itself is cockpit/secretargs.redact_argv, applied by the executor at the
# record boundary (executor.py) on EVERY persisted run — this driver does not touch it. What
# this does is VERIFY the redaction held on a real destructive run, whole AND in fragments:
# build #9 found that a `secret not in record` check alone passed while a fragment of the
# password sat in the stored args (the password contained '@' and an earlier redactor split
# on it). Fragments of 4+ chars only — shorter ones collide with ordinary text by chance.


def _leak_sweep(secret: str, run_id: str, label: str) -> None:
    if not run_id:
        result(f"{label}.secret_redacted", "NOTRUN", "no run_id to read the persisted record from")
        return
    rec = runstore.get_run(run_id)
    if rec is None:
        result(f"{label}.secret_redacted", "NOTRUN", f"run {run_id} not found in the store")
        return
    stored = _json(rec)
    frags = {f for sep in ("@", ":", "/", "\\", " ") for f in secret.split(sep) if len(f) >= 4}
    leaked = sorted(f for f in frags if f in stored)
    ok = bool(secret) and secret not in stored and not leaked
    result(f"{label}.secret_redacted", "PASS" if ok else "FAIL",
           "the WinRM credential is absent from the persisted record — whole and in fragments"
           if ok else f"CREDENTIAL LEAKED into run {run_id}: "
           + ("whole secret present" if secret and secret in stored else f"fragments {leaked}"))


def _json(obj) -> str:
    import json  # noqa: PLC0415
    try:
        return json.dumps(obj, default=lambda o: getattr(o, "__dict__", str(o)))
    except (TypeError, ValueError):
        return str(obj)


# --- the gated WinRM round-trip to the DC ----------------------------------------------- #


def _winrm_gated(profile_id: str, session_id: str, ack: bool, ps_text: str, label: str,
                 timeout_seconds: int = 180) -> tuple[int | None, str, str]:
    """Run ONE PowerShell string on the DC over WinRM, THROUGH the gate, proving the refusal
    first. Returns (exit_code, stdout, run_id). exit_code is None if nothing ran.

    ps_text is the whole script; it is passed as the command with no args, so the WHOLE script
    is what the danger classifier reads (build #5's Critical 2 — argv[0] is never the whole
    truth of a PowerShell one-liner)."""

    def req(**kw) -> ExecRequest:
        base = dict(command=ps_text, args=[], windows_profile_id=profile_id,
                    session_id=session_id or None, approved=True, dangerous_ack=ack,
                    timeout_seconds=timeout_seconds)
        base.update(kw)
        return ExecRequest(**base)

    # REFUSAL 1 — the approval gate. Unapproved, the executor must refuse with nothing run.
    rej = executor.validate_request(req(approved=False))
    result(f"{label}.refuse_unapproved", "PASS" if rej and rej.gate == "approval" else "FAIL",
           f"gate={getattr(rej, 'gate', None)!r} (unapproved WinRM command must be refused)")

    # REFUSAL 2 — the danger gate, but ONLY when this call carries the red-confirm, i.e. the
    # caller already knows the command is dangerous. If the classifier does not flag it, that
    # is reported honestly rather than asserted — a benign staging command is not dangerous and
    # forcing a danger refusal on it would be testing a fiction.
    if ack:
        rej = executor.validate_request(req(dangerous_ack=False))
        if rej and rej.gate == "danger":
            result(f"{label}.refuse_no_ack", "PASS",
                   "the command is danger-classified and refused without the explicit red-confirm")
        else:
            result(f"{label}.refuse_no_ack", "NOTRUN",
                   f"the pasted command was not danger-classified (gate={getattr(rej, 'gate', None)!r}); "
                   "the red-confirm is supplied below but no danger gate fired to refuse it first")

    # …then the approved run.
    events = list(executor.iter_run(req()))
    kinds = [e.get("type") for e in events]
    if "rejected" in kinds:
        rj = next(e for e in events if e["type"] == "rejected")
        result(f"{label}.ran", "FAIL",
               f"the approved run was REJECTED at gate={rj.get('gate')}: {rj.get('reason')}")
        return None, "", ""
    start = next((e for e in events if e.get("type") == "start"), {})
    exit_ev = next((e for e in events if e.get("type") == "exit"), {})
    run_id = start.get("run_id", "")
    stdout = "\n".join(e.get("line", "") for e in events if e.get("type") == "stdout")
    code = exit_ev.get("code")
    # Confirm the run landed on the profile host over winrm — the host is resolved server-side
    # from the profile id, never a request field, so a run can only reach the box you picked.
    locked = (start.get("mode") == "windows" and start.get("transport") == "winrm")
    result(f"{label}.host_locked", "PASS" if locked else "FAIL",
           f"mode={start.get('mode')!r} transport={start.get('transport')!r} "
           f"target={start.get('target')!r} (locked to the profile host, not a request field)")
    for line in stdout.splitlines():
        note(f"  DC> {line}")
    return code, stdout, run_id


# --- sandbox-side gated listeners (reused across the tunnel and beacon phases) ----------- #


def _assert_alive(label: str, registry: dict, rid: str, claimed: str) -> bool:
    """The spawned server process must still EXIST a moment after we were told it is up — the
    same independent liveness check live_fire_driver.py makes, because a status that trusts the
    value it is verifying is not a check. poll() is None for a running child."""
    time.sleep(4)
    live = registry.get(rid)
    proc = getattr(live, "proc", None) if live else None
    if proc is None:
        result(f"{label}.process_alive", "NOTRUN", "no process handle on the registry entry")
        return False
    code = proc.poll()
    if code is None:
        result(f"{label}.process_alive", "PASS",
               f"server process still running 4s after status={claimed!r} — observed, not assigned")
        return True
    result(f"{label}.process_alive", "FAIL",
           f"status={claimed!r} but the process ALREADY EXITED (code={code})")
    return False


def _refuses_listener(name: str, call, expect_gate: str) -> None:
    try:
        call()
    except obfuscation.ObfuscationRefused as exc:
        gate = getattr(exc, "gate", None)
        result(name, "PASS" if gate == expect_gate else "FAIL",
               f"refused at gate={gate}" + ("" if gate == expect_gate else f", expected {expect_gate}"))
        return
    except Exception as exc:  # noqa: BLE001
        result(name, "FAIL", f"unexpected error instead of a refusal: {exc!r}")
        return
    result(name, "FAIL", "THE GATE DID NOT FIRE — the listener started without the confirm")


def _refuses_server(name: str, call, expect_gate: str) -> None:
    try:
        call()
    except sliver.SliverRefused as exc:
        gate = getattr(exc, "gate", None)
        result(name, "PASS" if gate == expect_gate else "FAIL",
               f"refused at gate={gate}" + ("" if gate == expect_gate else f", expected {expect_gate}"))
        return
    except Exception as exc:  # noqa: BLE001
        result(name, "FAIL", f"unexpected error instead of a refusal: {exc!r}")
        return
    result(name, "FAIL", "THE GATE DID NOT FIRE — the server started without the confirm")


def _start_iodined(eid: str, zone: str, secret: str, tunnel_net: str):
    """Start the gated iodined server inside the engage sandbox, all three refusal limbs first.
    Returns the live listener model, or None. The DC is the CLIENT — no lab client is started
    here; the tunnel is completed over WinRM against the real box."""

    def req(**kw) -> obfuscation.ObfuscationRequest:
        base = dict(kind="iodine", zone=zone, secret=secret, tunnel_net=tunnel_net,
                    engagement_id=eid, approved=True, dangerous_ack=True)
        base.update(kw)
        return obfuscation.ObfuscationRequest(**base)

    _refuses_listener("iodine.gate.no_engagement",
                      lambda: obfuscation.start_listener(req(engagement_id=None)), "engagement")
    _refuses_listener("iodine.gate.unapproved",
                      lambda: obfuscation.start_listener(req(approved=False)), "approval")
    _refuses_listener("iodine.gate.no_red_confirm",
                      lambda: obfuscation.start_listener(req(dangerous_ack=False)), "danger")

    lis = obfuscation.start_listener(req())
    _assert_alive("iodine", obfuscation._listeners, lis.id, lis.status)
    value("IODINE_LISTENER_ID", lis.id)
    value("IODINE_CONTAINER", lis.container)
    value("IODINE_SERVER_TUN", tunnel_net.split("/")[0])
    result("iodine.start_listener", "PASS" if lis.status == "listening" else "NOTRUN",
           f"id={lis.id} zone={lis.zone} status={lis.status} — udp/53 held in {lis.container}")
    return lis if lis.status == "listening" else None


def _observe_dns_traffic(container: str, zone: str, seconds: int = 8) -> bool:
    """The server-side proof the tunnel carries traffic END TO END: capture UDP/53 in the
    sandbox for a window and count DNS queries encoded under the tunnel zone. This is measured
    FROM the server the DC dialled, never asserted from the DC's own log.

    `-l` (line-buffered) is load-bearing: tcpdump batches output, so a `timeout N tcpdump` to a
    file does not flush until it EXITS — an earlier build grepped the file mid-capture and saw
    zero packets on a tunnel that was demonstrably DNS-encapsulated."""
    _sh("docker", "exec", "-d", container, "sh", "-c",
        f"timeout {seconds} tcpdump -i any -n -l udp port 53 > /tmp/c2cap.txt 2>&1")
    time.sleep(seconds + 2)  # let the capture window close and tcpdump flush on exit
    cap = _sh("docker", "exec", container, "sh", "-c",
              f"grep -c '{zone}' /tmp/c2cap.txt 2>/dev/null").stdout.strip()
    n = int(cap) if cap.isdigit() else 0
    result("iodine.traffic_through_tunnel", "PASS" if n > 0 else "NOTRUN",
           f"{n} DNS-encoded queries under '{zone}' seen on UDP/53 in {container} — the DC's "
           "tunnel traffic is DNS-encapsulated end to end" if n > 0
           else f"no DNS-encoded queries under '{zone}' observed in {seconds}s — the DC client "
           "did not complete the tunnel (check the pasted iodine invocation and the TAP driver)")
    return n > 0


def _read_paste(path: str) -> str:
    """Read an operator-pasted command from a scratch file the shell wrote. Empty / all-comment
    / still-a-placeholder content is reported so a proof never silently runs an empty string."""
    text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    live = "\n".join(l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#"))
    return live.strip()


# --------------------------------------------------------------------------- #
# SUBCOMMANDS
# --------------------------------------------------------------------------- #


def cmd_preflight(profile_id: str, session_id: str = "") -> None:
    """The DC answers over WinRM, and the profile masks its secret. The single hardcoded probe
    is a `hostname`/`whoami` — the run's own output is the proof it landed on the real box."""
    profile = winprofiles.get_profile(profile_id)
    if not profile:
        result("preflight.profile", "NOTRUN", f"no such Windows profile {profile_id!r}")
        return
    value("DC_HOST", profile["host"])
    value("DC_PORT", str(profile["port"]))
    result("preflight.profile", "PASS",
           f"{profile_id} -> {profile['host']}:{profile['port']} "
           f"({profile['domain']}\\{profile['username']}, auth={profile['auth_kind']})")

    code, out, _rid = _winrm_gated(profile_id, session_id, ack=False,
                                   ps_text="hostname; whoami", label="preflight.whoami",
                                   timeout_seconds=60)
    reached = code == 0 and bool(out.strip())
    result("preflight.winrm_live", "PASS" if reached else "NOTRUN",
           f"live WinRM round-trip to the DC returned {out.strip()!r}" if reached
           else "the DC did not answer over WinRM — nothing downstream can run")


def cmd_winrm_run(profile_id: str, session_id: str, ack: str, label: str, cmdfile: str) -> None:
    """One operator-pasted PowerShell command on the DC, through the gate. Used by the staging
    script (idempotent steps) and the DCSync script (the destructive dump)."""
    ps = _read_paste(cmdfile)
    if not ps:
        result(f"{label}.paste", "NOTRUN",
               f"the paste file {cmdfile} is empty or still a placeholder — fill the [[PASTE]] in")
        return
    secret = winprofiles.get_secret(profile_id) or ""
    code, out, run_id = _winrm_gated(profile_id, session_id, ack in ("1", "true", "yes"),
                                     ps, label)
    value(f"{label.upper().replace('.', '_')}_EXIT", str(code))
    if run_id:
        value(f"{label.upper().replace('.', '_')}_RUN_ID", run_id)
    result(f"{label}.ran", "PASS" if code == 0 else ("NOTRUN" if code is None else "FAIL"),
           f"exit={code}" + (f" run={run_id}" if run_id else ""))
    _leak_sweep(secret, run_id, label)


def cmd_winrm_probe(profile_id: str, session_id: str, label: str, cmdfile: str) -> None:
    """A NEUTRAL WinRM round-trip for idempotency/verification checks, where a non-zero exit is
    a legitimate answer ("not staged yet"), not a failure. It still proves the approval refusal
    first — every WinRM touch goes through the gate, even a Test-Path — but reports the exit as
    DATA (VALUE) and leaves the pass/not-run judgement to the caller. Authored, benign scripts
    only; the offensive pastes go through winrm-run, which treats exit 0 as the success it is."""
    ps = _read_paste(cmdfile)
    if not ps:
        result(f"{label}.probe", "NOTRUN", f"empty probe script {cmdfile}")
        return
    code, out, _rid = _winrm_gated(profile_id, session_id, ack=False, ps_text=ps, label=label,
                                   timeout_seconds=60)
    key = label.upper().replace(".", "_")
    value(f"{key}_EXIT", str(code))
    first = next((l for l in out.splitlines() if l.strip()), "")
    if first:
        value(f"{key}_OUT1", first.strip())
    result(f"{label}.probe", "PASS" if code is not None else "NOTRUN",
           f"probe ran, exit={code}" if code is not None else "the DC did not answer")


def cmd_winrm_dcsync(profile_id: str, session_id: str, cmdfile: str, engagement_id: str = "") -> None:
    """The destructive DCSync dump on the DC, over gated WinRM — with the same transcript
    hygiene build #9 used: the raw output is dumped domain credential material, so it is NEVER
    folded into the committed transcript. Only a REDACTED summary (how many credential lines,
    whether krbtgt was among them) and the exit code are reported. The WinRM credential is then
    swept out of the persisted record (whole and in fragments) via build #9's redaction, which
    the executor already applied — this only verifies it held on a real destructive run.

    label='dcsync'. The refusal-first discipline: the approval gate and the danger gate are both
    proved to refuse before the acknowledged run, since a raw domain-wide credential dump is
    exactly what the red-confirm exists to gate."""
    ps = _read_paste(cmdfile)
    if not ps:
        result("dcsync.paste", "NOTRUN",
               f"the DCSync paste ({cmdfile}) is empty or still a placeholder — fill the [[PASTE]] in")
        return
    secret = winprofiles.get_secret(profile_id) or ""

    def req(**kw) -> ExecRequest:
        # engagement_id is threaded in too: for the destructive DCSync the engagement scope-lock
        # applies ON TOP of the windows-profile host-lock (build #9's belt-and-suspenders — a run
        # can reach the box only if the profile pins it AND the entered engagement's scope permits
        # it). The staging/tunnel WinRM touches stay windows-gated as in build #9.
        base = dict(command=ps, args=[], windows_profile_id=profile_id,
                    engagement_id=engagement_id or None,
                    session_id=session_id or None, approved=True, dangerous_ack=True,
                    timeout_seconds=180)
        base.update(kw)
        return ExecRequest(**base)

    rej = executor.validate_request(req(approved=False))
    result("dcsync.refuse_unapproved", "PASS" if rej and rej.gate == "approval" else "FAIL",
           f"gate={getattr(rej, 'gate', None)!r} — an unapproved DCSync must be refused")
    rej = executor.validate_request(req(dangerous_ack=False))
    result("dcsync.refuse_no_ack", "PASS" if rej and rej.gate == "danger" else "NOTRUN",
           "the DCSync dump is danger-classified and refused without the explicit red-confirm"
           if rej and rej.gate == "danger"
           else f"the pasted command was not danger-classified (gate={getattr(rej, 'gate', None)!r}) "
           "— it should trip the danger heuristic; check the paste is the real dcsync one-liner")

    events = list(executor.iter_run(req()))
    if any(e.get("type") == "rejected" for e in events):
        rj = next(e for e in events if e["type"] == "rejected")
        result("dcsync.ran", "FAIL", f"the acknowledged run was REJECTED at gate={rj.get('gate')}")
        return
    start = next((e for e in events if e.get("type") == "start"), {})
    exit_ev = next((e for e in events if e.get("type") == "exit"), {})
    run_id = start.get("run_id", "")
    out = "\n".join(e.get("line", "") for e in events if e.get("type") == "stdout")
    code = exit_ev.get("code")

    # A REDACTED summary only — count credential-shaped lines, never print them. A DCSync/
    # secretsdump line carries an NTLM hash (`user:rid:lm:nt:::`) or a `Hash NTLM:` field; both
    # are matched without echoing the material.
    import re  # noqa: PLC0415
    cred_lines = [ln for ln in out.splitlines()
                  if re.search(r":[0-9a-fA-F]{32}:", ln) or ln.count(":") >= 4
                  or "hash ntlm" in ln.lower() or "ntlm:" in ln.lower()]
    krbtgt = "krbtgt" in out.lower()
    result("dcsync.ran", "PASS" if code == 0 and cred_lines else ("NOTRUN" if code is None else "FAIL"),
           f"exit={code} run={run_id} — {len(cred_lines)} credential-shaped line(s) returned "
           f"(krbtgt present: {krbtgt}); raw material withheld from the transcript by design"
           if code == 0 and cred_lines else
           f"exit={code} — no credential material recognised in the output (is the tool staged "
           "under the excluded path, and is the paste the real dcsync one-liner?)")
    value("DCSYNC_CRED_LINES", str(len(cred_lines)))
    value("DCSYNC_KRBTGT", "true" if krbtgt else "false")
    if run_id:
        value("DCSYNC_RUN_ID", run_id)
    _leak_sweep(secret, run_id, "dcsync")


def cmd_enter_engagement(target: str, scope: str) -> None:
    rec = engagement.enter(
        target=target,
        authorization="build #10 C2 proof: operator-owned VMware lab (corp.local DC) + the "
                      "engage sandbox; DC callback lands on the opt-in UDP/53 published to "
                      "the VMnet8 host address only",
        scope_spec=scope,
    )
    value("ENGAGEMENT_ID", rec.engagement_id)
    result("engagement.enter", "PASS", f"id={rec.engagement_id} scope={scope}")


def cmd_iodine_phase(profile_id: str, session_id: str, eid: str, zone: str, secret: str,
                     tunnel_net: str, client_cmdfile: str) -> None:
    """ONE PROCESS: start the gated iodined server, bring the DC's tunnel up against it over
    WinRM (the operator-pasted client invocation, launched detached), and confirm on the
    sandbox's own wire that DNS-encoded traffic crossed. The listener is stopped at the end so
    the phase leaves nothing bound."""
    lis = _start_iodined(eid, zone, secret, tunnel_net)
    if lis is None:
        result("iodine.phase", "NOTRUN", "the iodined server did not reach LISTEN; phase aborted")
        return
    try:
        client = _read_paste(client_cmdfile)
        if not client:
            result("iodine.client_launch", "NOTRUN",
                   f"the iodine client paste ({client_cmdfile}) is empty/placeholder — fill it in. "
                   "It MUST connect the DC to 192.168.13.1 over UDP/53 for the tunnel zone and "
                   "launch DETACHED (e.g. via Start-Process) so the WinRM call returns")
            return
        # Launch the DC client THROUGH the gate. It must be detached (the paste's job), so the
        # gated WinRM call returns promptly and we observe the tunnel from the server side.
        _winrm_gated(profile_id, session_id, ack=False, ps_text=client,
                     label="iodine.client_launch", timeout_seconds=60)
        note("  waiting for the DC's iodine client to negotiate the DNS tunnel...")
        time.sleep(6)
        _observe_dns_traffic(lis.container, zone)
    finally:
        stopped = obfuscation.stop_listener(lis.id)
        result("iodine.teardown", "PASS" if stopped.status != "listening" else "FAIL",
               f"listener {lis.id} stopped (status={stopped.status}) — udp/53 released")


def cmd_beacon_phase(profile_id: str, session_id: str, eid: str, zone: str, secret: str,
                     tunnel_net: str, client_cmdfile: str, implant_gen_file: str,
                     implant_run_file: str) -> None:
    """ONE PROCESS: iodined + Sliver server held, the DC's tunnel raised over WinRM, the
    implant generated (operator paste, in the sandbox console) and run on the DC over WinRM,
    and the Sliver session list watched for the beacon. Every held thing is torn down in the
    finally guard so the phase leaves no listener and no server."""
    lis = _start_iodined(eid, zone, secret, tunnel_net)
    srv = None
    if lis is None:
        result("beacon.phase", "NOTRUN", "no iodined tunnel server; the beacon has nowhere to land")
        return
    try:
        # The C2 server, GATED — all three limbs proved to refuse first.
        def sreq(**kw):
            base = dict(engagement_id=eid, approved=True, dangerous_ack=True)
            base.update(kw)
            return sliver.SliverServerRequest(**base)

        _refuses_server("sliver.server.gate.no_engagement",
                        lambda: sliver.start_server(sreq(engagement_id=None)), "engagement")
        _refuses_server("sliver.server.gate.unapproved",
                        lambda: sliver.start_server(sreq(approved=False)), "approval")
        _refuses_server("sliver.server.gate.no_red_confirm",
                        lambda: sliver.start_server(sreq(dangerous_ack=False)), "danger")
        srv = sliver.start_server(sreq())
        _assert_alive("sliver.server", sliver._servers, srv.id, srv.status)
        value("SLIVER_SERVER_ID", srv.id)
        value("SLIVER_PORT", str(srv.port))
        result("sliver.start_server", "PASS" if srv.status == "listening" else "NOTRUN",
               f"id={srv.id} port={srv.port} status={srv.status}")

        # Bring the DC's tunnel up so the beacon has a DNS path back to the sandbox.
        client = _read_paste(client_cmdfile)
        if not client:
            result("beacon.tunnel", "NOTRUN", "iodine client paste empty/placeholder — fill it in")
            return
        _winrm_gated(profile_id, session_id, ack=False, ps_text=client,
                     label="beacon.tunnel_launch", timeout_seconds=60)
        time.sleep(6)
        if not _observe_dns_traffic(lis.container, zone):
            result("beacon.tunnel", "NOTRUN",
                   "the DC tunnel did not come up; a beacon over it cannot be demonstrated")
            return

        # OPERATOR INFRA — the implant is BUILT by the operator's own pasted `generate` line in
        # the Sliver console, exactly as a human does it. HackPit never generates offense for
        # you; the harness runs the paste in the sandbox on the operator's behalf (the same
        # boundary live_fire_proof.sh crosses for the mTLS listener setup).
        gen = _read_paste(implant_gen_file)
        if not gen:
            result("sliver.implant_build", "NOTRUN",
                   "the Sliver implant-generation paste is empty/placeholder. It MUST build a "
                   "WINDOWS implant whose C2 reaches the server through the tunnel endpoint "
                   f"{tunnel_net.split('/')[0]}, and write it to a path the harness can copy off")
            return
        built = _sh("docker", "exec", ENGAGE, "sh", "-c", gen, timeout=240)
        note(f"  sliver-build> {(built.stdout + built.stderr).strip()[-400:]}")
        result("sliver.implant_build", "PASS" if built.returncode == 0 else "NOTRUN",
               "operator-pasted generate line ran in the sandbox console"
               if built.returncode == 0 else f"generate line exited {built.returncode}")

        # Run the implant ON the DC over gated WinRM (operator paste — staging/exec of the
        # artifact the generate step produced). Detached, so the gated call returns and the
        # beacon runs in the background while we watch the server.
        run_impl = _read_paste(implant_run_file)
        if not run_impl:
            result("beacon.implant_launch", "NOTRUN",
                   "the implant-execution paste is empty/placeholder — it MUST launch the built "
                   "implant on the DC detached (e.g. Start-Process)")
            return
        _winrm_gated(profile_id, session_id, ack=True, ps_text=run_impl,
                     label="beacon.implant_launch", timeout_seconds=120)

        # OBSERVE THE CALLBACK from the server side — poll Sliver's own session list.
        note("  watching the Sliver server's session list for the beacon...")
        seen = False
        for _ in range(10):
            time.sleep(6)
            q = _sh("docker", "exec", ENGAGE, "sh", "-c",
                    "echo sessions | timeout 30 sliver-client 2>/dev/null", timeout=45).stdout or ""
            if any(k in q.lower() for k in ("session", "beacon")) and "no sessions" not in q.lower():
                seen = True
                note(f"  sliver-sessions> {q.strip().splitlines()[-1][:160] if q.strip() else ''}")
                break
        result("sliver.beacon_callback", "PASS" if seen else "NOTRUN",
               "THE BEACON CALLED BACK — the DC implant registered a session with the C2 server "
               "over the iodine DNS tunnel" if seen
               else "no session registered within the watch window — the implant ran but no "
               "callback was observed (operator infra: the server needs an active listener the "
               "implant's C2 config points at; see the paste comments)")
    finally:
        if srv is not None:
            s = sliver.stop_server(srv.id)
            result("sliver.server.teardown", "PASS" if s.status != "listening" else "FAIL",
                   f"C2 server {srv.id} stopped (status={s.status})")
        s2 = obfuscation.stop_listener(lis.id)
        result("iodine.teardown", "PASS" if s2.status != "listening" else "FAIL",
               f"tunnel server {lis.id} stopped (status={s2.status}) — udp/53 released")


COMMANDS = {
    "preflight": cmd_preflight,
    "winrm-run": cmd_winrm_run,
    "winrm-probe": cmd_winrm_probe,
    "winrm-dcsync": cmd_winrm_dcsync,
    "enter-engagement": cmd_enter_engagement,
    "iodine-phase": cmd_iodine_phase,
    "beacon-phase": cmd_beacon_phase,
}


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        sys.exit(f"usage: c2_winrm_driver.py <{'|'.join(COMMANDS)}> [args...]")
    name = sys.argv[1]
    try:
        COMMANDS[name](*sys.argv[2:])
    except Exception as exc:  # noqa: BLE001
        # NOTRUN, not FAIL: a step that could not execute is not a step that proved something.
        result(name, "NOTRUN", f"{type(exc).__name__}: {exc}")
        traceback.print_exc(file=sys.stderr)
        sys.exit(3)
