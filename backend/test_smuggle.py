"""Request-smuggling detector locks (smuggle-probe build).  Run:  python test_smuggle.py

*** THE ARGUMENT THIS FILE ENFORCES — THE INTRUDER'S / RACE'S, FOR A DESYNC SWEEP. ***
HackPit refuses BATCHING ACROSS APPROVALS. It has never refused ONE approval that produces many
requests, and could not: ffuf, nuclei, the intruder and the race tester are each a single approval
buying many. A smuggling sweep is that same shape — one probe per chosen mutation from one press:
ONE gated job, the SAME four gates, NO new ones.

And it enforces the split that IS this build's safety story:

  * DETECTION is safe-by-default (timing-differential, self-contained — no co-tenant impact).
  * CONFIRMATION (socket poisoning, which CAN affect co-tenant traffic) is a SEPARATE approve-each
    carrying a plain-language co-tenant warning, and CANNOT run without its own approval. Still the
    same four gates — NO new gate class.
"""

from __future__ import annotations

import ast
import inspect
import json

from cockpit import config, smuggle


def _req(**kw):
    base = dict(url=f"http://{config.LAB_TARGET_HOST}/login", method="POST",
                mutations=["CL.TE", "TE.CL"], approved=True)
    base.update(kw)
    return smuggle.SmuggleRequest(**base)


def _not_refused_at(verdict, gate: str) -> bool:
    """"NOT REFUSED AT **THIS** GATE" — an approved in-lab job legitimately ends at the isolation
    gate when Docker is absent (CI / the docker-stripped local run), so this never asserts
    `verdict is None`."""
    return verdict is None or verdict.gate != gate


# --------------------------------------------------------------------------- #
# the gate — the scanner's four, unchanged
# --------------------------------------------------------------------------- #
def test_all_four_gates_fire_EACH_WITH_A_CONTROL() -> None:
    ok = smuggle.validate(_req())
    for gate in ("approval", "target", "danger"):
        assert _not_refused_at(ok, gate), f"an approved in-lab job was refused at {gate}: {ok}"

    unapproved = smuggle.validate(_req(approved=False))
    assert unapproved is not None and unapproved.gate == "approval", unapproved

    offlab = smuggle.validate(_req(url="http://example.com/login"))
    assert offlab is not None and offlab.gate == "target", offlab

    shelly = smuggle.validate(_req(body="x| sh"))
    assert shelly is not None and shelly.gate == "danger", shelly
    assert any("| sh" in f for f in shelly.dangerous_flags), shelly.dangerous_flags
    acked = smuggle.validate(_req(body="x| sh", dangerous_ack=True))
    assert _not_refused_at(acked, "danger"), f"the red-confirm did not clear the danger gate: {acked}"
    print("  approval / target / danger each fire, and the ack clears danger: PASS")


def test_the_argv_carries_THE_RIGHT_MUTATIONS_AND_STAGE() -> None:
    """*** THE JOB BUILDS THE RIGHT ARGV PER MUTATION TYPE. *** Every chosen mutation and the stage
    ride in the approved surface, and the whole request is complete (Critical 2)."""
    from cockpit.repeater import RepeaterHeader

    headers = [RepeaterHeader(name=f"X-H{i}", value=f"v{i}") for i in range(6)]
    req = _req(mutations=["CL.TE", "TE.CL", "CL.0", "H2.CL"], headers=headers,
               body="q=1&note=evil| sh")
    argv = smuggle.smuggle_argv_for(req)
    joined = " ".join(argv)
    assert "smuggle-probe" == argv[0], argv
    assert "--stage detect" in joined, joined
    # dot-free on the surface so the dotted canonical name is not read as a host by the target lock
    assert "--mutations cl-te,te-cl,cl-0,h2-cl" in joined, joined
    assert req.url in joined and "-X POST" in joined, joined
    for i in range(6):
        assert f"X-H{i}: v{i}" in joined, f"header X-H{i} missing from the surface"
    assert "evil| sh" in joined and "more" not in joined.lower(), joined
    # the danger gate SEES the complete surface — the reason completeness matters.
    verdict = smuggle.validate(req)
    assert verdict is not None and verdict.gate == "danger", "a shell body did not reach the gate"
    print("  argv carries the exact mutation set + stage, complete and gate-visible: PASS")


def test_an_unknown_mutation_is_DROPPED_WITH_A_WARNING_not_refused() -> None:
    stage, muts, warnings = smuggle.plan(_req(mutations=["CL.TE", "bogus", "TE.CL"]))
    assert muts == ["CL.TE", "TE.CL"], muts
    assert any("unknown mutation" in w for w in warnings), warnings
    # an empty set falls back to the safe default, not to nothing
    _, defs, _ = smuggle.plan(_req(mutations=[]))
    assert defs == list(smuggle.DEFAULT_MUTATIONS), defs
    print("  an unknown mutation is dropped with a warning; empty uses the safe default: PASS")


# --------------------------------------------------------------------------- #
# DETECTION vs CONFIRMATION — the split
# --------------------------------------------------------------------------- #
def test_CONFIRMATION_IS_A_SEPARATE_APPROVAL_WITH_THE_WARNING() -> None:
    """*** THE SPEC'S CORE REQUIREMENT. *** The confirm stage carries the co-tenant warning, the
    detect stage does not, and confirmation cannot run without its own approval."""
    # detect plan is silent on co-tenant risk; confirm plan surfaces the warning.
    _, _, dwarn = smuggle.plan(_req(stage="detect"))
    assert not any("CO-TENANT" in w for w in dwarn), "detection carries a co-tenant warning it should not"
    cstage, _, cwarn = smuggle.plan(_req(stage="confirm"))
    assert cstage == "confirm"
    assert any("CO-TENANT" in w for w in cwarn), "confirmation does not carry the co-tenant warning"
    assert smuggle.CO_TENANT_WARNING and "CO-TENANT" in smuggle.CO_TENANT_WARNING

    # confirmation CANNOT run without its OWN approval — the approval gate refuses an unapproved
    # confirm exactly as it refuses an unapproved detect.
    unapproved = smuggle.validate(_req(stage="confirm", approved=False))
    assert unapproved is not None and unapproved.gate == "approval", unapproved

    # the routes PIN the stage, so /smuggle can never run confirm and /smuggle/confirm can never
    # run detect — a confirmation is only ever a deliberate hit on its own endpoint.
    from cockpit import router

    detect_src = inspect.getsource(router.start_smuggle)
    confirm_src = inspect.getsource(router.start_smuggle_confirm)
    assert '"stage": "detect"' in detect_src, "the detect route does not pin the stage"
    assert '"stage": "confirm"' in confirm_src, "the confirm route does not pin the stage"
    print("  confirmation is a separate, self-approved stage carrying the co-tenant warning: PASS")


def test_an_unknown_stage_FALLS_BACK_TO_DETECT_never_escalates() -> None:
    """A typo must degrade to the SAFE path, never silently escalate to co-tenant confirmation."""
    stage, _, warnings = smuggle.plan(_req(stage="attack"))
    assert stage == "detect", stage
    assert any("unknown stage" in w for w in warnings), warnings
    print("  an unknown stage falls back to safe detection, never to confirm: PASS")


# --------------------------------------------------------------------------- #
# containment: the box, the wire, the argv, the record
# --------------------------------------------------------------------------- #
def test_the_container_is_a_CONSTANT_never_a_request_field() -> None:
    for field in ("container", "target", "host", "sandbox"):
        assert field not in smuggle.SmuggleRequest.model_fields, (
            f"SmuggleRequest grew a {field!r} field — the box must be a code constant"
        )
    assert "config.KALI_OPEN_CONTAINER" in inspect.getsource(smuggle._engine_argv)
    print("  the sandbox is a code constant, not a request field: PASS")


def test_the_engine_is_argv_only_with_the_request_on_STDIN() -> None:
    argv = smuggle._engine_argv()
    assert argv[:3] == ["docker", "exec", "-i"], argv
    assert "smuggle-probe" in argv and "--job-stdin" in argv, argv
    assert config.KALI_OPEN_CONTAINER in argv, argv
    runsrc = inspect.getsource(smuggle._run)
    assert "input=json.dumps(spec)" in runsrc, "the request does not travel on stdin"
    print("  the engine runs argv-only with the whole request on stdin: PASS")


def test_the_scope_check_runs_ON_THE_WIRE_URL_BEFORE_ANYTHING_IS_PROBED() -> None:
    src = inspect.getsource(smuggle._run)
    assert "_scope_ok(req, req.url)" in src, "the scope check does not read the wire URL"
    assert src.find("_scope_ok(req, req.url)") < src.find("subprocess.run"), (
        "the sweep is probed before the scope check"
    )
    assert "j.scope_refusals = len(mutations)" in src, "an off-scope host does not refuse the sweep"
    refuse = src[src.find("if not ok:"):src.find("cookie_header = ")]
    assert "return" in refuse, "an off-scope URL does not stop before the engine runs"
    assert "scope_refusals" in smuggle.SmuggleJob.model_fields
    print("  the wire URL is scope-checked before the sweep; off-scope refuses every mutation: PASS")


def test_the_run_record_does_NOT_carry_the_body_or_headers() -> None:
    src = inspect.getsource(smuggle._run)
    rec = src[src.find("RunRecord("):]
    assert "req.body" not in rec, "the run record carries the request body into the report"
    assert "req.headers" not in rec, "the run record carries the request headers into the report"
    assert "req.url" in rec and "mutations=" in rec
    print("  the run record carries the URL, stage and mutation set, never the body/headers: PASS")


# --------------------------------------------------------------------------- #
# verdicts — fixture timing set + external smuggler.py transcript
# --------------------------------------------------------------------------- #
def test_the_verdict_TURNS_A_TIMING_SET_INTO_PER_MUTATION_VERDICTS() -> None:
    """*** THE DETECTION SIGNAL. *** A probe hanging >= the threshold over the baseline is
    susceptible; a small delta is clear; an error row is inconclusive, never a hit."""
    rows = [
        {"mutation": "CL.TE", "baseline_ms": 40, "probe_ms": 6040, "error": ""},   # +6000 -> hit
        {"mutation": "TE.CL", "baseline_ms": 40, "probe_ms": 70, "error": ""},     # +30   -> clear
        {"mutation": "H2.CL", "baseline_ms": 40, "probe_ms": 0,
         "error": "inconclusive — no h2"},                                          # error -> not a hit
    ]
    vs = {v.mutation: v for v in smuggle.detection_verdicts(rows)}
    assert vs["CL.TE"].susceptible is True and vs["CL.TE"].delta_ms == 6000, vs["CL.TE"]
    assert vs["TE.CL"].susceptible is False, vs["TE.CL"]
    assert vs["H2.CL"].susceptible is False and vs["H2.CL"].error, vs["H2.CL"]

    # threshold boundary: exactly the threshold is a hit, one under is not.
    on = smuggle.verdict_for("CL.TE", 0, smuggle.SUSCEPTIBLE_DELTA_MS)
    off = smuggle.verdict_for("CL.TE", 0, smuggle.SUSCEPTIBLE_DELTA_MS - 1)
    assert on.susceptible is True and off.susceptible is False
    print("  a timing set becomes per-mutation verdicts, threshold pinned, errors excluded: PASS")


def test_parse_engine_output_reads_detect_AND_confirm() -> None:
    detect = json.dumps({"stage": "detect", "error": "", "verdicts": [
        {"mutation": "CL.TE", "baseline_ms": 40, "probe_ms": 6040, "error": ""},
    ]})
    dv, cv, err = smuggle.parse_engine_output(detect, "detect")
    assert len(dv) == 1 and dv[0].susceptible is True and not cv and not err, (dv, cv, err)

    confirm = json.dumps({"stage": "confirm", "error": "", "confirms": [
        {"mutation": "CL.TE", "poisoned": True, "status": 405,
         "evidence": "smuggled prefix altered the follow-up: HTTP/1.1 405", "error": ""},
    ]})
    dv2, cv2, err2 = smuggle.parse_engine_output(confirm, "confirm")
    assert not dv2 and len(cv2) == 1 and cv2[0].confirmed is True, (dv2, cv2)
    # a poisoned row WITH an error is never counted confirmed.
    conf_err = json.dumps({"stage": "confirm", "confirms": [
        {"mutation": "TE.CL", "poisoned": True, "error": "connect failed"}]})
    _, cv3, _ = smuggle.parse_engine_output(conf_err, "confirm")
    assert cv3[0].confirmed is False, cv3
    print("  parse_engine_output reads detect verdicts and confirm verdicts, errors demote: PASS")


def test_a_smuggler_py_transcript_MAPS_TO_VERDICTS() -> None:
    """*** THE SPEC'S 'fixture smuggler.py output' CLAUSE. *** A manual defparam run pastes back
    into the same table: a line naming a mutation with a hit marker is susceptible."""
    txt = (
        "[+] Potentially vulnerable to a CL.TE desync\n"
        "[INFO] TE.CL looks clean\n"
        "[CRIT] TE.CL DISCONNECT / TIMEOUT observed\n"
        "some banner line with no mutation\n"
    )
    vs = {v.mutation: v for v in smuggle.parse_smuggler_output(txt)}
    assert vs.keys() == {"CL.TE", "TE.CL"}, vs.keys()
    assert all(v.susceptible for v in vs.values()), vs
    # a transcript with no hit markers yields nothing.
    assert smuggle.parse_smuggler_output("CL.TE tested\nTE.CL tested\n") == []
    print("  a smuggler.py transcript maps its hits to per-mutation verdicts: PASS")


def test_a_hit_BECOMES_a_finding_detection_high_confirm_critical() -> None:
    """A susceptible detection -> a High finding; a confirmed desync -> a Critical one. Both gate on
    both a hit AND a session, and neither writes without them."""
    src = inspect.getsource(smuggle._write_finding)
    assert '"high"' in src and '"critical"' in src, src
    assert "if not (hits and req.session_id)" in src, "a finding is written without a hit/session"
    assert 'vuln_class="request-smuggling"' in src and 'tool="smuggle-probe"' in src
    # the worker feeds confirmed=True on the confirm stage and the susceptible set on detect.
    runsrc = inspect.getsource(smuggle._run)
    assert "_write_finding(req, stage, confirmed, confirmed=True)" in runsrc
    assert "_write_finding(req, stage, susceptible, confirmed=False)" in runsrc
    print("  a susceptible detection is a High finding; a confirmed desync is Critical: PASS")


# --------------------------------------------------------------------------- #
# stop + no-new-gate
# --------------------------------------------------------------------------- #
def test_STOP_IS_UNGATED() -> None:
    src = inspect.getsource(smuggle.stop)
    for token in ("approved", "dangerous_ack", "validate", "executor"):
        assert token not in src, f"stop() consults {token!r}"
    from cockpit import router

    rsrc = inspect.getsource(router.stop_smuggle_job)
    for token in ("approved", "dangerous_ack", "validate"):
        assert token not in rsrc, f"the stop route consults {token!r}"
    print("  stop is ungated in the module and on the route: PASS")


def test_the_preview_PROBES_NOTHING_and_uses_the_same_functions() -> None:
    from cockpit import router

    src = inspect.getsource(router._smuggle_preview)
    assert "smuggle_mod.plan(" in src and "smuggle_mod.validate(" in src
    assert "smuggle_mod.start(" not in src, "the preview route can start a job"
    tree = ast.parse(inspect.getsource(smuggle.plan))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("run", "Popen"), "plan() spawns a process"
    print("  the preview reuses plan+validate and probes nothing: PASS")


def test_smuggle_adds_NO_NEW_GATE_to_the_executor() -> None:
    """*** THE FOUR GATES, NO NEW ONES. *** start() raises SmuggleRefused exactly three times: the
    URL-shape input guard (not a safety gate), the gate-verdict relay, and the availability check."""
    src = inspect.getsource(smuggle)
    assert "executor.validate_request" in src
    start_src = inspect.getsource(smuggle.start)
    assert start_src.count("raise SmuggleRefused") == 3, (
        f"SmuggleRefused is raised {start_src.count('raise SmuggleRefused')} times in start() — "
        "there should be exactly three: URL-input guard, gate relay and availability check"
    )
    print("  the module relays the executor's verdict and invents no gate of its own: PASS")


def test_a_plain_smuggle_STILL_NEEDS_NO_RED_CONFIRM() -> None:
    """The declared command is CLEAN by binary identity — a timing probe is not code execution — so
    a plain detection adds no red-confirm, exactly like a plain ffuf. The co-tenant risk of the
    confirm stage is handled by its separate approval + warning, not by a binary-identity flag."""
    plain = smuggle.validate(_req(body="username=admin"))
    assert _not_refused_at(plain, "danger"), (
        f"a plain in-lab smuggle now needs a red-confirm ({plain}) — this build added a confirm"
    )
    print("  a plain smuggle still needs no red-confirm — no confirm was added: PASS")


if __name__ == "__main__":
    print("== smuggle-probe ==")
    test_all_four_gates_fire_EACH_WITH_A_CONTROL()
    test_the_argv_carries_THE_RIGHT_MUTATIONS_AND_STAGE()
    test_an_unknown_mutation_is_DROPPED_WITH_A_WARNING_not_refused()
    test_CONFIRMATION_IS_A_SEPARATE_APPROVAL_WITH_THE_WARNING()
    test_an_unknown_stage_FALLS_BACK_TO_DETECT_never_escalates()
    test_the_container_is_a_CONSTANT_never_a_request_field()
    test_the_engine_is_argv_only_with_the_request_on_STDIN()
    test_the_scope_check_runs_ON_THE_WIRE_URL_BEFORE_ANYTHING_IS_PROBED()
    test_the_run_record_does_NOT_carry_the_body_or_headers()
    test_the_verdict_TURNS_A_TIMING_SET_INTO_PER_MUTATION_VERDICTS()
    test_parse_engine_output_reads_detect_AND_confirm()
    test_a_smuggler_py_transcript_MAPS_TO_VERDICTS()
    test_a_hit_BECOMES_a_finding_detection_high_confirm_critical()
    test_STOP_IS_UNGATED()
    test_the_preview_PROBES_NOTHING_and_uses_the_same_functions()
    test_smuggle_adds_NO_NEW_GATE_to_the_executor()
    test_a_plain_smuggle_STILL_NEEDS_NO_RED_CONFIRM()
    print("ALL smuggle locks pass")
