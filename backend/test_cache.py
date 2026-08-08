"""Web-cache-poisoning / cache-deception detector locks (cache-probe build).  Run: python test_cache.py

*** THE ARGUMENT THIS FILE ENFORCES — THE INTRUDER'S / SMUGGLE'S, FOR A CACHE SWEEP. ***
HackPit refuses BATCHING ACROSS APPROVALS. It has never refused ONE approval that produces many
requests, and could not: ffuf, nuclei, the intruder, the race tester and the smuggling sweep are
each a single approval buying many. A cache-poisoning sweep is that same shape — one probe per
candidate unkeyed input from one press: ONE gated job, the SAME four gates, NO new ones.

And it enforces the split that IS this build's safety story:

  * DETECTION is safe-by-default (reflection + cacheability — it plants NO cache entry).
  * CONFIRMATION (poison-plant, which CAN serve a poisoned response to other users of the cache) is
    a SEPARATE approve-each carrying a plain-language co-user warning, and CANNOT run without its own
    approval. Still the same four gates — NO new gate class.
"""

from __future__ import annotations

import ast
import inspect
import json

from cockpit import cache, config


def _req(**kw):
    base = dict(url=f"http://{config.LAB_TARGET_HOST}/", method="GET",
                inputs=["X-Forwarded-Host", "X-Original-URL"], approved=True)
    base.update(kw)
    return cache.CacheRequest(**base)


def _not_refused_at(verdict, gate: str) -> bool:
    """"NOT REFUSED AT **THIS** GATE" — an approved in-lab job legitimately ends at the isolation
    gate when Docker is absent (CI / the docker-stripped local run), so this never asserts
    `verdict is None`."""
    return verdict is None or verdict.gate != gate


# --------------------------------------------------------------------------- #
# the gate — the scanner's four, unchanged
# --------------------------------------------------------------------------- #
def test_all_four_gates_fire_EACH_WITH_A_CONTROL() -> None:
    ok = cache.validate(_req())
    for gate in ("approval", "target", "danger"):
        assert _not_refused_at(ok, gate), f"an approved in-lab job was refused at {gate}: {ok}"

    unapproved = cache.validate(_req(approved=False))
    assert unapproved is not None and unapproved.gate == "approval", unapproved

    offlab = cache.validate(_req(url="http://example.com/"))
    assert offlab is not None and offlab.gate == "target", offlab

    shelly = cache.validate(_req(body="x| sh"))
    assert shelly is not None and shelly.gate == "danger", shelly
    assert any("| sh" in f for f in shelly.dangerous_flags), shelly.dangerous_flags
    acked = cache.validate(_req(body="x| sh", dangerous_ack=True))
    assert _not_refused_at(acked, "danger"), f"the red-confirm did not clear the danger gate: {acked}"
    print("  approval / target / danger each fire, and the ack clears danger: PASS")


def test_the_argv_carries_THE_RIGHT_INPUTS_AND_STAGE() -> None:
    """*** THE JOB BUILDS THE RIGHT ARGV. *** Every chosen input and the stage ride in the approved
    surface, and the whole request is complete (Critical 2)."""
    from cockpit.repeater import RepeaterHeader

    headers = [RepeaterHeader(name=f"X-H{i}", value=f"v{i}") for i in range(6)]
    req = _req(inputs=["X-Forwarded-Host", "X-Original-URL", "param-cloak"], headers=headers,
               body="q=1&note=evil| sh")
    argv = cache.cache_argv_for(req)
    joined = " ".join(argv)
    assert "cache-probe" == argv[0], argv
    assert "--stage detect" in joined, joined
    assert "--inputs x-forwarded-host,x-original-url,param-cloak" in joined, joined
    assert "--deception" in joined, joined
    assert req.url in joined, joined  # GET -> no -X
    for i in range(6):
        assert f"X-H{i}: v{i}" in joined, f"header X-H{i} missing from the surface"
    assert "evil| sh" in joined and "more" not in joined.lower(), joined
    # the danger gate SEES the complete surface — the reason completeness matters.
    verdict = cache.validate(req)
    assert verdict is not None and verdict.gate == "danger", "a shell body did not reach the gate"
    print("  argv carries the exact input set + stage, complete and gate-visible: PASS")


def test_an_unknown_input_is_DROPPED_WITH_A_WARNING_not_refused() -> None:
    stage, ins, warnings = cache.plan(_req(inputs=["X-Forwarded-Host", "bogus", "X-Original-URL"]))
    assert ins == ["X-Forwarded-Host", "X-Original-URL"], ins
    assert any("unknown input" in w for w in warnings), warnings
    # an empty set falls back to the safe default, not to nothing
    _, defs, _ = cache.plan(_req(inputs=[]))
    assert defs == list(cache.DEFAULT_INPUTS), defs
    print("  an unknown input is dropped with a warning; empty uses the safe default: PASS")


# --------------------------------------------------------------------------- #
# DETECTION vs CONFIRMATION — the split
# --------------------------------------------------------------------------- #
def test_CONFIRMATION_IS_A_SEPARATE_APPROVAL_WITH_THE_WARNING() -> None:
    """*** THE SPEC'S CORE REQUIREMENT. *** The confirm stage carries the co-user warning, the detect
    stage does not, and confirmation cannot run without its own approval."""
    _, _, dwarn = cache.plan(_req(stage="detect"))
    assert not any("CO-USER" in w.upper() for w in dwarn), "detection carries a co-user warning it should not"
    cstage, _, cwarn = cache.plan(_req(stage="confirm"))
    assert cstage == "confirm"
    assert any("OTHER USERS" in w.upper() for w in cwarn), "confirmation does not carry the co-user warning"
    assert cache.CO_USER_WARNING and "OTHER USERS" in cache.CO_USER_WARNING.upper()

    # confirmation CANNOT run without its OWN approval — the approval gate refuses an unapproved
    # confirm exactly as it refuses an unapproved detect.
    unapproved = cache.validate(_req(stage="confirm", approved=False))
    assert unapproved is not None and unapproved.gate == "approval", unapproved

    # the routes PIN the stage, so /cache can never run confirm and /cache/confirm can never run
    # detect — a confirmation is only ever a deliberate hit on its own endpoint.
    from cockpit import router

    detect_src = inspect.getsource(router.start_cache)
    confirm_src = inspect.getsource(router.start_cache_confirm)
    assert '"stage": "detect"' in detect_src, "the detect route does not pin the stage"
    assert '"stage": "confirm"' in confirm_src, "the confirm route does not pin the stage"
    print("  confirmation is a separate, self-approved stage carrying the co-user warning: PASS")


def test_an_unknown_stage_FALLS_BACK_TO_DETECT_never_escalates() -> None:
    """A typo must degrade to the SAFE path, never silently escalate to co-user confirmation."""
    stage, _, warnings = cache.plan(_req(stage="attack"))
    assert stage == "detect", stage
    assert any("unknown stage" in w for w in warnings), warnings
    print("  an unknown stage falls back to safe detection, never to confirm: PASS")


# --------------------------------------------------------------------------- #
# containment: the box, the wire, the argv, the record
# --------------------------------------------------------------------------- #
def test_the_container_is_a_CONSTANT_never_a_request_field() -> None:
    for field in ("container", "target", "host", "sandbox"):
        assert field not in cache.CacheRequest.model_fields, (
            f"CacheRequest grew a {field!r} field — the box must be a code constant"
        )
    assert "config.KALI_OPEN_CONTAINER" in inspect.getsource(cache._engine_argv)
    print("  the sandbox is a code constant, not a request field: PASS")


def test_the_engine_is_argv_only_with_the_request_on_STDIN() -> None:
    argv = cache._engine_argv()
    assert argv[:3] == ["docker", "exec", "-i"], argv
    assert "cache-probe" in argv and "--job-stdin" in argv, argv
    assert config.KALI_OPEN_CONTAINER in argv, argv
    runsrc = inspect.getsource(cache._run)
    assert "input=json.dumps(spec)" in runsrc, "the request does not travel on stdin"
    print("  the engine runs argv-only with the whole request on stdin: PASS")


def test_the_scope_check_runs_ON_THE_WIRE_URL_BEFORE_ANYTHING_IS_PROBED() -> None:
    src = inspect.getsource(cache._run)
    assert "_scope_ok(req, req.url)" in src, "the scope check does not read the wire URL"
    assert src.find("_scope_ok(req, req.url)") < src.find("subprocess.run"), (
        "the sweep is probed before the scope check"
    )
    assert "j.scope_refusals = len(inputs)" in src, "an off-scope host does not refuse the sweep"
    refuse = src[src.find("if not ok:"):src.find("cookie_header = ")]
    assert "return" in refuse, "an off-scope URL does not stop before the engine runs"
    assert "scope_refusals" in cache.CacheJob.model_fields
    print("  the wire URL is scope-checked before the sweep; off-scope refuses every input: PASS")


def test_the_run_record_does_NOT_carry_the_body_or_headers() -> None:
    src = inspect.getsource(cache._run)
    rec = src[src.find("RunRecord("):]
    assert "req.body" not in rec, "the run record carries the request body into the report"
    assert "req.headers" not in rec, "the run record carries the request headers into the report"
    assert "req.url" in rec and "inputs=" in rec
    print("  the run record carries the URL, stage and input set, never the body/headers: PASS")


# --------------------------------------------------------------------------- #
# verdicts — fixture engine output + external wcvs transcript
# --------------------------------------------------------------------------- #
def test_the_verdict_TURNS_REFLECTION_AND_CACHEABILITY_INTO_CANDIDATES() -> None:
    """*** THE DETECTION SIGNAL. *** Reflected AND cacheable is a candidate; either alone is not; an
    error row is inconclusive, never a candidate. The backend owns the rule (candidate_of)."""
    rows = [
        {"input": "X-Forwarded-Host", "reflected": True, "cacheable": True, "error": ""},   # candidate
        {"input": "X-Host", "reflected": False, "cacheable": True, "error": ""},             # not
        {"input": "X-Original-URL", "reflected": True, "cacheable": False, "error": ""},     # not
        {"input": "param-cloak", "reflected": True, "cacheable": True,
         "error": "request failed: no route"},                                              # error -> not
    ]
    vs = {v.input: v for v in cache.detection_verdicts(rows)}
    assert vs["X-Forwarded-Host"].candidate is True, vs["X-Forwarded-Host"]
    assert vs["X-Host"].candidate is False, vs["X-Host"]
    assert vs["X-Original-URL"].candidate is False, vs["X-Original-URL"]
    assert vs["param-cloak"].candidate is False and vs["param-cloak"].error, vs["param-cloak"]

    # candidate_of is the single rule — reflected AND cacheable, nothing else.
    assert cache.candidate_of(True, True) is True
    assert cache.candidate_of(True, False) is False
    assert cache.candidate_of(False, True) is False
    print("  reflection + cacheability become per-input candidates, errors excluded: PASS")


def test_the_deception_verdict_flags_a_CACHED_DYNAMIC_PATH() -> None:
    rows = [
        {"path": "/account/foo.css", "extension": "css", "cached": True, "error": ""},
        {"path": "/account/;foo.css", "extension": "css", "cached": False, "error": ""},
        {"path": "/account/x.css", "extension": "css", "cached": True, "error": "request failed"},
    ]
    ds = {d.path: d for d in cache.deception_verdicts(rows)}
    assert ds["/account/foo.css"].cached is True, ds["/account/foo.css"]
    assert ds["/account/;foo.css"].cached is False, ds["/account/;foo.css"]
    assert ds["/account/x.css"].cached is False and ds["/account/x.css"].error, ds["/account/x.css"]
    print("  the deception verdict flags a dynamic page cached under a static path, errors excluded: PASS")


def test_parse_engine_output_reads_detect_AND_confirm() -> None:
    detect = json.dumps({"stage": "detect", "error": "", "verdicts": [
        {"input": "X-Forwarded-Host", "reflected": True, "cacheable": True, "error": ""},
    ], "deceptions": [{"path": "/a/foo.css", "extension": "css", "cached": True, "error": ""}]})
    dv, de, cv, err = cache.parse_engine_output(detect, "detect")
    assert len(dv) == 1 and dv[0].candidate is True, (dv, err)
    assert len(de) == 1 and de[0].cached is True, de
    assert not cv and not err

    confirm = json.dumps({"stage": "confirm", "error": "", "confirms": [
        {"input": "X-Forwarded-Host", "poisoned": True, "status": 200,
         "evidence": "a fresh request received the planted marker", "error": ""},
    ]})
    dv2, de2, cv2, err2 = cache.parse_engine_output(confirm, "confirm")
    assert not dv2 and not de2 and len(cv2) == 1 and cv2[0].poisoned is True, (cv2, err2)
    # a poisoned row WITH an error is never counted confirmed.
    conf_err = json.dumps({"stage": "confirm", "confirms": [
        {"input": "X-Host", "poisoned": True, "error": "victim request failed"}]})
    _, _, cv3, _ = cache.parse_engine_output(conf_err, "confirm")
    assert cv3[0].poisoned is False, cv3
    print("  parse_engine_output reads detect verdicts + deceptions and confirm verdicts: PASS")


def test_a_wcvs_transcript_MAPS_TO_VERDICTS() -> None:
    """*** THE SPEC'S 'or the in-module confirmation / wcvs drives it' CLAUSE. *** A manual wcvs run
    pastes back into the same table: a line naming a header with a hit marker is a candidate."""
    txt = (
        "[+] X-Forwarded-Host is reflected and the response is cacheable — vulnerable\n"
        "[INFO] X-Host tested, no reflection\n"
        "[+] X-Original-URL poisoning confirmed\n"
        "some banner line with no header\n"
    )
    vs = {v.input: v for v in cache.parse_wcvs_output(txt)}
    assert vs.keys() == {"X-Forwarded-Host", "X-Original-URL"}, vs.keys()
    assert all(v.candidate for v in vs.values()), vs
    # a transcript with no hit markers yields nothing.
    assert cache.parse_wcvs_output("X-Forwarded-Host tested\nX-Host tested\n") == []
    print("  a wcvs transcript maps its hits to per-input candidate verdicts: PASS")


def test_a_hit_BECOMES_a_finding_detection_high_confirm_critical() -> None:
    """A candidate/deception -> a High finding; a confirmed poisoning -> a Critical one. All gate on
    both a hit AND a session, and none writes without them."""
    src = inspect.getsource(cache._write_finding)
    assert '"high"' in src and '"critical"' in src, src
    assert "if not (hits and req.session_id)" in src, "a finding is written without a hit/session"
    assert 'tool="cache-probe"' in src and '"cache-poisoning"' in src
    # the worker feeds confirmed on the confirm stage and candidates/deception on detect.
    runsrc = inspect.getsource(cache._run)
    assert 'kind="confirmed"' in runsrc
    assert 'kind="candidate"' in runsrc and 'kind="deception"' in runsrc
    print("  a candidate/deception is a High finding; a confirmed poisoning is Critical: PASS")


# --------------------------------------------------------------------------- #
# stop + no-new-gate
# --------------------------------------------------------------------------- #
def test_STOP_IS_UNGATED() -> None:
    src = inspect.getsource(cache.stop)
    for token in ("approved", "dangerous_ack", "validate", "executor"):
        assert token not in src, f"stop() consults {token!r}"
    from cockpit import router

    rsrc = inspect.getsource(router.stop_cache_job)
    for token in ("approved", "dangerous_ack", "validate"):
        assert token not in rsrc, f"the stop route consults {token!r}"
    print("  stop is ungated in the module and on the route: PASS")


def test_the_preview_PROBES_NOTHING_and_uses_the_same_functions() -> None:
    from cockpit import router

    src = inspect.getsource(router._cache_preview)
    assert "cache_mod.plan(" in src and "cache_mod.validate(" in src
    assert "cache_mod.start(" not in src, "the preview route can start a job"
    tree = ast.parse(inspect.getsource(cache.plan))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("run", "Popen"), "plan() spawns a process"
    print("  the preview reuses plan+validate and probes nothing: PASS")


def test_cache_adds_NO_NEW_GATE_to_the_executor() -> None:
    """*** THE FOUR GATES, NO NEW ONES. *** start() raises CacheRefused exactly three times: the
    URL-shape input guard (not a safety gate), the gate-verdict relay, and the availability check."""
    src = inspect.getsource(cache)
    assert "executor.validate_request" in src
    start_src = inspect.getsource(cache.start)
    assert start_src.count("raise CacheRefused") == 3, (
        f"CacheRefused is raised {start_src.count('raise CacheRefused')} times in start() — "
        "there should be exactly three: URL-input guard, gate relay and availability check"
    )
    print("  the module relays the executor's verdict and invents no gate of its own: PASS")


def test_a_plain_cache_STILL_NEEDS_NO_RED_CONFIRM() -> None:
    """The declared command is CLEAN by binary identity — marking a page and reading it back is not
    code execution — so a plain detection adds no red-confirm, exactly like a plain ffuf. The
    co-user risk of the confirm stage is handled by its separate approval + warning, not by a
    binary-identity flag."""
    plain = cache.validate(_req(body="username=admin"))
    assert _not_refused_at(plain, "danger"), (
        f"a plain in-lab cache probe now needs a red-confirm ({plain}) — this build added a confirm"
    )
    print("  a plain cache probe still needs no red-confirm — no confirm was added: PASS")


if __name__ == "__main__":
    print("== cache-probe ==")
    test_all_four_gates_fire_EACH_WITH_A_CONTROL()
    test_the_argv_carries_THE_RIGHT_INPUTS_AND_STAGE()
    test_an_unknown_input_is_DROPPED_WITH_A_WARNING_not_refused()
    test_CONFIRMATION_IS_A_SEPARATE_APPROVAL_WITH_THE_WARNING()
    test_an_unknown_stage_FALLS_BACK_TO_DETECT_never_escalates()
    test_the_container_is_a_CONSTANT_never_a_request_field()
    test_the_engine_is_argv_only_with_the_request_on_STDIN()
    test_the_scope_check_runs_ON_THE_WIRE_URL_BEFORE_ANYTHING_IS_PROBED()
    test_the_run_record_does_NOT_carry_the_body_or_headers()
    test_the_verdict_TURNS_REFLECTION_AND_CACHEABILITY_INTO_CANDIDATES()
    test_the_deception_verdict_flags_a_CACHED_DYNAMIC_PATH()
    test_parse_engine_output_reads_detect_AND_confirm()
    test_a_wcvs_transcript_MAPS_TO_VERDICTS()
    test_a_hit_BECOMES_a_finding_detection_high_confirm_critical()
    test_STOP_IS_UNGATED()
    test_the_preview_PROBES_NOTHING_and_uses_the_same_functions()
    test_cache_adds_NO_NEW_GATE_to_the_executor()
    test_a_plain_cache_STILL_NEEDS_NO_RED_CONFIRM()
    print("ALL cache locks pass")
