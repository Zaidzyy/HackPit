"""SAFETY INVARIANTS for the bespoke evasion engine (build #4, item C).

This engine is the sharpest surface in HackPit: it BUILDS artifacts whose purpose is to be
harder to detect. What keeps it a purple-team tool rather than an evasion how-to is a short
list of properties, and these tests exist so that list cannot quietly erode:

  1. NO AGENT PATH — no orchestrator / loop / agent module can reach it. A human invokes it
     through the HTTP endpoint or not at all.
  2. GENERATE-ONLY — it never runs or deploys what it builds. The produced artifact path is
     never argv[0], and no deploy/execute primitive exists in the package.
  3. GATED — every build runs the SAME gates a one-shot command does: approval, scope, and
     the heuristic red-confirm. Both generators are in allowlist._FRAMEWORKS so the
     red-confirm always fires.
  4. NO SHELL, CONSTANT CONTAINER — argv lists only; the container comes from the resolved
     execution mode and can never be set by a request.
  5. FORCED HONESTY — every result carries the blue-view footprint AND an OPSEC note whose
     `still_recorded` names what catches it anyway. There is no flag to suppress either, and
     the engine RAISES rather than emit an artifact it cannot describe.
  6. AUDITED — every build is recorded.

Hermetic: no Docker, no LLM, no network.  Run:  python test_evasion_safety.py
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import allowlist, config, executor as EX, loot, runstore  # noqa: E402
from evasion import engine as G  # noqa: E402
from test_support import scans  # noqa: E402

BACKEND = Path(__file__).resolve().parent
PKG = BACKEND / "evasion"
SRC = (PKG / "engine.py").read_text(encoding="utf-8")
TREE = ast.parse(SRC)

# Files that are allowed to name the evasion package: the package itself, its tests, and the
# HTTP layer that exposes it. main.py holds the route because the cockpit and arsenal packages
# may not reference each other, so cross-cutting endpoints live there.
# Matched on the path RELATIVE TO backend/, not the basename: a bare-basename allowlist
# exempted every package's __init__.py from the scan, not just the evasion package's.
_ALLOWED = {"evasion/engine.py", "evasion/__init__.py", "test_evasion.py",
            "test_evasion_safety.py", "main.py"}
# Modules that must NEVER reach this engine, matched on filename. "plan" is here because a
# planner PROPOSES steps, which is the same hazard as an orchestrator running them.
_AGENT_MARKERS = ("orchestrat", "loop", "adorch", "agent", "propose", "plan")
# Matched as MODULE REFERENCES, not as the word. The AST pass is the load-bearing half — it
# sees an aliased import, an import opened inside a function body, and importlib/getattr
# indirection, none of which a regex can. The regexes are belt-and-braces for a qualified use.
_EVASION_PATTERNS = [r"^\s*(?:from|import)\s+evasion\b", r"\bevasion\.engine\b"]
_EVASION_AST_TARGETS = ["evasion", "evasion.engine"]


def _fn(tree: ast.AST, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name}() not found — a safety test is pinned to a symbol that moved")


def _call_names(fn: ast.FunctionDef) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


class _Spy:
    """Hermetic stand-in for everything the engine can reach outside itself."""

    def __init__(self, *, returncode: int = 0) -> None:
        self.returncode = returncode
        self.run_argv: list[list[str]] = []
        self.saved: list = []

    def __enter__(self) -> "_Spy":
        self._orig = (G.subprocess.run, runstore.save_run, loot.workdir_for,
                      EX.assert_isolation_proven)

        def fake_run(argv, **kw):
            self.run_argv.append(list(argv))
            return subprocess.CompletedProcess(argv, self.returncode, "ok", "")

        G.subprocess.run = fake_run
        runstore.save_run = lambda rec: self.saved.append(rec)
        loot.workdir_for = lambda mode, eid: (f"/loot/{eid}" if mode == "engagement" and eid
                                              else None)
        EX.assert_isolation_proven = lambda *a, **k: None
        return self

    def __exit__(self, *exc) -> None:
        (G.subprocess.run, runstore.save_run, loot.workdir_for,
         EX.assert_isolation_proven) = self._orig


def _req(**kw) -> G.EvasionRequest:
    base = dict(payload_path="/loot/in.exe", techniques=["donut-pack"],
                approved=True, dangerous_ack=True)
    base.update(kw)
    return G.EvasionRequest(**base)


# --------------------------------------------------------------------------- #
# 1. NO AGENT PATH
# --------------------------------------------------------------------------- #
def test_no_orchestrator_or_agent_path_to_evasion() -> None:
    """No module outside the allow-list may name the evasion engine.

    THE FILENAME FILTER IS GONE, and that was the last half of this defect. Build #4 fixed the
    COUNT (it used to increment before the filter, so `assert scanned > 40` reported 99 while 5
    files were really inspected) but kept the filter itself: only modules whose NAME contained
    orchestrat/loop/adorch/agent/propose/plan had their content read. `from evasion import
    engine` in cockpit/executor.py, chat.py or adgraph/techniques.py was never looked at.

    A module named something nobody predicted is exactly the case a name filter cannot cover,
    so there is no name filter. Every backend module is read; the allow-list names the files
    that legitimately reference the engine, keyed on repo-relative paths, and each of them is
    asserted to STILL match so a rename cannot quietly empty the patterns.

    THE PREDICATE TIGHTENED AT THE SAME TIME, and widening the file set is what forced it. The
    old check was a bare ``"evasion" in line``, which is fine over five hand-picked files and
    wrong over the whole tree: the detection package's ANTI-evasion guard — the code that
    REFUSES prescriptive evasion copy — says the word constantly and imports nothing. Flagging
    it would be a false positive, and the answer to a false positive is a better predicate, not
    a narrower file set. So the claim asserted is the one the invariant makes: no module reaches
    the engine, matched as an IMPORT (in every form the AST can see) or a qualified reference.
    """
    res = scans.scan_source_tree(
        patterns=_EVASION_PATTERNS, allowed=_ALLOWED, ast_targets=_EVASION_AST_TARGETS,
    )
    scans.assert_clean(
        res,
        what="an agent/orchestrator module reaches the evasion engine",
        # The two real orchestrators, plus the modules the old filename filter could never
        # reach — named explicitly so a rename fails HERE rather than silently losing coverage.
        must_have_scanned=["orchestrator.py", "adgraph/orchestrator.py", "cockpit/executor.py",
                           "cockpit/router.py", "chat.py", "adgraph/techniques.py",
                           "detection/resolver.py", "report.py"],
        min_checked=60,
        # main.py is the only allow-listed file that CAN match: the other two are the engine's
        # own package, and a module does not import itself. Demanding a control from them would
        # be a permanently-failing assertion, not a guarantee.
        require_controls=["main.py"],
    )
    scans.assert_catches_a_planted_violation(
        plant="from evasion import engine",
        patterns=_EVASION_PATTERNS, allowed=_ALLOWED, ast_targets=_EVASION_AST_TARGETS,
        where="cockpit/executor.py",
    )
    print(f"  all {len(res.checked)} backend modules content-scanned: ZERO path to evasion "
          "(+ planted-violation control): PASS")


def test_the_engine_imports_no_agent_module() -> None:
    for node in ast.walk(TREE):
        mod = ""
        if isinstance(node, ast.Import):
            mod = " ".join(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
        for marker in ("orchestrat", "loop", "adorch", "llm"):
            assert marker not in mod.lower(), f"the engine must not import {mod!r}"
    print("  the engine imports no orchestrator/loop/model module: PASS")


# --------------------------------------------------------------------------- #
# 2. GENERATE-ONLY
# --------------------------------------------------------------------------- #
def test_the_package_has_no_deploy_or_execute_primitive() -> None:
    for banned in ("def deploy", "def run_artifact", "def execute", "def upload",
                   "def deliver", "docker cp", "scp ", "Invoke-WebRequest"):
        assert banned not in SRC, f"the engine must have no delivery primitive (found {banned!r})"
    # argv-form too: a list-built `docker cp` would not match the substring above.
    for node in ast.walk(TREE):
        if isinstance(node, ast.List):
            lits = [e.value for e in node.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            assert lits[:2] != ["docker", "cp"], "argv-form `docker cp` is a delivery primitive"
    print("  no deploy / execute / delivery primitive exists in the package: PASS")


def test_the_artifact_is_never_executed() -> None:
    """Only the generator is exec'd; the produced path is never the program.

    The old form of the last assertion compared `artifact_path` to argv[3] — a filename against
    the string "donut" — which cannot fail. What has to hold is that the produced path appears
    ONLY as the value of an output flag, never in a program position.
    """
    with _Spy() as spy:
        res = G.generate(_req())
    assert len(spy.run_argv) == 1, spy.run_argv
    argv = spy.run_argv[0]
    assert argv[0] == "docker" and argv[1] == "exec"
    assert argv[3] in ("donut", "ScareCrow"), f"argv[3] must be the generator, got {argv[3]!r}"

    # The artifact path is present, and its ONLY occurrence is preceded by an output flag.
    assert res.artifact_path, "this build should have produced a path"
    positions = [i for i, tok in enumerate(argv) if tok == res.artifact_path]
    assert positions, f"the artifact path is not in the argv at all: {argv}"
    for i in positions:
        assert argv[i - 1] in ("-o", "-O"), (
            f"the artifact path appears at argv[{i}] after {argv[i - 1]!r} — it must only ever "
            f"be an output-flag VALUE, never a program or a bare operand: {argv}")
    # ...and nothing after `docker exec <container>` is the artifact.
    assert res.artifact_path != argv[3], "the artifact must never be the executed program"
    print("  only the generator runs; the artifact is an output value, never a program: PASS")


def test_stub_techniques_execute_nothing_at_all() -> None:
    for technique in ("amsi-patch", "etw-blind"):
        with _Spy() as spy:
            G.generate(_req(techniques=[technique]))
        assert not spy.run_argv, f"{technique} must not exec anything"
    print("  stub techniques exec nothing: PASS")


# --------------------------------------------------------------------------- #
# 3. GATED
# --------------------------------------------------------------------------- #
def test_generation_routes_through_the_real_gates() -> None:
    """validate_build must call the REAL executor gate, not a local copy."""
    calls = _call_names(_fn(TREE, "validate_build"))
    assert "validate_request" in calls, "the gate must be executor.validate_request itself"
    assert "validate_request" in _call_names(_fn(TREE, "generate")) or \
        "validate_build" in _call_names(_fn(TREE, "generate")), \
        "generate() must run the gate"
    print("  generation routes through executor.validate_request: PASS")


def test_both_generators_trip_the_red_confirm() -> None:
    """If a generator is not in _FRAMEWORKS the red-confirm never fires and the ack is a lie."""
    for binary in ("donut", "ScareCrow"):
        reasons = allowlist.dangerous_command_heuristic(binary, ["-i", "x", "-o", "y"])
        assert reasons, f"{binary} must be flagged dangerous or dangerous_ack is meaningless"
    print("  donut and ScareCrow both trip the danger heuristic: PASS")


def test_no_parameter_combination_escapes_the_red_confirm() -> None:
    """Brute-force the request surface: nothing may build without dangerous_ack.

    The old form varied technique x `target_os` — and `target_os` was a field no code read, so
    half the "combinations" were the same request twice. It now varies the fields that actually
    reach the argv or the gate. Every combination here is lab-valid, so the FIRST gate any of
    them can hit is the danger gate; a refusal at any other gate means this test stopped
    testing what it says it tests.
    """
    escaped = []
    combos = 0
    for technique in G.TECHNIQUES:
        for payload_path in ("/loot/in.exe", "", "nested/dir/in.exe"):
            for target in ("", config.LAB_TARGET_HOST):
                combos += 1
                req = _req(techniques=[technique], payload_path=payload_path,
                           target=target, dangerous_ack=False)
                with _Spy() as spy:
                    try:
                        G.generate(req)
                        escaped.append((technique, payload_path, target))
                    except G.EvasionRefused as exc:
                        assert exc.gate == "danger", (
                            f"{technique}/{payload_path!r}/{target!r}: refused by {exc.gate!r}, "
                            "not the red-confirm — this combination is no longer lab-valid and "
                            "the test is not exercising the danger gate")
                    assert not spy.run_argv, f"{technique}: nothing may run without the ack"
    assert not escaped, f"these combinations built with no red-confirm: {escaped}"
    print(f"  all {combos} technique/payload/target combinations demand the red-confirm: PASS")


# --------------------------------------------------------------------------- #
# 4. NO SHELL / CONSTANT CONTAINER
# --------------------------------------------------------------------------- #
def test_no_shell_and_the_container_is_a_code_constant() -> None:
    for token in ("shell=True", "os.system", "os.popen", "commands.getoutput", "pty.spawn"):
        assert token not in SRC, f"the engine must not use {token!r}"
    fields = set(G.EvasionRequest.model_fields)
    for banned in ("container", "sandbox", "image", "docker"):
        assert banned not in fields, f"a {banned!r} request field would break containment"
    # Every subprocess call is given a LIST, never a string.
    for node in ast.walk(TREE):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("run", "Popen") and node.args:
            assert isinstance(node.args[0], (ast.List, ast.Name)), \
                "subprocess must be handed an argv LIST, never a shell string"
    print("  no shell; the container is a code constant, not a request field: PASS")


def test_the_container_comes_from_the_resolved_mode() -> None:
    with _Spy() as spy:
        G.generate(_req())
    assert spy.run_argv[0][2] in (config.SANDBOX_CONTAINER, config.ENGAGE_SANDBOX_CONTAINER)
    print("  the container is whatever resolve_mode returned: PASS")


# --------------------------------------------------------------------------- #
# 5. FORCED HONESTY — the invariant this whole build turns on
# --------------------------------------------------------------------------- #
def test_every_result_carries_a_footprint_and_a_still_recorded_note() -> None:
    for technique in G.TECHNIQUES:
        with _Spy():
            res = G.generate(_req(techniques=[technique]))
        assert res.footprint.get("activity"), f"{technique}: blue footprint missing"
        assert res.opsec_note["still_recorded"].strip(), f"{technique}: honesty marker missing"
        assert res.footprint.get("blue_view"), f"{technique}: the defender's view is empty"
    print(f"  all {len(G.TECHNIQUES)} techniques emit a footprint + still_recorded note: PASS")


def test_the_honest_half_is_computed_before_anything_is_built() -> None:
    """Ordering matters: the engine must not build first and describe afterwards.

    Checked TWICE, because the lexical half alone is brittle. The AST check reads line order
    inside generate(), so extracting the subprocess call into a helper would remove `run` from
    the tree and the check would silently stop protecting anything — hence the explicit
    assertion that all three calls are still IN generate(). The runtime check then observes the
    real call order, which no refactor can fake.
    """
    fn = _fn(TREE, "generate")
    order: list[tuple[int, str]] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
            if name in ("_honest_footprint", "run", "Popen", "render_stub"):
                order.append((node.lineno, name))
    order.sort()
    names = [n for _, n in order]
    assert names and names[0] == "_honest_footprint", \
        f"_honest_footprint must be computed FIRST, got {names}"
    # If any of these moved out of generate(), the line-order check above is no longer looking
    # at the thing it claims to check. Fail loudly rather than pass vacuously.
    for required in ("_honest_footprint", "run", "render_stub"):
        assert required in names, (
            f"{required}() is no longer called directly inside generate() — the AST ordering "
            f"check has stopped covering it. Saw: {names}")

    # RUNTIME control-flow check: the honest half must actually be computed before the
    # generator is invoked, whatever the source layout looks like.
    seen: list[str] = []
    orig = G._honest_footprint
    try:
        def spy_footprint(techniques):
            seen.append("_honest_footprint")
            return orig(techniques)

        G._honest_footprint = spy_footprint
        with _Spy() as spy:
            spy_run = G.subprocess.run

            def watched(argv, **kw):
                seen.append("generator")
                return spy_run(argv, **kw)

            G.subprocess.run = watched
            G.generate(_req())
        assert seen == ["_honest_footprint", "generator"], \
            f"the honest half must be computed before the generator runs, got {seen}"
        assert spy.run_argv, "the generator should have been invoked in this check"
    finally:
        G._honest_footprint = orig
    print("  the honest half is computed before anything is generated (AST + runtime): PASS")


def test_a_missing_opsec_note_refuses_the_build() -> None:
    """Negative control: strip the note and the engine must refuse, not degrade."""
    from detection import resolver as det
    orig = det._opsec_grounded
    try:
        det._opsec_grounded = lambda key: None
        with _Spy() as spy:
            try:
                G.generate(_req())
                assert False, "a missing OPSEC note must refuse the build"
            except G.EvasionError as exc:
                assert "still records" in str(exc), exc
        assert not spy.run_argv and not spy.saved, "nothing may be built or recorded"
    finally:
        det._opsec_grounded = orig
    print("  a missing honesty marker REFUSES the build (negative control): PASS")


def test_there_is_no_switch_to_turn_the_footprint_off() -> None:
    for off in ("include_footprint", "no_footprint", "quiet", "suppress", "skip_footprint"):
        assert off not in G.EvasionRequest.model_fields, f"{off!r} must not exist"
        # Identifier form only — the word "quieter" legitimately appears in the module's own
        # prose (that is what the OPSEC channel is about); what must not exist is a NAME.
        for form in (f"{off}=", f"{off}:", f"{off} =", f'"{off}"', f"'{off}'"):
            assert form not in SRC, f"{off!r} must not exist as a name/field (found {form!r})"
    assert G.EvasionResult.model_fields["footprint"].is_required()
    assert G.EvasionResult.model_fields["opsec_note"].is_required()
    print("  the footprint has no off switch anywhere: PASS")


def test_every_stub_template_names_what_still_records_it() -> None:
    """The honesty travels WITH the artifact, so it survives leaving HackPit."""
    templates = sorted((PKG / "templates").glob("*.tmpl"))
    assert templates, "no stub templates found"
    for t in templates:
        text = t.read_text(encoding="utf-8").lower()
        assert "still sees" in text, f"{t.name}: must name what a defender still sees"
        assert "tradeoff" in text, f"{t.name}: must state the tradeoff"
    print(f"  all {len(templates)} stub templates carry the honesty header: PASS")


# --------------------------------------------------------------------------- #
# 6. AUDITED
# --------------------------------------------------------------------------- #
def test_every_build_is_audited_and_refusals_record_nothing() -> None:
    with _Spy() as spy:
        G.generate(_req())
    assert len(spy.saved) == 1 and spy.saved[0].command == "evasion-generate"
    with _Spy() as spy2:
        try:
            G.generate(_req(approved=False))
        except G.EvasionRefused:
            pass
    assert not spy2.saved, "a refused build must record nothing (it never ran)"
    print("  every build is audited; refusals run and record nothing: PASS")


# --------------------------------------------------------------------------- #
# 7. THE HTTP SURFACE adds no capability
# --------------------------------------------------------------------------- #
def test_the_http_routes_add_no_capability_and_always_return_the_footprint() -> None:
    """The routes must expose generate-only, and must not be able to hide the honest half."""
    import main

    routes = {(tuple(sorted(r.methods)), r.path) for r in main.app.routes
              if "/api/evasion" in getattr(r, "path", "")}
    paths = {p for _, p in routes}
    assert paths == {"/api/evasion/techniques", "/api/evasion/preview",
                     "/api/evasion/generate"}, f"unexpected evasion route set: {sorted(paths)}"

    # No route may deliver, deploy, execute or fetch an artifact.
    for verb in ("deploy", "deliver", "execute", "run", "upload", "download", "artifact"):
        assert not [p for p in paths if verb in p], f"an evasion route named {verb!r} must not exist"

    # The response model itself makes the honest half non-optional, so no route can omit it.
    assert G.EvasionResult.model_fields["footprint"].is_required()
    assert G.EvasionResult.model_fields["opsec_note"].is_required()

    # And the generate route really does declare that model as its response.
    gen = next(r for r in main.app.routes if getattr(r, "path", "") == "/api/evasion/generate")
    assert getattr(gen, "response_model", None) is G.EvasionResult, \
        "the generate route must return EvasionResult, which carries the mandatory footprint"
    print(f"  {len(paths)} /api/evasion routes: generate-only, footprint non-optional: PASS")


if __name__ == "__main__":
    test_no_orchestrator_or_agent_path_to_evasion()
    test_the_engine_imports_no_agent_module()
    test_the_package_has_no_deploy_or_execute_primitive()
    test_the_artifact_is_never_executed()
    test_stub_techniques_execute_nothing_at_all()
    test_generation_routes_through_the_real_gates()
    test_both_generators_trip_the_red_confirm()
    test_no_parameter_combination_escapes_the_red_confirm()
    test_no_shell_and_the_container_is_a_code_constant()
    test_the_container_comes_from_the_resolved_mode()
    test_every_result_carries_a_footprint_and_a_still_recorded_note()
    test_the_honest_half_is_computed_before_anything_is_built()
    test_a_missing_opsec_note_refuses_the_build()
    test_there_is_no_switch_to_turn_the_footprint_off()
    test_every_stub_template_names_what_still_records_it()
    test_every_build_is_audited_and_refusals_record_nothing()
    test_the_http_routes_add_no_capability_and_always_return_the_footprint()
    print("ALL evasion safety invariants hold")
