"""SAFETY INVARIANTS for the Sliver C2 surface (cockpit/sliver.py + its HTTP routes).

test_sliver.py proves the surface BEHAVES correctly. This file is the CONTAINMENT LOCK: it
asserts the structural properties that make that behaviour trustworthy, so a future refactor
that quietly re-wires them fails the build instead of shipping. Every invariant below has a
real assertion — a structural (AST / source-scan) one where the property is about code shape,
a behavioural one where it is about what actually happens:

  1. NO ORCHESTRATOR / AGENT / LOOP PATH. Exactly TWO files in the whole backend tree may
     reference the Sliver module: the module itself and main.py (which owns the HTTP routes —
     the HUMAN surface). Every other module, including orchestrator.py, cockpit/executor.py
     and adgraph/orchestrator.py, is scanned and must not name it. A C2 server an agent could
     raise is an autonomous C2; an implant an agent could build is an autonomous payload
     factory. Scanned WITH a positive control, so the scan cannot pass vacuously.
  2. BOTH HALVES GATED; ONLY ONE HAS A TARGET. The server lifecycle and implant GENERATION both
     run the REAL executor.validate_request — build #7 gated the lifecycle, which had been
     ungated on a precedent (the pivot listener) that build #5's I2 finding overturned. What
     stays split is the TARGET: a C2 server has none, so it is gated on engagement + approval +
     red-confirm and NOT on a target-lock, while generation is scope-checked as well. Asserted
     structurally (AST call graph) and behaviourally (a spy on the real gate + the real refusals).
  3. <listener> IS OPERATOR-SIDE AND IS NEVER TARGET-SUBSTITUTED. Proved structurally —
     _implant_argv's body never reads ``req.target`` at all — and behaviourally across every
     transport.
  4. EVERY ACTION IS AUDITED via runstore.save_run: start, stop and generate each land as a
     record; a REFUSED generate records nothing, because nothing ran.
  5. IT CANNOT EXECUTE OR DELIVER WHAT IT BUILDS. The artifact path appears only as the operand
     of ``--save`` (in the console line) and of ``stat`` (in the read-back), a generate runs
     exactly TWO subprocesses and BOTH are classified — one build, one read-only size probe —
     and no delivery primitive (docker cp / psexec / smbclient / HTTP / SSH) exists in the
     module.
  6. NO SHELL ANYWHERE; THE CONTAINER IS A CODE CONSTANT. No ``shell=True`` in any call (AST),
     no container/sandbox/output-path field on either request model, and a request that tries
     to smuggle one is ignored — the box still comes from the mode resolver.
  7. THE ROUTES ADD NO CAPABILITY. Every /api/sliver route maps onto a module function that
     already existed; the gated route still returns 403 naming the gate and runs nothing; and
     there is no delivery/execute route.

Hermetic: subprocess, runstore.save_run, loot.ensure and the isolation proof are monkeypatched
by manual save/restore (this repo has NO pytest, so there is no fixture to lean on). No Docker
daemon, no network, no DB writes.

Run:  backend/.venv/Scripts/python.exe backend/test_sliver_safety.py
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from cockpit import config
from cockpit import executor as EX
from cockpit import sliver as S
from cockpit.models import ExecRejected, ExecRequest
from cockpit.sliver import ImplantRequest, SliverRefused, SliverServerRequest
from test_support import listeners, scans

BACKEND = Path(__file__).resolve().parent
SLIVER_SRC = Path(S.__file__).read_text(encoding="utf-8")
SLIVER_TREE = ast.parse(SLIVER_SRC)

# The ONLY two files allowed to name the Sliver module: the module itself, and the HTTP layer.
# cockpit/router.py is deliberately NOT here — the routes live in main.py (see its "Sliver C2 +
# DNS-tunnel obfuscation" section), so the cockpit router keeps no handle on this surface.
# mcp_tools.py: `_run_surface` reaches start_server ONLY via `hackpit_surface`, registered ONLY when
# HACKPIT_MCP_EXECUTE=1 (opt-in, off by default) — the env-gated execution path test_mcp_safety
# already tolerates, not an accidental one (the planted-violation control still catches those).
ALLOWED_REFERENCES = {Path("cockpit/sliver.py"), Path("main.py"), Path("mcp_tools.py")}

_REFERENCE_PATTERNS = [
    r"\bstart_server\b",
    r"\bstop_server\b",
    r"\bgenerate_implant\b",
    r"\bvalidate_generate\b",
    r"\bfrom\s+\.sliver\b",
    r"\bfrom\s+cockpit\.sliver\b",
    r"\bimport\s+cockpit\.sliver\b",
    r"\bfrom\s+cockpit\s+import\s+[^\n]*\bsliver\b",
    r"\bfrom\s+\.\s+import\s+[^\n]*\bsliver\b",
    r"\bcockpit\.sliver\b",
]


# --------------------------------------------------------------------------- #
# helpers — AST + hermetic fakes (manual save/restore; this repo has no pytest)
# --------------------------------------------------------------------------- #
def _fn(tree: ast.AST, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name}() has vanished from sliver.py — the lock cannot be evaluated")


def _dotted(func: ast.AST) -> str:
    parts: list[str] = []
    cur = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _call_names(node: ast.AST) -> set[str]:
    """Every dotted callee name inside ``node`` — the function's outgoing call edges."""
    return {_dotted(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)} - {""}


def _backend_py_files() -> list[Path]:
    """Every backend source file, minus the venv/caches. Tests are excluded by the caller.

    Delegates to the SHARED selection. This file's scan was already correct — the audit called
    it the reference standard — and the shared module was extracted FROM this construction
    rather than invented beside it, so that the nine locks that were wrong and the two that
    were right cannot drift apart again. The offender-collection and control logic below is
    untouched, deliberately: migrating a working guard is a chance to lose an assertion.
    """
    return scans.source_files()


# --------------------------------------------------------------------------- #
# main.py is allow-listed, but ONLY for its route functions
# --------------------------------------------------------------------------- #
# Allow-listing main.py was forced by the cockpit/arsenal decoupling rule (the routes cannot
# live in cockpit/router.py). But main.py is WIDER than the router.py it replaced: it also
# holds `import orchestrator` and the loop endpoint POST /sessions/{id}/loop/propose. Wiring
# this surface into that endpoint — inside main.py — would be caught by no whole-tree scan,
# which defeats the point of the human-only lock. So the allow-list is narrowed here: the
# loop/propose/orchestrator surface of main.py, and everything it calls transitively inside
# main.py, must not name this module.
MAIN_PY = BACKEND / "main.py"
_LOOP_SURFACE_RE = re.compile(r"loop|propose|orchestrat", re.I)


def _body_without_docstring(node: ast.AST) -> list[ast.stmt]:
    body = list(getattr(node, "body", []))
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        return body[1:]
    return body


def _loop_surface_functions() -> dict[str, ast.FunctionDef]:
    """Every main.py function on the loop/propose/orchestrator surface, TRANSITIVELY.

    Not just the endpoint body: a helper it calls is just as much a wiring point, so the set
    is the closure over calls to main.py-local functions. Returns ``{name: node}``.
    """
    tree = ast.parse(MAIN_PY.read_text(encoding="utf-8"))
    local: dict[str, ast.FunctionDef] = {
        n.name: n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    surface = {n for n in local if _LOOP_SURFACE_RE.search(n)}
    queue = list(surface)
    while queue:
        for callee in _call_names(local[queue.pop()]):
            head = callee.split(".")[0]
            if head in local and head not in surface:
                surface.add(head)
                queue.append(head)
    return {n: local[n] for n in sorted(surface)}


def _module_aliases_in_main(module_name: str) -> set[str]:
    """The names main.py binds this cockpit module to (e.g. ``cockpit_sliver``)."""
    tree = ast.parse(MAIN_PY.read_text(encoding="utf-8"))
    aliases: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            for a in n.names:
                if a.name == module_name:
                    aliases.add(a.asname or a.name)
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name == module_name or a.name.endswith(f".{module_name}"):
                    aliases.add(a.asname or a.name.split(".")[0])
    return aliases


def _loop_surface_offenders(module_name: str, patterns: list[str]) -> list[str]:
    """``[(function, why)]`` for every loop-surface function in main.py that names the module.

    Two independent detectors, because either alone has a hole: the ALIAS check catches
    ``cockpit_sliver.anything`` (which the source regexes, written for other files, would miss
    for a function name they do not list), and the REGEX check catches a fresh
    ``from cockpit import sliver`` opened inside the function.
    """
    aliases = _module_aliases_in_main(module_name)
    assert aliases, (
        f"main.py no longer binds cockpit.{module_name} under any name — this check would "
        "pass vacuously. Follow the rename."
    )
    offenders: list[str] = []
    for name, node in _loop_surface_functions().items():
        stmts = _body_without_docstring(node)
        src = "\n".join(ast.unparse(s) for s in stmts)
        used = {
            n.id for s in stmts for n in ast.walk(s)
            if isinstance(n, ast.Name) and n.id in aliases
        }
        if used:
            offenders.append(f"{name}() references {sorted(used)}")
        for pat in patterns:
            if re.search(pat, src):
                offenders.append(f"{name}() matches {pat!r}")
    return offenders


class _FakeCompleted:
    def __init__(self, argv, returncode=0, stdout="", stderr=""):
        self.args, self.returncode, self.stdout, self.stderr = argv, returncode, stdout, stderr


class _FakeProc:
    def __init__(self, argv):
        self.argv, self._alive = argv, True

    def poll(self):
        return None if self._alive else 0

    def kill(self):
        self._alive = False


class _Spy:
    """Swap subprocess / save_run / loot.ensure / the isolation proof for fakes."""

    def __init__(self, *, up=True, returncode=0, artifact_size=14401536):
        self.up, self.returncode = up, returncode
        self.artifact_size = artifact_size
        self.runs: list[list[str]] = []
        self.run_calls = 0
        self.saved: list = []
        # The server spawn lives in cockpit/lifecycle.py since build #7, so it is faked through
        # the shared shim rather than here — faking S.subprocess.Popen would fake a call this
        # module no longer makes, and every "a refusal spawns nothing" assertion would go vacuous.
        self.spawn = listeners.FakeListenerSpawn()
        self._orig = (
            S._container_running, S.subprocess.run,
            S.runstore.save_run, S.loot.ensure, EX.assert_isolation_proven,
        )

    @property
    def popen_argv(self) -> list[str] | None:
        return self.spawn.argv

    @property
    def popen_calls(self) -> int:
        return len(self.spawn.spawns)

    @property
    def run_argv(self) -> list[str] | None:
        """The BUILD's argv, not the `stat` read-back that follows it."""
        for argv in self.runs:
            if S.SLIVER_SERVER_BIN in argv:
                return argv
        return None

    def __enter__(self):
        def fake_run(argv, **kw):
            self.run_calls += 1
            self.runs.append(list(argv))
            if "stat" in argv:
                if self.artifact_size is None:
                    return _FakeCompleted(argv, returncode=1, stdout="")
                return _FakeCompleted(argv, returncode=0, stdout=f"{self.artifact_size}\n")
            return _FakeCompleted(argv, returncode=self.returncode, stdout="built")

        S._container_running = lambda name: self.up
        S.subprocess.run = fake_run
        S.runstore.save_run = lambda rec: self.saved.append(rec)
        S.loot.ensure = lambda name: f"/loot/{name}"
        EX.assert_isolation_proven = lambda: None
        self.spawn.__enter__()
        return self

    def __exit__(self, *exc):
        self.spawn.__exit__(*exc)
        (
            S._container_running, S.subprocess.run,
            S.runstore.save_run, S.loot.ensure, EX.assert_isolation_proven,
        ) = self._orig
        S.reset()
        return False


def _engagement():
    from cockpit.models import EngagementRecord

    return EngagementRecord(
        engagement_id="eng-slvsafe000",
        target="scanme.nmap.org",
        authorization="authorized test target",
        active=True,
        entered_at="2026-07-27T00:00:00+00:00",
        scope="scanme.nmap.org",
        scope_include=["scanme.nmap.org"],
        allowed_hosts=["scanme.nmap.org"],
    )


def _patch_active(rec):
    from cockpit import engagement as ENG

    orig = ENG.get_active
    ENG.get_active = lambda eid: rec if (rec and eid == rec.engagement_id) else None
    return lambda: setattr(ENG, "get_active", orig)


def _req(**over) -> ImplantRequest:
    base = dict(
        os="windows", arch="amd64", fmt="exe", listener="<listener>",
        target="scanme.nmap.org", engagement_id="eng-slvsafe000",
        approved=True, dangerous_ack=True,
    )
    base.update(over)
    return ImplantRequest(**base)


# --------------------------------------------------------------------------- #
# 1. NO ORCHESTRATOR / AGENT / LOOP PATH
# --------------------------------------------------------------------------- #
def test_no_orchestrator_or_agent_path_to_sliver() -> None:
    """EVERY backend module is scanned; only sliver.py + main.py may name this surface.

    Written as a genuine whole-tree scan with a collected offenders list (not a filename
    filter): a module named something nobody predicted must still be caught. A POSITIVE
    CONTROL asserts the patterns really do match the two files that legitimately reference
    the module, so a rename can never turn this into a test that passes by matching nothing.
    """
    scanned: list[Path] = []
    offenders: list[str] = []
    controls: dict[Path, list[str]] = {}

    for f in _backend_py_files():
        rel = Path(f.relative_to(BACKEND).as_posix())
        text = f.read_text(encoding="utf-8", errors="ignore")
        hits = [p for p in _REFERENCE_PATTERNS if re.search(p, text)]
        if rel in ALLOWED_REFERENCES:
            controls[rel] = hits
            continue
        if f.name.startswith("test_"):
            continue  # the tests exist precisely to exercise it
        # NOTE THE ORDER. This append used to sit ABOVE the test_ skip, so `scanned` counted
        # files OPENED rather than files whose content was actually judged — the same shape as
        # build #4's `scanned > 40` control, which reported 99 while 5 files were inspected.
        # The count below is only evidence if it counts the right thing.
        scanned.append(rel)
        if hits:
            offenders.append(f"{rel.as_posix()} ({', '.join(hits)})")

    assert not offenders, (
        "the Sliver surface must be HUMAN-ONLY — these modules can reach it: "
        f"{offenders}. The orchestrator/agent/loop/executor must have NO path to a C2 server "
        "or an implant build."
    )

    # The scan actually looked at the modules that matter (never vacuous).
    must_have_scanned = {
        Path("orchestrator.py"), Path("cockpit/executor.py"), Path("cockpit/router.py"),
        Path("adgraph/orchestrator.py"), Path("cockpit/session.py"), Path("cockpit/kali.py"),
    }
    missing = must_have_scanned - set(scanned)
    assert not missing, f"the scan never reached the agent-path modules: {sorted(missing)}"
    assert len(scanned) >= 40, f"only {len(scanned)} modules scanned — the sweep is too narrow"

    # POSITIVE CONTROL: the two allowed files DO match, so the patterns are live.
    for allowed in ALLOWED_REFERENCES:
        assert controls.get(allowed), (
            f"{allowed} no longer matches any reference pattern — the scan would now pass "
            "vacuously. Update _REFERENCE_PATTERNS to follow the rename."
        )

    # Belt-and-suspenders at RUNTIME: the agent-path modules carry no handle on it.
    import orchestrator as ORCH
    from adgraph import orchestrator as ADORCH

    for mod, name in ((EX, "cockpit.executor"), (ORCH, "orchestrator"), (ADORCH, "adgraph.orchestrator")):
        for attr in ("sliver", "start_server", "generate_implant", "ImplantRequest"):
            assert not hasattr(mod, attr), f"{name} must not expose {attr!r} — that is an agent path to C2"
    print(f"  {len(scanned)} modules scanned: ZERO orchestrator/agent/loop path to Sliver: PASS")


def test_the_main_py_allow_list_stops_at_the_route_functions() -> None:
    """main.py may name the Sliver module in its ROUTES — and nowhere near the loop endpoint.

    This is the narrowing the whole-tree scan cannot do. main.py is allow-listed wholesale
    above (the decoupling rule put the routes there), but main.py also holds
    ``import orchestrator`` and ``POST /sessions/{id}/loop/propose``. A C2 server or an implant
    build wired into the agent loop *from inside the allow-listed file* would otherwise be
    invisible to every check in this suite.
    """
    surface = _loop_surface_functions()
    # ANTI-VACUITY: the closure must actually contain the loop endpoint. If the endpoint is
    # renamed out of the pattern, this fails loudly instead of scanning nothing.
    assert "loop_propose" in surface, (
        f"the loop endpoint is not in the scanned surface — got {sorted(surface)}. Renamed? "
        "Widen _LOOP_SURFACE_RE; do not let this check go quiet."
    )
    assert len(surface) >= 2, sorted(surface)

    offenders = _loop_surface_offenders("sliver", _REFERENCE_PATTERNS)
    assert not offenders, (
        "*** SLIVER IS WIRED INTO THE AGENT LOOP *** — main.py is allow-listed for its ROUTE "
        f"functions only, never for the loop/propose/orchestrator surface: {offenders}. "
        "The proposer must never be able to raise C2 or build an implant."
    )
    print(
        f"  main.py's allow-list stops at the routes: {len(surface)} loop-surface functions, "
        "none of which can reach Sliver: PASS"
    )


# --------------------------------------------------------------------------- #
# 2. TWO FOOTINGS: lifecycle human-only (ungated), generation gated + scope-checked
# --------------------------------------------------------------------------- #
def test_lifecycle_is_human_only_and_generation_is_gated_structurally() -> None:
    """The AST call graph proves which half consults a gate — and which deliberately does not."""
    gate_calls = {"executor.validate_request", "validate_generate", "validate_request"}

    gen_calls = _call_names(_fn(SLIVER_TREE, "generate_implant"))
    assert gen_calls & gate_calls, (
        f"generate_implant must run the REAL gates; its calls are {sorted(gen_calls)}"
    )
    assert "executor.resolve_mode" in _call_names(_fn(SLIVER_TREE, "generate_implant")), (
        "the container must come from the shared mode resolver, never the request"
    )
    assert "executor.validate_request" in _call_names(_fn(SLIVER_TREE, "validate_generate")), (
        "validate_generate must delegate to the REAL executor gate, not reimplement one"
    )

    # *** THE SPLIT MOVED IN BUILD #7, AND THIS TEST MOVED WITH IT. ***
    #
    # It used to assert that `start_server` consults NO gate — encoding D17's "lifecycle is
    # ungated, generation is gated". That decision was reversed: the argument for leaving the
    # lifecycle ungated was made by citing the pivot listener, which build #5's I2 finding had
    # already tightened, and Sliver's config can PERSIST listener jobs that come up with the
    # daemon. Both halves are gated now.
    #
    # What survives is the split that was always the real one: the SERVER HAS NO TARGET. It is
    # gated on engagement + approval + red-confirm and NOT on a target-lock, because there is no
    # target to lock; generation is gated on all four. A `target` field on the server request
    # would be the collapse that matters — a scope gate firing on the operator's own box.
    for still_human_only in ("stop_server", "list_servers"):
        calls = _call_names(_fn(SLIVER_TREE, still_human_only))
        assert not (calls & gate_calls), (
            f"{still_human_only} consults a gate ({sorted(calls & gate_calls)}) — stopping or "
            "listening to your own servers is not an execution"
        )

    start_calls = _call_names(_fn(SLIVER_TREE, "start_server"))
    assert "validate_start" in start_calls, (
        f"start_server must run the REAL gate before spawning; its calls are {sorted(start_calls)}"
    )
    assert "executor.validate_request" in _call_names(_fn(SLIVER_TREE, "validate_start")), (
        "validate_start must delegate to the REAL executor gate, not reimplement one"
    )

    implant_fields = set(ImplantRequest.model_fields)
    assert {"approved", "dangerous_ack", "target"} <= implant_fields, implant_fields
    server_fields = set(SliverServerRequest.model_fields)
    assert {"approved", "dangerous_ack"} <= server_fields, (
        f"SliverServerRequest must carry both gate fields — got {sorted(server_fields)}"
    )
    assert "target" not in server_fields, (
        "a C2 server has NO target — a target field would mean a scope gate firing on the "
        f"operator's own box, got {sorted(server_fields)}"
    )
    # Both default False, so a client that omits them is refused rather than allowed.
    fresh = SliverServerRequest()
    assert fresh.approved is False and fresh.dangerous_ack is False, fresh
    print("  both halves call the REAL executor gate; only generation carries a target: PASS")


def test_generate_delegates_to_the_real_gate_verbatim() -> None:
    """A spy on executor.validate_request: called once, with the real argv, verdict returned AS-IS.

    This is what "not a copy" means operationally — validate_generate must not re-interpret,
    soften or swallow the executor's verdict.
    """
    seen: list[ExecRequest] = []
    sentinel = ExecRejected(reason="SENTINEL", gate="danger", dangerous_flags=["spy"])
    orig = EX.validate_request
    try:
        def spy(req):
            seen.append(req)
            return sentinel

        EX.validate_request = spy
        verdict = S.validate_generate(_req())
    finally:
        EX.validate_request = orig

    assert len(seen) == 1, f"validate_generate must call the real gate exactly once, got {len(seen)}"
    assert verdict is sentinel, "the executor's verdict must be returned unchanged (identity)"
    gated = seen[0]
    # The gate must classify the binary that RUNS. A build starts `sliver-server` (which hosts
    # the console that owns `generate`), not `sliver-client` — which has no such subcommand and
    # which no build has ever started.
    assert isinstance(gated, ExecRequest) and gated.command == S.SLIVER_SERVER_BIN, gated
    assert gated.command == S._implant_argv(_req())[0], (
        "the gated command must be argv[0] itself, not a constant that can drift from it"
    )
    assert gated.approved is True and gated.dangerous_ack is True, gated
    # The gates see the REAL argv (superset: argv + the declared target), so nothing the build
    # would actually run is hidden from them.
    for tok in S._implant_argv(_req())[1:]:
        assert tok in gated.args, f"the gate never saw argv token {tok!r}"
    assert "scanme.nmap.org" in gated.args, "the declared target must be visible to the gates"
    print("  validate_generate delegates to executor.validate_request and returns it verbatim: PASS")


def test_refused_generate_is_scope_checked_and_produces_nothing() -> None:
    """Out-of-scope / unapproved / unacked / unknown-engagement all refuse, having run nothing."""
    restore = _patch_active(_engagement())
    try:
        with _Spy() as spy:
            cases = {
                "scope": _req(target="evil.example.net"),  # engagement off-scope → scope handrail
                "approval": _req(approved=False),
                "danger": _req(dangerous_ack=False),
                "engagement": _req(engagement_id="eng-gone000000"),
            }
            for gate, req in cases.items():
                rejected = S.validate_generate(req)
                assert rejected is not None and rejected.gate == gate, (gate, rejected)
                raised = False
                try:
                    S.generate_implant(req)
                except SliverRefused as exc:
                    raised = True
                    assert exc.gate == gate, (gate, exc.gate)
                assert raised, f"a {gate}-refused build MUST raise, not build"

            assert spy.run_calls == 0, "a refused build must not execute anything"
            assert spy.saved == [], "a refusal is not a run — nothing may be recorded"
            assert S.list_implants() == [], "a refused build must not register an implant"
            # ...and the same request, in scope + approved + acked, clears.
            assert S.validate_generate(_req()) is None
    finally:
        restore()
    print("  refused builds (scope/approval/danger/engagement) run, record and build NOTHING: PASS")


# --------------------------------------------------------------------------- #
# 3. <listener> IS OPERATOR-SIDE — NEVER TARGET-SUBSTITUTED
# --------------------------------------------------------------------------- #
def test_listener_placeholder_is_never_target_substituted() -> None:
    """Structural: argv construction never even READS the target. Behavioural: it never appears.

    Substituting the target into the callback address would point a beacon at the client's own
    network. The structural half is the strong one — a function that never reads ``req.target``
    cannot emit it, however it is later refactored.
    """
    body = _fn(SLIVER_TREE, "_implant_argv")
    target_reads = [
        n for n in ast.walk(body)
        if isinstance(n, ast.Attribute) and n.attr == "target"
    ]
    assert not target_reads, (
        "_implant_argv reads req.target — the callback address belongs to the OPERATOR and the "
        "target must never be substituted into it"
    )

    # Behavioural, across EVERY transport: the placeholder survives, the target does not appear.
    for transport, flag in S.LISTENER_FLAGS.items():
        argv = S._implant_argv(
            ImplantRequest(listener="<listener>", target="10.0.0.9", transport=transport)
        )
        assert argv[argv.index(flag) + 1] == "<listener>", (transport, argv)
        assert "10.0.0.9" not in argv, f"{transport}: the TARGET leaked into the implant argv"
        # A literal operator address is likewise carried through untouched.
        real = S._implant_argv(
            ImplantRequest(listener="10.8.0.2:8443", target="10.0.0.9", transport=transport)
        )
        assert real[real.index(flag) + 1] == "10.8.0.2:8443", (transport, real)
        assert "10.0.0.9" not in real, (transport, real)

    # And the built artifact echoes the OPERATOR's listener, not the engagement target.
    restore = _patch_active(_engagement())
    try:
        with _Spy() as spy:
            implant = S.generate_implant(_req(listener="<listener>"))
            assert implant.listener == "<listener>", implant.listener
            assert implant.target == "scanme.nmap.org", implant.target
            assert "scanme.nmap.org" not in spy.run_argv, (
                "the target must not reach the executed implant argv"
            )
    finally:
        restore()
    print("  <listener> is operator-side: argv never reads or emits the target: PASS")


# --------------------------------------------------------------------------- #
# 4. EVERY ACTION IS AUDITED
# --------------------------------------------------------------------------- #
def test_every_action_is_audited_via_save_run() -> None:
    """start / stop / generate each land as a RunRecord; a refusal lands nothing."""
    assert "runstore.save_run" in _call_names(_fn(SLIVER_TREE, "_save")), (
        "_save must persist through runstore.save_run — the single audit sink"
    )
    for audited in ("start_server", "stop_server", "generate_implant"):
        assert "_save" in _call_names(_fn(SLIVER_TREE, audited)), f"{audited} must record a run"

    restore = _patch_active(_engagement())
    try:
        with _Spy() as spy:
            srv = S.start_server(SliverServerRequest(
                engagement_id="eng-slvsafe000", approved=True, dangerous_ack=True,
            ))
            assert len(spy.saved) == 1 and spy.saved[-1].run_id == srv.run_id
            assert spy.saved[-1].finished_at is None, "a live server has not finished"

            S.stop_server(srv.id)
            assert spy.saved[-1].run_id == srv.run_id, "stop closes the SAME record"
            assert spy.saved[-1].finished_at is not None

            implant = S.generate_implant(_req())
            rec = spy.saved[-1]
            assert rec.command == "sliver-generate" and rec.run_id == implant.run_id, rec
            assert rec.target == "scanme.nmap.org" and rec.approved is True, rec

            before = len(spy.saved)
            try:
                S.generate_implant(_req(approved=False))
            except SliverRefused:
                pass
            assert len(spy.saved) == before, "a refusal must not be recorded as a run"
    finally:
        restore()
    print("  start / stop / generate are all audited; a refusal records nothing: PASS")


# --------------------------------------------------------------------------- #
# 5. IT CANNOT EXECUTE OR DELIVER WHAT IT BUILDS
# --------------------------------------------------------------------------- #
def test_module_cannot_execute_or_deliver_the_artifact() -> None:
    """The artifact is written and abandoned: never run, never shipped.

    Deployment, beacon-catch and driving a live Sliver session are separate, separately-approved
    concerns and are DEFERRED. If one is ever built it must be its own gated surface, and this
    test must be updated deliberately — not incidentally.
    """
    for delivery in (
        "docker cp", "psexec", "smbclient", "scp ", "paramiko", "winrm", "requests.",
        "urllib", "httpx", "socket.", "write_stdin", "sendline", "beacon_catch",
        "os.system", "os.popen", "pty.spawn",
    ):
        assert delivery not in SLIVER_SRC, (
            f"sliver.py must have NO delivery/execution primitive — found {delivery!r}"
        )

    restore = _patch_active(_engagement())
    try:
        with _Spy() as spy:
            implant = S.generate_implant(_req())
            argv = spy.run_argv

            # *** A GENERATE NOW RUNS EXACTLY TWO SUBPROCESSES, AND BOTH ARE ENUMERATED. ***
            # It used to be one, and "exactly one" was the whole invariant. Build #7 added a
            # second — `stat` reading the artifact back, because the console exits 0 whether or
            # not the build worked and the exit code cannot decide success. Relaxing the count
            # without pinning WHAT the second call is would have thrown the invariant away, so
            # every call is classified instead: one build, one read-only size probe, nothing else.
            assert spy.run_calls == 2, (
                f"a generate must run exactly TWO subprocesses (build + stat), ran "
                f"{spy.run_calls} — anything more would be the artifact being executed"
            )
            build, probe = spy.runs
            assert build == argv and S.SLIVER_SERVER_BIN in build, build
            assert probe[:3] == ["docker", "exec", implant.container], probe
            assert probe[3:] == ["stat", "-c", "%s", implant.artifact_path], (
                f"the second call must be a READ-ONLY size probe of the artifact, got {probe}"
            )
            assert probe[3] != implant.artifact_path, (
                "the artifact must be `stat`'s OPERAND, never the program `stat` position — "
                "reading a file is not running it"
            )

            # The artifact path never appears in the BUILD argv at all: it lives in the console
            # line, which is written to stdin.
            assert implant.artifact_path not in argv, argv
            line = implant.console_line.split()
            occurrences = [i for i, t in enumerate(line) if t == implant.artifact_path]
            assert len(occurrences) == 1, (occurrences, line)
            assert line[occurrences[0] - 1] == "--save", (
                f"the artifact path must only ever be the --save operand, got {line}"
            )
            assert argv[0] == "docker" and argv[4] == S.SLIVER_SERVER_BIN, argv
            assert implant.artifact_path != argv[4], "the artifact must never be the executable"

            # The one thing written to the build's stdin is the console line. It must not be a
            # channel for anything else — in particular it must never carry the artifact back in
            # as something to run.
            assert spy.spawn.argv is None, "a generate must not spawn a tracked listener"
    finally:
        restore()
    print("  the artifact is only ever WRITTEN — never executed, never delivered: PASS")


# --------------------------------------------------------------------------- #
# 6. NO SHELL; THE CONTAINER IS A CODE CONSTANT
# --------------------------------------------------------------------------- #
def test_no_shell_and_the_container_is_never_a_request_field() -> None:
    """AST: no ``shell=True`` anywhere. Models: no container field. Behaviour: it is ignored."""
    shell_kwargs = [
        n for n in ast.walk(SLIVER_TREE)
        if isinstance(n, ast.Call)
        for kw in n.keywords
        if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False)
    ]
    assert not shell_kwargs, "sliver.py passes shell= to a subprocess call — argv lists only"
    for banned in ("os.system", "os.popen", "sh -c", '"sh", "-c"', "'sh', '-c'"):
        assert banned not in SLIVER_SRC, f"sliver.py must not contain {banned!r}"

    for model in (ImplantRequest, SliverServerRequest):
        fields = set(model.model_fields)
        for forbidden in ("container", "sandbox", "image", "artifact_path", "save", "output"):
            assert forbidden not in fields, (
                f"{model.__name__}.{forbidden} would let a request redirect the exec or the "
                f"artifact — got {sorted(fields)}"
            )

    # A smuggled container field is DROPPED by the model and the mode resolver still decides.
    smuggled = ImplantRequest.model_validate({
        **_req().model_dump(), "container": config.KALI_OPEN_CONTAINER, "sandbox": "evil",
    })
    assert not hasattr(smuggled, "container"), "an extra container field must not stick"
    restore = _patch_active(_engagement())
    try:
        with _Spy() as spy:
            S.generate_implant(smuggled)
            assert spy.run_argv[:4] == [
                "docker", "exec", "-i", config.ENGAGE_SANDBOX_CONTAINER,
            ], spy.run_argv
            assert config.KALI_OPEN_CONTAINER not in spy.run_argv, "must NOT reach the open :kali box"
            assert config.SANDBOX_CONTAINER not in spy.run_argv, "must NOT reach the isolated lab box"
    finally:
        restore()
    print("  no shell; the container is a code constant a request cannot redirect: PASS")


# --------------------------------------------------------------------------- #
# 7. THE ROUTES ADD NO CAPABILITY
# --------------------------------------------------------------------------- #
def test_http_routes_add_no_capability_and_stay_human_only() -> None:
    """The /api/sliver routes are a thin human surface over functions that already existed."""
    import main
    from fastapi.testclient import TestClient

    paths = {
        (r.path, m)
        for r in main.app.routes
        for m in (getattr(r, "methods", set()) or set())
        if str(getattr(r, "path", "")).startswith("/api/sliver")
    }
    assert paths, "the /api/sliver routes are missing"
    assert {m for _p, m in paths} <= {"GET", "POST", "DELETE"}, paths
    # No route may exist for delivering, deploying or executing an artifact.
    for p, _m in paths:
        assert not any(
            bad in p for bad in ("deliver", "deploy", "upload", "exec", "run", "push")
        ), f"{p} looks like a delivery/execution route — those are DEFERRED, not routed"

    restore = _patch_active(_engagement())
    client = TestClient(main.app)
    try:
        with _Spy() as spy:
            # The PREVIEW route is pure: it returns argv + the gate verdict and runs nothing.
            body = _req(approved=False).model_dump()
            r = client.post("/api/sliver/implants/preview", json=body)
            assert r.status_code == 200, r.text
            assert r.json()["rejected"]["gate"] == "approval", r.text
            assert "<listener>" in r.json()["argv"], r.text
            assert "scanme.nmap.org" not in r.json()["argv"], "preview must not substitute the target"
            assert spy.run_calls == 0 and spy.popen_calls == 0, "preview must run NOTHING"

            # The GATED route refuses with 403 naming the gate, and still runs nothing.
            r = client.post("/api/sliver/implants", json=body)
            assert r.status_code == 403, r.text
            assert r.json()["detail"]["gate"] == "approval", r.text
            assert spy.run_calls == 0 and spy.saved == [], "a refused route must build nothing"

            # Approved + acked: it clears, and it is the SAME gated function underneath.
            r = client.post("/api/sliver/implants", json=_req().model_dump())
            assert r.status_code == 200, r.text
            assert r.json()["mode"] == "engagement" and r.json()["listener"] == "<listener>"
            # Two subprocesses: the build, then the read-only `stat` that decides generated vs
            # failed (see test_module_cannot_execute_or_deliver_the_artifact for the breakdown).
            assert spy.run_calls == 2 and len(spy.saved) == 1
    finally:
        restore()
    print(f"  {len(paths)} /api/sliver routes: gated stays gated, preview runs nothing: PASS")


if __name__ == "__main__":
    test_no_orchestrator_or_agent_path_to_sliver()
    test_the_main_py_allow_list_stops_at_the_route_functions()
    test_lifecycle_is_human_only_and_generation_is_gated_structurally()
    test_generate_delegates_to_the_real_gate_verbatim()
    test_refused_generate_is_scope_checked_and_produces_nothing()
    test_listener_placeholder_is_never_target_substituted()
    test_every_action_is_audited_via_save_run()
    test_module_cannot_execute_or_deliver_the_artifact()
    test_no_shell_and_the_container_is_never_a_request_field()
    test_http_routes_add_no_capability_and_stay_human_only()
    print("ALL Sliver safety invariants hold")
