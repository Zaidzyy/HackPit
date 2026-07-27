"""SAFETY INVARIANTS for the DNS-tunnel obfuscation surface (cockpit/obfuscation.py + routes).

test_obfuscation.py proves the surface BEHAVES correctly. This file is the CONTAINMENT LOCK:
it asserts the structural properties that make that behaviour trustworthy, so a refactor that
quietly re-wires them fails the build. Every invariant has a real assertion — structural
(AST / source-scan) where the property is about code shape, behavioural where it is about what
actually happens:

  1. NO ORCHESTRATOR / AGENT / LOOP PATH. Exactly TWO files in the backend tree may reference
     the module: itself and main.py (the HTTP layer — the HUMAN surface). Every other module,
     orchestrator.py / cockpit/executor.py / adgraph/orchestrator.py included, is scanned and
     must not name it. A covert channel an agent could raise is an autonomous covert channel.
     Scanned WITH a positive control, so the scan cannot pass vacuously.
  2. THE LIFECYCLE IS HUMAN-ONLY AND UNGATED BY DESIGN. There is no target, so there is
     nothing to scope-check: the AST call graph must show NO gate call in start/stop, and the
     request must carry no approval/red-confirm/target field. (Contrast Sliver, whose implant
     GENERATION is gated — that surface has an artifact aimed at someone else's machine.)
  3. *** THE CLIENT HALF IS NEVER DELIVERED. *** operator_oneliner is a pure string builder —
     asserted at the AST level (its only calls are list/string construction) — and the module
     contains NO delivery primitive at all: no file copy, no stdin pipe, no HTTP/SSH/SMB.
  4. THE ZONE AND TUNNEL NET ARE OPERATOR-OWNED AND ARE NEVER TARGET-SUBSTITUTED. The request
     has no target field, and the catalog's <tunnel-zone>/<tunnel-net> placeholders survive the
     composer's real target-substitution pass untouched — the same property <listener> has.
  5. EVERY ACTION IS AUDITED via runstore.save_run, with the operator's pre-shared key REDACTED
     in the record.
  6. NO SHELL ANYWHERE; THE CONTAINER IS A CODE CONSTANT a request cannot redirect.
  7. *** THE SECRET NEVER CROSSES THE HTTP BOUNDARY. *** The listener model carries the
     operator's tunnel key — start_listener has to hand it to the server process — and the
     RunRecord redaction covers the audit trail only, so an HTTP route is a SECOND, independent
     export path. Held STRUCTURALLY rather than at the edge: ``client_command`` is RENDERED
     from a ``_mask_secret`` copy inside the module, so no route can export the key through it
     even by forgetting to scrub, and no short/colliding key can corrupt the rendered line.
     Asserted at the AST level, on the raw model, and against real HTTP response bodies from
     every read route under both prefixes, enumerated from the live router.

Hermetic: subprocess, the container liveness probe and runstore.save_run are monkeypatched by
manual save/restore (this repo has NO pytest). No Docker daemon, no network, no DB writes.

Run:  backend/.venv/Scripts/python.exe backend/test_obfuscation_safety.py
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from cockpit import config
from cockpit import executor as EX
from cockpit import obfuscation as O
from cockpit.obfuscation import ObfuscationRefused, ObfuscationRequest
from test_support import scans

BACKEND = Path(__file__).resolve().parent
OBF_SRC = Path(O.__file__).read_text(encoding="utf-8")
OBF_TREE = ast.parse(OBF_SRC)

# The ONLY two files allowed to name the module: the module itself, and the HTTP layer.
# cockpit/router.py is deliberately NOT here — the routes live in main.py, so the cockpit
# router keeps no handle on this surface.
ALLOWED_REFERENCES = {Path("cockpit/obfuscation.py"), Path("main.py")}

_REFERENCE_PATTERNS = [
    r"\bstart_listener\b",
    r"\bstop_listener\b",
    r"\boperator_oneliner\b",
    r"\bfrom\s+\.obfuscation\b",
    r"\bfrom\s+cockpit\.obfuscation\b",
    r"\bimport\s+cockpit\.obfuscation\b",
    r"\bfrom\s+cockpit\s+import\s+[^\n]*\bobfuscation\b",
    r"\bfrom\s+\.\s+import\s+[^\n]*\bobfuscation\b",
    r"\bcockpit\.obfuscation\b",
]

SECRET = "s3cr3t-tunnel-pw-DO-NOT-LEAK"


# --------------------------------------------------------------------------- #
# helpers — AST + hermetic fakes (manual save/restore; this repo has no pytest)
# --------------------------------------------------------------------------- #
def _fn(tree: ast.AST, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name}() has vanished from the parsed source — the lock cannot be evaluated")


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
    return {_dotted(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)} - {""}


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
    """The names main.py binds this cockpit module to (e.g. ``cockpit_obfuscation``)."""
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
    ``cockpit_obfuscation.anything`` (which the source regexes, written for other files, would
    miss for a function name they do not list), and the REGEX check catches a fresh
    ``from cockpit import obfuscation`` opened inside the function.
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


# Both surfaces that can hold a listener/implant. The secret sweep runs over EVERY read route
# under these, enumerated from the live router — not a hard-coded list of today's four.
_EXPORT_PREFIXES = ("/api/obfuscation", "/api/sliver")


def _sweep_read_routes(client, live_id: str) -> list[tuple[str, int, str]]:
    """GET every read route under both prefixes; return ``(path, status, body)`` for each.

    Enumerated from ``main.app.routes`` so a route added later is swept the day it lands,
    rather than the day someone remembers to extend this test. Path parameters are filled with
    a real live listener id, so ``/…/{lid}``-shaped routes return a real object rather than a
    404 that would make the sweep pass vacuously.
    """
    import main

    out: list[tuple[str, int, str]] = []
    for r in main.app.routes:
        path = str(getattr(r, "path", ""))
        if not path.startswith(_EXPORT_PREFIXES):
            continue
        if "GET" not in (getattr(r, "methods", set()) or set()):
            continue
        try:
            resp = client.get(re.sub(r"\{[^}]+\}", live_id, path))
        except Exception as exc:  # a route that cannot run under the fakes is not a leak —
            out.append((path, -1, repr(exc)))  # but its traceback is still swept for the key
            continue
        out.append((path, resp.status_code, resp.text))
    return out


def _backend_py_files() -> list[Path]:
    """The SHARED tree selection — see test_support/scans.py. This scan was already correct;
    only the file-selection primitive moved, so the one implementation the locks share cannot
    drift back into eleven copies. The offender/control logic below is untouched."""
    return scans.source_files()


class _FakeProc:
    def __init__(self, argv):
        self.argv, self._alive = argv, True

    def poll(self):
        return None if self._alive else 0

    def kill(self):
        self._alive = False


class _Spy:
    def __init__(self, *, up=True):
        self.up = up
        self.popen_argv: list[str] | None = None
        self.popen_calls = 0
        self.saved: list = []
        self._orig = (O._container_running, O.subprocess.Popen, O.runstore.save_run)

    def __enter__(self):
        def fake_popen(argv, **kw):
            self.popen_calls += 1
            self.popen_argv = argv
            return _FakeProc(argv)

        O._container_running = lambda name: self.up
        O.subprocess.Popen = fake_popen
        O.runstore.save_run = lambda rec: self.saved.append(rec)
        return self

    def __exit__(self, *exc):
        (O._container_running, O.subprocess.Popen, O.runstore.save_run) = self._orig
        O.reset()
        return False


def _dnscat(**over) -> ObfuscationRequest:
    base = dict(
        kind="dnscat2", zone="tunnel.operator-owned.example", secret=SECRET,
        engagement_id="eng-obfsafe000",
    )
    base.update(over)
    return ObfuscationRequest(**base)


def _iodine(**over) -> ObfuscationRequest:
    base = dict(
        kind="iodine", zone="t.operator-owned.example", secret=SECRET,
        tunnel_net="10.99.53.1/24", engagement_id="eng-obfsafe000",
    )
    base.update(over)
    return ObfuscationRequest(**base)


# --------------------------------------------------------------------------- #
# 1. NO ORCHESTRATOR / AGENT / LOOP PATH
# --------------------------------------------------------------------------- #
def test_no_orchestrator_or_agent_path_to_obfuscation() -> None:
    """EVERY backend module is scanned; only obfuscation.py + main.py may name this surface."""
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
        scanned.append(rel)
        if f.name.startswith("test_"):
            continue
        if hits:
            offenders.append(f"{rel.as_posix()} ({', '.join(hits)})")

    assert not offenders, (
        "the DNS-tunnel surface must be HUMAN-ONLY — these modules can reach it: "
        f"{offenders}. The orchestrator/agent/loop/executor must have NO path to a covert channel."
    )

    must_have_scanned = {
        Path("orchestrator.py"), Path("cockpit/executor.py"), Path("cockpit/router.py"),
        Path("adgraph/orchestrator.py"), Path("cockpit/session.py"), Path("cockpit/tunnels.py"),
    }
    missing = must_have_scanned - set(scanned)
    assert not missing, f"the scan never reached the agent-path modules: {sorted(missing)}"
    assert len(scanned) >= 40, f"only {len(scanned)} modules scanned — the sweep is too narrow"

    for allowed in ALLOWED_REFERENCES:
        assert controls.get(allowed), (
            f"{allowed} no longer matches any reference pattern — the scan would now pass "
            "vacuously. Update _REFERENCE_PATTERNS to follow the rename."
        )

    import orchestrator as ORCH
    from adgraph import orchestrator as ADORCH

    for mod, name in ((EX, "cockpit.executor"), (ORCH, "orchestrator"),
                      (ADORCH, "adgraph.orchestrator")):
        for attr in ("obfuscation", "start_listener", "operator_oneliner", "ObfuscationRequest"):
            assert not hasattr(mod, attr), (
                f"{name} must not expose {attr!r} — that is an agent path to a covert channel"
            )
    print(f"  {len(scanned)} modules scanned: ZERO orchestrator/agent/loop path to the tunnel: PASS")


def test_the_main_py_allow_list_stops_at_the_route_functions() -> None:
    """main.py may name this module in its ROUTES — and nowhere near the loop endpoint.

    This is the narrowing the whole-tree scan cannot do. main.py is allow-listed wholesale
    above (the decoupling rule put the routes there), but main.py also holds
    ``import orchestrator`` and ``POST /sessions/{id}/loop/propose``. A covert channel wired
    into the agent loop *from inside the allow-listed file* would otherwise be invisible to
    every check in this suite.
    """
    surface = _loop_surface_functions()
    # ANTI-VACUITY: the closure must actually contain the loop endpoint. If the endpoint is
    # renamed out of the pattern, this fails loudly instead of scanning nothing.
    assert "loop_propose" in surface, (
        f"the loop endpoint is not in the scanned surface — got {sorted(surface)}. Renamed? "
        "Widen _LOOP_SURFACE_RE; do not let this check go quiet."
    )
    assert len(surface) >= 2, sorted(surface)

    offenders = _loop_surface_offenders("obfuscation", _REFERENCE_PATTERNS)
    assert not offenders, (
        "*** THE DNS TUNNEL IS WIRED INTO THE AGENT LOOP *** — main.py is allow-listed for its "
        f"ROUTE functions only, never for the loop/propose/orchestrator surface: {offenders}. "
        "A covert channel an agent can raise is an autonomous covert channel."
    )
    print(
        f"  main.py's allow-list stops at the routes: {len(surface)} loop-surface functions, "
        "none of which can reach the tunnel: PASS"
    )


# --------------------------------------------------------------------------- #
# 2. THE LIFECYCLE IS HUMAN-ONLY AND UNGATED BY DESIGN
# --------------------------------------------------------------------------- #
def test_listener_lifecycle_is_human_only_and_carries_no_gate_fields() -> None:
    """A listener has no target, so there is nothing to gate — and nothing that could widen it."""
    gate_calls = {
        "executor.validate_request", "validate_request", "EX.validate_request",
        "executor.resolve_mode", "executor.iter_run",
    }
    for human_only in ("start_listener", "stop_listener", "list_listeners"):
        calls = _call_names(_fn(OBF_TREE, human_only))
        assert not (calls & gate_calls), (
            f"{human_only} consults the executor ({sorted(calls & gate_calls)}) — the listener "
            "is operator infrastructure with NO target; wiring it to the gated path would give "
            "the executor (and therefore anything that can reach the executor) a route here"
        )
    # What is actually BOUND, read off the import statements — so the module docstring's prose
    # ("the executor must have NO path here") cannot trip this, and no spelling can slip past.
    imported: set[str] = set()
    for node in ast.walk(OBF_TREE):
        if isinstance(node, ast.Import):
            imported |= {a.asname or a.name.split(".")[0] for a in node.names}
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported |= {a.asname or a.name for a in node.names}
            imported.add(node.module or "")
    for forbidden in ("executor", "orchestrator", "kali", "session", "cockpit.executor",
                      "adgraph", "agent"):
        assert forbidden not in imported, (
            f"obfuscation.py imports {forbidden!r} — it must have no handle on the executor, "
            f"the agent/loop or the open :kali box. Imports: {sorted(imported)}"
        )
    for attr in ("executor", "orchestrator", "validate_request", "iter_run", "run_kali"):
        assert not hasattr(O, attr), f"obfuscation must not expose {attr!r}"

    fields = set(ObfuscationRequest.model_fields)
    for forbidden in ("approved", "dangerous_ack", "target", "host", "container", "sandbox"):
        assert forbidden not in fields, (
            f"ObfuscationRequest.{forbidden} would give the lifecycle a target or a gate it must "
            f"not have — got {sorted(fields)}"
        )
    print("  the listener lifecycle is ungated human-only and carries no target/gate field: PASS")


# --------------------------------------------------------------------------- #
# 3. *** THE CLIENT HALF IS NEVER DELIVERED ***
# --------------------------------------------------------------------------- #
def test_client_oneliner_is_pure_and_no_delivery_primitive_exists() -> None:
    """operator_oneliner builds a string and STOPS. Nothing in the module can ship it.

    The AST half is the strong one: the function's only outgoing calls are list/string
    construction, so it cannot acquire an I/O side effect without this test failing. The
    source scan is the second half — the module must own no delivery primitive at all, because
    the far side is a machine HackPit has not compromised and must not try to reach.
    """
    body = _fn(OBF_TREE, "operator_oneliner")
    allowed_calls = {"parts.append", "join", "str", "format"}
    actual = _call_names(body)
    assert actual <= allowed_calls, (
        f"operator_oneliner gained a call it must not have: {sorted(actual - allowed_calls)}. "
        "It is a PURE string builder — no I/O, no clock, no subprocess, no delivery."
    )
    # It must not touch a module that could perform I/O, even indirectly.
    for n in ast.walk(body):
        if isinstance(n, ast.Name):
            assert n.id not in {"subprocess", "os", "open", "socket", "requests", "shutil"}, (
                f"operator_oneliner references {n.id!r} — it must build a string and nothing else"
            )

    for delivery in (
        "docker cp", "write_stdin", "communicate(", "stdin=subprocess.PIPE", "scp ", "psexec",
        "smbclient", "requests.", "urllib", "httpx", "socket.", "paramiko", "winrm",
        "sendline", "os.system", "os.popen", "pty.spawn", "shutil.copy",
    ):
        assert delivery not in OBF_SRC, (
            f"obfuscation.py must not be able to DELIVER the client half — found {delivery!r}"
        )

    # Behavioural: building the line starts nothing and records nothing.
    with _Spy() as spy:
        lis = O.start_listener(_dnscat())
        assert spy.popen_calls == 1 and len(spy.saved) == 1
        for _ in range(3):
            line = O.operator_oneliner(lis)
        assert spy.popen_calls == 1, "operator_oneliner must not spawn a process"
        assert len(spy.saved) == 1, "operator_oneliner must not record anything"
        # The model echoes the SAME pure function's output — over a MASKED copy, which is what
        # keeps the key out of every field that can cross a boundary (see §7).
        assert lis.client_command == O.operator_oneliner(O._mask_secret(lis)), lis.client_command
        assert line == lis.client_command.replace(O.SECRET_MASK, SECRET), (
            "the masked render must differ from the raw one ONLY where the key was"
        )
        assert line.startswith(O.DNSCAT2_CLIENT_BIN), line
        assert O.DNSCAT2_SERVER_BIN not in line, "the one-liner is the CLIENT half"
    print("  operator_oneliner is a PURE string builder; the module has no delivery path: PASS")


# --------------------------------------------------------------------------- #
# 4. THE ZONE / TUNNEL NET ARE OPERATOR-OWNED — NEVER TARGET-SUBSTITUTED
# --------------------------------------------------------------------------- #
def test_zone_and_tunnel_net_survive_target_substitution() -> None:
    """The catalog placeholders are spelled so the composer's substitution CANNOT rewrite them.

    This is the obfuscation twin of the ``<listener>`` invariant: pointing a tunnel at the
    client's own zone (or handing the tunnel interface a range belonging to the engagement)
    would be both useless and harmful. Run against the REAL substitution pass, not a copy.
    """
    import attack_path

    target = "app.example.com"
    for template in (
        "dnscat2-server <tunnel-zone>",
        "dnscat2-client <tunnel-zone>",
        "iodined -f -c -P <password> <tunnel-net> <tunnel-zone>",
        "iodine -f -P <password> <tunnel-zone>",
    ):
        out = attack_path.substitute_target(template, target, scope="10.0.0.0/24")
        assert "<tunnel-zone>" in out, f"the composer rewrote the OPERATOR's zone: {out}"
        if "<tunnel-net>" in template:
            assert "<tunnel-net>" in out, f"the composer rewrote the tunnel's own range: {out}"
        assert target not in out, f"the TARGET was substituted into a tunnel template: {out}"

    # The module's own values come from the request and are echoed verbatim — no target exists
    # here to substitute in the first place.
    with _Spy() as spy:
        lis = O.start_listener(_iodine(zone="t.operator-owned.example"))
        assert lis.zone == "t.operator-owned.example"
        assert lis.tunnel_net == "10.99.53.1/24"
        assert "t.operator-owned.example" in spy.popen_argv, spy.popen_argv
        # The tunnel interface's range must be private by construction.
        for public in ("8.8.8.8/24", "1.1.1.1/32"):
            raised = False
            try:
                # NB: a valid-length secret, so tunnel_net is the only thing on trial here.
                ObfuscationRequest(
                    kind="iodine", zone="t.example", secret="tunnel-pw-01", tunnel_net=public
                )
            except Exception:
                raised = True
            assert raised, f"a public tunnel_net ({public}) must be refused"
    print("  <tunnel-zone>/<tunnel-net> survive the REAL target-substitution pass: PASS")


# --------------------------------------------------------------------------- #
# 5. EVERY ACTION IS AUDITED — WITH THE SECRET REDACTED
# --------------------------------------------------------------------------- #
def test_every_action_is_audited_with_the_secret_redacted() -> None:
    assert "runstore.save_run" in _call_names(_fn(OBF_TREE, "_save")), (
        "_save must persist through runstore.save_run — the single audit sink"
    )
    for audited in ("start_listener", "stop_listener"):
        assert "_save" in _call_names(_fn(OBF_TREE, audited)), f"{audited} must record a run"
    assert "_redacted" in _call_names(_fn(OBF_TREE, "start_listener")), (
        "the run record must go through _redacted — the audit trail is not a key store"
    )

    with _Spy() as spy:
        lis = O.start_listener(_iodine())
        rec = spy.saved[-1]
        assert rec.run_id == lis.run_id and rec.finished_at is None
        assert rec.target == config.ENGAGE_SANDBOX_CONTAINER, (
            "a listener has NO target — the audit row names the operator's own box"
        )
        blob = json.dumps(rec.model_dump(), default=str)
        assert SECRET not in blob, f"the operator's tunnel key reached the run record: {rec.args}"
        assert any("***" in a for a in rec.args), rec.args
        # ...but the REAL key still reaches the server process, or the tunnel would not work.
        assert SECRET in spy.popen_argv, "the real key must reach the server process"

        O.stop_listener(lis.id)
        closed = spy.saved[-1]
        assert closed.run_id == lis.run_id and closed.finished_at is not None
        assert SECRET not in json.dumps(closed.model_dump(), default=str)

        n = len(spy.saved)
        raised = False
        try:
            O.stop_listener("deadbeefdead")
        except ObfuscationRefused as exc:
            raised = True
            assert exc.gate == "unknown", exc.gate
        assert raised and len(spy.saved) == n, "a refusal is not a run — nothing may be recorded"
    print("  start/stop are audited; the pre-shared key is REDACTED in every record: PASS")


# --------------------------------------------------------------------------- #
# 6. NO SHELL; THE CONTAINER IS A CODE CONSTANT
# --------------------------------------------------------------------------- #
def test_no_shell_and_the_container_is_never_a_request_field() -> None:
    shell_kwargs = [
        n for n in ast.walk(OBF_TREE)
        if isinstance(n, ast.Call)
        for kw in n.keywords
        if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False)
    ]
    assert not shell_kwargs, "obfuscation.py passes shell= to a subprocess call — argv lists only"
    for banned in ("os.system", "os.popen", "sh -c", '"sh", "-c"', "'sh', '-c'"):
        assert banned not in OBF_SRC, f"obfuscation.py must not contain {banned!r}"
    assert "config.ENGAGE_SANDBOX_CONTAINER" in OBF_SRC, (
        "the container must come from a CODE CONSTANT, never a request field"
    )

    # A smuggled container field is DROPPED, and the constant still decides where it runs.
    smuggled = ObfuscationRequest.model_validate({
        **_dnscat().model_dump(), "container": config.KALI_OPEN_CONTAINER, "sandbox": "evil",
    })
    assert not hasattr(smuggled, "container"), "an extra container field must not stick"
    with _Spy() as spy:
        O.start_listener(smuggled)
        argv = spy.popen_argv
        assert argv[:3] == ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER], argv
        assert config.KALI_OPEN_CONTAINER not in argv, "must NOT reach the open :kali box"
        assert config.SANDBOX_CONTAINER not in argv, "must NOT reach the isolated lab box"
        assert "sh" not in argv and "-c" not in argv, "the listener is argv-only (no shell)"
    print("  no shell; the container is a code constant a request cannot redirect: PASS")


# --------------------------------------------------------------------------- #
# 7. *** THE SECRET NEVER CROSSES THE HTTP BOUNDARY ***
# --------------------------------------------------------------------------- #
def test_the_masked_one_liner_is_authoritative_in_the_module() -> None:
    """*** THE BOUNDARY IS STRUCTURAL: the key is never embedded in client_command AT ALL. ***

    The earlier shape put the masking at the route (``main._listener_public`` did a
    ``str.replace`` on the way out). Two things were wrong with that and both are asserted
    against here:

      1. It was ONE helper, and nothing forced a future route to call it. A route declaring
         ``response_model=ObfuscationListenerOut`` and returning the raw model would drop the
         ``secret`` FIELD and still export the key inside ``client_command``.
      2. ``str.replace`` is over-broad. A key that is short, or that happens to be a substring
         of the zone, mangles tokens that had nothing to do with it — the operator copies a
         corrupt command and the audit argv is wrong in the same way.

    So ``start_listener`` now RENDERS the one-liner from a ``_mask_secret`` copy: the mask is
    placed where the key would have gone and touches nothing else, and no caller can opt out.
    """
    # Structural: the rendered line and the audited argv are both built from a masked copy.
    start = _call_names(_fn(OBF_TREE, "start_listener"))
    assert "_mask_secret" in start, (
        "start_listener must render client_command from a _mask_secret copy — if the masking "
        "moved back out to a caller, the boundary is no longer structural"
    )
    assert "_mask_secret" in _call_names(_fn(OBF_TREE, "_redacted")), (
        "_redacted must REBUILD the argv from a masked copy, not string-substitute the live one"
    )
    assert "_server_args" in _call_names(_fn(OBF_TREE, "_redacted")), _call_names(
        _fn(OBF_TREE, "_redacted")
    )
    # And NOTHING on either side of the boundary scrubs by substitution any more — asserted at
    # the AST level, so prose about the old shape does not trip it and real code cannot hide.
    # (str.replace is over-broad: a key that is short, or a substring of the zone, eats tokens
    # that are not the key.)
    main_tree = ast.parse((BACKEND / "main.py").read_text(encoding="utf-8"))
    for label, node in (
        ("cockpit/obfuscation.py", OBF_TREE),
        ("main.py::_listener_public", _fn(main_tree, "_listener_public")),
    ):
        offending = {c for c in _call_names(node) if c.split(".")[-1] == "replace"}
        assert not offending, (
            f"{label} masks by str.replace ({sorted(offending)}) — mask by CONSTRUCTION "
            "(_mask_secret) instead, or a short/colliding key corrupts the rendered command"
        )

    # Behavioural: the RAW internal model — no route helper involved — is already clean.
    with _Spy():
        for req in (_dnscat(), _iodine()):
            lis = O.start_listener(req)
            assert SECRET not in lis.client_command, (
                "*** THE KEY IS EMBEDDED IN THE MODEL'S OWN client_command *** — any route "
                f"returning this model leaks it: {lis.client_command}"
            )
            assert O.SECRET_MASK in lis.client_command, lis.client_command
            assert lis.zone in lis.client_command, "the line must stay useful"
            assert lis.secret == SECRET, "the internal field still holds the real key"

        O.reset()  # both kinds are live and the cap is 2 — clear before the next start
        # THE CORRUPTION CASE. `operator` is a legal 8-char key AND a substring of the zone;
        # str.replace masking rendered `***-owned.example` here. Building cannot.
        lis = O.start_listener(
            ObfuscationRequest(kind="dnscat2", zone="operator-owned.example", secret="operator")
        )
        assert lis.client_command == (
            f"{O.DNSCAT2_CLIENT_BIN} --secret={O.SECRET_MASK} operator-owned.example"
        ), f"masking corrupted a token that was not the key: {lis.client_command!r}"

        # ...and the audit argv is correct rather than string-mangled, for the same reason.
        collide = ObfuscationRequest(
            kind="iodine", zone="operator-owned.example", secret="operator",
            tunnel_net="10.99.53.1/24",
        )
        assert O._redacted(collide) == [
            O.IODINE_SERVER_BIN, "-f", "-c", "-P", O.SECRET_MASK,
            "10.99.53.1/24", "operator-owned.example",
        ], f"the redacted audit argv is mangled: {O._redacted(collide)}"
    print("  the masked one-liner is built in the module, so no route can un-mask it: PASS")


def test_secret_never_crosses_the_http_boundary() -> None:
    """THE LOAD-BEARING ROUTE TEST. Adding an API is what creates the export path.

    ObfuscationListener carries the operator's pre-shared key on the model — start_listener has
    to hand the real key to the server process — and the RunRecord redaction covers the audit
    trail ONLY. So the HTTP boundary is held two ways: a response model with no ``secret``
    field, and a ``client_command`` that was already masked in the module (see
    :func:`test_the_masked_one_liner_is_authoritative_in_the_module`). Asserted against real
    response bodies, on EVERY route under the prefix — enumerated from ``main.app.routes``, not
    hard-coded, so a route added tomorrow is covered by this test today.
    """
    import main
    from fastapi.testclient import TestClient

    # The response model structurally cannot carry the key.
    out_fields = set(main.ObfuscationListenerOut.model_fields)
    assert "secret" not in out_fields, (
        f"ObfuscationListenerOut must have NO secret field — got {sorted(out_fields)}"
    )
    assert "secret" in set(O.ObfuscationListener.model_fields), (
        "the INTERNAL model is still expected to carry the key (the server process needs it) — "
        "if that changed, this test is now checking the wrong boundary"
    )

    client = TestClient(main.app)
    with _Spy() as spy:
        for req in (_dnscat(), _iodine()):
            payload = req.model_dump()
            r = client.post("/api/obfuscation/listeners", json=payload)
            assert r.status_code == 200, r.text
            assert SECRET not in r.text, (
                f"*** THE OPERATOR'S TUNNEL KEY LEAKED IN THE {req.kind} START RESPONSE *** "
                f"{r.text}"
            )
            body = r.json()
            assert "secret" not in body, body
            assert "***" in body["client_command"], (
                "the one-liner must arrive MASKED — it embeds the key verbatim internally"
            )
            # The line is still useful: the client binary and the operator's zone survive.
            assert req.zone in body["client_command"], body["client_command"]

            lid = body["id"]
            # Grab the start argv NOW: the sweep below calls status routes that probe the
            # container, which would overwrite the spy's last-argv.
            started_argv = list(spy.popen_argv or [])

            # ...and on EVERY OTHER READ ROUTE UNDER BOTH PREFIXES, enumerated from the app.
            # This is the part that survives someone adding a route: it is not a list of the
            # four that exist today, it is whatever the router holds when the test runs.
            swept = _sweep_read_routes(client, lid)
            assert len(swept) >= 4, f"the route sweep found almost nothing: {swept}"
            for path, status, text in swept:
                assert SECRET not in text, (
                    f"*** THE OPERATOR'S TUNNEL KEY LEAKED FROM {path} (HTTP {status}) *** {text}"
                )

            r = client.delete(f"/api/obfuscation/listeners/{lid}")
            assert r.status_code == 200, r.text
            assert SECRET not in r.text, f"the key leaked in the STOP response: {r.text}"
            assert r.json()["status"] == "down", r.text

            # The key DID reach the server process — only the wire is clean. (Counter-assertion:
            # without it, "no key in the response" would also be satisfied by losing the key.)
            assert any(SECRET in t for t in started_argv), (  # dnscat2 fuses it into --secret=
                f"the real key must still reach the {req.kind} server process: {started_argv}"
            )

        assert any(SECRET in (l.secret or "") for l in O.list_listeners()), (
            "the internal model must still hold the key; only the HTTP boundary strips it"
        )
        # And nothing about the export path is recorded with the key either.
        assert SECRET not in json.dumps([r.model_dump() for r in spy.saved], default=str)

    # An unknown id is a 404, not a leak-shaped 500.
    r = client.delete("/api/obfuscation/listeners/deadbeefdead")
    assert r.status_code == 404, r.text
    print("  the pre-shared key never crosses the HTTP boundary (start/list/status/stop): PASS")


def test_http_routes_add_no_capability_and_stay_human_only() -> None:
    """The /api/obfuscation routes are a thin human surface — and none of them delivers."""
    import main

    paths = {
        (r.path, m)
        for r in main.app.routes
        for m in (getattr(r, "methods", set()) or set())
        if str(getattr(r, "path", "")).startswith("/api/obfuscation")
    }
    assert paths, "the /api/obfuscation routes are missing"
    assert {m for _p, m in paths} <= {"GET", "POST", "DELETE"}, paths
    for p, _m in paths:
        assert not any(
            bad in p for bad in ("deliver", "deploy", "upload", "exec", "run", "client-command",
                                 "push", "send")
        ), (
            f"{p} looks like a delivery route — the client half is carried across BY HAND, and "
            "there must be no endpoint that ships it"
        )
    print(f"  {len(paths)} /api/obfuscation routes, none of which can deliver anything: PASS")


if __name__ == "__main__":
    test_no_orchestrator_or_agent_path_to_obfuscation()
    test_the_main_py_allow_list_stops_at_the_route_functions()
    test_listener_lifecycle_is_human_only_and_carries_no_gate_fields()
    test_client_oneliner_is_pure_and_no_delivery_primitive_exists()
    test_zone_and_tunnel_net_survive_target_substitution()
    test_every_action_is_audited_with_the_secret_redacted()
    test_no_shell_and_the_container_is_never_a_request_field()
    test_the_masked_one_liner_is_authoritative_in_the_module()
    test_secret_never_crosses_the_http_boundary()
    test_http_routes_add_no_capability_and_stay_human_only()
    print("ALL DNS-tunnel obfuscation safety invariants hold")
