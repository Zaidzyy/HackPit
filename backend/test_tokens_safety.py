"""Token workbench containment + disclosure invariants.  Run:  python test_tokens_safety.py

This build adds no gate, no confirm, no blocklist. These tests guard the OTHER direction — that
the analysis/tamper core stays PURE, that a token found in traffic never leaks a value, that the
repeater stays human-only, and that the ONE thing that runs — the weak-secret crack — is the
ordinary gated job behind the same four gates, with no secret on its command line.

  1. THE PURE MODULE IS PURE. `cockpit/tokens.py` executes nothing: no subprocess, socket, os,
     requests or urlopen. Checked by AST, not substring — with a planted control, because a
     substring scan for "subprocess" passes the moment somebody spells it `"sub"+"process"`.
  2. THE PURE MODULE NEVER REFUSES. It warns in a `note`; it raises nothing. A later "tightening"
     into a refusal would be a regression — human approval is the only bound.
  3. NAMES, NEVER VALUES. `TokenDetection` carries header params + claim NAMES + the non-secret
     timing claims, and CANNOT hold a claim value or the signature — a JWT claim is routinely a
     secret. Never handing a value over cannot regress; redacting one afterwards can.
  4. THE REPEATER STAYS HUMAN-ONLY. Neither `tokens.py` nor `tokenjobs.py` references `.send`,
     and the pure core imports nothing from the repeater.
  5. THE CRACK IS THE ORDINARY GATED JOB. `tokenjobs.validate`/`start_crack` reach
     `executor.validate_request` BEFORE anything spawns; approval + red-confirm default FALSE; it
     is engagement-bound; and NO secret rides the argv — the token goes to a loot file.
  6. THE TRANSFORM ROUTES EXECUTE NOTHING. The decode/detect/tamper/oauth/saml/crack-preview
     routes reach no execution path, by AST. Only the gated crack route runs anything.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import inspect
import json
from pathlib import Path

from cockpit import tokens, tokenjobs

BACKEND = Path(__file__).parent

_BANNED_MODULES = {"subprocess", "socket", "os", "shutil", "requests", "urllib.request",
                   "http.client", "docker"}
_BANNED_CALLS = {"run", "Popen", "system", "popen", "call", "check_output", "exec", "eval",
                 "__import__", "urlopen"}


def _purity_offences(tree: ast.AST) -> list[str]:
    """Every import-of-an-executor or call-of-an-executor in a module. Empty == pure."""
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _BANNED_MODULES:
                    out.append(f"import {alias.name}")
        if isinstance(node, ast.ImportFrom):
            if (node.module or "") in _BANNED_MODULES:
                out.append(f"from {node.module} import ...")
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name in _BANNED_CALLS:
                out.append(f"call {name}()")
    return out


# --------------------------------------------------------------------------- #
# 1. the pure module is pure  (+ a control)
# --------------------------------------------------------------------------- #
def test_the_token_core_executes_nothing() -> None:
    tree = ast.parse(Path(tokens.__file__).read_text(encoding="utf-8"))
    offences = _purity_offences(tree)
    assert not offences, f"cockpit/tokens.py is not pure: {offences}"

    # CONTROL: the same check on a planted violation must FLAG it, or it is checking nothing.
    planted = ast.parse("import subprocess\nsubprocess.run(['x'])\nurlopen('http://x')\n")
    assert _purity_offences(planted), "the purity check cannot detect a planted subprocess call"
    print("  cockpit/tokens.py imports nothing that executes and calls nothing that does "
          "(AST, with a control): PASS")


# --------------------------------------------------------------------------- #
# 2. the pure module never refuses
# --------------------------------------------------------------------------- #
def test_the_token_core_warns_and_never_raises() -> None:
    """The analysis/tamper core returns a `note`/`ok=false`; it raises nothing. A tamper that
    cannot be built comes back with a reason, not an exception — the same position the GraphQL
    composer takes."""
    tree = ast.parse(Path(tokens.__file__).read_text(encoding="utf-8"))
    raises = [n for n in ast.walk(tree) if isinstance(n, ast.Raise)]
    assert not raises, f"cockpit/tokens.py raises {len(raises)} time(s) — it must warn and continue"

    # And it holds in practice: garbage in gives a note, not a traceback.
    assert tokens.decode_jwt("garbage").note
    assert not tokens.tamper_alg_confusion(tokens.decode_jwt("garbage"), "").ok
    assert not tokens.edit_and_resign("x.y.z", "{bad", "s").ok
    print("  the token core warns via a note and raises nothing: PASS")


# --------------------------------------------------------------------------- #
# 3. names, never values
# --------------------------------------------------------------------------- #
def test_a_detected_token_cannot_carry_a_value() -> None:
    fields = set(tokens.TokenDetection.model_fields)
    for forbidden in ("claims", "signature", "value", "raw", "token"):
        assert forbidden not in fields, f"TokenDetection grew a {forbidden!r} field: {sorted(fields)}"

    def _b64url(o: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(
            b"=").decode()

    si = f"{_b64url({'alg': 'HS256', 'kid': 'k'})}.{_b64url({'sub': '1', 'ssn': 'SECRET-VALUE'})}"
    sig = base64.urlsafe_b64encode(hmac.new(b'k', si.encode(), hashlib.sha256).digest()).rstrip(
        b"=").decode()
    tok = f"{si}.{sig}"

    det = tokens.detect("GET", f"https://x/a?jwt={tok}", [], "")
    blob = det.model_dump_json()
    assert "SECRET-VALUE" not in blob, "a claim value reached the detection model"
    assert sig not in blob, "the signature reached the detection model"
    assert "ssn" in det.claim_names and det.alg == "HS256"
    print("  a detected token carries claim NAMES + header params, never a value or signature: PASS")


# --------------------------------------------------------------------------- #
# 4. the repeater stays human-only
# --------------------------------------------------------------------------- #
def test_neither_module_reaches_repeater_send() -> None:
    # The pure core imports nothing from the repeater at all.
    core = ast.parse(Path(tokens.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(core):
        if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("repeater"):
            raise AssertionError("cockpit/tokens.py imports from repeater")
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.endswith("repeater"), "tokens.py imports the repeater"

    # Neither module references `.send` — the crack worker may use the repeater module for the
    # container-running probe (as credjobs does), but never its send path.
    for module in (tokens, tokenjobs):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "send":
                raise AssertionError(f"{module.__name__} references .send")
    print("  the pure core imports no repeater; neither module references .send: PASS")


# --------------------------------------------------------------------------- #
# 5. the crack is the ordinary gated job
# --------------------------------------------------------------------------- #
def test_the_crack_gates_before_it_spawns_and_leaks_no_secret() -> None:
    # validate reaches the executor gate.
    vsrc = inspect.getsource(tokenjobs.validate)
    assert "validate_request" in vsrc, "the crack's validate does not reach the executor gate"

    # start_crack GATES BEFORE IT SPAWNS: the _gate() call textually precedes the Thread spawn.
    ssrc = inspect.getsource(tokenjobs.start_crack)
    assert "_gate(" in ssrc, "start_crack does not gate"
    assert ssrc.index("_gate(") < ssrc.index("threading.Thread("), \
        "start_crack spawns BEFORE it gates — a gate after the spawn is no gate"

    # _gate is the executor's gate, nothing added.
    assert "validate_request" in inspect.getsource(tokenjobs._gate)

    # approval + red-confirm default FALSE — an omitted field is refused, never assumed.
    req = tokenjobs.TokenCrackRequest(token="x.y.z")
    assert req.approved is False and req.dangerous_ack is False

    # Engagement-bound: no engagement -> refused, and nothing spawned (a raise, before the thread).
    try:
        tokenjobs._require_engagement(None)
        raise AssertionError("a crack with no engagement was NOT refused")
    except tokenjobs.TokenCrackRefused as exc:
        assert exc.gate == "engagement", exc.gate

    # NO SECRET ON THE ARGV: the token rides as a FILE PATH; the token string is not on the line.
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SIGNATURE"
    argv = tokenjobs.crack_argv(tokenjobs.TokenCrackRequest(token=token), token_path="/loot/s/t.jwt")
    assert token not in argv, "the token itself reached the argv"
    assert "/loot/s/t.jwt" in argv, "the token file path is not on the argv"
    assert argv[:5] == ["hashcat", "-a", "0", "-m", "16500"], argv
    print("  the crack gates before spawning, defaults refuse, is engagement-bound, no secret on "
          "the argv: PASS")


def test_stop_is_ungated() -> None:
    """The panic switch cannot be refused — a gate that could decline to stop a live crack would
    make the system less safe. `stop()` reaches no executor gate."""
    src = inspect.getsource(tokenjobs.stop)
    assert "validate_request" not in src and "_gate" not in src, "stop() consults a gate"
    print("  stop() reaches no gate — the panic switch is ungated: PASS")


# --------------------------------------------------------------------------- #
# 6. the transform routes execute nothing
# --------------------------------------------------------------------------- #
def test_the_token_transform_routes_reach_no_execution_path() -> None:
    from cockpit import router as router_mod

    tree = ast.parse(Path(router_mod.__file__).read_text(encoding="utf-8"))
    wanted = {"tokens_decode", "tokens_detect", "tokens_jwt_tamper", "tokens_oauth_parse",
              "tokens_oauth_build", "tokens_saml_parse", "tokens_saml_build",
              "token_crack_preview"}
    seen: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name not in wanted:
            continue
        seen.add(node.name)
        called = {n.func.attr for n in ast.walk(node)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        for bad in ("run_kali", "execute", "start_scan", "send", "run", "Popen", "start_crack"):
            assert bad not in called, f"{node.name} calls {bad}()"
    assert seen == wanted, f"token transform routes not found in router.py: {sorted(wanted - seen)}"
    print(f"  {len(seen)} token transform routes reach no execution path (AST): PASS")


if __name__ == "__main__":
    test_the_token_core_executes_nothing()
    test_the_token_core_warns_and_never_raises()
    test_a_detected_token_cannot_carry_a_value()
    test_neither_module_reaches_repeater_send()
    test_the_crack_gates_before_it_spawns_and_leaks_no_secret()
    test_stop_is_ungated()
    test_the_token_transform_routes_reach_no_execution_path()
    print("ALL token workbench safety tests pass")
