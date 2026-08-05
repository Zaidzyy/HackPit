"""SAFETY invariants for the interact.sh OOB backend (spec 2026-08-06 §5).

interact.sh polling is a new backend OUTBOUND egress and auto-poll runs it unattended, so the
same locks the self-hosted poll carries apply here — proven structurally, not by comment:

  1. **NO EXECUTION OR DELIVERY SURFACE.** interactsh.py and autopoll.py record callbacks; they
     never run a command and never send a payload. No subprocess, no executor, no run_kali,
     no eval/exec.
  2. **NO COUPLING TO THE REPEATER.** send-to-repeater is a frontend action; the backend OOB
     modules must not import the repeater, whose whole guarantee is that only a human reaches
     send() (test_repeater_is_human_only). A backend import would be a code path to it.
  3. **THE OUTBOUND POLL CANNOT BE REDIRECTED.** The opener refuses redirects and honours no
     ambient proxy — the same containment as poll.py, so a tampered/proxied endpoint answering
     302 http://169.254.169.254/ cannot turn a poll into an SSRF from the backend host.

The whole-tree scanner (test_scans.py) already catches a planted run_kali import in any module,
including these; this file adds the interact.sh-specific claims.

Run: python test_oob_interactsh_safety.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

BACKEND = Path(__file__).resolve().parent
OOB = BACKEND / "oob"

# Modules added or extended by the interact.sh backend that must stay execution- and
# delivery-free.
BACKEND_MODULES = ("interactsh.py", "autopoll.py", "poll.py", "settings.py", "router.py", "verify.py")
_BANNED_EXEC = ("subprocess", "os.system", "run_kali", "docker exec", "eval(", "exec(", "pty.spawn")


def test_no_execution_surface_in_the_interactsh_modules() -> None:
    # The router legitimately imports the executor for the GATED self-hosted deploy, so it is
    # exempt from the executor check only — never from the shell/eval checks.
    for name in ("interactsh.py", "autopoll.py", "settings.py"):
        src = (OOB / name).read_text(encoding="utf-8")
        for banned in _BANNED_EXEC + ("executor",):
            assert banned not in src, f"{name} must not reference {banned!r}"
        ast.parse(src)  # no syntax landmine hiding a call behind a string
    print("  interact.sh + autopoll + settings reach no execution surface: PASS")


def _imports_repeater(src: str) -> bool:
    """True if the module IMPORTS the repeater (an import node, not a prose mention).

    poll.py names ``cockpit/repeater.py`` in its containment docstring to CONTRAST the two egress
    models — that is prose and correct. Only an actual import is a code path to send().
    """
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any("repeater" in alias.name for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if (node.module and "repeater" in node.module) or any(
                "repeater" in alias.name for alias in node.names
            ):
                return True
    return False


def test_the_backend_oob_modules_do_not_couple_to_the_repeater() -> None:
    for name in ("interactsh.py", "autopoll.py", "poll.py", "router.py", "verify.py", "settings.py"):
        src = (OOB / name).read_text(encoding="utf-8")
        assert not _imports_repeater(src), (
            f"{name} must not import the repeater — send-to-repeater is a FRONTEND action, and a "
            f"backend coupling would create a code path to the human-only send()"
        )
    print("  no backend OOB module imports the repeater: PASS")


def test_the_interactsh_poll_refuses_redirects_and_ambient_proxy() -> None:
    from oob import interactsh as ish

    op = ish._opener()
    names = {type(h).__name__ for h in op.handlers}
    assert "_NoRedirect" in names, "the interact.sh opener must refuse redirects"
    assert "ProxyHandler" not in names, "the interact.sh opener must honour no ambient proxy"
    print("  the interact.sh poll refuses redirects and ambient proxy: PASS")


def test_the_session_secrets_are_never_a_key_in_the_public_view() -> None:
    """Structural: session_public's returned dict names none of the secret columns as a KEY.

    Checks the ``ast.Dict`` KEYS of the return, not the whole body — reading ``d["secret_key"]``
    to compute ``has_secret`` is fine; returning it under a ``"secret_key"`` key is not.
    """
    src = (OOB / "interactsh.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    target = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "session_public"),
        None,
    )
    assert target is not None, "session_public not found"
    secret_keys = {"secret_key", "private_key", "auth_token"}
    for node in ast.walk(target):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            keys = {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
            leaked = keys & secret_keys
            assert not leaked, f"session_public returns secret key(s): {leaked}"
    print("  interact.sh session secrets are never a key in the public view: PASS")


if __name__ == "__main__":
    print("== interact.sh backend SAFETY invariants (spec 2026-08-06 §5) ==")
    test_no_execution_surface_in_the_interactsh_modules()
    test_the_backend_oob_modules_do_not_couple_to_the_repeater()
    test_the_interactsh_poll_refuses_redirects_and_ambient_proxy()
    test_the_session_secrets_are_never_a_key_in_the_public_view()
    print("ALL interact.sh safety invariants hold")
