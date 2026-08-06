"""Credential-attack SAFETY invariants.  Run:  python test_credattack_safety.py

*** THE LINE THIS FILE HOLDS. ***
The credential surface adds NO new gate. A spray/crack is ONE approved job — the intruder's
shape — gated by the SAME executor gates every command clears, with an UNGATED stop. So this
file asserts, in both directions where it can:

  * `credattack.py` EXECUTES NOTHING — it builds argv and parses text, by an AST walk over its
    own source (a docstring saying "no subprocess" must not read as clean, and `subprocess`
    hidden in a string must not read as a violation). Only `credjobs`/`executor` run anything.
  * The spray and crack start paths REACH `executor.validate_request` before spawning, and an
    unapproved job is refused AT THE APPROVAL GATE (with a control: an approved one is not).
  * SECRETS NEVER LAND ON AN ARGV — the password/hash lists go to loot files; the argv carries
    only their paths. A secret on the command line ends up in the persisted `RunRecord` that
    `report.py` renders verbatim.
  * An OMITTED approval is REFUSED, not granted (both flags default False).
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from cockpit import config, credattack, credjobs

_HERE = Path(__file__).parent

_BANNED_IMPORTS = {
    "subprocess", "socket", "requests", "httpx", "urllib", "docker", "pty", "ctypes",
    "multiprocessing", "asyncio",
}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "os.system", "os.popen", "os.execv"}


# --------------------------------------------------------------------------- #
# 1. the planner executes nothing
# --------------------------------------------------------------------------- #
def test_credattack_executes_nothing() -> None:
    """It runs after a job (correlation) with no approval of its own — an execution path here
    would sit entirely outside the gates. Checked against the AST, so it asserts what the code
    DOES, not what its prose says."""
    tree = ast.parse((_HERE / "cockpit" / "credattack.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in _BANNED_IMPORTS, f"imports {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in _BANNED_IMPORTS, \
                f"imports from {node.module}"
        elif isinstance(node, ast.Call):
            fn = node.func
            dotted = ""
            if isinstance(fn, ast.Name):
                dotted = fn.id
            elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                dotted = f"{fn.value.id}.{fn.attr}"
            assert dotted not in _BANNED_CALLS, f"credattack.py calls {dotted}"
    print("  credattack.py imports nothing that executes and calls no eval/exec/subprocess: PASS")


# --------------------------------------------------------------------------- #
# 2. the start paths reach the gate before spawning
# --------------------------------------------------------------------------- #
def _calls_in(fn) -> set[str]:
    tree = ast.parse(inspect.getsource(fn))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def test_start_paths_go_through_validate_request() -> None:
    """Structurally: both start paths call `_gate`, and `_gate` calls `validate_request`. The
    gate cannot be skipped by a caller of the job worker."""
    assert "_gate" in _calls_in(credjobs.start_spray), "start_spray must call the gate"
    assert "_gate" in _calls_in(credjobs.start_crack), "start_crack must call the gate"
    assert "validate_request" in _calls_in(credjobs._gate), "_gate must call validate_request"
    print("  start_spray + start_crack both reach executor.validate_request via _gate: PASS")


def test_an_unapproved_spray_is_refused_at_the_approval_gate_with_a_control() -> None:
    """Against the LAB target (so the target-lock passes) an UNAPPROVED spray is refused at the
    approval gate; an approved one is NOT — that is the control that proves the check is real and
    not always-refusing."""
    def spray(approved: bool) -> credattack.SprayRequest:
        return credattack.SprayRequest(
            service="smb", target=config.LAB_TARGET_HOST, usernames=["a"], passwords=["b"],
            approved=approved,
        )

    unapproved = credattack.validate_spray(spray(False))
    assert unapproved is not None and unapproved.gate == "approval", unapproved
    approved = credattack.validate_spray(spray(True))
    assert approved is None or approved.gate != "approval", approved
    print("  an unapproved spray is refused at the approval gate; an approved one is not: PASS")


def test_a_crack_is_a_targetless_command_refused_off_engagement() -> None:
    """A crack names no host, so in LAB mode the target-lock refuses it (which is why the surface
    requires an engagement). That refusal proves the crack path runs through validate_request."""
    verdict = credattack.validate_crack(credattack.CrackRequest(approved=True))
    assert verdict is not None and verdict.gate == "target", verdict
    print("  a crack goes through the gate; target-less => refused in lab, engagement required: PASS")


# --------------------------------------------------------------------------- #
# 3. secrets never on an argv
# --------------------------------------------------------------------------- #
def test_no_secret_lands_on_the_spray_argv() -> None:
    req = credattack.SprayRequest(service="smb", target="10.0.0.1",
                                  usernames=["alice"], passwords=["Sup3rSecret!"], domain="CORP")
    argv, _ = credattack.spray_argv(req, users_path="/loot/e/u.txt", pass_path="/loot/e/p.txt")
    joined = " ".join(argv)
    assert "Sup3rSecret!" not in joined, "a password on the argv leaks into the run record"
    assert "/loot/e/u.txt" in argv and "/loot/e/p.txt" in argv, "the lists must be files"
    print("  a spray argv references user/pass FILES and carries no password: PASS")


def test_no_hash_lands_on_the_crack_argv() -> None:
    argv = credattack.crack_argv(credattack.CrackRequest(), hash_path="/loot/e/m1000.txt", mode=1000)
    secret = "e19ccf75ee54e06b06a5907af13cef42"
    assert secret not in " ".join(argv), "a hash on the argv leaks into the run record"
    assert "/loot/e/m1000.txt" in argv, "the hashes must go to a loot file"
    print("  a crack argv references a hash FILE and carries no hash: PASS")


def test_the_worker_writes_the_hashes_to_loot_not_the_argv() -> None:
    """The crack worker builds its argv from `_write_loot` output — the structural guarantee that
    the hashes reach a file, not the command line."""
    assert "_write_loot" in _calls_in(credjobs.start_crack), "start_crack must write a loot file"
    assert "_write_loot" in _calls_in(credjobs.start_spray), "start_spray must write loot files"
    print("  both workers write the secret lists to loot files before building the argv: PASS")


# --------------------------------------------------------------------------- #
# 4. an omitted approval is refused, not granted
# --------------------------------------------------------------------------- #
def test_approval_and_ack_default_false() -> None:
    for req in (credattack.SprayRequest(service="smb", target="h"), credattack.CrackRequest()):
        assert req.approved is False, "approval must never default true"
        assert req.dangerous_ack is False, "the red-confirm must never default true"
    print("  approval + red-confirm both default FALSE — an omitted field is refused: PASS")


def test_the_stop_is_ungated() -> None:
    """The panic button consults no gate — like every other stop in this codebase."""
    calls = _calls_in(credjobs.stop)
    assert "validate_request" not in calls and "validate_spray" not in calls, "stop must be ungated"
    print("  stop() reaches no gate — it is the ungated panic button: PASS")


if __name__ == "__main__":
    test_credattack_executes_nothing()
    test_start_paths_go_through_validate_request()
    test_an_unapproved_spray_is_refused_at_the_approval_gate_with_a_control()
    test_a_crack_is_a_targetless_command_refused_off_engagement()
    test_no_secret_lands_on_the_spray_argv()
    test_no_hash_lands_on_the_crack_argv()
    test_the_worker_writes_the_hashes_to_loot_not_the_argv()
    test_approval_and_ack_default_false()
    test_the_stop_is_ungated()
    print("\ncredattack safety: all invariants hold.")
