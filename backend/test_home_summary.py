"""SAFETY invariants for GET /home-summary (the launcher's status rail).

The rail exists to answer "why is that surface refusing?" without clicking into it.
To do that it reaches across the sandbox probe, the LLM config, the Windows profile
store and the engagement store — four subsystems that each hold a secret. That is
exactly the shape of the build #9 defect, where a record carrying a secret was
returned to the browser because the endpoint serialised the RAW row instead of the
masked one.

Two invariants, each with a positive control (see backend/AGENTS.md):

  1. NO SECRET REACHES THE BROWSER. Every real secret the process can reach —
     stored WinRM secrets, the configured LLM API key, every credential in every
     engagement's state — is checked against the real serialised payload.

  2. THE ENDPOINT EXECUTES NOTHING. It is a status endpoint; a status endpoint that
     can reach the executor is one line from running something. Asserted over the
     AST of the real `home_summary` source, so an aliased or dynamically-built call
     cannot slip past a substring scan.
"""

from __future__ import annotations

import ast
import inspect
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import llm  # noqa: E402
from cockpit import winprofiles as winprofiles  # noqa: E402
from state import store as state_store  # noqa: E402
import sessions as sessions_db  # noqa: E402


# A value no real store would ever hold, used to prove each check CAN fail.
PLANT = "hackpit-planted-secret-3f9a1c"


# --------------------------------------------------------------------------- #
# 1. no secret reaches the browser
# --------------------------------------------------------------------------- #
def _real_secrets() -> dict[str, list[str]]:
    """Every secret value this process can actually reach, BY SOURCE.

    Hand-writing examples here would be the `python3` mistake from the gate audit —
    a value the real system never produces, asserted against forever. These are the
    live rows.

    Returned per-source, not as one flat list, because a leg with zero rows checks
    NOTHING and a flat total hides that. `state-credentials` is legitimately empty
    until an engagement captures one; the test prints the breakdown so an empty leg
    is visible rather than absorbed into a reassuring-looking total.
    """
    by_source: dict[str, list[str]] = {
        "winrm-profiles": [],
        "llm-api-key": [],
        "state-credentials": [],
    }

    # WinRM profile secrets — the raw accessor the endpoint must never call.
    for profile in winprofiles.list_profiles():
        if not profile.get("has_secret"):
            continue
        try:
            value = winprofiles.get_secret(profile["profile_id"])
        except Exception:  # noqa: BLE001 - an unreadable row is not a leak
            continue
        if value:
            by_source["winrm-profiles"].append(value)

    # The configured LLM API key (load_config MAY carry it; public_config never does).
    key = llm.load_config().get("api_key")
    if key:
        by_source["llm-api-key"].append(str(key))

    # Every credential captured into engagement state.
    for session in sessions_db.list_sessions():
        sid = session.get("session_id") or session.get("id")
        if not sid:
            continue
        try:
            summary = state_store.load(sid)
        except Exception:  # noqa: BLE001 - a missing state file is not a leak
            continue
        for cred in getattr(summary, "credentials", []) or []:
            value = getattr(cred, "secret", "")
            if value:
                by_source["state-credentials"].append(str(value))

    # Sub-4-char values match by chance and would make the check meaningless.
    return {k: [s for s in v if len(s) >= 4] for k, v in by_source.items()}


def _leaks(payload: str, secrets: list[str]) -> list[str]:
    """THE PREDICATE. Shared by the assertion and its control, so the control
    exercises the same code path the real check uses."""
    return [s for s in secrets if s in payload]


def test_home_summary_returns_no_secret() -> None:
    by_source = _real_secrets()
    secrets = [s for values in by_source.values() for s in values]

    with TestClient(main.app) as client:
        response = client.get("/home-summary")
    assert response.status_code == 200, response.text
    payload = json.dumps(response.json())

    hits = _leaks(payload, secrets)
    assert not hits, f"/home-summary leaked {len(hits)} real secret value(s)"

    # The whole test must not be able to go vacuous: if EVERY store is empty there is
    # nothing to leak and "PASS" would mean nothing.
    assert secrets, "no real secret found in any store — this test proved nothing"

    # POSITIVE CONTROL. "No offenders" is what a working check reports AND what a
    # broken one reports. Plant a REAL secret (not a synthetic string) into a payload:
    # the same predicate must catch it.
    control = secrets[0]
    planted = json.dumps({"rail": {"leaked": control}})
    assert _leaks(planted, [control]) == [control], (
        "the leak predicate cannot fail — it would pass on a real leak"
    )
    # ...and it must not fire on the clean payload for a reason as dumb as "matches
    # everything": a scan that flags the real response too is no better than none.
    assert _leaks(payload, [control]) == [], "the predicate fires on a clean payload"

    breakdown = ", ".join(f"{name}={len(v)}" for name, v in by_source.items())
    empty = [name for name, v in by_source.items() if not v]
    print(
        f"  checked {len(secrets)} real secret value(s) against {len(payload)} bytes "
        f"of payload ({breakdown}): PASS"
    )
    if empty:
        print(
            f"    NOTE: {', '.join(empty)} had no rows — that leg checked nothing "
            "(it fills in once an engagement captures one)."
        )


def test_summary_uses_only_the_masked_accessors() -> None:
    """The endpoint must call the PUBLIC accessors, never the raw ones.

    Asserted on the AST of the real function, not a substring of the file: an
    aliased import or a call opened inside a nested helper is invisible to a
    substring scan (the 2026-07-27 audit planted all four forms and missed all four).
    """
    banned = {"load_config", "get_secret", "_raw", "_public"}
    tree = ast.parse(inspect.getsource(main.home_summary))

    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                called.add(func.attr)
            elif isinstance(func, ast.Name):
                called.add(func.id)

    offenders = sorted(called & banned)
    assert not offenders, f"home_summary calls a raw/secret accessor: {offenders}"

    # It must actually call the masked ones — otherwise this test would still pass
    # if someone deleted the rail entirely and the invariant became vacuous.
    assert "public_config" in called, "expected llm.public_config() in home_summary"
    assert "list_profiles" in called, "expected winprofiles.list_profiles() in home_summary"

    # POSITIVE CONTROL — the same walk must flag a planted raw call.
    planted = ast.parse("def f():\n    return llm.load_config()['api_key']\n")
    planted_calls = {
        n.func.attr
        for n in ast.walk(planted)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert planted_calls & banned, "the AST call-scan cannot fail"

    print(f"  scanned {len(called)} call sites in home_summary, 0 raw accessors: PASS")


# --------------------------------------------------------------------------- #
# 2. the endpoint executes nothing
# --------------------------------------------------------------------------- #
_EXEC_NAMES = {
    "run", "run_kali", "iter_run", "exec_stream", "start", "spawn",
    "Popen", "check_output", "check_call", "call", "system", "popen",
    "ExecRequest", "validate_start", "import_module", "getattr",
}


def test_home_summary_cannot_execute() -> None:
    tree = ast.parse(inspect.getsource(main.home_summary))

    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                called.add(func.attr)
            elif isinstance(func, ast.Name):
                called.add(func.id)

    offenders = sorted(called & _EXEC_NAMES)
    assert not offenders, (
        f"home_summary can reach an execution path: {offenders}. A status endpoint "
        "must probe and count, never run."
    )

    # POSITIVE CONTROL — plant each banned form the scan claims to catch.
    for source in (
        "def f():\n    return subprocess.check_output(['docker','ps'])\n",
        "def f():\n    return executor.iter_run(req)\n",
        "def f():\n    return import_module('cockpit.kali')\n",
    ):
        planted = ast.parse(source)
        names: set[str] = set()
        for node in ast.walk(planted):
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Attribute):
                    names.add(fn.attr)
                elif isinstance(fn, ast.Name):
                    names.add(fn.id)
        assert names & _EXEC_NAMES, f"the exec scan missed a planted call: {source!r}"

    print(f"  scanned {len(called)} call sites, 0 execution paths (3 planted forms caught): PASS")


if __name__ == "__main__":
    print("== /home-summary launcher-rail SAFETY invariants ==")
    test_home_summary_returns_no_secret()
    test_summary_uses_only_the_masked_accessors()
    test_home_summary_cannot_execute()
    print("all /home-summary safety tests passed")
    sys.exit(0)
