"""SAFETY INVARIANTS for the finding pipeline (backend/findings/). Spec §0.

The claims this feature makes; if one stops being true, this file fails.

  1. EXECUTES NOTHING — schema / dedup / ranking / post-scripts are pure data. The package
     makes no eval/exec/compile, no subprocess, no socket, no HTTP call — proven by AST, WITH A
     CONTROL that plants a violation and shows the scanner catches it.
  2. NO NEW GATE — the package imports no cockpit / executor / engagement / sandbox / state /
     attack_path module and references no gate symbol. The coupling (dict -> Finding, command
     post-script -> gated executor) lives in the app layer, so a finding operation can never
     reach a gate, a target or a sandbox from here.
  3. A COMMAND POST-SCRIPT IS APPROVE-EACH — a PoC post-script returns a proposal
     (needs_approval, executed:false) and never fires. Data post-scripts run in-process.
  4. THE 3-SCHEMA-PLACES RULE — the new structured fields survive the response round-trip:
     built into a Finding, they read back through GET /sessions/{id}/state AND through the
     pipeline route, so no response_model strips them.

Run:  python test_finding_pipeline_safety.py
"""

from __future__ import annotations

import ast
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# *** temp DB BEFORE any connection opens (test_zap_scan_ingest house style). *** #
# The state package spreads across store/tasks/governance, and tasks.py + governance.py each did
# `from .store import DB_PATH` at import — capturing a *copy* of the path. Redirecting only
# store.DB_PATH therefore leaves those two pointed at the real (gitignored) sessions.db, and
# store.init_db() alone never creates state_tasks. On a clean CI checkout the pipeline route then
# raised `no such table: state_tasks`. Redirect all three captured paths to the temp DB, then
# create every state table through the package-level init (store + tasks + governance).
import state as _engagement_state  # noqa: E402
from state import store  # noqa: E402
from state import governance as _gov  # noqa: E402
from state import tasks as _tasks  # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix="hackpit-fp-safety-")) / "sessions.db"
store.DB_PATH = _TMP
_tasks.DB_PATH = _TMP
_gov.DB_PATH = _TMP
_engagement_state.init_db()

from fastapi.testclient import TestClient  # noqa: E402

import findings  # noqa: E402
import main  # noqa: E402
from findings import postscripts  # noqa: E402
from state.models import Finding  # noqa: E402

_PKG = Path(findings.__file__).parent
_SOURCES = sorted(_PKG.glob("*.py"))


def _all_source() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in _SOURCES)


# --------------------------------------------------------------------------- #
# the shared AST scanner (also used against a planted control)
# --------------------------------------------------------------------------- #
_CALL_NAMES = {"eval", "exec", "compile", "__import__"}
_CALL_ATTRS = {
    ("os", "system"), ("os", "popen"), ("os", "exec"), ("subprocess", "Popen"),
    ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "check_output"),
    ("subprocess", "getoutput"), ("socket", "socket"), ("pickle", "load"),
    ("pickle", "loads"),
}
_BANNED_IMPORTS = {"subprocess", "socket", "requests", "httpx", "aiohttp", "pickle",
                   "ctypes", "urllib"}


def _execution_offenses(source: str, label: str) -> list[str]:
    """Return the execution primitives found in ``source`` by AST (empty == clean)."""
    tree = ast.parse(source)
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in _CALL_NAMES:
                out.append(f"{label}: call to {fn.id}()")
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                if (fn.value.id, fn.attr) in _CALL_ATTRS:
                    out.append(f"{label}: call to {fn.value.id}.{fn.attr}()")
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _BANNED_IMPORTS:
                    out.append(f"{label}: import {alias.name}")
        if isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in _BANNED_IMPORTS:
                out.append(f"{label}: from {node.module} import …")
    return out


def test_the_package_executes_nothing() -> None:
    """AST over every findings/*.py: no execution primitive anywhere."""
    offenses: list[str] = []
    for p in _SOURCES:
        offenses += _execution_offenses(p.read_text(encoding="utf-8"), p.name)
    assert not offenses, "the finding pipeline must execute nothing:\n  " + "\n  ".join(offenses)

    # POSITIVE CONTROL — the scanner must catch a planted violation, or its silence means nothing.
    planted = (
        "import subprocess, socket\n"
        "def go(x):\n"
        "    eval(x)\n"
        "    subprocess.Popen(['id'])\n"
        "    socket.socket()\n"
    )
    caught = _execution_offenses(planted, "control")
    assert any("eval" in c for c in caught) and any("Popen" in c for c in caught) \
        and any("subprocess" in c for c in caught), caught
    print("  findings/ makes no eval/exec/subprocess/socket call, and the scanner catches a "
          "planted one: PASS")


def test_no_new_gate_and_full_orthogonality() -> None:
    """The package imports no attack-surface module and names no gate symbol."""
    src = _all_source()
    for module in ("cockpit", "executor", "engagement", "sandbox", "allowlist",
                   "orchestrator", "sessions", "attack_path", "adgraph", "cloudgraph"):
        assert not any(
            (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == module)
            or (isinstance(n, ast.Import) and any(
                a.name.split(".")[0] == module for a in n.names))
            for n in ast.walk(ast.parse(src))
        ), f"findings/ must not import {module} — it is orthogonal to the attack surface"
    # findings/ does not even import state: the dict -> Finding bridge lives in main.py.
    assert "import state" not in src and "from state" not in src, (
        "findings/ must not import state — the persistence bridge lives in the app layer")
    for symbol in ("validate_request", "check_target_lock", "run_kali", "assert_isolation_proven",
                   "dangerous_ack", "resolve_mode", "target_lock"):
        assert symbol not in src, f"findings/ must not reference the gate symbol {symbol}"
    print("  findings/ imports no cockpit/executor/state/attack-surface module, names no gate: "
          "PASS")


def test_command_postscript_never_auto_fires() -> None:
    """Every command post-script is approve-each; every data one runs in-process — and neither
    the module nor the route can execute a command."""
    finding = {"title": "SQLi", "severity": "critical", "target": "https://x/api?id=1",
               "reference": "CWE-89", "source_refs": ["api/db.py:42"],
               "attacker_path": "id=1 OR 1=1"}
    for meta in postscripts.list_postscripts():
        ps = postscripts.get_postscript(meta["id"])
        result = postscripts.run(ps, finding)
        if meta["mode"] == "command":
            assert result["needs_approval"] is True and result["executed"] is False, meta
            assert result["command"], "a command post-script must yield a command to approve"
        else:
            assert result["mode"] == "data", meta
            assert "command" not in result or not result.get("command"), (
                "a data post-script must not produce a command to run")
    # the app-layer route surfaces the proposal; it does not fire it.
    client = TestClient(main.app)
    r = client.post("/sessions/preview/findings/postscript",
                    json={"postscript_id": "poc-curl", "finding": finding})
    assert r.status_code == 200, r.text[:300]
    res = r.json()["result"]
    assert res["executed"] is False and res["needs_approval"] is True, res
    print("  command post-scripts are approve-each (proposal only) end to end; data ones run "
          "in-process: PASS")


def test_new_schema_fields_survive_the_response_round_trip() -> None:
    """THE 3-SCHEMA-PLACES RULE. The structured fields, built into a Finding, must read back
    through BOTH the state route and the pipeline route — proof no response_model strips them."""
    sid = "s-fp-roundtrip"
    store.clear(sid)
    store.upsert_findings([Finding(
        session_id=sid, title="SSRF in the image proxy", severity="high",
        target="https://x/proxy?url=", vuln_class="ssrf",
        attacker_path="url=http://169.254.169.254/ reaches IMDS",
        source_refs=["proxy/fetch.py:34", "proxy/fetch.py:40"],
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        extra={"bounty_tier": "P2"}, merged_count=2, ranker="bug-bounty-payout",
    )])

    client = TestClient(main.app)

    # (a) GET /sessions/{id}/state — the read every surface uses.
    st = client.get(f"/sessions/{sid}/state")
    assert st.status_code == 200, st.text[:300]
    fs = st.json()["findings"]
    assert len(fs) == 1, fs
    f = fs[0]
    for key in ("attacker_path", "source_refs", "cvss", "vuln_class", "extra",
                "merged_count", "ranker"):
        assert key in f, f"the state route stripped the structured field '{key}'"
    assert f["source_refs"] == ["proxy/fetch.py:34", "proxy/fetch.py:40"], f["source_refs"]
    assert f["extra"]["bounty_tier"] == "P2", f["extra"]
    assert f["merged_count"] == 2 and f["vuln_class"] == "ssrf", f

    # (b) POST /sessions/{id}/findings/pipeline — the new route round-trips them too.
    pipe = client.post(f"/sessions/{sid}/findings/pipeline",
                       json={"ranker_id": "bug-bounty-payout", "persist": False})
    assert pipe.status_code == 200, pipe.text[:300]
    body = pipe.json()
    assert body["findings"], body
    pf = body["findings"][0]
    for key in ("attacker_path", "source_refs", "cvss", "vuln_class", "extra", "merged_count"):
        assert key in pf, f"the pipeline route stripped the structured field '{key}'"
    print("  the structured schema survives BOTH the state route and the pipeline route "
          "(no response_model strips it): PASS")


def test_persisted_pipeline_collapses_but_never_multiplies() -> None:
    """Persisting the pipeline is a pure data op: duplicates collapse, and re-running is
    idempotent (the finding count never grows)."""
    sid = "s-fp-persist"
    store.clear(sid)
    store.upsert_findings([
        Finding(session_id=sid, title="SQL injection in ?id=1", severity="high",
                vuln_class="sqli", reference="CWE-89", source_refs=["db.py:42"]),
        Finding(session_id=sid, title="SQLi via sort=", severity="critical",
                vuln_class="sqli", reference="CWE-89", source_refs=["db.py:42"]),
    ])
    client = TestClient(main.app)
    before = len(store.load(sid).findings)
    assert before == 2, before
    r1 = client.post(f"/sessions/{sid}/findings/pipeline",
                     json={"ranker_id": "default", "persist": True})
    assert r1.status_code == 200, r1.text[:300]
    after = store.load(sid).findings
    assert len(after) == 1, f"the two SQLi should collapse to one, got {len(after)}"
    assert after[0].severity == "critical", "the worst severity survives the collapse"
    # re-running persist must NOT multiply or re-inflate
    client.post(f"/sessions/{sid}/findings/pipeline",
                json={"ranker_id": "default", "persist": True})
    assert len(store.load(sid).findings) == 1, "re-persisting must stay idempotent"
    print("  persisting the pipeline collapses duplicates and stays idempotent: PASS")


if __name__ == "__main__":
    test_the_package_executes_nothing()
    test_no_new_gate_and_full_orthogonality()
    test_command_postscript_never_auto_fires()
    test_new_schema_fields_survive_the_response_round_trip()
    test_persisted_pipeline_collapses_but_never_multiplies()
    print("ALL finding-pipeline SAFETY-invariant tests pass")
