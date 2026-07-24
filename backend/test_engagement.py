"""Tests for the M3 engagement/report path (hermetic — stdlib + local modules only).

Covers:
  1. a cockpit run is RECORDED against a session and listed back READ-ONLY
     (runstore.save_run + list_runs_for_session, and the router's GET handler);
  2. the report generator folds a recorded run's command + VERBATIM output into the
     authoritative (code-built, not model-written) Evidence section, and cites it by
     run id in the prompt;
  3. out-of-scope hosts from the composed path's scope are surfaced so the report
     excludes them from findings.

No live LLM: report.py builds the Evidence section + prompt deterministically (the LLM
only writes prose around them), so these assertions are exact and repeatable. A real
Ollama end-to-end gen was verified interactively in the M3 session log.

Uses a throwaway temp DB (the real sessions.db is never touched). Run:
  python test_engagement.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import report as R
import sessions as sessions_db
from cockpit import runstore
from cockpit.models import RunRecord
from cockpit.router import list_runs


def _use_temp_db():
    """Point BOTH the sessions layer and the cockpit runstore at one throwaway DB
    file (they share sessions.db in production). Returns a restore fn."""
    tmp = Path(tempfile.mkdtemp()) / "test_sessions.db"
    orig = (sessions_db.DB_PATH, runstore.DB_PATH)
    sessions_db.DB_PATH = tmp
    runstore.DB_PATH = tmp
    sessions_db.init_db()
    runstore.init_db()

    def restore():
        sessions_db.DB_PATH, runstore.DB_PATH = orig

    return restore


_SAMPLE_PATH = {
    "goal": "web app bug bounty on hackpit-lab-target",
    "target_type": "bugbounty",
    "target": "hackpit-lab-target",
    "profile": {"out_of_scope": ["/admin", "billing.internal"]},
    "phases": [
        {
            "phase": "recon",
            "label": "Recon",
            "steps": [
                {"id": "recon-1", "title": "probe web", "why": "surface",
                 "commands": [], "checked": False, "result_text": ""}
            ],
        }
    ],
    "model_used": "test",
    "provider": "test",
}


def _run_for(sid: str) -> RunRecord:
    return RunRecord(
        run_id="ffd5acb0e78a",
        command="curl",
        args=["-sSI", "http://hackpit-lab-target:3000/"],
        target="hackpit-lab-target",
        approved=True,
        exit_code=0,
        stdout="HTTP/1.1 200 OK\nX-Frame-Options: SAMEORIGIN\n",
        stderr="",
        started_at="2026-07-24T00:00:00+00:00",
        finished_at="2026-07-24T00:00:01+00:00",
        session_id=sid,
        step_id=None,
    )


def test_run_recorded_and_listed_readonly() -> None:
    restore = _use_temp_db()
    try:
        sid = sessions_db.create_session(
            _SAMPLE_PATH["goal"], "bugbounty", _SAMPLE_PATH
        )
        # a cockpit run is recorded against the session
        runstore.save_run(_run_for(sid))

        # listed back by session — this is what GET /cockpit/runs returns
        runs = runstore.list_runs_for_session(sid)
        assert len(runs) == 1, "the recorded run must be listed for its session"
        r = runs[0]
        assert r.session_id == sid and r.command == "curl" and r.exit_code == 0
        assert "HTTP/1.1 200 OK" in r.stdout, "verbatim output must be retained"

        # the router's GET handler returns the same, READ-ONLY (no mutation)
        via_router = list_runs(session_id=sid)
        assert [x.run_id for x in via_router] == ["ffd5acb0e78a"]
        assert len(runstore.list_runs_for_session(sid)) == 1, "listing must not mutate"

        # a different / unknown session sees nothing (scoped read)
        assert runstore.list_runs_for_session("nope") == []
        print("  run recorded + listed read-only: PASS")
    finally:
        restore()


def test_report_folds_run_into_evidence() -> None:
    """The report's authoritative Evidence section reproduces the run's command +
    output VERBATIM, and the prompt cites the run by id."""
    restore = _use_temp_db()
    try:
        sid = sessions_db.create_session(
            _SAMPLE_PATH["goal"], "bugbounty", _SAMPLE_PATH
        )
        runstore.save_run(_run_for(sid))
        session = sessions_db.get_session(sid)
        assert session is not None
        # main.py attaches the runs exactly like this before compose_report
        session["execution_runs"] = [
            r.model_dump() for r in runstore.list_runs_for_session(sid)
        ]

        evidence = R.build_evidence_section(session)
        assert "run-ffd5acb0e78a · sandbox execution" in evidence, "run must head an Evidence block"
        assert "curl -sSI http://hackpit-lab-target:3000/" in evidence, "command line verbatim"
        assert "HTTP/1.1 200 OK" in evidence and "X-Frame-Options: SAMEORIGIN" in evidence, \
            "captured output must be reproduced verbatim"
        assert "Output (exit 0):" in evidence, "exit code must be recorded"

        prompt = R.build_prompt(session)
        assert "[EXECUTED] (run-ffd5acb0e78a)" in prompt, "run listed as executed evidence"
        assert "Evidence: run-ffd5acb0e78a" in prompt, "prompt must instruct citing by run id"
        print("  report folds run into Evidence + cites run id: PASS")
    finally:
        restore()


def test_report_excludes_out_of_scope() -> None:
    """Out-of-scope hosts/paths from the scope are surfaced so the report keeps them
    out of findings (and never as a discovered vuln)."""
    restore = _use_temp_db()
    try:
        sid = sessions_db.create_session(
            _SAMPLE_PATH["goal"], "bugbounty", _SAMPLE_PATH
        )
        session = sessions_db.get_session(sid)
        assert session is not None
        prompt = R.build_prompt(session)
        assert "OUT OF SCOPE" in prompt, "scope must produce an OUT OF SCOPE directive"
        assert "/admin" in prompt and "billing.internal" in prompt, \
            "each out-of-scope host/path must be named so it is excluded from findings"
        assert "never report these as findings" in prompt.lower() or \
               "never report as findings" in prompt.lower(), \
            "the directive must forbid reporting out-of-scope items as findings"

        # a path with NO out-of-scope must not emit the directive (additive behaviour)
        no_scope = dict(_SAMPLE_PATH)
        no_scope["profile"] = {"out_of_scope": []}
        sid2 = sessions_db.create_session(no_scope["goal"], "bugbounty", no_scope)
        s2 = sessions_db.get_session(sid2)
        assert s2 is not None
        assert "OUT OF SCOPE" not in R.build_prompt(s2), \
            "no scope => no OUT OF SCOPE directive (Companion behaviour unchanged)"
        print("  report excludes out-of-scope hosts: PASS")
    finally:
        restore()


if __name__ == "__main__":
    test_run_recorded_and_listed_readonly()
    test_report_folds_run_into_evidence()
    test_report_excludes_out_of_scope()
    print("ALL engagement/report path tests pass")
