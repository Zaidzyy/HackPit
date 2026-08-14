"""Phase 1 steps 3-6 — per-request timeouts, background jobs, loot, reconciliation.

Hermetic: nothing here starts a container or touches the network. The one place a real
`docker exec` would happen is stubbed, and the assertions are about the argv that WOULD
have run — which is exactly where the safety-relevant properties live.

What these guard:
  * a per-request timeout is CLAMPED, never unbounded, and never a way past a gate
  * backgrounding changes WHEN output is read, never WHETHER a command was allowed
  * the LAB argv stays byte-identical to what it was before loot existed
  * loot directory names are validated, not sanitised
  * an unreconciled catalog reports UNKNOWN and filters nothing
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit import config, jobs, loot, reconcile  # noqa: E402
from cockpit.models import ExecRequest  # noqa: E402


# --------------------------------------------------------------------------- #
# step 3 — per-request timeout
# --------------------------------------------------------------------------- #
def test_timeout_is_clamped_never_unbounded() -> None:
    assert config.clamp_timeout(None) == config.EXEC_TIMEOUT_SECONDS, "unset -> default"
    assert config.clamp_timeout(0) == config.EXEC_TIMEOUT_SECONDS, "0 must not mean 'forever'"
    assert config.clamp_timeout(-5) == config.EXEC_TIMEOUT_SECONDS, "negative must not disable"
    assert config.clamp_timeout(600) == 600, "a reasonable ask is honoured"
    assert config.clamp_timeout(10**9) == config.MAX_TIMEOUT_SECONDS, "clamped to the ceiling"
    assert config.MAX_TIMEOUT_SECONDS <= 3600, "the ceiling must stay bounded"
    print("  timeout: unset/0/negative -> default, large -> clamped to the ceiling: PASS")


def test_timeout_is_not_a_gate_bypass() -> None:
    """A timeout is a resource bound, not a permission. It must not appear anywhere in the
    gate decision — an unapproved command is refused no matter how long it asked for."""
    from cockpit import executor as E

    r = E.validate_request(
        ExecRequest(command="nmap", args=["hackpit-lab-target"], timeout_seconds=3600)
    )
    assert r is not None and r.gate == "approval", (
        "a long timeout must not smuggle a command past the approval gate"
    )
    src = (Path(__file__).parent / "cockpit" / "executor.py").read_text(encoding="utf-8")
    gate_src = src.split("def resolve_mode")[0]
    assert "timeout_seconds" not in gate_src, (
        "the timeout must not be readable by any gate function"
    )
    print("  timeout is a resource bound, never part of a gate decision: PASS")


def test_idle_timeout_never_kills_a_streaming_run() -> None:
    """The per-run timeout on the streaming path is an IDLE window, not a wall-clock cap: a
    command that keeps producing output is 'properly running' and must never be timed out. This
    pins the pure watchdog policy so the streaming exec can't silently regress to a flat cap
    that killed a gau/ffuf/nuclei run mid-stream."""
    from cockpit.executor import _timeout_verdict

    # Actively streaming, well past the old flat 180s cap but under the ceiling -> keep running.
    assert _timeout_verdict(idle=2.0, total=3000.0, idle_limit=180, ceiling=3600) == ""
    # Gone silent past the idle window -> looks stuck, killed.
    assert _timeout_verdict(idle=181.0, total=181.0, idle_limit=180, ceiling=3600) == "idle"
    # Streaming forever (idle tiny) but at the absolute ceiling -> runaway backstop fires.
    assert _timeout_verdict(idle=1.0, total=3600.0, idle_limit=180, ceiling=3600) == "ceiling"
    # Just under both bounds -> keep running.
    assert _timeout_verdict(idle=179.9, total=3599.9, idle_limit=180, ceiling=3600) == ""
    print("  idle timeout: a streaming run is never killed; silence + ceiling still reap: PASS")


# --------------------------------------------------------------------------- #
# step 4 — loot
# --------------------------------------------------------------------------- #
def test_loot_names_are_validated_not_sanitised() -> None:
    """A loot name reaches both a host path and a `docker exec -w` argument. Anything that
    is not a plain token must be REFUSED — quietly rewriting it could land files somewhere
    the operator did not intend."""
    for bad in ("../etc", "a/b", "", " ", "-w", "x;rm -rf /", "a" * 200, "$(id)"):
        try:
            loot.container_dir(bad)
        except loot.LootError:
            continue
        raise AssertionError(f"unsafe loot name accepted: {bad!r}")
    assert loot.container_dir("a1b2c3d4") == "/loot/a1b2c3d4"
    print("  loot names: traversal / separators / shell metachars all refused: PASS")


def test_lab_runs_get_no_workdir_and_no_loot_mount() -> None:
    """The isolated lab sandbox deliberately has NO host mount, so a lab run must add no
    -w flag at all — its argv stays byte-identical to the pre-loot behaviour."""
    assert loot.workdir_for("lab", None) is None, "lab mode must not get a loot workdir"
    assert loot.workdir_for("lab", "deadbeef") is None, (
        "even with an id, LAB must not be pointed at loot — the lab has no mount"
    )
    assert loot.exec_flags(None) == [], "no workdir must mean no flags, not an empty -w"
    assert loot.describe()["lab_sandbox_has_loot"] is False
    print("  lab runs: no loot workdir, no -w flag, argv unchanged: PASS")


def test_engagement_runs_get_their_own_loot_dir() -> None:
    eid = "testeng0001"
    got = loot.workdir_for("engagement", eid)
    assert got == f"/loot/{eid}", f"engagement must work in its own loot dir, got {got}"
    assert loot.host_dir(eid).is_dir(), "the host side must exist or `docker exec -w` fails"
    assert loot.exec_flags(got) == ["-w", got]
    loot.host_dir(eid).rmdir()
    print("  engagement runs work in /loot/<engagement_id>, created on demand: PASS")


# --------------------------------------------------------------------------- #
# step 3 — background jobs
# --------------------------------------------------------------------------- #
def test_background_job_replays_then_follows() -> None:
    """The point of the job buffer: a client that attaches LATE still sees everything."""
    jobs.reset()

    def _events():
        yield {"type": "start", "run_id": "job1"}
        yield {"type": "stdout", "line": "one"}
        yield {"type": "stdout", "line": "two"}
        yield {"type": "exit", "run_id": "job1", "code": 0}

    jobs.start("job1", _events())
    for _ in range(200):                       # let the drain thread finish
        if not jobs.get("job1").done:
            time.sleep(0.01)
    seen = [e for e in jobs.follow("job1")]
    kinds = [e["type"] for e in seen]
    assert kinds == ["start", "stdout", "stdout", "exit"], kinds
    again = [e["type"] for e in jobs.follow("job1")]
    assert again == kinds, "every attach must replay from the beginning — reconnect is lossless"
    print("  background job: full replay, and replay is repeatable per attach: PASS")


def test_unknown_job_reads_as_an_error_event_not_an_exception() -> None:
    jobs.reset()
    out = list(jobs.follow("nosuchjob"))
    assert len(out) == 1 and out[0]["type"] == "error", out
    assert jobs.status("nosuchjob") is None
    print("  unknown/expired job: one error event, never a crash: PASS")


def test_job_buffer_is_capped_but_lifecycle_still_arrives() -> None:
    """A flooding job must not exhaust memory — but the client must still learn it exited."""
    jobs.reset()
    flood = "x" * 5000

    def _events():
        yield {"type": "start", "run_id": "job2"}
        for _ in range(int(config.JOB_OUTPUT_CAP / 5000) + 50):
            yield {"type": "stdout", "line": flood}
        yield {"type": "exit", "run_id": "job2", "code": 0}

    jobs.start("job2", _events())
    for _ in range(500):
        if not jobs.get("job2").done:
            time.sleep(0.01)
    job = jobs.get("job2")
    assert job.truncated, "a flooding job must be truncated"
    assert job.chars <= config.JOB_OUTPUT_CAP + 5000, "the cap must actually bound the buffer"
    kinds = [e["type"] for e in job.events]
    assert kinds[0] == "start" and kinds[-1] == "exit", (
        "lifecycle events must survive truncation — a client must always learn it exited"
    )
    print("  job buffer capped; start/exit still delivered through truncation: PASS")


def test_finished_jobs_are_reaped_on_a_timer_not_only_on_the_next_start() -> None:
    """Retention must mean elapsed time, not "until someone runs another command".

    The reaper originally ran ONLY inside start(), so a finished job's buffer was held
    until the next run began — which, on a box where you fire one long scan and walk away,
    is indefinite. reap_now() is the same sweep the background thread performs.
    """
    jobs.reset()

    def _events():
        yield {"type": "start", "run_id": "job3"}
        yield {"type": "exit", "run_id": "job3", "code": 0}

    jobs.start("job3", _events())
    for _ in range(300):
        if jobs.get("job3") and jobs.get("job3").done:
            break
        time.sleep(0.01)

    assert jobs.reap_now() == 0, "a just-finished job is inside the retention window"
    assert jobs.get("job3") is not None

    jobs.get("job3").finished_at = time.time() - config.JOB_RETENTION_SECONDS - 1
    assert jobs.reap_now() == 1, "a job past its retention window must be dropped"
    assert jobs.get("job3") is None, "the buffer must actually be released"

    src = (Path(__file__).parent / "cockpit" / "jobs.py").read_text(encoding="utf-8")
    assert "_ensure_reaper" in src and "_reaper_loop" in src, (
        "retention must be swept by a timer, not only when a new job starts"
    )
    print("  finished jobs reaped on elapsed time, not on the next start: PASS")


def test_a_running_job_is_never_reaped() -> None:
    """Retention applies to FINISHED jobs. Reaping a live one would strand its follower."""
    jobs.reset()
    started = {"go": True}

    def _events():
        yield {"type": "start", "run_id": "job4"}
        while started["go"]:
            time.sleep(0.01)
        yield {"type": "exit", "run_id": "job4", "code": 0}

    jobs.start("job4", _events())
    time.sleep(0.1)
    assert jobs.reap_now() == 0, "a running job must never be reaped"
    assert jobs.get("job4") is not None
    started["go"] = False
    print("  a still-running job is never reaped: PASS")


def test_backgrounding_is_not_an_approval_bypass() -> None:
    """`background` must be a transport choice and nothing more."""
    from cockpit import executor as E

    r = E.validate_request(
        ExecRequest(command="nmap", args=["hackpit-lab-target"], background=True)
    )
    assert r is not None and r.gate == "approval", (
        "backgrounding must NOT let an unapproved command through"
    )
    src = (Path(__file__).parent / "cockpit" / "jobs.py").read_text(encoding="utf-8")
    for banned in ("subprocess", "Popen", "docker", "validate_request", "os.system"):
        assert banned not in src, f"jobs.py must not reference {banned} — it is a consumer only"
    print("  backgrounding bypasses no gate; jobs.py starts nothing itself: PASS")


# --------------------------------------------------------------------------- #
# step 5/6 — reconciliation
# --------------------------------------------------------------------------- #
def test_unknown_availability_filters_nothing() -> None:
    """Absence must be PROVEN. If the probe could not run, every tool reads as present —
    the alternative (an empty prompt block) is a far stranger failure than proposing a
    tool that turns out to be missing."""
    state = reconcile.Reconciliation()
    assert state.available is False
    assert state.is_present("anything-at-all") is True, (
        "an unavailable probe must not report tools as missing"
    )
    state.available = True
    state.present = {"nmap"}
    assert state.is_present("nmap") is True
    assert state.is_present("ghidra") is False
    print("  unknown availability filters nothing; a real probe does: PASS")


def test_windows_only_tools_are_excluded_from_the_prompt() -> None:
    """They cannot run on a Linux sandbox by construction, so the model must never see
    them — regardless of what `command -v` says. Kali ships mimikatz/winpeas WRAPPERS that
    resolve on PATH but only stage the Windows binaries, so the probe alone is not enough."""
    from arsenal import loader, planner

    ars = loader.load()
    win = [t for t in ars.tools if not t.runs_here()]
    assert win, "the catalog must still mark its Windows-only entries"
    block = planner.prompt_block(ars).lower()
    for tool in win:
        assert tool.name.lower() not in block, (
            f"{tool.name} cannot run on the Linux sandbox and must not be proposable"
        )
    print(f"  {len(win)} Windows-only tools kept in the catalog but never proposed: PASS")


def test_prompt_block_is_unchanged_without_a_filter() -> None:
    """The availability filter is ADDITIVE: a caller that does not opt in gets exactly the
    block it got before reconciliation existed."""
    from arsenal import loader, planner

    ars = loader.load()
    assert planner.prompt_block(ars) == planner.prompt_block(ars, is_available=None)
    filtered = planner.prompt_block(ars, is_available=lambda n: False)
    assert "## recon" not in filtered, "filtering everything must empty the phase sections"
    print("  prompt block byte-identical without a filter; filter actually filters: PASS")


def test_orchestrator_prompt_names_no_specific_tools() -> None:
    """The prompt used to hardcode 'gobuster, nikto' — tools the image did not have. The
    tool list must come from the reconciled catalog block, never from prose."""
    src = (Path(__file__).parent / "orchestrator.py").read_text(encoding="utf-8")
    head = src.split("def build_user_prompt")[0]
    for tool in ("gobuster", "nikto", "sqlmap", "ffuf"):
        assert f"{tool}," not in head, (
            f"the system prompt must not hardcode {tool} — that is what drifted from reality"
        )
    print("  orchestrator prompt no longer hardcodes a tool list: PASS")


def test_the_ui_can_actually_reach_the_new_run_controls() -> None:
    """A backend capability the UI cannot send is not a delivered feature.

    The first cut of this work shipped `timeout_seconds` and `background` on the API while
    the frontend payload types carried neither — so from the app every command was still
    capped at 180s and nothing could be detached. This guards the wiring, not the styling.
    """
    fe = Path(__file__).parent.parent / "frontend" / "src"
    api = (fe / "lib" / "api.ts").read_text(encoding="utf-8")
    for field in ("timeout_seconds", "background"):
        assert field in api, f"the frontend API layer must be able to send {field}"
    for fn in ("execCockpitBackground", "attachCockpitStream"):
        assert fn in api, f"the frontend needs {fn} to drive a detached run"

    cockpit = (fe / "components" / "CockpitScreen.tsx").read_text(encoding="utf-8")
    assert "timeout_seconds" in cockpit, "the cockpit must send a per-run timeout"
    assert "execCockpitBackground" in cockpit, "the cockpit must offer a detached run"

    # :kali drives the persistent shell now (Phase-3 step 13); the per-command timeout is
    # passed to runInKaliShell, whose API wrapper sends it as timeout_seconds.
    kali = (fe / "components" / "KaliShell.tsx").read_text(encoding="utf-8")
    assert "KALI_TIMEOUT_CHOICES" in kali and "runInKaliShell" in kali, (
        ":kali must send a per-command timeout through the persistent shell (was a hard 60s)"
    )
    assert "timeout_seconds" in api, "the api layer must send :kali's per-command timeout"
    print("  the cockpit and :kali UIs can send timeout + detach: PASS")


if __name__ == "__main__":
    test_timeout_is_clamped_never_unbounded()
    test_timeout_is_not_a_gate_bypass()
    test_idle_timeout_never_kills_a_streaming_run()
    test_loot_names_are_validated_not_sanitised()
    test_lab_runs_get_no_workdir_and_no_loot_mount()
    test_engagement_runs_get_their_own_loot_dir()
    test_background_job_replays_then_follows()
    test_unknown_job_reads_as_an_error_event_not_an_exception()
    test_job_buffer_is_capped_but_lifecycle_still_arrives()
    test_finished_jobs_are_reaped_on_a_timer_not_only_on_the_next_start()
    test_a_running_job_is_never_reaped()
    test_backgrounding_is_not_an_approval_bypass()
    test_the_ui_can_actually_reach_the_new_run_controls()
    test_unknown_availability_filters_nothing()
    test_windows_only_tools_are_excluded_from_the_prompt()
    test_prompt_block_is_unchanged_without_a_filter()
    test_orchestrator_prompt_names_no_specific_tools()
    print("ALL Phase-1 runtime tests pass")
