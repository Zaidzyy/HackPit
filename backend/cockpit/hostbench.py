"""`:capture` — launch the mobile-capture BENCH on the HOST, as a gated, HUMAN-ONLY job.

*** THIS IS THE ONE SURFACE THAT RUNS A HOST COMMAND, NOT A SANDBOXED ONE. *** Every other surface
``docker exec``s into a sandbox; the capture bench needs the host's emulator / adb / frida / KVM,
which the sandbox does not have. Because it shells out to the host, it is boxed in three ways:

  * ON BY DEFAULT — the operator's standing choice (host-exec always available). The kill-switch is
    ``HACKPIT_HOST_BENCH=0`` (or false/no/off), which makes :func:`start` refuse and spawn NOTHING.
    Note the posture: the env flag is no longer the wall — the two guardrails BELOW are, and they do
    not depend on it.
  * PROPOSER EXECUTES NOTHING + A HUMAN APPROVES. The loop MAY propose ``:capture`` as a surface
    action (the operator's standing choice), but the proposer RUNS NOTHING — it emits a proposal the
    human approves, and the FRONTEND routes that approved call to the gated ``/cockpit/bench/start``.
    There is no MCP tool and no backend path from the proposer to this launcher, so a human always
    approves before the bench boots. ``test_hostbench_safety`` locks the proposer-executes-nothing line.
  * A FIXED SCRIPT with WHITELISTED args — not a host shell. It runs exactly
    ``bash tools/capture-bench.sh`` with a validated arg set, passed as ARGV (never a shell string),
    so there is no injection and it can launch only that one known script.

It automates the mechanical bench (boot -> install -> cert -> proxy) and stops at the script's
"log in now" pause. Login and the capture-paste into ``:repeater`` stay human — this is the setup
half, made one click.
"""
from __future__ import annotations

import os
import re
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

#: The bench script, resolved from THIS file's location — never from an argv input.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_BENCH = _REPO_ROOT / "tools" / "capture-bench.sh"

#: The env flag. The launcher is ON BY DEFAULT (operator's standing choice); this flag is the
#: kill-switch — set it to 0/false/no/off to disable. The real safety is the human-only + fixed-script
#: constraints, which hold regardless of this flag.
ENABLE_ENV = "HACKPIT_HOST_BENCH"

#: A conservative allowlist for the operator-supplied path / name args. Blocks every shell
#: metacharacter (`;` `$` `` ` `` `|` `&` `<` `>` quotes, newline) — defence in depth on top of the
#: fact that these already travel as argv, never a shell string.
_SAFE = re.compile(r"^[A-Za-z0-9 ._:/\\()+-]*$")


def enabled() -> bool:
    """ON by default (the operator's standing choice) — the host-bench endpoint is always live.
    Disabled only when HACKPIT_HOST_BENCH is explicitly 0/false/no/off."""
    return os.environ.get(ENABLE_ENV, "1").strip().lower() not in ("0", "false", "no", "off")


class BenchStartRequest(BaseModel):
    apk: str = Field("", description="Path to an app bundle (.apkm/.xapk/.apk) to install. Optional.")
    pkg: str = Field("", description="APP_MATCH — a package-name substring to target. Optional.")
    avd: str = Field("", description="AVD name to boot (blank = the first available AVD).")
    port: int = Field(8080, ge=1, le=65535, description="mitmproxy port.")
    frida: bool = Field(False, description="Also push+start frida-server (for pinned apps).")


class BenchJob(BaseModel):
    id: str
    argv: list[str] = Field(default_factory=list)
    state: str = Field("running", description="running | finished")
    lines: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    started_at: str = ""


class BenchRefused(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


_lock = threading.Lock()
_job: BenchJob | None = None
_proc: "subprocess.Popen[str] | None" = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bash() -> str:
    """The bash to run the bench with. On Windows, PREFER Git Bash — it accepts ``C:/…`` paths and
    ships the unix userland the harness needs; the ``bash`` on PATH can resolve to WSL's bash, which
    needs ``/mnt/c/…`` and a different userland and so fails to even open the script. Falls back to
    whatever ``bash`` is found (correct on Linux/macOS)."""
    import shutil
    for cand in (
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ):
        if os.path.exists(cand):
            return cand
    return shutil.which("bash") or "bash"


def bench_argv(req: BenchStartRequest) -> list[str]:
    """The FIXED script + whitelisted args, as argv. PURE — validates, spawns nothing. Rejects any
    arg that is not on the allowlist (the one place operator text reaches the host)."""
    def ok(v: str, what: str) -> str:
        v = (v or "").strip()
        if v and not _SAFE.match(v):
            raise BenchRefused(f"illegal characters in {what} — refused")
        return v

    # Git Bash (resolved above) + forward slashes: bash must not eat a native Windows path's
    # backslashes as escapes, and WSL's bash cannot open a `C:/…` path at all.
    argv = [_bash(), str(_BENCH).replace("\\", "/")]
    apk, pkg, avd = ok(req.apk, "apk path"), ok(req.pkg, "pkg"), ok(req.avd, "avd name")
    if apk:
        argv += ["--apk", apk]
    if pkg:
        argv += ["--pkg", pkg]
    if avd:
        argv += ["--avd", avd]
    argv += ["--port", str(int(req.port))]
    if req.frida:
        argv += ["--frida"]
    return argv


def start(req: BenchStartRequest) -> BenchJob:
    """Launch the bench — ONLY when enabled. Refuses (nothing spawns) when the env flag is unset,
    the script is missing, a job is already running, or an arg fails the allowlist."""
    if not enabled():
        raise BenchRefused(
            f"{ENABLE_ENV} is not set — the host-bench launcher is OFF by default (nothing ran)"
        )
    if not _BENCH.exists():
        raise BenchRefused(f"bench script not found at {_BENCH}")
    argv = bench_argv(req)  # may raise BenchRefused (allowlist)
    global _job
    with _lock:
        if _job is not None and _job.state == "running":
            raise BenchRefused("a bench job is already running — stop it first")
        job = BenchJob(id=uuid.uuid4().hex[:12], argv=argv, started_at=_now())
        _job = job
    threading.Thread(target=_run, args=(job, argv), daemon=True, name=f"bench-{job.id}").start()
    return job


def _run(job: BenchJob, argv: list[str]) -> None:
    """Stream the bench's output into the job. Never raises."""
    global _proc
    try:
        proc = subprocess.Popen(
            argv, cwd=str(_REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        with _lock:
            _proc = proc
        assert proc.stdout is not None
        for line in proc.stdout:
            with _lock:
                if len(job.lines) < 5000:
                    job.lines.append(line.rstrip("\n"))
        proc.wait()
        with _lock:
            job.exit_code = proc.returncode
            job.state = "finished"
    except Exception as exc:  # noqa: BLE001 - a launcher failure must not take the backend down
        with _lock:
            job.lines.append(f"bench error: {exc}")
            job.state = "finished"
            job.exit_code = -1


def status() -> dict[str, Any]:
    with _lock:
        return {
            "enabled": enabled(),
            "enable_env": ENABLE_ENV,
            "bench_path": str(_BENCH),
            "job": _job.model_dump() if _job is not None else None,
        }


def stop() -> dict[str, Any]:
    """Ungated stop — killing the process removes capability, never adds it (mirrors every surface's
    ungated stop)."""
    with _lock:
        p = _proc
    if p is not None and p.poll() is None:
        try:
            p.terminate()
        except Exception:  # noqa: BLE001
            pass
    return {"stopped": True}
