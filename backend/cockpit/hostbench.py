"""`:capture` — launch the mobile-capture BENCH on the HOST, as a gated, HUMAN-ONLY job.

*** THIS IS THE ONE SURFACE THAT RUNS A HOST COMMAND, NOT A SANDBOXED ONE. *** Every other surface
``docker exec``s into a sandbox; the capture bench needs the host's emulator / adb / frida / KVM,
which the sandbox does not have. Because it shells out to the host, it is boxed in three ways:

  * OFF BY DEFAULT. Enabled only when ``HACKPIT_HOST_BENCH=1`` (the same opt-in shape as
    ``HACKPIT_MCP_EXECUTE``). With it unset, :func:`start` refuses and NOTHING spawns — the backend
    has ZERO host-exec capability by default, so an audit of the default build finds none.
  * HUMAN-ONLY. Like ``:kali`` / ``run_kali``, the orchestrator/loop can NEVER reach this: there is
    no surface-proposal kind and no MCP tool for it. A human clicks the button; that is the only
    caller. ``test_hostbench_safety`` asserts the orchestrator cannot invoke it.
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

#: The env flag that turns the host-bench launcher ON. OFF (unset) is the default and the audit-safe
#: state: with it unset the backend cannot run a host command at all.
ENABLE_ENV = "HACKPIT_HOST_BENCH"

#: A conservative allowlist for the operator-supplied path / name args. Blocks every shell
#: metacharacter (`;` `$` `` ` `` `|` `&` `<` `>` quotes, newline) — defence in depth on top of the
#: fact that these already travel as argv, never a shell string.
_SAFE = re.compile(r"^[A-Za-z0-9 ._:/\\()+-]*$")


def enabled() -> bool:
    return os.environ.get(ENABLE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


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


def bench_argv(req: BenchStartRequest) -> list[str]:
    """The FIXED script + whitelisted args, as argv. PURE — validates, spawns nothing. Rejects any
    arg that is not on the allowlist (the one place operator text reaches the host)."""
    def ok(v: str, what: str) -> str:
        v = (v or "").strip()
        if v and not _SAFE.match(v):
            raise BenchRefused(f"illegal characters in {what} — refused")
        return v

    argv = ["bash", str(_BENCH)]
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
