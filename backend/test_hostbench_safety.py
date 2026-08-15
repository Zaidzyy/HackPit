"""`:capture` host-bench launcher SAFETY invariants — the line this file holds.

The host-bench is the ONE surface that runs a HOST command, not a sandboxed one, so it is boxed:

  1. OFF BY DEFAULT. With HACKPIT_HOST_BENCH unset, start() REFUSES and nothing spawns — the backend
     has zero host-exec capability in the default build.
  2. FIXED SCRIPT + WHITELISTED ARGV. bench_argv() always yields `bash <tools/capture-bench.sh> …`;
     an arg carrying a shell metacharacter is REFUSED. It can launch only that one known script.
  3. HUMAN-ONLY. The orchestrator/loop cannot reach it — no surface-proposal name, no reference in
     orchestrator.py. A human clicks the button; that is the only caller.

Run:  python test_hostbench_safety.py
"""
from __future__ import annotations

import os
from pathlib import Path

import orchestrator

from cockpit import hostbench


def _with_env(value: str | None):
    prev = os.environ.get(hostbench.ENABLE_ENV)
    if value is None:
        os.environ.pop(hostbench.ENABLE_ENV, None)
    else:
        os.environ[hostbench.ENABLE_ENV] = value
    return prev


def test_off_by_default_refuses_and_spawns_nothing() -> None:
    prev = _with_env(None)  # ensure unset
    try:
        assert hostbench.enabled() is False
        try:
            hostbench.start(hostbench.BenchStartRequest(pkg="fishbowl"))
        except hostbench.BenchRefused:
            pass
        else:
            raise AssertionError("start() must refuse when the env flag is unset")
        # the refusal happens BEFORE any spawn, so no job/process was created
        assert hostbench.status()["job"] is None
        assert hostbench.status()["enabled"] is False
    finally:
        _with_env(prev)
    print("  OFF by default: start() refuses, nothing spawns: PASS")


def test_bench_argv_is_the_one_fixed_script() -> None:
    argv = hostbench.bench_argv(
        hostbench.BenchStartRequest(apk="C:/x/app.apkm", pkg="fishbowl", port=8080, frida=True)
    )
    assert argv[0] == "bash"
    assert argv[1].replace("\\", "/").endswith("tools/capture-bench.sh")
    assert "--apk" in argv and "--pkg" in argv and "--frida" in argv
    assert "8080" in argv
    print("  bench_argv is always `bash tools/capture-bench.sh …` with the operator's args: PASS")


def test_injection_in_args_is_refused() -> None:
    for bad in ["app.apkm; rm -rf /", "$(whoami)", "a && b", "`id`", "x|y", "a>b", 'q"uote']:
        try:
            hostbench.bench_argv(hostbench.BenchStartRequest(apk=bad))
        except hostbench.BenchRefused:
            continue
        raise AssertionError(f"a shell metacharacter in an arg must be refused: {bad!r}")
    print("  an arg carrying a shell metacharacter is refused (no injection): PASS")


def test_orchestrator_cannot_invoke_the_host_bench() -> None:
    # the loop's invokable surfaces must NOT include the host bench
    assert "bench" not in orchestrator._SURFACE_NAMES, orchestrator._SURFACE_NAMES
    assert "capture" not in orchestrator._SURFACE_NAMES
    # and the orchestrator source must not reference it at all
    src = Path(orchestrator.__file__).read_text(encoding="utf-8")
    for needle in ("hostbench", "bench_argv", "/bench/start", "capture-bench"):
        assert needle not in src, f"orchestrator must not reference {needle!r}"
    print("  HUMAN-ONLY: the orchestrator/loop cannot reach the host bench: PASS")


if __name__ == "__main__":
    test_off_by_default_refuses_and_spawns_nothing()
    test_bench_argv_is_the_one_fixed_script()
    test_injection_in_args_is_refused()
    test_orchestrator_cannot_invoke_the_host_bench()
    print("host-bench safety: all invariants hold.")
