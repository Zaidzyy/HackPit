"""`:capture` host-bench launcher SAFETY invariants — the line this file holds.

The host-bench is the ONE surface that runs a HOST command, not a sandboxed one, so it is boxed:

  1. ON BY DEFAULT (operator's standing choice) — unset => enabled. The kill-switch
     HACKPIT_HOST_BENCH=0 disables it: start() then REFUSES and nothing spawns.
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


def test_on_by_default_and_kill_switch_refuses_and_spawns_nothing() -> None:
    # ON by default: unset => enabled. (We do NOT call start() here — enabled, it would really spawn.)
    prev = _with_env(None)
    try:
        assert hostbench.enabled() is True
    finally:
        _with_env(prev)
    # kill-switch: HACKPIT_HOST_BENCH=0 disables -> start() refuses, nothing spawns.
    prev = _with_env("0")
    try:
        assert hostbench.enabled() is False
        try:
            hostbench.start(hostbench.BenchStartRequest(pkg="fishbowl"))
        except hostbench.BenchRefused:
            pass
        else:
            raise AssertionError("start() must refuse when disabled via HACKPIT_HOST_BENCH=0")
        assert hostbench.status()["job"] is None  # refusal is BEFORE any spawn
        assert hostbench.status()["enabled"] is False
    finally:
        _with_env(prev)
    print("  ON by default; HACKPIT_HOST_BENCH=0 disables -> start refuses, nothing spawns: PASS")


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


def test_loop_may_propose_capture_but_the_proposer_executes_nothing() -> None:
    # Operator's standing choice: the loop MAY propose :capture as a surface action.
    assert "capture" in orchestrator._SURFACE_NAMES, orchestrator._SURFACE_NAMES
    # But the proposer still EXECUTES NOTHING — it emits a proposal; the human approves it and the
    # frontend routes the approved call to the gated /cockpit/bench/start. The orchestrator must
    # never import or call the host-bench itself (proposer-executes-nothing holds even here).
    src = Path(orchestrator.__file__).read_text(encoding="utf-8")
    for needle in ("hostbench", "bench_argv", "hostbench.start", "/bench/start"):
        assert needle not in src, f"the PROPOSER must not execute the host bench ({needle})"
    print("  loop may PROPOSE :capture; the proposer executes nothing (human-approved frontend does): PASS")


if __name__ == "__main__":
    test_on_by_default_and_kill_switch_refuses_and_spawns_nothing()
    test_bench_argv_is_the_one_fixed_script()
    test_injection_in_args_is_refused()
    test_loop_may_propose_capture_but_the_proposer_executes_nothing()
    print("host-bench safety: all invariants hold.")
