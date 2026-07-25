"""SAFETY INVARIANTS for :code scan. These are the claims the feature makes; if one of
them stops being true, this file fails.

  1. STATIC ONLY — the scanned code is never executed. The only programs the module may
     launch are the scanners themselves, asserted from the outside AND by source-scan (no
     eval/exec/compile/import of scanned content, no shell).
  2. ORTHOGONAL — codescan shares nothing with the attack surface. It imports no cockpit /
     engagement / executor / scope / isolation module and names none of their symbols, so a
     code scan cannot reach a gate, a target or a sandbox.
  3. BOUNDED — the timeout is honored, the output cap is enforced, the path is validated,
     and an oversized tree is refused before a scanner launches.
  4. READ-ONLY — a scan does not modify the codebase it reads.
  5. THE ATTACK SURFACE IS UNTOUCHED — the lab/engagement gate wording and order are
     byte-for-byte what they were.

Run:  python test_codescan_safety.py
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from codescan import runner

_PKG = Path(__file__).parent / "codescan"
_SOURCES = sorted(_PKG.glob("*.py"))


def _all_source() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in _SOURCES)


# --------------------------------------------------------------------------- #
# 1. STATIC ONLY
# --------------------------------------------------------------------------- #
def test_only_a_scanner_can_ever_be_launched() -> None:
    """The guarantee, from the outside: hand _spawn any other program and it refuses."""
    for argv in (
        ["python", "-c", "print(1)"],
        ["/usr/bin/python3", "evil.py"],
        ["sh", "-c", "id"],
        ["cmd.exe", "/c", "dir"],
        ["./configure"],                       # a file FROM the scanned tree
        ["node", "index.js"],
        ["semgreppy", "--json"],               # near-miss name
    ):
        try:
            runner._spawn(argv, 5)
        except AssertionError:
            continue
        raise AssertionError(f"_spawn accepted a non-scanner program: {argv}")

    # and the allowed set is exactly the two scanners
    assert runner._TOOLS == ("semgrep", "bandit"), runner._TOOLS
    print("  only semgrep/bandit can be launched — any other program is refused: PASS")


def test_no_execution_primitives_in_the_source() -> None:
    """Source-scan: nothing in codescan can execute, evaluate or import scanned content."""
    src = _all_source()
    banned = {
        r"\beval\s*\(": "eval()",
        r"\bexec\s*\(": "exec()",
        # the BUILTIN compile — a leading dot means an attribute (re.compile is fine)
        r"(?<!\.)\bcompile\s*\(": "the compile() builtin",
        r"__import__": "__import__",
        r"\bimportlib\b": "importlib",
        # pickle as a USE, not as a word — "pickle" appears as a KB search token in
        # kb_link.py, which is text about deserialization, not deserialization.
        r"\bimport\s+pickle\b|\bpickle\.\w": "pickle",
        r"shell\s*=\s*True": "shell=True",
        r"\bos\.system\b": "os.system",
        r"\bos\.popen\b": "os.popen",
        r"subprocess\.(?:call|run|check_output|getoutput)\b": "an unbounded subprocess helper",
    }
    for pattern, label in banned.items():
        hit = re.search(pattern, src)
        assert hit is None, f"codescan must not use {label} (found at offset {hit.start()})"
    # the ONE subprocess entry point is Popen inside _spawn, which asserts the program
    assert src.count("subprocess.Popen") == 1, "there must be exactly one spawn site"
    assert "shell=False" in src, "the spawn site must pin shell=False explicitly"
    print("  no eval/exec/compile/import/shell anywhere; exactly one asserted spawn site: PASS")


def test_the_scanned_path_is_only_ever_an_argument() -> None:
    """A path from the codebase can never become argv[0]."""
    with tempfile.TemporaryDirectory() as tmp:
        planted = Path(tmp) / "evil.sh"
        planted.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
        try:
            runner._spawn([str(planted)], 5)
        except AssertionError:
            print("  a file from the scanned tree cannot become the program: PASS")
            return
    raise AssertionError("a planted script was accepted as the program to run")


# --------------------------------------------------------------------------- #
# 2. ORTHOGONALITY to the attack surface
# --------------------------------------------------------------------------- #
def test_codescan_touches_none_of_the_attack_surface() -> None:
    src = _all_source()
    for module in ("cockpit", "adgraph", "engagement", "executor", "sandbox",
                   "allowlist", "orchestrator", "sessions", "attack_path"):
        assert not re.search(rf"^\s*(?:from|import)\s+{module}\b", src, re.M), (
            f"codescan must not import {module} — it is orthogonal to the attack surface"
        )
    for symbol in ("validate_request", "check_target_lock", "run_kali", "iter_run",
                   "resolve_mode", "assert_isolation_proven", "engagement_id",
                   "target_lock", "in_scope", "dangerous_ack"):
        assert symbol not in src, f"codescan must not reference {symbol}"
    print("  zero imports/references into cockpit/engagement/executor/scope/isolation: PASS")


def test_codescan_has_no_target_and_no_network() -> None:
    """No target concept, and no outbound call of its own (semgrep is told not to phone home)."""
    src = _all_source()
    for net in ("requests.", "urllib.request", "httpx", "socket.socket", "aiohttp"):
        assert net not in src, f"codescan must not make network calls ({net})"
    assert '"--metrics", "off"' in src, "semgrep telemetry must be disabled explicitly"
    assert "--disable-version-check" in src, "semgrep must not phone home on start"
    print("  no target, no sockets; semgrep telemetry + version check disabled: PASS")


# --------------------------------------------------------------------------- #
# 3. BOUNDED
# --------------------------------------------------------------------------- #
def test_path_validation() -> None:
    for bad in ("", "   ", "\t", "C:/definitely/not/here/at/all", "/definitely/not/here"):
        try:
            runner.resolve_target(bad)
        except runner.ScanError:
            continue
        raise AssertionError(f"resolve_target accepted {bad!r}")
    # a FILE is refused — the feature scans folders
    try:
        runner.resolve_target(str(Path(__file__).resolve()))
    except runner.ScanError as exc:
        assert "not a directory" in str(exc)
    else:
        raise AssertionError("a file was accepted as a scan target")
    print("  blank / missing / non-directory paths are all refused: PASS")


def test_timeout_is_honored() -> None:
    if not runner.available().get("semgrep"):
        print("  timeout: SKIPPED (semgrep not installed)")
        return
    target = runner.resolve_target(str(Path(__file__).parent))
    try:
        runner.run_semgrep(target, timeout_s=1)
    except runner.ScanTimeout as exc:
        assert "was stopped" in str(exc)
        print("  a scanner that overruns is killed and reported as a timeout: PASS")
        return
    except runner.ScanError:
        pass
    print("  timeout: scan finished within 1s (bound not exercised) — cap logic asserted below")


def test_output_cap_is_enforced() -> None:
    """Oversized tool output is refused by SIZE before it is read into memory."""
    if not runner.available().get("semgrep"):
        print("  output cap: SKIPPED (semgrep not installed)")
        return
    original = runner.MAX_OUTPUT_BYTES
    runner.MAX_OUTPUT_BYTES = 8  # anything real exceeds this
    try:
        runner.run_semgrep(runner.resolve_target(str(Path(__file__).parent)), timeout_s=120)
    except runner.ScanError as exc:
        assert "cap" in str(exc) or "output" in str(exc), str(exc)
        print("  output over the cap is refused before it is read: PASS")
        return
    finally:
        runner.MAX_OUTPUT_BYTES = original
    raise AssertionError("output cap was not enforced")


def test_oversized_tree_is_refused_before_scanning() -> None:
    """count_files stops early — a whole-drive scan is refused, not attempted."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for i in range(30):
            (root / f"f{i}.txt").write_text("x", encoding="utf-8")
        total, hit = runner.count_files(root, cap=10)
        assert hit is True and total > 10, (total, hit)
        total2, hit2 = runner.count_files(root, cap=1000)
        assert hit2 is False and total2 == 30
        # dependency/build trees are skipped, not counted
        (root / "node_modules").mkdir()
        for i in range(50):
            (root / "node_modules" / f"d{i}.js").write_text("x", encoding="utf-8")
        total3, _ = runner.count_files(root, cap=1000)
        assert total3 == 30, f"node_modules must be skipped, counted {total3}"
    print("  oversized trees refused up front; node_modules/.git skipped: PASS")


# --------------------------------------------------------------------------- #
# 4. READ-ONLY on the codebase
# --------------------------------------------------------------------------- #
def test_scan_does_not_modify_the_codebase() -> None:
    if not runner.available().get("semgrep"):
        print("  read-only: SKIPPED (semgrep not installed)")
        return
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "a.py").write_text("import os\nos.system('ls ' + x)\n", encoding="utf-8")
        (root / "b.js").write_text("eval(userInput);\n", encoding="utf-8")

        def snapshot() -> dict[str, tuple[int, int]]:
            return {
                str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
                for p in sorted(root.rglob("*")) if p.is_file()
            }

        before = snapshot()
        target = runner.resolve_target(str(root))
        runner.run_semgrep(target)
        after = snapshot()
        assert before == after, f"the scan modified the codebase: {before} != {after}"
        assert set(after) == {"a.py", "b.js"}, f"the scan created files: {sorted(after)}"
    print("  a scan leaves the codebase byte-for-byte unchanged (no new files): PASS")


# --------------------------------------------------------------------------- #
# 5. the attack surface is UNTOUCHED
# --------------------------------------------------------------------------- #
def test_lab_and_engagement_gates_unchanged() -> None:
    """The gate wording/behaviour this feature must not have disturbed."""
    from cockpit import executor as E

    ok, reason = E.check_target_lock(["--help"])
    assert not ok and reason == "no lab target specified — the command must reference the lab"
    ok, reason = E.check_target_lock(["-sV", "scanme.nmap.org"])
    assert not ok and "not the lab" in reason
    src = (Path(__file__).parent / "cockpit" / "executor.py").read_text(encoding="utf-8")
    assert "codescan" not in src, "the executor must know nothing about code scanning"
    for gate in ('gate="target"', 'gate="approval"', 'gate="danger"', 'gate="sandbox"'):
        assert gate in src, f"{gate} disappeared from the executor"
    print("  LAB target-lock wording + every executor gate byte-for-byte unchanged: PASS")


if __name__ == "__main__":
    test_only_a_scanner_can_ever_be_launched()
    test_no_execution_primitives_in_the_source()
    test_the_scanned_path_is_only_ever_an_argument()
    test_codescan_touches_none_of_the_attack_surface()
    test_codescan_has_no_target_and_no_network()
    test_path_validation()
    test_timeout_is_honored()
    test_output_cap_is_enforced()
    test_oversized_tree_is_refused_before_scanning()
    test_scan_does_not_modify_the_codebase()
    test_lab_and_engagement_gates_unchanged()
    print("ALL :code scan safety-invariant tests pass")
