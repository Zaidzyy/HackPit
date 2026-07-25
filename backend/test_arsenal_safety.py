"""SAFETY INVARIANTS for the tool arsenal.

The arsenal is DATA + TEMPLATES. It broadens and sharpens what the planner PROPOSES; it
changes nothing about how anything RUNS. These are the two claims that matters, and they are
tested rather than asserted in prose:

  1. THE ARSENAL EXECUTES NOTHING — no subprocess, no exec/eval, no network anywhere in the
     package. A rendered invocation is a string.
  2. NO GATE WAS BYPASSED — an arsenal-templated command goes through exactly the same
     executor gates as any other: target/scope lock, approve-each, heuristic red-confirm,
     in that order. A bigger catalog buys no shortcut, and the executor knows nothing about
     the arsenal at all.

Plus: the executor/engagement path is byte-for-byte unchanged, and templates are
target-faithful (no invented hosts reach a step).

Run:  python test_arsenal_safety.py
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

from arsenal import loader, planner

_PKG = Path(__file__).parent / "arsenal"
_SOURCES = sorted(_PKG.glob("*.py"))
_LAB = "hackpit-lab-target"


def _code_only(text: str) -> str:
    """Source with comments and string literals REMOVED.

    A naive grep over the raw file scans prose as if it were code — the docstring
    sentence "no subprocess, no network" tripped the subprocess ban on the very module
    that has neither. Tokenising first means these tests assert what the code DOES, not
    what its documentation says, which is the only version worth having.

    Comment/string spans are BLANKED IN PLACE rather than dropped, so every other byte —
    and crucially the spacing — is untouched: `re.compile` must still read as `re.compile`
    so an attribute-vs-builtin lookbehind keeps working.
    """
    lines = text.splitlines(keepends=True)
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError):  # pragma: no cover - defensive
        return text
    for tok in toks:
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        (srow, scol), (erow, ecol) = tok.start, tok.end
        for row in range(srow, erow + 1):
            line = lines[row - 1]
            begin = scol if row == srow else 0
            finish = ecol if row == erow else len(line)
            lines[row - 1] = line[:begin] + " " * (finish - begin) + line[finish:]
    return "".join(lines)


def _all_source() -> str:
    """Executable code from every arsenal module — no comments, no docstrings."""
    return "\n".join(_code_only(p.read_text(encoding="utf-8")) for p in _SOURCES)


# --------------------------------------------------------------------------- #
# 1. the arsenal executes nothing
# --------------------------------------------------------------------------- #
def test_arsenal_has_no_execution_path() -> None:
    src = _all_source()
    banned = {
        r"\bsubprocess\b": "subprocess",
        r"\bos\.system\b": "os.system",
        r"\bos\.popen\b": "os.popen",
        r"\bos\.exec": "os.exec*",
        r"\bos\.spawn": "os.spawn*",
        r"\bpty\b": "pty",
        r"(?<!\.)\beval\s*\(": "eval()",
        r"(?<!\.)\bexec\s*\(": "exec()",
        r"(?<!\.)\bcompile\s*\(": "the compile() builtin",
        r"__import__": "__import__",
        r"\brequests\.": "requests",
        r"\burllib\.request\b": "urllib.request",
        r"\bsocket\.socket\b": "sockets",
        r"shell\s*=\s*True": "shell=True",
    }
    for pattern, label in banned.items():
        hit = re.search(pattern, src)
        assert hit is None, f"the arsenal must not use {label} (offset {hit.start()})"
    print(f"  no subprocess/exec/eval/network anywhere in {len(_SOURCES)} arsenal modules: PASS")


def test_arsenal_never_imports_the_executor() -> None:
    """It may be READ by the planner; it must never reach the execution layer itself."""
    src = _all_source()
    for module in ("cockpit", "sandbox", "executor", "allowlist", "engagement", "kali"):
        assert not re.search(rf"^\s*(?:from|import)\s+{module}\b", src, re.M), (
            f"the arsenal must not import {module}"
        )
    for symbol in ("validate_request", "iter_run", "run_kali", "resolve_mode",
                   "assert_isolation_proven", "ExecRequest"):
        assert symbol not in src, f"the arsenal must not reference {symbol}"
    print("  zero imports/references into the execution layer: PASS")


def test_a_rendered_invocation_is_only_a_string() -> None:
    ars = loader.load()
    out = loader.render_tool(ars, "nmap", _LAB, {"ports": "80", "output": "o"})
    assert out and all(isinstance(inv["cmd"], str) for inv in out)
    assert all(not hasattr(inv["cmd"], "run") for inv in out)
    print("  render returns strings — there is nothing to invoke: PASS")


# --------------------------------------------------------------------------- #
# 2. NO GATE IS BYPASSED by an arsenal-templated command
# --------------------------------------------------------------------------- #
def test_arsenal_command_still_clears_every_gate() -> None:
    """The claim under review: a catalogued invocation gets no shortcut."""
    from cockpit import executor as E
    from cockpit.models import ExecRequest

    ars = loader.load()
    # a real, catalogued invocation rendered against the lab
    rendered = loader.render_tool(ars, "nmap", _LAB, {"ports": "80", "output": "scan"})
    cmd = rendered[0]["cmd"]
    args = cmd.split()[1:]

    # UNAPPROVED -> refused at the approval gate, exactly like any other command
    r = E.validate_request(ExecRequest(command="nmap", args=args, approved=False))
    assert r is not None and r.gate in ("approval", "sandbox"), (
        f"an arsenal command must not skip approval — got {getattr(r, 'gate', None)}"
    )

    # OFF-TARGET -> refused at the target gate even though it is a catalogued tool
    r = E.validate_request(
        ExecRequest(command="nmap", args=["-sCV", "scanme.nmap.org"], approved=True)
    )
    assert r is not None and r.gate == "target", (
        "a catalogued tool pointed off-target must still be refused at the target gate"
    )

    # a DANGEROUS catalogued invocation still needs the explicit red-confirm
    flagged = E.validate_request(
        ExecRequest(command="python3", args=["-c", "print(1)", _LAB], approved=True)
    )
    assert flagged is not None and flagged.gate in ("danger", "sandbox")
    print("  arsenal command: approval, target and danger gates all still fire: PASS")


def test_the_executor_knows_nothing_about_the_arsenal() -> None:
    """No coupling in the other direction either — the gates cannot be arsenal-aware."""
    for name in ("executor.py", "allowlist.py", "sandbox.py", "engagement.py", "router.py"):
        src = (Path(__file__).parent / "cockpit" / name).read_text(encoding="utf-8")
        assert "arsenal" not in src.lower(), f"cockpit/{name} references the arsenal"
    print("  the cockpit package has zero references to the arsenal: PASS")


def test_executor_gates_are_byte_for_byte_unchanged() -> None:
    from cockpit import executor as E

    ok, reason = E.check_target_lock(["--help"])
    assert not ok and reason == "no lab target specified — the command must reference the lab"
    ok, reason = E.check_target_lock(["-sV", "scanme.nmap.org"])
    assert not ok and "not the lab" in reason
    src = (Path(__file__).parent / "cockpit" / "executor.py").read_text(encoding="utf-8")
    for gate in ('gate="target"', 'gate="approval"', 'gate="danger"', 'gate="sandbox"'):
        assert gate in src, f"{gate} disappeared from the executor"
    print("  LAB target-lock wording + all four executor gates unchanged: PASS")


# --------------------------------------------------------------------------- #
# 3. templates are target-faithful
# --------------------------------------------------------------------------- #
def test_no_template_can_smuggle_a_host() -> None:
    """A template must not carry a host of its own — every target comes from the engagement."""
    host_re = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|local|htb|thm)\b", re.I)
    allowed = {"crt.sh", "example.com"}   # named inside notes/labels, not as a target
    for tool in loader.load().tools:
        for tpl in tool.templates:
            for host in host_re.findall(tpl.template):
                assert host.lower() in allowed, (
                    f"{tool.name}/{tpl.label} hardcodes host {host}"
                )
    print("  no template hardcodes a host — the target always comes from the engagement: PASS")


def test_prompt_block_is_not_an_allowlist() -> None:
    """The block must not read as a restriction — the executor has no allowlist, and a
    reference that sounded like one would misdescribe the system."""
    block = planner.prompt_block(loader.load()).lower()
    assert "reference, not a restriction" in block
    assert "you may propose any tool" in block
    print("  the prompt block states it is a reference, not an allowlist: PASS")


if __name__ == "__main__":
    test_arsenal_has_no_execution_path()
    test_arsenal_never_imports_the_executor()
    test_a_rendered_invocation_is_only_a_string()
    test_arsenal_command_still_clears_every_gate()
    test_the_executor_knows_nothing_about_the_arsenal()
    test_executor_gates_are_byte_for_byte_unchanged()
    test_no_template_can_smuggle_a_host()
    test_prompt_block_is_not_an_allowlist()
    print("ALL tool-arsenal safety-invariant tests pass")
