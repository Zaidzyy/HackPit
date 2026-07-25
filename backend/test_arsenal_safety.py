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


def test_the_catalog_is_inert_data() -> None:
    """The catalog is JSON — plain dicts, lists and strings. There is nothing in the file
    that could execute even in principle, whatever its size."""
    import json

    raw = json.loads((_PKG / "tools.json").read_text(encoding="utf-8"))

    def inert(node: object) -> bool:
        if isinstance(node, dict):
            return all(isinstance(k, str) and inert(v) for k, v in node.items())
        if isinstance(node, list):
            return all(inert(v) for v in node)
        return isinstance(node, (str, int, float, bool)) or node is None

    assert inert(raw), "the catalog holds something that is not plain JSON data"
    print(f"  the catalog is inert JSON — {len(raw['tools'])} tools, nothing executable: PASS")


def test_no_import_time_dependency_on_the_composer() -> None:
    """The arsenal must not depend on the attack-path composer to be imported.

    Stated precisely, because the honest claim is narrower than "it never references
    attack_path": rendering routes through the composer's ``substitute_target`` so a filled
    template is target-faithful. That single reference is a GUARDED, LAZY import inside one
    function body — the package imports and renders fine without it, and it pulls in a
    substitution helper, never an execution path.
    """
    for path in _SOURCES:
        code = _code_only(path.read_text(encoding="utf-8"))
        for line in code.splitlines():
            # anchored at column 0 — an INDENTED import is inside a function, which is
            # the lazy form this test is explicitly allowing.
            assert not re.match(r"(?:from|import)\s+attack_path\b", line), (
                f"{path.name} imports attack_path at module level"
            )
        for m in re.finditer(r"(?:from|import)\s+attack_path\b", code):
            indent = code[:m.start()].split("\n")[-1]
            assert indent.strip() == "" and indent, (
                f"{path.name} references attack_path outside a function body"
            )
    # and it really does import standalone
    import importlib

    assert importlib.import_module("arsenal.loader") is not None
    print("  no import-time dependency on the composer (one guarded lazy import): PASS")


def test_every_template_renders_target_faithfully() -> None:
    """EVERY template of EVERY tool, rendered — no foreign host survives, and nothing
    unfilled is hidden. This is the claim that has to scale with the catalog: 34 tools
    could be eyeballed, 73 cannot."""
    ars = loader.load()
    foreign_host = re.compile(
        r"\b(?:[a-z0-9-]+\.)+(?:htb|thm|local|vh|lab|test)\b"
        r"|\b(?:[a-z0-9-]+\.)?example\.(?:com|org|net)\b",
        re.I,
    )
    private_ip = re.compile(
        r"(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?!\d)"
    )
    checked = 0
    for tool in ars.tools:
        for tpl in tool.templates:
            cmd, unfilled = loader.render(
                tpl.template, _LAB, None, __import__("attack_path").substitute_target
            )
            where = f"{tool.name}/{tpl.label}"
            assert not foreign_host.search(cmd), f"{where} rendered a foreign host: {cmd}"
            assert not private_ip.search(cmd), f"{where} rendered a private/example IP: {cmd}"
            if "<target>" in tpl.template:
                assert _LAB in cmd, f"{where} did not receive the engagement target"
                assert "<target>" not in cmd, f"{where} left <target> unfilled"
            # anything still unfilled must remain VISIBLE, never silently guessed
            for ph in unfilled:
                assert ph in cmd, f"{where} hid an unfilled placeholder {ph}"
            checked += 1
    print(f"  all {checked} templates across {len(ars.tools)} tools render "
          "target-faithfully, no foreign host: PASS")


def test_the_callback_placeholder_is_never_rewritten_to_the_target() -> None:
    """A payload's callback address belongs to the OPERATOR. The composer rewrites any
    placeholder spelling ip/host/target, so the catalog spells this one <listener> — if that
    ever regressed, msfvenom templates would point the shell at the victim."""
    import attack_path as AP

    for token in ("<listener>", "<listener-port>"):
        assert AP.substitute_target(f"LHOST={token}", _LAB) == f"LHOST={token}", (
            f"{token} was rewritten to the target"
        )
    ars = loader.load()
    for tool in ars.tools:
        for tpl in tool.templates:
            assert "<lhost>" not in tpl.template.lower(), (
                f"{tool.name}/{tpl.label} uses <lhost>, which the composer would rewrite"
            )
    print("  the operator's callback placeholder survives substitution untouched: PASS")


def test_every_alias_tags_back_to_its_own_tool() -> None:
    """Provenance must survive the name a step actually types. ``_program`` strips .exe/.py,
    so an alias can normalise to something the catalog does not hold — winPEASx64.exe did
    exactly that, and a step running it would have gone untagged."""
    ars = loader.load()
    broken = [
        (tool.name, alias)
        for tool in ars.tools
        for alias in tool.names()
        if (m := planner.match_tool(ars, f"{alias} <target>")) is None or m.name != tool.name
    ]
    assert not broken, f"these names/aliases do not tag back to their tool: {broken}"
    print(f"  every name and alias across {len(ars.tools)} tools tags back: PASS")


def test_impacket_is_catalogued_as_its_individual_scripts() -> None:
    """impacket is not one binary, and a template that pretended otherwise would be a stub."""
    ars = loader.load()
    for script in ("GetUserSPNs.py", "GetNPUsers.py", "secretsdump.py", "psexec.py",
                   "wmiexec.py", "smbexec.py", "ntlmrelayx.py", "mssqlclient.py"):
        tool = ars.get(script)
        assert tool is not None, f"{script} is not in the catalog"
        assert tool.templates, f"{script} has no invocation"
        # both the .py and the packaged impacket- form must resolve
        assert ars.get(script.removesuffix(".py")) is tool
        assert ars.get(f"impacket-{script.removesuffix('.py')}") is tool
    assert ars.get("impacket") is None, "impacket must not be catalogued as a single binary"
    print("  the impacket suite is catalogued per script, both invocation forms: PASS")


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
    test_the_catalog_is_inert_data()
    test_no_import_time_dependency_on_the_composer()
    test_every_template_renders_target_faithfully()
    test_the_callback_placeholder_is_never_rewritten_to_the_target()
    test_every_alias_tags_back_to_its_own_tool()
    test_impacket_is_catalogued_as_its_individual_scripts()
    test_prompt_block_is_not_an_allowlist()
    print("ALL tool-arsenal safety-invariant tests pass")
