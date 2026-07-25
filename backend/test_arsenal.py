"""Unit tests for the tool arsenal — catalog integrity, lookup, rendering, tagging.

Run:  python test_arsenal.py
"""

from __future__ import annotations

import json
import re

import arsenal
from arsenal import loader, planner


def _load() -> loader.Arsenal:
    return loader.load()


# --------------------------------------------------------------------------- #
# 1. the catalog itself
# --------------------------------------------------------------------------- #
def test_catalog_is_well_formed() -> None:
    raw = json.loads(loader.CATALOG_PATH.read_text(encoding="utf-8"))
    declared = set(raw["placeholders"])
    ars = _load()
    assert len(ars.tools) >= 30, f"expected the standard toolbox, got {len(ars.tools)}"

    names: set[str] = set()
    for tool in ars.tools:
        assert tool.name and tool.purpose and tool.category, tool.name
        assert tool.templates, f"{tool.name} has no invocation template"
        assert tool.phases, f"{tool.name} has no phase"
        for alias in tool.names():
            assert alias.lower() not in names, f"duplicate tool/alias {alias}"
            names.add(alias.lower())
        for tpl in tool.templates:
            assert tpl.label and tpl.template
            # every placeholder must be declared — an undeclared one renders as
            # literal <angle-brackets> in a command the operator is invited to run
            for ph in tpl.placeholders():
                assert ph in declared, f"{tool.name}/{tpl.label}: undeclared {ph}"
    print(f"  {len(ars.tools)} tools, every template placeholdered + declared: PASS")


def test_every_category_and_phase_is_covered() -> None:
    ars = _load()
    for category in ("recon", "web", "network-ad", "credentials", "cloud", "binary"):
        assert ars.by_category(category), f"no tools in category {category}"
    for phase in ("recon", "enumeration", "exploitation"):
        assert ars.by_phase(phase), f"no tools for phase {phase}"
    print("  every category and the core phases have tools: PASS")


# --------------------------------------------------------------------------- #
# 2. lookup
# --------------------------------------------------------------------------- #
def test_lookup_by_name_alias_and_technique() -> None:
    ars = _load()
    assert ars.get("nmap") is not None
    assert ars.get("NMAP").name == "nmap", "lookup is case-insensitive"
    assert ars.get("nxc").name == "netexec", "aliases resolve to the tool"
    assert ars.get("cme").name == "netexec"
    assert ars.get("definitely-not-a-tool") is None
    assert "kerbrute" in [t.name for t in ars.by_technique("kerberos")]
    assert ars.by_technique("") == []
    print("  lookup by name / alias / case / technique: PASS")


# --------------------------------------------------------------------------- #
# 3. rendering is target-faithful
# --------------------------------------------------------------------------- #
def test_render_fills_target_and_keeps_gaps_visible() -> None:
    ars = _load()
    rendered = loader.render_tool(ars, "nmap", "10.10.11.55", {"ports": "80", "output": "o"})
    assert rendered, "nmap must render"
    for inv in rendered:
        assert "10.10.11.55" in inv["cmd"], inv["cmd"]
        assert "<target>" not in inv["cmd"]
        assert inv["ready"] is True, f"still unfilled: {inv['unfilled']}"

    # a template with no value for a placeholder KEEPS IT VISIBLE rather than guessing
    partial = loader.render_tool(ars, "ffuf", "https://shop.example.com")
    first = partial[0]
    assert "<wordlist>" in first["cmd"], "an unfilled placeholder must stay visible"
    assert first["ready"] is False and "<wordlist>" in first["unfilled"]
    print("  render fills <target>, leaves unknown placeholders VISIBLE: PASS")


def test_render_never_invents_a_host() -> None:
    """With no target, nothing host-shaped is fabricated — the placeholder survives."""
    cmd, unfilled = loader.render("nmap -sCV <target>", None, None)
    assert cmd == "nmap -sCV <target>" and "<target>" in unfilled
    # and no template in the catalog carries a hardcoded host/IP an operator might run at
    ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for tool in _load().tools:
        for tpl in tool.templates:
            found = [x for x in ip.findall(tpl.template) if x != "127.0.0.1"]
            assert not found, f"{tool.name}/{tpl.label} hardcodes an address: {found}"
    print("  no target -> no invented host; no template hardcodes an address: PASS")


def test_render_uses_the_composers_substitution() -> None:
    import attack_path

    ars = _load()
    out = loader.render_tool(ars, "nmap", "10.0.0.9", {"ports": "22", "output": "o"},
                             attack_path.substitute_target)
    assert all("10.0.0.9" in inv["cmd"] for inv in out)
    print("  rendering routes through the composer's substitute_target: PASS")


# --------------------------------------------------------------------------- #
# 4. provenance tagging is deterministic
# --------------------------------------------------------------------------- #
def test_tagging_reads_the_command_not_the_model() -> None:
    ars = _load()
    phases = [{"phase": "recon", "steps": [
        {"title": "a", "ai_suggested": True, "commands": [{"cmd": "nmap -sCV 10.0.0.5"}]},
        {"title": "b", "ai_suggested": False, "commands": [{"cmd": "sudo /usr/bin/ffuf -u x"}]},
        {"title": "c", "ai_suggested": True, "commands": [{"cmd": "subfinder -d x | httpx"}]},
        {"title": "d", "ai_suggested": True, "commands": [{"cmd": "echo hello"}]},
        {"title": "e", "ai_suggested": True, "commands": []},
    ]}]
    before = [(s["title"], s["ai_suggested"]) for s in phases[0]["steps"]]
    tagged = planner.tag_steps(ars, phases)
    assert tagged == 3, tagged
    got = {s["title"]: (s.get("arsenal") or {}).get("tool") for s in phases[0]["steps"]}
    assert got["a"] == "nmap"
    assert got["b"] == "ffuf", "a wrapper (sudo) and an absolute path must be stripped"
    assert got["c"] == "subfinder", "a pipeline's first program counts"
    assert got["d"] is None and got["e"] is None, "an uncatalogued command is not tagged"
    after = [(s["title"], s["ai_suggested"]) for s in phases[0]["steps"]]
    assert before == after, "tagging must not change grounded/ai_suggested labelling"
    print("  tagging reads the program name; labels untouched; unknown stays untagged: PASS")


def test_empty_arsenal_is_a_no_op() -> None:
    empty = loader.Arsenal()
    assert planner.prompt_block(empty) == ""
    phases = [{"phase": "recon", "steps": [{"title": "a", "commands": [{"cmd": "nmap x"}]}]}]
    assert planner.tag_steps(empty, phases) == 0
    assert "arsenal" not in phases[0]["steps"][0]
    print("  an empty catalog degrades to no prompt block and no tags: PASS")


# --------------------------------------------------------------------------- #
# 5. the prompt block is bounded and honest
# --------------------------------------------------------------------------- #
def test_prompt_block_is_bounded_and_says_it_is_a_reference() -> None:
    block = planner.prompt_block(_load())
    assert block, "a loaded catalog must produce a block"
    assert len(block) <= planner.MAX_BLOCK_CHARS
    assert not block.endswith(("-", "<")), "must not cut mid-token"
    low = block.lower()
    assert "reference, not a restriction" in low, (
        "the block must not read as an allowlist — the executor has none"
    )
    assert "approval" in low, "the block must restate that a command needs approval"
    print("  prompt block bounded, line-cut, and framed as reference not allowlist: PASS")


def _block_tools(block: str) -> list[str]:
    return [ln[2:].split(" — ")[0] for ln in block.splitlines() if ln.startswith("- ")]


def test_prompt_block_ranks_on_the_goals_words() -> None:
    """The block is capped, so at 73 tools WHICH tools it carries is the whole question.

    Ranking is per WORD. A whole-phrase substring test never matched a real goal, so every
    goal scored zero and the block fell back to one fixed slice of the catalog regardless of
    what was being attacked.
    """
    ars = _load()

    ad = _block_tools(planner.prompt_block(ars, needle="kerberoast the domain controller"))
    assert any(t in ad for t in ("GetUserSPNs.py", "rubeus", "secretsdump.py")), (
        f"an AD goal must surface the AD tools — got {ad}"
    )

    web = _block_tools(planner.prompt_block(ars, needle="find SQL injection and XSS in the web app"))
    assert "sqlmap" in web and "dalfox" in web, f"a web goal must surface the web tools — got {web}"
    assert "GetUserSPNs.py" not in web, f"a web goal must not lead with kerberoasting — got {web}"

    # the two goals must actually differ — that is the whole point of ranking
    assert set(ad) != set(web), "ranking produced the same block for AD and web goals"

    # a needle that matches nothing is not a reshuffle: the sort is stable on relevance
    # alone, so it must reproduce the no-needle block byte for byte.
    assert planner.prompt_block(ars, needle="zzz qqq nothingmatches") == planner.prompt_block(ars)
    print("  prompt block ranks on the goal's words; a non-matching goal is unchanged: PASS")


if __name__ == "__main__":
    test_catalog_is_well_formed()
    test_every_category_and_phase_is_covered()
    test_lookup_by_name_alias_and_technique()
    test_render_fills_target_and_keeps_gaps_visible()
    test_render_never_invents_a_host()
    test_render_uses_the_composers_substitution()
    test_tagging_reads_the_command_not_the_model()
    test_empty_arsenal_is_a_no_op()
    test_prompt_block_is_bounded_and_says_it_is_a_reference()
    test_prompt_block_ranks_on_the_goals_words()
    print("ALL tool-arsenal tests pass")
