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
def test_no_duplicate_json_keys() -> None:
    """A duplicated key is INVISIBLE to json.load — it silently keeps the last one.

    `"<payload>"` was declared twice with different descriptions; the first was being
    discarded on every parse, and any tool that round-tripped the catalog would have written
    the loss back to disk. `object_pairs_hook` is the only way to see it.
    """
    dupes: list[str] = []

    def _catch(pairs):
        seen: set[str] = set()
        for k, _v in pairs:
            if k in seen:
                dupes.append(k)
            seen.add(k)
        return dict(pairs)

    json.loads(loader.CATALOG_PATH.read_text(encoding="utf-8"), object_pairs_hook=_catch)
    assert not dupes, f"duplicate keys in tools.json (json.load silently drops all but the last): {dupes}"
    print("  no duplicate keys anywhere in tools.json: PASS")


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
    for category in ("recon", "web", "network-ad", "credentials", "cloud", "binary-re",
                     "forensics-ctf", "c2", "evasion"):
        assert ars.by_category(category), f"no tools in category {category}"
    for phase in ("recon", "enumeration", "exploitation"):
        assert ars.by_phase(phase), f"no tools for phase {phase}"
    print("  every category and the core phases have tools: PASS")


def test_c2_and_evasion_tools_catalogued() -> None:
    """The AV/EDR-evasion + traffic-obfuscation toolset, and Sliver filed as the C2 it is.

    These are catalog entries — DATA. A template here is a string; it becomes a command
    only by going through the same gated executor as everything else.
    """
    ars = _load()
    for name in ("dnscat2", "iodine", "donut", "ScareCrow", "Invoke-Obfuscation"):
        tool = ars.get(name)
        assert tool is not None, f"missing arsenal entry {name!r}"
        assert tool.category == "evasion", f"{name} should sit in the evasion category"
        assert tool.templates and tool.phases, f"{name} is a stub"

    # Invoke-Obfuscation is a PowerShell module: catalogued to PLAN and WRITE UP with,
    # never implied to be runnable on the Linux sandbox.
    io_ = ars.get("Invoke-Obfuscation")
    assert io_.platform == "windows" and io_.runs_here() is False

    assert ars.by_category("c2"), "no tools in category c2"
    sliver = ars.get("sliver")
    assert sliver is not None and sliver.category == "c2", (
        f"Sliver is a C2 framework, not a persistence tool — got {sliver and sliver.category}"
    )
    assert "build #4" not in sliver.purpose, (
        "the Sliver entry still defers itself to the build that is adding it"
    )

    # A DNS tunnel's zone belongs to the OPERATOR, exactly like <listener>. Spelling it
    # <domain> would hand the composer's target substitution a tunnel pointed at the
    # system under test.
    import attack_path

    for tool in (ars.get("dnscat2"), ars.get("iodine")):
        for tpl in tool.templates:
            assert "<domain>" not in tpl.template, (
                f"{tool.name}/{tpl.label}: <domain> is rewritten to the target"
            )
            survived = attack_path.substitute_target(tpl.template, "hackpit-lab-target")
            assert "<tunnel-zone>" in survived, (
                f"{tool.name}/{tpl.label}: the operator's tunnel zone did not survive "
                f"substitution — got {survived}"
            )
    print("  c2 + evasion tools catalogued, Sliver in c2, tunnel zone stays the "
          "operator's: PASS")


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


def test_a_leading_comment_does_not_hide_the_tool() -> None:
    """KB entries routinely open with an explanatory comment. Reading only the first line
    meant the step went untagged even though the next line ran a catalogued tool."""
    ars = _load()
    phases = [{"phase": "enumeration", "steps": [
        {"title": "commented", "commands": [
            {"cmd": "# enumerate SMB shares on the DC\nnxc smb 10.0.0.5 -u u -p p --shares"}]},
        {"title": "blank-first", "commands": [{"cmd": "\n\nnmap -sCV 10.0.0.5"}]},
        {"title": "multi-comment", "commands": [
            {"cmd": "# step 1\n#  (and a note)\nsudo /usr/bin/ffuf -u http://x/FUZZ"}]},
        {"title": "comment-only", "commands": [{"cmd": "# just a note, nothing to run"}]},
    ]}]
    planner.tag_steps(ars, phases)
    got = {s["title"]: (s.get("arsenal") or {}).get("tool") for s in phases[0]["steps"]}
    assert got["commented"] == "netexec", f"a leading # comment must not hide the tool: {got}"
    assert got["blank-first"] == "nmap"
    assert got["multi-comment"] == "ffuf", "wrapper+path stripping still applies after comments"
    assert got["comment-only"] is None, "a comment-only block runs nothing and stays untagged"

    # …and a NORMAL command is parsed exactly as before — the change is leading-only
    for cmd, expect in (("nmap -sCV 10.0.0.5", "nmap"),
                        ("sudo /usr/bin/ffuf -u x", "ffuf"),
                        ("subfinder -d x | httpx", "subfinder"),
                        ("echo hello", None)):
        tool = planner.match_tool(ars, cmd)
        assert (tool.name if tool else None) == expect, f"{cmd!r} changed: {tool}"
    # a '#' that is an ARGUMENT, not a comment line, is untouched
    assert planner._program("nmap -sCV 10.0.0.5 # scan") == "nmap"
    print("  a leading #-comment no longer hides the tool; normal commands parse unchanged: PASS")


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


def test_response_model_carries_platform_and_runs_here() -> None:
    """FastAPI filters every response through its response_model and SILENTLY DROPS any
    field the model does not declare. ToolOut once omitted `platform`/`runs_here`, so
    `runs_here` reached the UI as undefined and `!runs_here` badged EVERY tool — nmap
    included — as 'windows only'. This pins both fields into the response contract.

    (The classic three-places trap: a per-tool field needs the dataclass, to_dict AND the
    Pydantic response model, or the API strips it. See the arsenal-schema memory.)
    """
    from arsenal.router import ToolOut

    fields = set(ToolOut.model_fields)
    assert "platform" in fields, "ToolOut must declare platform or the API strips it"
    assert "runs_here" in fields, "ToolOut must declare runs_here or the API strips it"

    # And a serialized tool must actually carry them with the right values.
    ars = _load()
    nmap = ars.get("nmap")
    rubeus = ars.get("rubeus")
    assert nmap is not None and rubeus is not None
    assert ToolOut(**nmap.to_dict()).runs_here is True, "nmap runs on Linux"
    assert ToolOut(**rubeus.to_dict()).runs_here is False, "rubeus is Windows-only"
    assert ToolOut(**rubeus.to_dict()).platform == "windows"
    print("  response model carries platform + runs_here (nmap runs, rubeus does not): PASS")


if __name__ == "__main__":
    test_no_duplicate_json_keys()
    test_catalog_is_well_formed()
    test_every_category_and_phase_is_covered()
    test_c2_and_evasion_tools_catalogued()
    test_lookup_by_name_alias_and_technique()
    test_render_fills_target_and_keeps_gaps_visible()
    test_render_never_invents_a_host()
    test_render_uses_the_composers_substitution()
    test_tagging_reads_the_command_not_the_model()
    test_a_leading_comment_does_not_hide_the_tool()
    test_empty_arsenal_is_a_no_op()
    test_prompt_block_is_bounded_and_says_it_is_a_reference()
    test_prompt_block_ranks_on_the_goals_words()
    test_response_model_carries_platform_and_runs_here()
    print("ALL tool-arsenal tests pass")
