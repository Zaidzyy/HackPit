"""How the planner draws on the arsenal.

Two directions, both purely informational:

* **Into the prompt** — :func:`prompt_block` renders the catalog's invocations for the
  relevant phases as a reference the composer and the guided loop write from. This is what
  makes proposed commands well-formed and consistent across a broad toolset instead of
  improvised per goal. It is a reference, not an allowlist: the executor has no allowlist, so
  the model was always free to propose any tool, and it still is. The block only raises the
  quality of what it proposes.

* **Out of the result** — :func:`tag_steps` reads back over the composed steps and records
  which catalog tool each one actually uses, deterministically, from the command's own program
  name. Nothing is asked of the model and nothing is taken on trust, so the provenance can't
  be hallucinated: either the step runs `nmap` or it doesn't.

Provenance, not authority. An ``arsenal`` tag says "this step uses a catalogued tool, here is
its entry" — it does NOT mean the command was verified, and it changes nothing about how the
step runs. Every command, tagged or not, goes through the same gated executor.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from .loader import Arsenal, Tool

# how much catalog goes into one prompt — enough to steer, small enough to leave room
_TOOLS_PER_PHASE = 5
_TEMPLATES_PER_TOOL = 2
MAX_BLOCK_CHARS = 4000

# a leading wrapper that isn't the tool being run
_WRAPPER_RE = re.compile(r"^\s*(?:sudo|time|env\s+\S+=\S+|nohup)\s+", re.I)


def _program(cmd: str) -> str:
    """The program a command line actually runs — first token, wrappers and paths stripped.

    Leading blank and ``#`` comment lines are skipped to find the first REAL command line.
    KB entries routinely open with an explanatory comment (``# enumerate SMB shares``), and
    reading only line one meant the whole step went untagged even though the next line ran a
    catalogued tool. Only LEADING comments/blanks are skipped — once a real line is found it
    is parsed exactly as before.
    """
    text = (cmd or "").strip()
    if not text:
        return ""
    text = next(
        (ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")),
        "",
    )
    if not text:
        return ""
    # take the last pipeline segment's head too, so `subfinder ... | httpx ...` reports both
    text = _WRAPPER_RE.sub("", text)
    head = text.split()[0] if text.split() else ""
    head = head.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return head.lower().removesuffix(".exe").removesuffix(".py")


def programs(cmd: str) -> list[str]:
    """Every program in a command line, including across pipes."""
    out: list[str] = []
    for segment in re.split(r"[|;&]+", cmd or ""):
        prog = _program(segment)
        if prog and prog not in out:
            out.append(prog)
    return out


# --------------------------------------------------------------------------- #
# into the prompt
# --------------------------------------------------------------------------- #
_WORD_RE = re.compile(r"[a-z0-9.+-]{3,}")


def _haystack(tool: Tool) -> str:
    return " ".join(
        (tool.name, " ".join(tool.aliases), tool.category, tool.purpose,
         " ".join(tool.techniques), " ".join(t.label for t in tool.templates))
    ).lower()


def _relevance(tool: Tool, needle: str) -> int:
    """How many of the needle's WORDS this tool matches.

    Token-wise on purpose. The needle is a real phrase — a goal, or the profiler's
    priority bug classes ("IDOR SSRF authentication bypass") — and a whole-phrase
    substring test never matches anything, so every goal scored zero and the block
    fell back to one fixed alphabetical slice of the catalog. Scoring per word makes
    an AD goal actually surface the AD tools. A tool that matches nothing scores 0,
    and the sort below is stable, so a needle that matches nothing leaves the order
    exactly as the no-needle block has it.
    """
    hay = _haystack(tool)
    return sum(1 for w in set(_WORD_RE.findall((needle or "").lower())) if w in hay)


def prompt_block(
    arsenal: Arsenal,
    phases: list[str] | None = None,
    needle: str | None = None,
    cap: int = MAX_BLOCK_CHARS,
    is_available: Callable[[str], bool] | None = None,
) -> str:
    """The catalog rendered as prompt reference. "" when the catalog is empty, so a caller
    with no arsenal produces byte-for-byte the prompt it produced before.

    ``is_available`` filters out tools the sandbox does not actually have (D7). Pass
    ``reconcile.current().is_present`` to ground the block in the live image. Omit it and
    the block is byte-for-byte what it was before reconciliation existed — the filter is
    additive, never a behaviour change for callers that do not opt in.

    Tools marked ``platform: windows`` are ALWAYS excluded regardless of the filter: they
    cannot run on a Linux sandbox by construction, so proposing one is never useful (D9).
    """
    if not arsenal.tools:
        return ""
    wanted = phases or ["recon", "enumeration", "exploitation", "privesc", "post-exploitation"]
    lines: list[str] = [
        "",
        "TOOL ARSENAL — the standard toolbox, with well-formed invocations. When a step calls "
        "for one of these tools, FOLLOW THE TEMPLATE's shape and flags (substituting the real "
        "target and parameters) so the command is correct and consistent. This is a "
        "REFERENCE, not a restriction: you may propose any tool that fits the goal, and a "
        "command still needs the operator's approval before it runs.",
    ]
    def _proposable(tool) -> bool:
        if not tool.runs_here():
            return False
        return is_available(tool.name) if is_available is not None else True

    seen: set[str] = set()
    for phase in wanted:
        picks = [t for t in arsenal.by_phase(phase) if t.name not in seen and _proposable(t)]
        if needle:
            # STABLE sort on relevance alone — ties keep catalog order, so a needle
            # that matches nothing yields byte-for-byte the no-needle block.
            picks.sort(key=lambda t: -_relevance(t, needle))
        picks = picks[:_TOOLS_PER_PHASE]
        if not picks:
            continue
        lines.append("")
        lines.append(f"## {phase}")
        for tool in picks:
            seen.add(tool.name)
            lines.append(f"- {tool.name} — {tool.purpose[:110]}")
            for tpl in tool.templates[:_TEMPLATES_PER_TOOL]:
                lines.append(f"    {tpl.label}: {tpl.template}")
    block = "\n".join(lines)
    if len(block) <= cap:
        return block
    # Cut at a line boundary — a template truncated mid-flag would read as a real
    # invocation with a mangled argument, which is worse than one fewer example.
    return block[:cap].rsplit("\n", 1)[0]


# --------------------------------------------------------------------------- #
# out of the result
# --------------------------------------------------------------------------- #
def match_tool(arsenal: Arsenal, cmd: str) -> Tool | None:
    """The catalog tool a command actually invokes, or None. Deterministic — read from the
    command's own program name, never from anything the model claimed."""
    for prog in programs(cmd):
        tool = arsenal.get(prog)
        if tool is not None:
            return tool
    return None


def tag_steps(arsenal: Arsenal, phases: list[dict[str, Any]]) -> int:
    """Annotate every step that runs a catalogued tool. Returns how many were tagged.

    Additive only: it attaches an ``arsenal`` dict and touches nothing else — not the
    commands, not ``ai_suggested``, not ``entry_id``. A step's grounded/AI labelling is
    exactly what it was.
    """
    if not arsenal.tools:
        return 0
    tagged = 0
    for phase in phases or []:
        for step in phase.get("steps") or []:
            # EVERY catalogued tool the step runs, in command order. A step whose first
            # command is uncatalogued (impacket-GetUserSPNs) and whose second is not
            # (hashcat) would otherwise be described by the second alone, which reads as
            # wrong next to the headline command. `tool` stays the first match — the
            # primary — and `tools` says what else it runs.
            found: list[Tool] = []
            for cmd in step.get("commands") or []:
                tool = match_tool(arsenal, cmd.get("cmd") or "")
                if tool is not None and tool.name not in [t.name for t in found]:
                    found.append(tool)
            if not found:
                continue
            primary = found[0]
            step["arsenal"] = {
                "tool": primary.name,
                "tools": [t.name for t in found],
                "category": primary.category,
                "purpose": primary.purpose,
                "kb_entry_id": primary.kb_entry_id,
                "docs": primary.docs,
            }
            tagged += 1
    return tagged
