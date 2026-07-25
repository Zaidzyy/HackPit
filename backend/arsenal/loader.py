"""Load the tool catalog, index it, and render an invocation.

Pure data operations. This module reads a JSON file and does string substitution — it has no
subprocess, no network, no filesystem writes and no execution path of any kind. A rendered
invocation is a STRING; it becomes a command only when a human approves it through the same
cockpit executor every other command goes through (see docs/TOOL-ARSENAL.md).

Two things are deliberately conservative:

* **KB links are resolved, not stored.** The catalog carries no entry ids. A tool is linked to
  a KB technique only when an entry's TITLE names that tool and the entry is step-eligible and
  actually carries commands — so a broad "hacking methodology resource" page that merely
  mentions masscan is never cited, and a link can never dangle as the KB changes.
* **Rendering never invents a target.** ``<target>`` is filled through the composer's
  ``substitute_target``, so a rendered command points at the real engagement target or keeps
  the placeholder visible. An unfilled placeholder stays visible on purpose — a half-filled
  command the operator can see is safe; a silently-guessed host is not.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

CATALOG_PATH = Path(__file__).parent / "tools.json"

_PLACEHOLDER_RE = re.compile(r"<[a-z][a-z-]*>")


@dataclass(frozen=True)
class Template:
    """One invocation template for a tool."""

    label: str
    template: str
    note: str = ""

    def placeholders(self) -> list[str]:
        seen: list[str] = []
        for m in _PLACEHOLDER_RE.finditer(self.template):
            if m.group(0) not in seen:
                seen.append(m.group(0))
        return seen


@dataclass(frozen=True)
class Tool:
    """One catalog entry."""

    name: str
    category: str
    purpose: str
    phases: tuple[str, ...]
    techniques: tuple[str, ...]
    docs: str
    templates: tuple[Template, ...]
    flags: tuple[dict[str, str], ...] = ()
    aliases: tuple[str, ...] = ()
    kb_entry_id: str | None = None      # resolved at load time, never stored in the catalog
    kb_title: str | None = None

    def names(self) -> tuple[str, ...]:
        return (self.name, *self.aliases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "aliases": list(self.aliases),
            "category": self.category,
            "purpose": self.purpose,
            "phases": list(self.phases),
            "techniques": list(self.techniques),
            "docs": self.docs,
            "templates": [
                {"label": t.label, "template": t.template, "note": t.note,
                 "placeholders": t.placeholders()}
                for t in self.templates
            ],
            "flags": [dict(f) for f in self.flags],
            "kb_entry_id": self.kb_entry_id,
            "kb_title": self.kb_title,
        }


@dataclass
class Arsenal:
    """The loaded catalog + its indexes."""

    tools: list[Tool] = field(default_factory=list)
    placeholders: dict[str, str] = field(default_factory=dict)
    schema_version: str = ""
    _by_name: dict[str, Tool] = field(default_factory=dict, repr=False)

    # -- lookup ------------------------------------------------------------- #
    def get(self, name: str) -> Tool | None:
        """By name or alias, case-insensitively."""
        return self._by_name.get((name or "").strip().lower())

    def by_category(self, category: str) -> list[Tool]:
        cat = (category or "").strip().lower()
        return [t for t in self.tools if t.category == cat]

    def by_phase(self, phase: str) -> list[Tool]:
        ph = (phase or "").strip().lower()
        return [t for t in self.tools if ph in t.phases]

    def by_technique(self, needle: str) -> list[Tool]:
        """Substring match across techniques, purpose and template labels — the loose
        lookup the planner and the UI search box both use."""
        q = (needle or "").strip().lower()
        if not q:
            return []
        out: list[Tool] = []
        for t in self.tools:
            hay = " ".join(
                (t.name, " ".join(t.aliases), t.purpose, " ".join(t.techniques),
                 " ".join(x.label for x in t.templates))
            ).lower()
            if q in hay:
                out.append(t)
        return out

    def categories(self) -> list[str]:
        seen: list[str] = []
        for t in self.tools:
            if t.category not in seen:
                seen.append(t.category)
        return seen


# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #
def _coerce_tool(raw: dict[str, Any]) -> Tool | None:
    """One catalog record -> Tool, or None when it is too malformed to use."""
    name = str(raw.get("name") or "").strip()
    if not name:
        return None
    templates = tuple(
        Template(
            label=str(t.get("label") or "").strip(),
            template=str(t.get("template") or "").strip(),
            note=str(t.get("note") or "").strip(),
        )
        for t in (raw.get("templates") or [])
        if isinstance(t, dict) and str(t.get("template") or "").strip()
    )
    return Tool(
        name=name,
        category=str(raw.get("category") or "other").strip().lower(),
        purpose=str(raw.get("purpose") or "").strip(),
        phases=tuple(str(p).strip().lower() for p in (raw.get("phases") or [])),
        techniques=tuple(str(x).strip() for x in (raw.get("techniques") or [])),
        docs=str(raw.get("docs") or "").strip(),
        templates=templates,
        flags=tuple(
            {"flag": str(f.get("flag") or ""), "what": str(f.get("what") or "")}
            for f in (raw.get("flags") or [])
            if isinstance(f, dict)
        ),
        aliases=tuple(str(a).strip() for a in (raw.get("aliases") or []) if str(a).strip()),
    )


def load(path: Path | None = None) -> Arsenal:
    """Read + index the catalog. Raises only if the file itself is unreadable."""
    src = path or CATALOG_PATH
    data = json.loads(src.read_text(encoding="utf-8"))
    tools = [t for raw in (data.get("tools") or []) if (t := _coerce_tool(raw)) is not None]
    by_name: dict[str, Tool] = {}
    for tool in tools:
        for alias in tool.names():
            by_name.setdefault(alias.lower(), tool)
    return Arsenal(
        tools=tools,
        placeholders=dict(data.get("placeholders") or {}),
        schema_version=str(data.get("schema_version") or ""),
        _by_name=by_name,
    )


# --------------------------------------------------------------------------- #
# KB linking — strict, resolved at load time
# --------------------------------------------------------------------------- #
def link_kb(
    arsenal: Arsenal,
    by_id: dict[str, dict],
    eligible: Callable[[dict], bool] | None = None,
) -> int:
    """Attach a KB entry to each tool the KB genuinely documents. Returns how many linked.

    THE RULE, both halves required: the entry's TITLE must name the tool (word-boundary)
    AND the entry must actually INVOKE it — the tool appears as the program at the head of a
    command. The entry must also be step-eligible.

    The second half is not redundant. A title match alone linked the `strings` tool to a page
    called "Format Strings" — a binary-exploitation concept that has nothing to do with the
    tool. Requiring a real invocation kills that class of collision, at the cost of leaving
    more tools unlinked, which is the honest answer when the KB doesn't document them.
    """
    if not by_id:
        return 0
    linked = 0
    for i, tool in enumerate(arsenal.tools):
        best: tuple[int, str, str] | None = None
        patterns = [
            re.compile(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", re.I) for n in tool.names()
        ]
        for entry in by_id.values():
            title = entry.get("title") or ""
            if not any(p.search(title) for p in patterns):
                continue
            if eligible is not None and not eligible(entry):
                continue
            cmds = [
                cmd for s in (entry.get("steps") or []) for c in (s.get("code") or [])
                if (cmd := (c.get("cmd") or "").strip())
            ]
            if not cmds:
                continue
            # …and the entry must actually INVOKE the tool: it appears as the program at
            # the head of a command (allowing a leading sudo/env or a pipe segment).
            invoked = sum(
                1
                for cmd in cmds
                for segment in re.split(r"[|;&]+|\n", cmd)
                if any(
                    p.match(re.sub(r"^\s*(?:sudo|time|env\s+\S+=\S+)\s+", "", segment).lstrip())
                    for p in patterns
                )
            )
            if not invoked:
                continue
            # prefer the entry that invokes it most — the fuller worked example
            rank = (invoked, entry["id"], title)
            if best is None or rank[0] > best[0]:
                best = rank
        if best is not None:
            arsenal.tools[i] = Tool(
                **{**tool.__dict__, "kb_entry_id": best[1], "kb_title": best[2]}
            )
            linked += 1
    arsenal._by_name = {
        alias.lower(): t for t in arsenal.tools for alias in t.names()
    }
    return linked


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def render(
    template: str,
    target: str | None = None,
    params: dict[str, str] | None = None,
    substitute: Callable[[str, str | None], str] | None = None,
) -> tuple[str, list[str]]:
    """Fill a template. Returns ``(rendered, still_unfilled)``.

    ``<target>`` is filled through ``substitute`` (the composer's ``substitute_target``) so the
    rendered command points at the real engagement target and at nothing else. Any placeholder
    with no value STAYS VISIBLE — a command the operator can see is incomplete is safe; one
    where a host was silently guessed is not.
    """
    out = template or ""
    values = {k: v for k, v in (params or {}).items() if v}

    if target:
        out = out.replace("<target>", target)
    for key, value in values.items():
        token = key if key.startswith("<") else f"<{key}>"
        out = out.replace(token, value)

    # A second pass through the composer's substitution catches example hosts/IPs that a
    # template's NOTE-style literals might carry, using the exact rules the planner uses.
    if substitute is not None and target:
        out = substitute(out, target)

    unfilled = sorted({m.group(0) for m in _PLACEHOLDER_RE.finditer(out)})
    return out, unfilled


def render_tool(
    arsenal: Arsenal,
    name: str,
    target: str | None = None,
    params: dict[str, str] | None = None,
    substitute: Callable[[str, str | None], str] | None = None,
) -> list[dict[str, Any]]:
    """Every template for one tool, rendered. [] when the tool isn't in the catalog."""
    tool = arsenal.get(name)
    if tool is None:
        return []
    out: list[dict[str, Any]] = []
    for tpl in tool.templates:
        cmd, unfilled = render(tpl.template, target, params, substitute)
        out.append({
            "tool": tool.name,
            "label": tpl.label,
            "cmd": cmd,
            "note": tpl.note,
            "unfilled": unfilled,
            "ready": not unfilled,
        })
    return out


def suggest(
    arsenal: Arsenal,
    phase: str | None = None,
    needle: str | None = None,
    limit: int = 6,
) -> list[Tool]:
    """Tools worth proposing for a phase / technique. Phase narrows, needle ranks."""
    pool: Iterable[Tool] = arsenal.by_phase(phase) if phase else arsenal.tools
    pool = list(pool)
    if needle:
        matched = arsenal.by_technique(needle)
        matched_names = {t.name for t in matched}
        pool = [t for t in pool if t.name in matched_names] or pool
    return pool[:limit]
