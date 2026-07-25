"""arsenal — the curated tool catalog the planner draws on.

DATA + TEMPLATES, not an engine. It improves the QUALITY and BREADTH of the commands the
composer and the guided loop propose; it changes nothing about how anything runs. Every
arsenal-templated command still goes through the same cockpit executor — human approval of
each command, heuristic red-confirm, target/scope lock, argv-only. The arsenal is generative
and informational; it is never a gate and never a bypass, and it executes nothing itself.

See docs/TOOL-ARSENAL.md.
"""

from .loader import (  # noqa: F401
    Arsenal,
    Template,
    Tool,
    link_kb,
    load,
    render,
    render_tool,
    suggest,
)
