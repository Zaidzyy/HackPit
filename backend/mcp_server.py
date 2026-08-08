"""The HackPit MCP server — stdio transport over the registry in `mcp_tools.py`.

Run it:

    cd backend && .venv/Scripts/python.exe mcp_server.py

...or register it with a client (Claude Code, Claude Desktop, any MCP host)::

    {"mcpServers": {"hackpit": {
        "command": "C:/Users/.../HackPit/backend/.venv/Scripts/python.exe",
        "args": ["C:/Users/.../HackPit/backend/mcp_server.py"]}}}

*** THIS FILE IS TRANSPORT AND NOTHING ELSE. ***
Every tool, every schema and both safety audits live in `mcp_tools.py`, which does not import
`mcp`. That split is structural rather than tidy: it means the lock test can enumerate every
exposed tool and assert the line holds **with no MCP SDK installed**, which is the situation in
CI. A server that could only be audited when an optional dependency was present would be audited
on this laptop and nowhere else.

*** STDIO, NOT HTTP, AND BUILD #19's OWN WEEK IS THE REASON. ***
Burp's MCP server was measured answering **403 to every combination tried** — it rejects
browser-looking `User-Agent`s and non-allowlisted `Origin` headers as DNS-rebinding defence. That
is a real threat against a localhost HTTP MCP server: any page in the operator's browser can POST
to `127.0.0.1`. stdio has no port, so there is no rebinding surface. If this is ever moved to
HTTP it needs that same protection, and HackPit's route auth is still not built.

*** THE SERVER REFUSES TO START IF THE AUDIT FAILS. ***
This is the one refusal in build #19, and it is not a prohibition on the operator — it is a
self-check. It refuses to expose a tool surface that has grown an approval field or an execution
path, which is the failure the whole item exists to prevent. It never refuses a user action.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import mcp_tools  # noqa: E402


class AuditFailed(RuntimeError):
    """The exposed surface violated the line. The server does not start."""


def preflight() -> None:
    """Run both audits. Raises rather than warning — see the module docstring.

    *** THE APPROVAL-FIELD LINE IS ABSOLUTE; THE EXECUTION LINE HAS ONE OPT-IN DOOR. ***
    By default both audits must come back empty or the server refuses to start. When the operator
    sets HACKPIT_MCP_EXECUTE=1, the execution audit still runs and stays honest — we tolerate ONLY
    the named opt-in execution tools (`mcp_tools.EXECUTION_TOOL_NAMES`), say so loudly on stderr,
    and refuse on anything else. The approval-FIELD audit is NEVER relaxed: an agent that could
    NAME `approved` would approve itself, which no opt-in changes.
    """
    approval = mcp_tools.audit_no_approval_fields()
    execution = mcp_tools.audit_no_execution_paths()

    if getattr(mcp_tools, "EXECUTE_ENABLED", False):
        allowed = tuple(getattr(mcp_tools, "EXECUTION_TOOL_NAMES", ()))
        tolerated = [e for e in execution if e.split(" ->")[0] in allowed]
        execution = [e for e in execution if e not in tolerated]
        if tolerated:
            print(
                "!! HACKPIT MCP EXECUTION MODE IS ON (HACKPIT_MCP_EXECUTE=1).\n"
                "!! The agent can RUN commands against targets with NO human approval.\n"
                "!! Tolerated execution paths: " + ", ".join(tolerated),
                file=sys.stderr,
            )

    if approval or execution:
        raise AuditFailed(
            "REFUSING TO START. The MCP tool surface violates the one non-negotiable line.\n"
            + ("  approval fields exposed: " + ", ".join(approval) + "\n" if approval else "")
            + ("  execution paths reachable: " + ", ".join(execution) + "\n" if execution else "")
            + "An MCP tool that can set an approval field lets the agent approve itself, and "
              "every gate in this codebase becomes theatre."
        )


async def _serve() -> None:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool

    server: Server = Server("hackpit")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(name=spec.name, description=spec.description, inputSchema=spec.input_schema)
            for spec in mcp_tools.tools()
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict | None) -> list[TextContent]:
        # `mcp_tools.call` never raises — a failing read comes back as an error VALUE so the
        # agent is told what went wrong instead of the read looking like an empty result. That
        # is this repo's silent-empty rule applied to a protocol boundary.
        result = mcp_tools.call(name, arguments or {})
        return [TextContent(type="text",
                            text=json.dumps(result, indent=2, default=str, ensure_ascii=False))]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> int:
    try:
        preflight()
    except AuditFailed as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        from mcp.server import Server                              # noqa: F401
    except ImportError:
        print(
            "the `mcp` package is not installed in this interpreter.\n"
            "  cd backend && uv pip install --python .venv/Scripts/python.exe mcp\n"
            "(it is declared as the optional dependency group `mcp` in pyproject.toml — the "
            "backend serves every route without it, and the safety lock does not need it)",
            file=sys.stderr,
        )
        return 3
    asyncio.run(_serve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
