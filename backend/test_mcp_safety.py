"""MCP server SAFETY invariants (build #19 item 6).  Run:  python test_mcp_safety.py

*** THE ONE NON-NEGOTIABLE LINE, AND THIS FILE IS WHERE IT IS ENFORCED. ***
HackPit's action routes take ``approved=true`` and ``dangerous_ack=true`` **in the request body**.
If an MCP tool could set those fields, the agent would approve itself and every gate in this
codebase would become theatre. That is exactly why ``proxy._gate_request`` passes
``GATE_KEY_PLACEHOLDER`` — the gate is never given the real thing.

This file ENUMERATES EVERY EXPOSED TOOL and asserts, for all of them:

  1. no approval field is nameable — not in a schema property at any depth, and not through an
     open schema (``additionalProperties`` must be False, or `{"approved": true}` is sendable
     whether or not the handler reads it)
  2. no handler reaches an execution path, by AST — including through the module's own helpers

IT NEEDS NO MCP SDK. `mcp_tools.py` is the registry and imports nothing from `mcp`; the transport
lives in `mcp_server.py`. That split is what lets this lock run in CI, where the optional
dependency is absent — a line that could only be checked on one laptop is not a line.

AST, NEVER SUBSTRING. This module's own docstrings NAME `run_kali` and `start_scan` while
explaining that they must never be called, and a substring scan would trip on the very sentence
written to prevent the problem. That trap has bitten this repo twice.
"""

from __future__ import annotations

import ast
import inspect

import mcp_tools
from cockpit import proposals


# --------------------------------------------------------------------------- #
# THE LINE
# --------------------------------------------------------------------------- #
def test_there_ARE_tools_to_check() -> None:
    """A lock that passes because the registry is empty proves nothing. This is the same
    'a zero is not a result' rule the rest of the codebase runs on."""
    tools = mcp_tools.tools()
    assert len(tools) >= 10, f"only {len(tools)} tools registered — is the registry importing?"
    names = {t.name for t in tools}
    assert "propose_command" in names
    print(f"  {len(tools)} tools are registered and enumerable: PASS")


def test_NO_EXPOSED_TOOL_CAN_SET_AN_APPROVAL_FIELD() -> None:
    """*** THE LINE. *** Enumerates every tool's schema and every nested property name."""
    offenders = mcp_tools.audit_no_approval_fields()
    assert offenders == [], (
        "AN MCP TOOL CAN SET AN APPROVAL FIELD — the agent can approve itself and every gate in "
        f"this codebase is theatre: {offenders}"
    )
    print("  no exposed tool declares an approval field, at any depth: PASS")


def test_the_approval_audit_ACTUALLY_CATCHES_ONE() -> None:
    """*** THE CONTROL. *** An audit that always returns [] would pass the test above forever.
    Registers a deliberately-bad tool, asserts it is caught, and removes it."""
    @mcp_tools.tool("planted_bad_tool", "control", mcp_tools._schema({
        "target": {"type": "string"},
        "approved": {"type": "boolean"},
    }))
    def _planted(target: str = "", approved: bool = False) -> dict:
        return {}

    try:
        offenders = mcp_tools.audit_no_approval_fields()
        assert any("planted_bad_tool.approved" in o for o in offenders), offenders
    finally:
        mcp_tools._REGISTRY.pop("planted_bad_tool", None)
        mcp_tools._HANDLERS.pop("planted_bad_tool", None)
    assert mcp_tools.audit_no_approval_fields() == [], "the planted tool was not removed"
    print("  positive control: a planted approval field IS caught, then cleaned up: PASS")


def test_an_OPEN_SCHEMA_is_treated_as_an_offence() -> None:
    """A schema allowing extra properties lets a client send `{"approved": true}` alongside the
    declared arguments. Whether the handler reads it is beside the point — the claim is that an
    agent cannot NAME an approval field."""
    @mcp_tools.tool("planted_open_tool", "control",
                    {"type": "object", "properties": {"a": {"type": "string"}}})
    def _planted_open(a: str = "") -> dict:
        return {}

    try:
        offenders = mcp_tools.audit_no_approval_fields()
        assert any("planted_open_tool" in o and "additionalProperties" in o for o in offenders), (
            f"an open schema was not flagged: {offenders}"
        )
    finally:
        mcp_tools._REGISTRY.pop("planted_open_tool", None)
        mcp_tools._HANDLERS.pop("planted_open_tool", None)
    print("  an open schema is an offence, because it makes the field nameable: PASS")


def test_EVERY_SCHEMA_IS_CLOSED() -> None:
    for spec in mcp_tools.tools():
        assert spec.input_schema.get("additionalProperties") is False, (
            f"{spec.name} has an open schema — extra properties are sendable"
        )
    print("  every registered schema is closed: PASS")


def test_NO_TOOL_REACHES_AN_EXECUTION_PATH() -> None:
    """By AST, following the module's own helpers, because a handler that calls a local helper
    that calls `subprocess.run` has hands at one remove."""
    offenders = mcp_tools.audit_no_execution_paths()
    assert offenders == [], f"an MCP tool reaches an execution path: {offenders}"
    print("  no tool handler reaches an execution path: PASS")


def test_the_execution_audit_ACTUALLY_CATCHES_ONE() -> None:
    """*** THE SECOND CONTROL. *** A planted handler that spawns must be caught."""
    @mcp_tools.tool("planted_exec_tool", "control", mcp_tools._schema({}))
    def _planted_exec() -> dict:
        import subprocess

        return {"out": subprocess.run(["echo", "hi"], capture_output=True).returncode}

    try:
        offenders = mcp_tools.audit_no_execution_paths()
        assert any("planted_exec_tool" in o for o in offenders), offenders
    finally:
        mcp_tools._REGISTRY.pop("planted_exec_tool", None)
        mcp_tools._HANDLERS.pop("planted_exec_tool", None)
    assert mcp_tools.audit_no_execution_paths() == []
    print("  positive control: a planted subprocess call IS caught, then cleaned up: PASS")


def test_EXACTLY_ONE_TOOL_IS_WRITE_SHAPED_and_it_is_propose_command() -> None:
    writers = [t.name for t in mcp_tools.tools() if t.writes]
    assert writers == ["propose_command"], (
        f"the write-shaped surface is {writers} — it must be exactly ['propose_command']"
    )
    print("  exactly one write-shaped tool, and it is propose_command: PASS")


def test_propose_command_DOES_NOT_RUN_and_says_so() -> None:
    """It appends to a queue. A human reads it and then sends it to the execution route
    themselves, with the gate fields THEY set."""
    proposals.clear()
    out = mcp_tools.call("propose_command", {
        "command": "nmap", "args": ["-sV", "example.com"], "rationale": "enumerate",
    })
    assert "proposal_id" in out, out
    assert out["status"] == "pending"
    assert "NOT RUN" in out["note"]
    rows = proposals.listing()
    assert len(rows) == 1 and rows[0].command == "nmap"
    assert rows[0].status == "pending"
    proposals.clear()
    print("  propose_command queues a pending row and runs nothing: PASS")


def test_the_PROPOSAL_MODEL_carries_no_gate_field_names() -> None:
    """If this object carried the gate's own field names, the next person to wire it into an
    ExecRequest would do so by copying them across — and the AGENT would have written the value.
    The names are different because the concepts are, and keeping them different stops the copy."""
    for name in ("approved", "dangerous_ack", "ack", "confirm"):
        assert name not in proposals.Proposal.model_fields, (
            f"Proposal grew a {name!r} field — that is a gate field name on an agent-writable row"
        )
    assert "status" in proposals.Proposal.model_fields
    assert set(proposals.STATUSES) == {"pending", "approved", "rejected"}
    print("  the proposal model has a review status, never a gate field: PASS")


def test_APPROVING_A_PROPOSAL_EXECUTES_NOTHING() -> None:
    """The obvious next feature is "approve and run". It is deliberately absent: it would make
    this a SECOND place that can set an approval field, reachable by anything that reaches the
    queue."""
    tree = ast.parse(inspect.getsource(proposals))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            assert name not in ("run", "Popen", "run_kali", "start_scan", "check_output",
                                "system", "spawn"), (
                f"cockpit/proposals.py reaches {name} — the queue must be a piece of paper"
            )
    # ...and reviewing never coerces to approved.
    proposals.clear()
    p = proposals.propose("id", [])
    reviewed = proposals.review(p.id, "not-a-status")
    assert reviewed is not None and reviewed.status == "rejected", reviewed.status
    proposals.clear()
    print("  the queue executes nothing, and an unknown status never becomes 'approved': PASS")


def test_the_gate_preview_ASKS_WITH_BOTH_FLAGS_FALSE() -> None:
    """Asking with them set would answer "this would be allowed", which reads as permission and
    is a question nobody asked."""
    src = inspect.getsource(proposals.gate_preview)
    assert "approved=False" in src and "dangerous_ack=False" in src, (
        "gate_preview asks with an approval flag set — its answer would read as permission"
    )
    proposals.clear()
    p = proposals.propose("nmap", ["-sV", "example.com"])
    preview = proposals.gate_preview(p)
    assert preview["would_refuse"] is True, preview
    assert preview["gate"] in ("approval", "target", "danger", "isolation"), preview
    proposals.clear()
    print("  the gate preview asks unapproved and reports the first gate in the way: PASS")


def test_the_registry_does_NOT_import_the_mcp_sdk() -> None:
    """The split is what lets this lock run in CI, where the optional dependency is absent."""
    tree = ast.parse(inspect.getsource(mcp_tools))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert not a.name.split(".")[0] == "mcp", f"mcp_tools imports {a.name}"
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] != "mcp", f"mcp_tools imports from {node.module}"
    print("  the registry imports no MCP SDK, so this lock runs without one: PASS")


def test_the_SERVER_REFUSES_TO_START_if_either_audit_fails() -> None:
    """The one refusal in build #19, and it is a self-check rather than a prohibition on the
    operator: it refuses to EXPOSE a surface that violates the line. It never refuses a user
    action."""
    import mcp_server

    mcp_server.preflight()          # the real surface passes

    @mcp_tools.tool("planted_start_blocker", "control", mcp_tools._schema({
        "dangerous_ack": {"type": "boolean"}}))
    def _planted(dangerous_ack: bool = False) -> dict:
        return {}

    try:
        raised = False
        try:
            mcp_server.preflight()
        except mcp_server.AuditFailed as exc:
            raised = True
            assert "REFUSING TO START" in str(exc)
        assert raised, "preflight() accepted a tool exposing dangerous_ack"
    finally:
        mcp_tools._REGISTRY.pop("planted_start_blocker", None)
        mcp_tools._HANDLERS.pop("planted_start_blocker", None)
    mcp_server.preflight()          # clean again
    print("  the server refuses to start on a violating surface, with a control: PASS")


def test_a_failing_read_is_an_ERROR_VALUE_not_an_empty_result() -> None:
    """This repo's silent-empty rule at a protocol boundary: a read that fails must not look
    like a read that found nothing."""
    out = mcp_tools.call("no_such_tool_at_all", {})
    assert "error" in out and "available" in out, out
    bad_args = mcp_tools.call("hackpit_kb_search", {"nonsense_argument": 1})
    assert "error" in bad_args, bad_args
    print("  an unknown tool and bad arguments both come back as errors, not as zeroes: PASS")


def test_the_intercept_read_does_NOT_hand_over_the_held_request() -> None:
    """A held request routinely carries a session cookie and an Authorization header — the one
    read whose payload is a live credential rather than recorded traffic. The agent is told THAT
    something is held, which is the actionable fact."""
    src = inspect.getsource(mcp_tools.hackpit_intercept_state)
    assert "held_message_bytes" in src
    assert '"message"' not in src and "state.message," not in src, (
        "the MCP intercept read now returns the held request body"
    )
    print("  the agent learns a request is held, never its contents: PASS")


def test_the_engagement_state_read_hands_over_NO_CREDENTIAL_VALUES() -> None:
    src = inspect.getsource(mcp_tools.hackpit_engagement_state)
    assert '"username"' in src and "k in (" in src, "the credential filter is gone"
    assert '"value"' not in src and '"password"' not in src
    print("  credentials come back as names and kinds, never values: PASS")


if __name__ == "__main__":
    print("== MCP server safety (build #19 item 6) ==")
    test_there_ARE_tools_to_check()
    test_NO_EXPOSED_TOOL_CAN_SET_AN_APPROVAL_FIELD()
    test_the_approval_audit_ACTUALLY_CATCHES_ONE()
    test_an_OPEN_SCHEMA_is_treated_as_an_offence()
    test_EVERY_SCHEMA_IS_CLOSED()
    test_NO_TOOL_REACHES_AN_EXECUTION_PATH()
    test_the_execution_audit_ACTUALLY_CATCHES_ONE()
    test_EXACTLY_ONE_TOOL_IS_WRITE_SHAPED_and_it_is_propose_command()
    test_propose_command_DOES_NOT_RUN_and_says_so()
    test_the_PROPOSAL_MODEL_carries_no_gate_field_names()
    test_APPROVING_A_PROPOSAL_EXECUTES_NOTHING()
    test_the_gate_preview_ASKS_WITH_BOTH_FLAGS_FALSE()
    test_the_registry_does_NOT_import_the_mcp_sdk()
    test_the_SERVER_REFUSES_TO_START_if_either_audit_fails()
    test_a_failing_read_is_an_ERROR_VALUE_not_an_empty_result()
    test_the_intercept_read_does_NOT_hand_over_the_held_request()
    test_the_engagement_state_read_hands_over_NO_CREDENTIAL_VALUES()
    print("ALL MCP safety locks pass")
