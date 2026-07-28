"""2.2 — hypothesis-first proposal schema (propose-only; nothing here executes).

A greedy loop pattern-matches: it sees a port and reaches for the tool it always reaches for.
A REASONING loop states a hypothesis, says what signal would confirm it, and only THEN draws
the command — which makes a wrong guess visible and correctable *before* a human approves it,
and enforces enumerate-before-exploit as a shape rather than a hope.

This module owns that shape in one place:

* :data:`SYSTEM_CONTRACT` is appended to the proposer's system prompt so the model leads with
  ``hypothesis`` + ``expected_signal`` + ``citations``, then the command.
* :func:`normalize` pulls those fields off a parsed model response with safe defaults.
* :func:`validate` is the gate a test asserts on: a proposal with no hypothesis, no
  expected_signal, or no citations FAILS. That is invariant 3 — a proposal with no "why" is a
  rubber stamp waiting to happen — expressed as code.

A citation is ``{"type": "kb"|"state", "id": "<entry id | state fact>"}``: the KB entry ids and
the state facts the proposal rests on. It is data, not a capability.
"""

from __future__ import annotations

from typing import Any

# Appended to BOTH proposer system prompts (lab + real-target) by orchestrator.py. It does not
# replace the existing command/rationale/step_id contract — it puts the reasoning FIRST.
SYSTEM_CONTRACT = (
    "\nREASON BEFORE YOU ACT. Lead every proposal with your reasoning, then the command:\n"
    '  "hypothesis": "<the specific thing you believe is true and are testing, e.g. the login '
    "form q parameter is SQL-injectable -- NOT a restatement of the tool>\",\n"
    '  "expected_signal": "<what output would CONFIRM the hypothesis, and what would refute it, '
    'so a wrong guess is visible>",\n'
    '  "citations": [{"type": "kb", "id": "<KB entry id you are relying on>"}, '
    '{"type": "state", "id": "<a host/service/finding from the ENGAGEMENT STATE this rests '
    'on>"}],\n'
    "Enumerate before you exploit: if the evidence does not yet support an exploit hypothesis, "
    "your hypothesis is an enumeration one and the command gathers the missing signal. A "
    "proposal with no hypothesis, no expected_signal, or no citation is rejected."
)

REQUIRED_FIELDS = ("hypothesis", "expected_signal", "citations")


def normalize_citations(raw: Any) -> list[dict[str, str]]:
    """Coerce whatever the model returned into a clean citation list.

    Accepts the canonical ``[{"type","id"}]`` and also degrades gracefully from a bare list of
    strings (``["kb-123", "host:10.0.0.5"]``) — a smaller local model often emits the latter, and
    dropping a real citation on a formatting technicality would punish grounding.
    """
    out: list[dict[str, str]] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if isinstance(item, dict):
            cid = str(item.get("id") or item.get("ref") or item.get("entry") or "").strip()
            ctype = str(item.get("type") or "").strip().lower() or _infer_type(cid)
            if cid:
                out.append({"type": ctype, "id": cid})
        elif isinstance(item, str) and item.strip():
            cid = item.strip()
            out.append({"type": _infer_type(cid), "id": cid})
    # de-dup preserving order
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, str]] = []
    for c in out:
        k = (c["type"], c["id"].lower())
        if k not in seen:
            seen.add(k)
            deduped.append(c)
    return deduped


def _infer_type(cid: str) -> str:
    low = cid.lower()
    if low.startswith(("host:", "svc:", "service:", "finding:", "cred:", "endpoint:", "state:")):
        return "state"
    if low.startswith(("cve-", "kb", "entry")) or low[:1].isdigit():
        return "kb"
    return "kb"


def normalize(parsed: dict[str, Any]) -> dict[str, Any]:
    """Extract the reasoning fields from a parsed model response, with safe defaults.

    Never raises: a model that ignored the contract yields empty strings / an empty citation
    list, which :func:`validate` then reports as invalid. Additive — the caller keeps its own
    command/args/rationale handling and merges this in.
    """
    return {
        "hypothesis": str(parsed.get("hypothesis") or "").strip(),
        "expected_signal": str(parsed.get("expected_signal") or "").strip(),
        "citations": normalize_citations(parsed.get("citations")),
    }


def validate(proposal: dict[str, Any]) -> tuple[bool, list[str]]:
    """Is this a reasoned proposal, or a rubber stamp? Returns (ok, problems).

    THE INVARIANT-3 GATE. Missing hypothesis, missing expected_signal, or zero citations each
    fail it. A test drives this with a stripped proposal and asserts it fails — the demonstration
    that the gate can fail, per the safety-test rule.
    """
    problems: list[str] = []
    if not str(proposal.get("hypothesis") or "").strip():
        problems.append("no hypothesis — the proposal does not say what it believes it is testing")
    if not str(proposal.get("expected_signal") or "").strip():
        problems.append("no expected_signal — nothing states what would confirm or refute it")
    cites = proposal.get("citations")
    if not isinstance(cites, list) or not [c for c in cites if isinstance(c, dict) and c.get("id")]:
        problems.append("no citations — the proposal rests on no KB entry or state fact")
    return (not problems, problems)
