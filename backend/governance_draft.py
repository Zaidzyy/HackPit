"""Propose-only drafter for the four governance documents (RoE / ConOps / Deconfliction / OPPLAN).

WHAT THIS IS. The generative layer for engagement governance — the counterpart to
``attack_path.py`` and ``chat.py``. From an engagement's scope + target profile it DRAFTS the
four documents so the operator starts from a filled-in form instead of a blank one. It is
PROPOSE-ONLY: it returns structured payloads (plain dicts), the human edits them, and nothing
is "live" until the human approves each document (see state/governance.py).

WHAT IT IS NOT. It executes NOTHING an engagement acts on: no subprocess, no gate, no executor,
no container, no objective is advanced here. Its only side effect is the LLM HTTP call inside
``llm.chat`` — the same generative call attack_path.py makes — and even that is optional: when
the provider is unreachable it degrades to a DETERMINISTIC skeleton derived from the scope, so
the operator always gets an editable starting point. A safety test proves this module reaches
no execution surface and touches no gate.

THE RoE IS A FRAME, NOT A VETO. The drafted RoE formalises the scope handrail (it references
scope.py's spec, it does not replace it) and proposes authorized/forbidden techniques, OPSEC,
windows and stop conditions. It is advisory to the human; per-command human approval stays the
actual bound. Nothing drafted here can block or run a command.
"""

from __future__ import annotations

from typing import Any

import llm
from state import governance
from state import killchain


# --------------------------------------------------------------------------- #
# system prompts — one per document. Each asks ONLY for a JSON body in the exact
# shape state/governance.default_payload() defines, so the drafter's output drops
# straight into save_doc() for the human to edit.
# --------------------------------------------------------------------------- #
_ROE_SYSTEM = """You are a senior penetration-test lead drafting the RULES OF ENGAGEMENT for
an AUTHORIZED engagement. You produce a proposal a human operator will review and edit before
anything runs. You never run anything and you never claim authority — the RoE is a written
frame the human approves against; per-command human approval remains the real control.

Return ONLY a JSON object with these keys:
  scope_spec: string (echo the authorized scope EXACTLY as given — never widen it)
  authorized_techniques: string[]  (MITRE ATT&CK ids or short names that are in-bounds)
  forbidden_techniques: string[]   (explicitly out of bounds: e.g. DoS, destructive impact)
  opsec_level: one of "loud","standard","careful","quiet","silent"
  time_windows: string[]           (permitted testing windows)
  excluded_targets: string[]       (hosts/systems that must not be touched)
  excluded_actions: string[]       (actions that must not be taken)
  sensitive_data_handling: string  (how captured secrets/PII are handled)
  stop_conditions: string[]        (what halts the engagement immediately)
  emergency_contacts: string[]     (who to call, as role placeholders — no real names)
No prose outside the JSON."""

_CONOPS_SYSTEM = """You are drafting the CONCEPT OF OPERATIONS for an authorized penetration
test — the high-level approach and phases the engagement will follow. Propose-only; a human
edits it. Return ONLY a JSON object:
  approach: string (2-4 sentences on the overall strategy)
  phases: array of {name, description, success_criteria}  (cover recon -> initial-access ->
          post-exploit -> c2 -> exfiltration)
  success_criteria: string[] (what "done" looks like for the whole engagement)
No prose outside the JSON."""

_DECONFLICTION_SYSTEM = """You are drafting a DECONFLICTION PLAN for an authorized engagement:
how this engagement's traffic is distinguished from a real incident so a blue team does not
chase it. Propose-only; a human edits it. Return ONLY a JSON object:
  engagement_signature: string (a per-engagement tag/marker to embed, e.g. a User-Agent tag)
  source_markers: string[]     (identifiable source IPs/marks the testing traffic carries)
  notification_contacts: string[] (blue-team/SOC contacts to notify, as role placeholders)
  traffic_identification: string  (how defenders recognise this as authorized testing)
  blue_team_notes: string      (coordination notes)
No prose outside the JSON."""

_OPPLAN_SYSTEM = """You are drafting an OPPLAN — a list of OBJECTIVES for an authorized
penetration test. Each objective is a concrete goal mapped to a MITRE ATT&CK technique. This
is a proposal a human edits; every objective starts pending and is advanced only by an
approved, exit-0 run. Return ONLY a JSON object:
  default_opsec: one of "loud","standard","careful","quiet","silent"
  notes: string
  objectives: array of {
     title: string,
     phase: one of "recon","initial-access","post-exploit","c2","exfiltration",
     technique_ids: string[]  (MITRE ATT&CK ids like T1190, T1078),
     opsec: one of "loud","standard","careful","quiet","silent",
     notes: string
  }
Propose 4-8 objectives that trace a realistic path from recon to the engagement's goal.
No prose outside the JSON."""


def _target_block(scope_spec: str, target: str, target_type: str, extra: str = "") -> str:
    lines = [
        f"AUTHORIZED SCOPE (do not widen): {scope_spec or '(none declared)'}",
        f"TARGET: {target or '(unnamed)'}",
        f"TARGET TYPE: {target_type or '(unspecified)'}",
    ]
    if extra:
        lines.append(f"KNOWN STATE:\n{extra}")
    return "\n".join(lines)


def _draft(system: str, user: str, max_tokens: int = 1400) -> dict[str, Any] | None:
    """One propose-only LLM round-trip → a dict, or None when the provider is unreachable or
    returns nothing usable. Never raises; the caller falls back to a deterministic skeleton."""
    try:
        cfg = llm.load_config()
        raw = llm.chat(system, user, cfg, max_tokens=max_tokens)
        parsed = llm.extract_json(raw)
    except llm.LLMError:
        return None
    return parsed if isinstance(parsed, dict) else None


# --------------------------------------------------------------------------- #
# deterministic fallbacks — a scope-derived skeleton so the operator always has a
# starting point, even with no LLM configured. Propose-only; the human fills it in.
# --------------------------------------------------------------------------- #
def _fallback_roe(scope_spec: str) -> dict[str, Any]:
    p = governance.default_payload(governance.DOC_ROE)
    p["scope_spec"] = scope_spec
    p["forbidden_techniques"] = ["T1499 Endpoint Denial of Service", "T1486 Data Encrypted for Impact"]
    p["stop_conditions"] = [
        "Any action that risks availability of a production service",
        "Discovery of a live incident already in progress",
        "Loss of positive control of a foothold",
    ]
    p["sensitive_data_handling"] = (
        "Captured credentials and PII stay in the local engagement vault; nothing is exfiltrated "
        "off-scope. Screenshots redact secrets before they enter the report."
    )
    p["emergency_contacts"] = ["Engagement lead", "Client technical point of contact"]
    return p


def _fallback_conops(target: str) -> dict[str, Any]:
    p = governance.default_payload(governance.DOC_CONOPS)
    p["approach"] = (
        f"Assess {target or 'the in-scope target'} through progressive phases, validating each "
        "finding with human approval before escalation. Objectives drive targeting; every "
        "command is approved individually."
    )
    p["phases"] = [
        {"name": "Reconnaissance", "description": "Enumerate the authorized attack surface.",
         "success_criteria": "Ranked, in-scope surface with services and endpoints mapped."},
        {"name": "Exploitation", "description": "Gain an initial foothold on an in-scope host.",
         "success_criteria": "Validated initial access with captured evidence."},
        {"name": "Post-exploitation", "description": "Escalate, move laterally, collect.",
         "success_criteria": "Privilege escalation and lateral movement demonstrated with proof."},
        {"name": "Actions on objectives", "description": "Demonstrate impact against the goal.",
         "success_criteria": "Engagement goal demonstrated; findings documented for the report."},
    ]
    p["success_criteria"] = ["Every objective reaches a terminal state with cited evidence."]
    return p


def _fallback_deconfliction(session_id: str, scope_spec: str) -> dict[str, Any]:
    p = governance.default_payload(governance.DOC_DECONFLICTION)
    tag = f"HACKPIT-{(session_id or 'engagement')[:8]}".upper()
    p["engagement_signature"] = tag
    p["source_markers"] = [f"X-Engagement: {tag} header on tool traffic where supported"]
    p["notification_contacts"] = ["Client SOC / blue-team lead"]
    p["traffic_identification"] = (
        f"Authorized testing carries the {tag} marker and originates from the agreed source "
        "addresses. If observed, coordinate rather than escalate."
    )
    p["blue_team_notes"] = "Notify the SOC at engagement start and end; share source IPs and windows."
    return p


def _fallback_opplan(target: str) -> dict[str, Any]:
    p = governance.default_payload(governance.DOC_OPPLAN)
    p["objectives"] = [
        {"title": f"Map the authorized attack surface of {target or 'the target'}",
         "phase": "recon", "technique_ids": ["T1595", "T1590"], "opsec": "standard", "notes": ""},
        {"title": "Gain initial access to an in-scope host",
         "phase": "initial-access", "technique_ids": ["T1190", "T1078"], "opsec": "standard", "notes": ""},
        {"title": "Escalate privileges on the foothold",
         "phase": "post-exploit", "technique_ids": ["T1068"], "opsec": "careful", "notes": ""},
        {"title": "Move laterally toward the objective system",
         "phase": "post-exploit", "technique_ids": ["T1021"], "opsec": "careful", "notes": ""},
        {"title": "Demonstrate impact against the engagement goal",
         "phase": "exfiltration", "technique_ids": ["T1005"], "opsec": "quiet", "notes": ""},
    ]
    return p


# --------------------------------------------------------------------------- #
# public drafters — each returns {payload, source} where source is "llm" | "fallback"
# --------------------------------------------------------------------------- #
def draft_roe(scope_spec: str, target: str, target_type: str = "", state_block: str = "") -> dict[str, Any]:
    body = _draft(_ROE_SYSTEM, _target_block(scope_spec, target, target_type, state_block))
    if body is None:
        return {"payload": _fallback_roe(scope_spec), "source": "fallback"}
    # Never let the drafter widen the scope: force the human-declared spec back in.
    body["scope_spec"] = scope_spec
    return {"payload": _merge_default(governance.DOC_ROE, body), "source": "llm"}


def draft_conops(scope_spec: str, target: str, target_type: str = "", state_block: str = "") -> dict[str, Any]:
    body = _draft(_CONOPS_SYSTEM, _target_block(scope_spec, target, target_type, state_block))
    if body is None:
        return {"payload": _fallback_conops(target), "source": "fallback"}
    return {"payload": _merge_default(governance.DOC_CONOPS, body), "source": "llm"}


def draft_deconfliction(
    session_id: str, scope_spec: str, target: str, target_type: str = "", state_block: str = ""
) -> dict[str, Any]:
    body = _draft(_DECONFLICTION_SYSTEM, _target_block(scope_spec, target, target_type, state_block))
    if body is None:
        return {"payload": _fallback_deconfliction(session_id, scope_spec), "source": "fallback"}
    if not str(body.get("engagement_signature") or "").strip():
        body["engagement_signature"] = f"HACKPIT-{(session_id or 'engagement')[:8]}".upper()
    return {"payload": _merge_default(governance.DOC_DECONFLICTION, body), "source": "llm"}


def draft_opplan(scope_spec: str, target: str, target_type: str = "", state_block: str = "") -> dict[str, Any]:
    """Draft OPPLAN SETTINGS + a proposed objectives list. The objectives are returned in the
    payload under ``objectives`` (the route creates them as pending Objective rows for the
    human to edit)."""
    body = _draft(_OPPLAN_SYSTEM, _target_block(scope_spec, target, target_type, state_block))
    if body is None:
        return {"payload": _fallback_opplan(target), "source": "fallback"}
    objectives = body.get("objectives")
    settings = _merge_default(governance.DOC_OPPLAN, body)
    settings["objectives"] = objectives if isinstance(objectives, list) else []
    return {"payload": settings, "source": "llm"}


def _merge_default(doc_type: str, body: dict[str, Any]) -> dict[str, Any]:
    """Fill any keys the model omitted from the default shape, and drop keys that are not part
    of the document's shape — so a malformed draft still saves as a well-formed (if sparse)
    document rather than corrupting the record."""
    shape = governance.default_payload(doc_type)
    out: dict[str, Any] = {}
    for key, default in shape.items():
        val = body.get(key, default)
        out[key] = val if type(val) is type(default) or default in ("", []) else default
    return out


def known_techniques() -> list[dict[str, str]]:
    """The ATT&CK techniques the reference knows about — offered to the operator as a picker
    when editing objectives/RoE. Pure data read; executes nothing."""
    out: list[dict[str, str]] = []
    for tactic in killchain.load_killchain()["tactics"]:
        for tech in tactic.get("techniques") or []:
            out.append({
                "id": str(tech.get("id") or ""),
                "name": str(tech.get("name") or ""),
                "tactic": str(tactic.get("name") or ""),
                "phase": str(tactic.get("phase") or ""),
            })
    return out
