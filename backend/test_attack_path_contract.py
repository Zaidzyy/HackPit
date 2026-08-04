"""THE RESPONSE CONTRACT for /attack-path — a lock on the "three places" trap.

An attack-path field lives in THREE files: `attack_path.py` produces it, main.py's Pydantic
models declare it, and the frontend renders it. Miss the middle one and FastAPI's
`response_model` drops the field on the way out — silently, with a 200 and a plausible
body. Nothing fails, nothing logs, and the feature simply is not there.

That is not hypothetical. `unverified` and `truncated` were being set on planned commands
by `_ai_commands`/`entry_commands` and thrown away by the response model for as long as
both have existed, because `AttackStep.commands` was typed `list[Code]` and `Code` (the KB
entry shape) declares neither. They only came back when `PlannedCode` was added for the
D8 scope check.

So this file does not check a list of field names — a list would need updating by exactly
the person who just forgot. It checks the PROPERTY: every key the composer puts in the
payload survives the response model. A new field that main.py never learned about fails
here whether or not anyone thought to add it to a test.

Two invariants:

  1. NOTHING IS DROPPED. A full composer-shaped payload round-trips through
     `AttackPathOut` with every key intact, at every level of nesting.
  2. AN UNKNOWN REQUEST FIELD IS REFUSED, NOT IGNORED. `AttackPathIn` used to accept
     `target` from a caller and silently discard it, so a request that named its target
     came back planned against nothing while looking like it had been honoured. A field
     the model does not know is now a 422.

Self-contained (no LLM, no network). Run:  python test_attack_path_contract.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402


# A payload shaped exactly like attack_path.compose()'s return — every optional field
# populated, because a field only present on some paths is precisely the one that gets
# forgotten. Values are synthetic; only the KEYS matter here.
def _payload() -> dict[str, Any]:
    return {
        "goal": "find IDOR in the checkout flow",
        "target_type": "bugbounty",
        "target": "www.example-shop.test",
        "target_source": "scope",
        "scope_checked": True,
        "commands_total": 3,
        "commands_unrunnable": 1,
        "phases": [
            {
                "phase": "recon",
                "label": "Recon",
                "steps": [
                    {
                        "id": "recon-1",
                        "title": "Enumerate subdomains",
                        "entry_id": "kb-123",
                        "why": "map the attack surface first",
                        "commands": [
                            {
                                "lang": "bash",
                                "cmd": "curl -s https://www.example-shop.test/",
                                "copyable": True,
                                "unverified": False,
                                "truncated": False,
                            },
                            {
                                "lang": "bash",
                                "cmd": "nmap -sV 10.10.11.5",
                                "copyable": True,
                                "unverified": True,
                                "truncated": True,
                                "runnable": False,
                                "unrunnable_reason": "points at 10.10.11.5 — not in scope",
                            },
                        ],
                        "unrunnable_commands": 1,
                        "ai_suggested": False,
                        "from_writeup": False,
                        "target_adaptation": "point this at the checkout host",
                        "on_success": "you have a subdomain list",
                        "on_blocked": "fall back to passive sources",
                        "attck": {
                            "techniques": [], "tactic": "reconnaissance", "noise": "quiet",
                        },
                        "arsenal": {
                            "tool": "nmap", "tools": ["nmap"], "category": "recon",
                            "purpose": "port/service discovery", "kb_entry_id": None,
                            "docs": "https://nmap.org/book/",
                        },
                        "foreign_refs": ["10.10.11.5"],
                    }
                ],
            }
        ],
        "profile": {
            "target_class": "e-commerce",
            "tech_signals": ["nextjs"],
            "priority_bug_classes": ["IDOR"],
            "out_of_scope": ["/admin"],
        },
        "scoped": True,
        "box_writeup": {"id": "wu-1", "title": "A box", "tier": 1},
        "origin": "composed",
        "origin_label": None,
        "origin_note": None,
        "augmented": True,
        "context_sources": [
            {"kind": "methodology", "id": "kb-9", "title": "IDOR notes", "chars": 1200}
        ],
        "context_leaks": 0,
        "model_used": "qwen3:8b",
        "provider": "ollama",
    }


def _missing(sent: Any, got: Any, path: str = "") -> list[str]:
    """Every key present in `sent` but absent from `got`, recursively.

    Only ever reports LOSS. The response model legitimately adds keys (a declared field the
    composer omitted comes back as its default), and flagging those would make the test
    fire on harmless additions and get switched off.
    """
    lost: list[str] = []
    if isinstance(sent, dict):
        if not isinstance(got, dict):
            return [f"{path or '<root>'}: whole object dropped"]
        for k, v in sent.items():
            here = f"{path}.{k}" if path else k
            if k not in got:
                lost.append(here)
            else:
                lost += _missing(v, got[k], here)
    elif isinstance(sent, list):
        if not isinstance(got, list) or len(got) != len(sent):
            return [f"{path}: list dropped or truncated"]
        for i, v in enumerate(sent):
            lost += _missing(v, got[i], f"{path}[{i}]")
    return lost


def test_no_composer_field_is_dropped_by_the_response_model() -> None:
    sent = _payload()
    got = main.AttackPathOut.model_validate(sent).model_dump()
    lost = _missing(sent, got)
    assert not lost, (
        "these fields never reach the browser — main.py's Pydantic models do not declare "
        "them, so response_model strips them silently: " + ", ".join(lost)
    )
    # POSITIVE CONTROL — the check must be able to fail. A field no model declares is
    # exactly what a forgotten one looks like, and it must be reported.
    planted = _payload()
    planted["phases"][0]["steps"][0]["commands"][0]["hackpit_planted_field"] = 1
    planted["hackpit_planted_top_level"] = 1
    control = _missing(planted, main.AttackPathOut.model_validate(planted).model_dump())
    assert "hackpit_planted_top_level" in control, control
    assert any("hackpit_planted_field" in c for c in control), control
    print(f"  every one of the {len(sent)} composer fields survives response_model: PASS")
    print("  positive control: an undeclared field IS reported as dropped: PASS")


def test_the_scope_check_fields_specifically_reach_the_browser() -> None:
    """The generic check above would still pass if the D8 fields were never sent. Name
    them once, at the level they live at, so a regression says which feature broke."""
    got = main.AttackPathOut.model_validate(_payload()).model_dump()
    for field in ("target_source", "scope_checked", "commands_total", "commands_unrunnable"):
        assert field in got, f"path-level {field} was stripped"
    step = got["phases"][0]["steps"][0]
    assert step["unrunnable_commands"] == 1
    flagged = step["commands"][1]
    assert flagged["runnable"] is False, flagged
    assert "not in scope" in (flagged["unrunnable_reason"] or ""), flagged
    # the pre-existing silent loss this model was introduced to repair
    assert flagged["unverified"] is True and flagged["truncated"] is True, flagged
    print("  D8 scope-check fields + the repaired unverified/truncated: PASS")


def test_an_unknown_request_field_is_refused_not_ignored() -> None:
    client = TestClient(main.app)

    # the field that used to vanish is now a real one
    ok = TestClient(main.app).post(
        "/attack-path",
        json={"goal": "test goal here", "target": "example.test", "scope_text": "example.test"},
    )
    assert ok.status_code != 422, (
        "`target` must be ACCEPTED — it is a declared field now: " + ok.text[:200]
    )

    # anything the model does not know is a 422, not a shrug
    bad = client.post(
        "/attack-path", json={"goal": "test goal here", "hackpit_unknown_field": "x"}
    )
    assert bad.status_code == 422, (
        f"an unknown request field must be refused, got {bad.status_code}: {bad.text[:200]}"
    )
    print("  /attack-path accepts `target` and REFUSES an unknown field (422): PASS")


if __name__ == "__main__":
    test_no_composer_field_is_dropped_by_the_response_model()
    test_the_scope_check_fields_specifically_reach_the_browser()
    test_an_unknown_request_field_is_refused_not_ignored()
    print("ALL /attack-path response-contract tests pass")
