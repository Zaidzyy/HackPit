"""Unit tests for the attack-path grounding fixes. Self-contained (synthetic
entries, stdlib only). Run:  python test_attack_path.py
"""
from __future__ import annotations

import attack_path as AP


def _entry(**kw) -> dict:
    e = {"id": "x", "title": "", "category": "web", "source": "s",
         "steps": [], "body_md": "", "meta": {}}
    e.update(kw)
    return e


def _steps(*cmds: str) -> list[dict]:
    return [{"n": i + 1, "text": "", "code": [{"lang": "bash", "cmd": c}]}
            for i, c in enumerate(cmds)]


# --------------------------------------------------------------------------- #
# meta/workflow docs (tools ARSENAL / "YOUR PLAN") are excluded from grounding
# --------------------------------------------------------------------------- #
def test_meta_doc_exclusion() -> None:
    # the reported class: an ARSENAL title whose "commands" are installs / a YOUR
    # PLAN block / checklists — must be step-INELIGIBLE.
    arsenal = _entry(
        title="AI TOOLS ARSENAL",
        steps=_steps(
            "✅ IDOR — changes IDs across accounts\n❌ not this",
            "git clone https://github.com/KeygraphHQ/shannon\ncd shannon && npm install",
            "ANTHROPIC_API_KEY=sk-ant-...\nLLM_PLANNER_MODEL=claude",
            "YOUR PLAN:\n1. Setup config (15 min)\n2. Run tool",
        ),
    )
    assert AP.is_meta_doc(arsenal) is True, "arsenal/plan doc should be a meta doc"
    assert AP.is_step_eligible(arsenal) is False, "meta doc must be step-ineligible"

    # a bare 'YOUR PLAN:' block alone is enough (unambiguous playbook)
    plan = _entry(title="Recon Notes", steps=_steps("YOUR PLAN:\n1. do X\n2. do Y"))
    assert AP.is_meta_doc(plan) is True

    # a real technique: target-directed attack commands, no meta markers → ELIGIBLE
    technique = _entry(
        title="SQL injection via the search parameter",
        steps=_steps(
            "sqlmap -u 'https://target/search?q=1' --batch --dbs",
            "curl 'https://target/api?id=1 UNION SELECT ...'",
        ),
    )
    assert AP.is_meta_doc(technique) is False, "real technique wrongly flagged meta"
    assert AP.is_step_eligible(technique) is True

    # a technique that installs ONE tool then attacks must NOT trip (not dominated)
    one_install = _entry(
        title="Kerberoasting",
        steps=_steps(
            "pip install impacket",
            "impacket-GetUserSPNs -request -dc-ip 10.10.11.5 corp.local/user",
            "hashcat -m 13100 spns.txt rockyou.txt",
        ),
    )
    assert AP.is_meta_doc(one_install) is False, "one install must not flag a technique"
    assert AP.is_step_eligible(one_install) is True

    # canonical_keys = trusted single technique, never a meta doc even if titled 'arsenal'
    keyed = _entry(title="GREP ARSENAL", meta={"canonical_keys": ["ssrf"]},
                   steps=_steps("git clone x", "pip install y", "docker run z"))
    assert AP.is_meta_doc(keyed) is False

    # broad-reference: an arsenal TITLE ranks as broad (loses to a focused one), but
    # a product name that merely contains "toolkit" is NOT swept up.
    assert AP.is_broad_reference(_entry(title="SECURITY ARSENAL")) is True
    assert AP.is_broad_reference(_entry(title="Google Web Toolkit")) is False
    assert AP.is_broad_reference(_entry(title="SQL injection")) is False
    print("  meta-doc exclusion: PASS")


if __name__ == "__main__":
    test_meta_doc_exclusion()
    print("ALL grounding-fix tests pass")
