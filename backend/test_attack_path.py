"""Unit tests for the two attack-path fixes:

  1. meta/workflow docs (tools ARSENAL / "YOUR PLAN" playbooks) are step-INELIGIBLE
     so they never get grounded as a step, while real techniques stay eligible;
  2. substitute_target only rewrites an example host in a real HOST POSITION — never
     inside a filename (.env.example) or a payload/<script> string.

Self-contained (synthetic entries, stdlib only). Run:  python test_attack_path.py
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
# FIX 1 — meta/workflow docs excluded from step-grounding
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
    print("  FIX 1 (meta-doc exclusion): PASS")


# --------------------------------------------------------------------------- #
# FIX 2 — substitute_target scoping
# --------------------------------------------------------------------------- #
def test_substitution_scoping() -> None:
    host = "scanme.sh"
    # MUST be left untouched (filenames / payloads / installs / unrelated hosts)
    for cmd in [
        "cp .env.example .env",
        "<script>alert('XSS')</script>",
        "pip install -r requirements.txt",
        "git clone https://github.com/x/y",
    ]:
        got = AP.substitute_target(cmd, host)
        assert got == cmd, f"must be UNCHANGED: {cmd!r} -> {got!r}"

    # MUST still substitute in a real host position
    assert AP.substitute_target("curl https://example.com/api", host) == \
        "curl https://scanme.sh/api"
    assert AP.substitute_target("-H 'Host: example.com'", host) == \
        "-H 'Host: scanme.sh'"
    assert AP.substitute_target("nmap example.com", host) == "nmap scanme.sh"
    assert AP.substitute_target("ssh user@target.htb", host) == "ssh user@scanme.sh"

    # example IP → target IP still works (target is an IP)
    assert AP.substitute_target("nmap 10.10.11.5", "10.10.14.9") == "nmap 10.10.14.9"

    # github stays github (not an example host)
    assert "github.com" in AP.substitute_target("wget https://github.com/a/b", host)

    # the exact MAF regressions must not recur, with the real MAF target
    maf = "production.maf.auth0.com"
    assert AP.substitute_target("cp .env.example .env", maf) == "cp .env.example .env"
    assert AP.substitute_target("<script>alert('XSS')</script>", maf) == \
        "<script>alert('XSS')</script>"
    print("  FIX 2 (substitution scoping): PASS")


if __name__ == "__main__":
    test_meta_doc_exclusion()
    test_substitution_scoping()
    print("ALL attack-path fix tests pass")
