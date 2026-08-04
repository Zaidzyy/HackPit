"""Unit tests for the attack-path composer:

  1. meta/workflow docs (tools ARSENAL / "YOUR PLAN" playbooks) are step-INELIGIBLE
     so they never get grounded as a step, while real techniques stay eligible;
  2. substitute_target only rewrites an example host in a real HOST POSITION — never
     inside a filename (.env.example)/payload/<script>, and never a partial prefix of
     a longer multi-label host (no Frankenstein "…auth0.comm" / "…auth0.coms-app…");
  3. a grounded step's target_adaptation may name ONLY real hosts from the goal/scope
     (invented hosts drop the whole line);
  4. every profiler priority bug class is guaranteed at least one covering step.

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

    # Frankenstein-host regressions: an example host that is only a PREFIX of a
    # longer multi-label token must NOT be partially swapped — no "…auth0.comm"
    # (double-m) and no "…auth0.coms-app.bugforge.io". Either the WHOLE host swaps
    # or nothing does; here nothing does (these aren't complete example hosts).
    for bad in [
        "Host: example.comm",                       # → used to yield ...auth0.comm
        "curl https://example.coms-app.bugforge.io/x",  # → ...auth0.coms-app...
        "nmap example.coms-app.bugforge.io",
    ]:
        got = AP.substitute_target(bad, maf)
        assert "auth0.comm" not in got and "auth0.coms" not in got, \
            f"mangled host produced from {bad!r}: {got!r}"
        assert got == bad, f"partial multi-label host must stay intact: {bad!r} -> {got!r}"

    # a COMPLETE example host in the same position still swaps cleanly (boundary
    # rejects a prefix, not a whole host)
    assert AP.substitute_target("curl https://example.com/x", maf) == \
        f"curl https://{maf}/x"
    print("  FIX 2 (substitution scoping): PASS")


# --------------------------------------------------------------------------- #
# CHANGE 1 — per-grounded-step target_adaptation guardrail (no invented hosts)
# --------------------------------------------------------------------------- #
def test_target_adaptation_guardrail() -> None:
    facts = (
        "Bug bounty on production.maf.auth0.com. In scope: "
        "maf-holding-prod.apigee.net, endpoint SaveOCRReceipt, two test accounts."
    )
    # references only real, in-facts identifiers → kept verbatim (trimmed)
    ok = ("Use the two test accounts as A/B; swap the card id on "
          "maf-holding-prod.apigee.net wallet calls to read B's card as A.")
    assert AP._target_adaptation(ok, facts) == ok

    # an endpoint name (no FQDN) is fine — only hostnames are boundary-checked
    ep = "Replay SaveOCRReceipt with account B's receipt id."
    assert AP._target_adaptation(ep, facts) == ep

    # invents a host not present in the facts → the WHOLE line is dropped
    bad = "Hit admin.evil-invented.com/internal to pivot."
    assert AP._target_adaptation(bad, facts) == "", "invented host must be dropped"

    # no facts to validate against, or empty adaptation → dropped
    assert AP._target_adaptation(ok, None) == ""
    assert AP._target_adaptation("", facts) == ""
    assert AP._target_adaptation("   ", facts) == ""
    print("  CHANGE 1 (target_adaptation guardrail): PASS")


# --------------------------------------------------------------------------- #
# CHANGE 3 — every priority bug class is guaranteed >=1 covering step
# --------------------------------------------------------------------------- #
def _phase(name: str, *steps: dict) -> dict:
    return {"phase": name, "label": name.title(), "steps": list(steps)}


def _step(title: str, **kw) -> dict:
    s = {"title": title, "entry_id": "e", "why": "", "commands": [],
         "ai_suggested": False, "from_writeup": False}
    s.update(kw)
    return s


def _exploitation_idor() -> list[dict]:
    # a fresh path each call — _ensure_priority_coverage renumbers/extends in place
    return [
        _phase("exploitation",
               _step("Cross-tenant IDOR on wallet",
                     commands=[{"lang": "bash", "cmd": "curl .../wallet?id=2"}])),
    ]


def test_priority_coverage() -> None:
    # IDOR is covered by a real step; "OCR receipt fraud" is NOT → one ai_suggested
    # step must be added for it (and only it — no duplicate for the covered class).
    out = AP._ensure_priority_coverage(
        _exploitation_idor(), ["cross-tenant IDOR", "OCR receipt fraud"]
    )
    exp = next(p for p in out if p["phase"] == "exploitation")
    titles = [s["title"] for s in exp["steps"]]
    assert "Probe: OCR receipt fraud" in titles, "uncovered class must gain a step"
    assert not any("IDOR" in t and t.startswith("Probe:") for t in titles), \
        "covered class must NOT gain a duplicate probe step"

    added = next(s for s in exp["steps"] if s["title"] == "Probe: OCR receipt fraud")
    assert added["ai_suggested"] is True and added["commands"] == [], \
        "coverage step must be a clearly-marked, command-less ai_suggested step"
    # ids re-numbered contiguously within the phase
    assert [s["id"] for s in exp["steps"]] == ["exploitation-1", "exploitation-2"]

    # fully-covered profile → no step added (no padding)
    covered = AP._ensure_priority_coverage(_exploitation_idor(), ["cross-tenant IDOR"])
    assert sum(len(p["steps"]) for p in covered) == 1

    # no priority classes → no-op
    base = _exploitation_idor()
    assert AP._ensure_priority_coverage(base, []) is base

    # no exploitation phase yet → one is created in canonical order
    recon_only = [_phase("recon", _step("port scan"))]
    out2 = AP._ensure_priority_coverage(recon_only, ["SSRF via metadata"])
    order = [p["phase"] for p in out2]
    assert order == ["recon", "exploitation"], f"phase order wrong: {order}"
    print("  CHANGE 3 (priority-class coverage): PASS")


def test_target_comes_from_scope_when_the_goal_names_none() -> None:
    """D8(a) — THE BUG THAT MADE SUBSTITUTION A NO-OP.

    The measured failing call passed the real hosts in ``scope_text`` and a goal that
    named none. ``extract_target`` reads only the goal, so it returned None, and
    ``substitute_target`` short-circuits on ``if not target`` — so of 32 returned
    commands, ZERO named the engagement. Nothing said so.
    """
    scope = "www.crateandbarrel.me, api-prod.thatconceptstore.com"
    rs = AP.resolve_scope(scope)
    goal = "find IDOR in the checkout flow"

    # the old path: nothing to substitute with
    assert AP.extract_target(goal) is None

    # the new one: the first CONCRETE in-scope host, and it says where it came from
    target, source = AP.primary_target(goal, rs)
    assert (target, source) == ("www.crateandbarrel.me", "scope"), (target, source)

    # and now the substitution it was always supposed to perform actually performs
    before = "ffuf -u https://FUZZ.example.com/api -w list.txt"
    after = AP.substitute_target(before, target, None)
    assert "example.com" not in after, after
    assert "www.crateandbarrel.me" in after, after
    assert AP.check_command_scope(after, rs)[0] is True

    # precedence: an explicit caller target beats the goal, which beats the scope
    assert AP.primary_target("pwn 10.10.11.5", rs) == ("10.10.11.5", "goal")
    assert AP.primary_target("pwn 10.10.11.5", rs, "api-prod.thatconceptstore.com") == (
        "api-prod.thatconceptstore.com", "caller",
    )

    # A WILDCARD IS NOT A HOST. '*.example.com' names nothing we could run against and
    # inventing 'www.' in front of it would be a fabricated target dressed as a real one.
    wild = AP.resolve_scope("*.crateandbarrel.me")
    assert AP.primary_target(goal, wild) == (None, None)

    # prose scope text parses word-by-word (accepted behaviour, audit §3.1a) — the
    # target picker must not hand back 'the' as a host
    prose = AP.resolve_scope("in scope are the assets listed at shop.example.org today")
    assert (AP.primary_target(goal, prose)[0] or "") in ("shop.example.org", ""), prose
    print("  D8(a) target from scope + precedence + wildcard/prose refusal: PASS")


def test_scope_check_marks_unrunnable_commands() -> None:
    """D8(c) — every returned command is judged against the declared scope.

    The point is HONESTY, not refusal: a plan whose commands are the KB author's own
    examples used to be indistinguishable from one adapted to the target.
    """
    rs = AP.resolve_scope("www.crateandbarrel.me, *.thatconceptstore.com")

    # in scope — left unmarked
    ok = "curl -s https://www.crateandbarrel.me/api/v1/orders/1234"
    assert AP.check_command_scope(ok, rs) == (True, None)
    # the wildcard resolves through the SAME scope model the executor uses
    assert AP.check_command_scope("nmap -sV api-prod.thatconceptstore.com", rs)[0] is True

    # a foreign host, in a host position → unrunnable, and the reason NAMES it
    bad, why = AP.check_command_scope("sublist3r -d tesla.com -t 100", rs)
    assert bad is False
    assert "tesla.com" in why, why

    # no host at all (an unsubstituted placeholder, or a prose excerpt) → its own reason
    none_bad, none_why = AP.check_command_scope("john --wordlist=rockyou.txt hash.txt", rs)
    assert none_bad is False
    assert "names no host" in none_why, none_why

    # NO SCOPE DECLARED → no verdict. 'unchecked' must never render as 'clean'.
    assert AP.check_command_scope(ok, None) == (None, None)
    assert AP.resolve_scope("") is None

    # NOT EVERY DOTTED TOKEN IS A HOST. Filenames and version strings are not targets,
    # and flagging them would put a warning on nearly every command — which is how a
    # warning stops being read.
    assert AP.command_hosts("cat .env.example && ./linpeas.sh > out.txt") == []
    assert AP.command_hosts("python3 -m http.server 8000") == []
    assert AP.command_hosts("wget https://www.crateandbarrel.me/x") == [
        "www.crateandbarrel.me"
    ]
    print("  D8(c) per-command scope verdicts + reasons + no-scope abstention: PASS")


def test_check_commands_annotates_and_counts() -> None:
    """The rollup the response reports — per-command marks, a per-step badge count,
    and the headline total. Additive: a runnable command is left exactly as it was."""
    rs = AP.resolve_scope("www.crateandbarrel.me")
    phases = [
        {"phase": "recon", "label": "Recon", "steps": [
            {"id": "recon-1", "title": "t", "commands": [
                {"lang": "bash", "cmd": "curl https://www.crateandbarrel.me/"},
                {"lang": "bash", "cmd": "nmap -sV 10.10.11.5"},
            ]},
            {"id": "recon-2", "title": "t", "commands": [
                {"lang": "bash", "cmd": "curl https://www.crateandbarrel.me/robots.txt"},
            ]},
        ]},
    ]
    total, unrunnable = AP.check_commands(phases, rs)
    assert (total, unrunnable) == (3, 1), (total, unrunnable)

    step1, step2 = phases[0]["steps"]
    good, bad = step1["commands"]
    assert "runnable" not in good and "unrunnable_reason" not in good, good
    assert bad["runnable"] is False and bad["unrunnable_reason"]
    assert step1["unrunnable_commands"] == 1
    assert "unrunnable_commands" not in step2, step2

    # with no scope there is nothing to judge: nothing marked, count 0
    fresh = [{"phase": "recon", "label": "R", "steps": [
        {"id": "recon-1", "title": "t",
         "commands": [{"lang": "bash", "cmd": "nmap -sV 10.10.11.5"}]}]}]
    assert AP.check_commands(fresh, None) == (1, 0)
    assert "runnable" not in fresh[0]["steps"][0]["commands"][0]
    print("  D8(c) rollup: per-step badge + headline count + no-scope no-op: PASS")


if __name__ == "__main__":
    test_meta_doc_exclusion()
    test_substitution_scoping()
    test_target_adaptation_guardrail()
    test_priority_coverage()
    test_target_comes_from_scope_when_the_goal_names_none()
    test_scope_check_marks_unrunnable_commands()
    test_check_commands_annotates_and_counts()
    print("ALL attack-path fix tests pass")
