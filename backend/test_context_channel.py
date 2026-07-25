"""Channel-2 (context grounding) tests — the two channels must stay separate.

What is guarded here:

  1. CHANNEL 1 IS UNCHANGED — writeups/CTF indexes and methodology/meta docs are
     still step-INELIGIBLE, and being READ on Channel 2 never makes a document
     step-eligible. A model that cites one gets no step.
  2. THE LEAKAGE GUARD — a writeup carrying a 10.x host, a credential, a path and
     a flag cannot put any of them into a generated step: hosts are re-pointed at
     the real target, secrets are dropped. A grounded step's KB commands and a
     writeup step's own commands are never touched.
  3. THE EXECUTOR IS STILL THE BACKSTOP — an off-target host is refused at the
     gate whether or not the guard caught it.
  4. NO-OP WHEN NOTHING MATCHES — no writeup, no methodology → the composer and
     augmentation prompts are byte-for-byte the pre-Channel-2 prompts and the
     phases are returned unchanged.
  5. THE BUDGET IS BOUNDED — no document, and no number of them, can push the
     injected block past a known ceiling.

Self-contained (synthetic entries, stdlib only). Run:  python test_context_channel.py
"""

from __future__ import annotations

import attack_path as AP
import context_channel as CC


def _entry(**kw) -> dict:
    e = {"id": "x", "title": "", "category": "web", "source": "s",
         "steps": [], "body_md": "", "meta": {}}
    e.update(kw)
    return e


# a writeup that leaks everything a box writeup leaks
_LEAKY_WRITEUP = _entry(
    id="wu-forest",
    title="Forest",
    category="writeup",
    tier=1,
    body_md=(
        "# Recon\n"
        "Scanned the box and added dev.forest.htb to /etc/hosts for 10.10.10.161.\n\n"
        "# Enumeration\n"
        "rpcclient enumerated users; AS-REP roasting looked viable.\n\n"
        "# Exploitation\n"
        "Cracked the hash — password: s3rvice — and got a shell.\n\n"
        "# Privilege escalation\n"
        "Read the flag at /home/svc-alfresco/Desktop/user.txt -> HTB{f0rest_pwn3d}\n"
        "Tooling came from https://github.com/SecureAuthCorp/impacket\n"
    ),
)

_METHODOLOGY = _entry(
    id="meth-recon",
    title="Red Team Reconnaissance Methodology",
    category="methodology",
    body_md=(
        "# Flow\nRecon, then enumeration, then exploitation, then privesc.\n\n"
        "# Prioritisation\nProbe authentication and access control before "
        "injection classes on a web target.\n"
    ),
)


# --------------------------------------------------------------------------- #
# 1 — Channel 1 is UNCHANGED: context is never a step
# --------------------------------------------------------------------------- #
def test_channel1_filters_unchanged() -> None:
    # writeups/CTF stay out of the step pool
    assert AP.EXCLUDED_STEP_CATEGORIES == {"writeup", "ctf"}
    assert AP.is_step_eligible(_LEAKY_WRITEUP) is False, "a writeup must never be a step"
    assert AP.is_step_eligible(_entry(category="ctf")) is False

    # a meta/workflow doc stays step-ineligible …
    arsenal = _entry(
        title="AI TOOLS ARSENAL",
        steps=[{"n": 1, "code": [{"lang": "bash", "cmd": "YOUR PLAN:\n1. install"}]}],
    )
    assert AP.is_step_eligible(arsenal) is False

    # … and READING a document on Channel 2 does not change that. Channel 2's
    # selection predicate is independent of step-eligibility in both directions.
    assert CC.is_methodology_doc(_METHODOLOGY) is True
    assert CC.is_methodology_doc(arsenal) is False  # "arsenal" is a Channel-1 concern
    # the KB's "methodology" CATEGORY is a section name and mostly holds ordinary
    # technique pages — one must never be read as "the methodology to follow".
    assert CC.is_methodology_doc(
        _entry(id="ht-docker-forensics", title="Docker Forensics", category="methodology")
    ) is False, "a technique page in the methodology category is not a methodology"
    for doc in (_LEAKY_WRITEUP, arsenal):
        before = AP.is_step_eligible(doc)
        CC.writeup_context(doc, "goal")
        CC.is_methodology_doc(doc)
        assert AP.is_step_eligible(doc) is before, "Channel 2 must not alter eligibility"

    # a real technique is still eligible — Channel 2 didn't narrow the pool
    technique = _entry(
        title="Kerberoasting",
        steps=[{"n": 1, "code": [{"lang": "bash", "cmd": "GetUserSPNs.py dom/u:p"}]}],
    )
    assert AP.is_step_eligible(technique) is True

    # and a model that CITES the writeup gets no step out of it
    by_id = {e["id"]: e for e in (_LEAKY_WRITEUP, _METHODOLOGY, technique)}
    by_id["kerb"] = technique
    parsed = {"phases": [{"phase": "enumeration", "steps": [
        {"entry_id": "wu-forest", "why": "the box was done this way"},
        {"entry_id": "meth-recon", "why": "follow the methodology"},
        {"entry_id": "kerb", "why": "SPN accounts are roastable"},
    ]}]}
    phases = AP._ground(parsed, by_id, "10.0.0.5", None)
    cited = [s["entry_id"] for ph in phases for s in ph["steps"]]
    assert "wu-forest" not in cited, "a writeup became a step"
    assert "meth-recon" not in cited, "a methodology doc became a step"
    assert "kerb" in cited, "the real technique should still ground a step"
    print("  Channel-1 filters unchanged (writeup/methodology never a step): PASS")


# --------------------------------------------------------------------------- #
# 2 — the leakage guard
# --------------------------------------------------------------------------- #
def test_leakage_guard() -> None:
    goal = "pentest the host 192.168.56.10"
    src = CC.writeup_context(
        _LEAKY_WRITEUP, "recon enumeration exploitation privilege escalation shell hash"
    )
    assert src is not None
    hosts, secrets = CC.collect_literals([src], goal)
    assert "10.10.10.161" in hosts and "dev.forest.htb" in hosts
    assert "forest.htb" in hosts, "a lab domain's parent is the same box's identity"
    assert "s3rvice" in secrets and "HTB{f0rest_pwn3d}" in secrets
    assert "/home/svc-alfresco/Desktop/user.txt" in secrets
    assert not any("github.com" in h for h in hosts), "public infra is not a box identity"

    phases = [{"phase": "exploitation", "steps": [
        # the model echoing the writeup's box into its OWN gap step
        {"id": "exploitation-1", "title": "AS-REP roast", "entry_id": "",
         "ai_suggested": True, "from_writeup": False,
         "why": "dev.forest.htb exposes an AS-REP roastable account.",
         "commands": [
             {"lang": "bash", "cmd": "GetNPUsers.py -dc-ip 10.10.10.161 -request"},
             {"lang": "bash", "cmd": "evil-winrm -i 10.10.10.161 -u svc -p s3rvice"},
             {"lang": "bash", "cmd": "git clone https://github.com/SecureAuthCorp/impacket"},
         ]},
        # a GROUNDED step: its commands are the KB entry's, not model output
        {"id": "exploitation-2", "title": "Kerberoasting", "entry_id": "kerb",
         "ai_suggested": False, "from_writeup": False,
         "why": "SPN accounts", "commands": [
             {"lang": "bash", "cmd": "GetUserSPNs.py -dc-ip 10.10.10.161"}]},
        # a WRITEUP step: the user's own, for THIS box
        {"id": "exploitation-3", "title": "own step", "entry_id": "wu-forest",
         "ai_suggested": False, "from_writeup": True,
         "why": "", "commands": [{"lang": "bash", "cmd": "nc 10.10.10.161 4444"}]},
    ]}]
    out, leaks = CC.scrub_phases(phases, hosts, secrets, "192.168.56.10")
    ai, grounded, wu = out[0]["steps"]

    assert leaks >= 3
    # hosts re-pointed at the REAL target, in prose and in the model's commands
    assert "192.168.56.10" in ai["why"] and "forest.htb" not in ai["why"]
    cmds = [c["cmd"] for c in ai["commands"]]
    assert any("192.168.56.10" in c for c in cmds)
    assert not any("10.10.10.161" in c for c in cmds), "a box IP survived into a step"
    # a credential can't be re-pointed — that command is gone entirely
    assert not any("s3rvice" in c for c in cmds), "another box's credential survived"
    # a legitimate public-infra command is untouched
    assert any("github.com/SecureAuthCorp/impacket" in c for c in cmds)
    # Channel-1 surfaces are NOT rewritten (they are not model output)
    assert grounded["commands"][0]["cmd"] == "GetUserSPNs.py -dc-ip 10.10.10.161"
    assert wu["commands"][0]["cmd"] == "nc 10.10.10.161 4444"
    print("  leakage guard (host re-pointed / secret dropped / KB untouched): PASS")


def test_goal_identifiers_are_not_leaks() -> None:
    """A host the OPERATOR named is this engagement's own identifier, not a leak."""
    src = [{"kind": "writeup", "id": "w", "title": "t", "chars": 1,
            "excerpt": "target shop.acme.com at 10.10.10.161"}]
    hosts, _secrets = CC.collect_literals(src, "pentest shop.acme.com in scope")
    assert "shop.acme.com" not in hosts, "an in-scope host must not be scrubbed"
    assert "10.10.10.161" in hosts
    print("  goal/scope identifiers are not treated as leaks: PASS")


# --------------------------------------------------------------------------- #
# 3 — the executor remains the SAFETY backstop
# --------------------------------------------------------------------------- #
def test_executor_backstop_still_refuses_off_target() -> None:
    """The guard above is PLAN QUALITY. Safety is the executor: even if a leaked
    host reached a step, the target-lock refuses it at execution time."""
    from cockpit import executor as E

    ok, reason = E.check_target_lock(["-sV", "10.10.10.161"])
    assert not ok and "not the lab" in reason, "leaked off-target host must be refused"
    ok, _ = E.check_target_lock(["-sV", "dev.forest.htb"])
    assert not ok, "leaked off-target hostname must be refused"
    print("  executor target-lock still refuses an off-target host: PASS")


# --------------------------------------------------------------------------- #
# 4 — NO-OP when nothing matches
# --------------------------------------------------------------------------- #
def test_no_op_when_nothing_matches() -> None:
    grouped = {"recon": [{"entry_id": "a", "title": "T", "category": "recon",
                          "summary": "s", "commands": [{"lang": "bash", "cmd": "nmap x"}]}]}
    goal, tt = "find IDOR in the web app", "bugbounty"

    assert CC.build_context_block([]) == ""
    assert CC.provenance([]) == []

    base = AP.build_user_prompt(goal, tt, grouped)
    for block in (None, "", CC.build_context_block([])):
        assert AP.build_user_prompt(goal, tt, grouped, None, None, None, block) == base, (
            "an empty Channel-2 block must leave the composer prompt byte-identical"
        )

    a_base = AP.build_augment_prompt(goal, {}, {"recon": ["x"]}, grouped, {"recon"})
    for block in (None, "", CC.build_context_block([])):
        assert AP.build_augment_prompt(
            goal, {}, {"recon": ["x"]}, grouped, {"recon"}, block
        ) == a_base, "an empty block must leave the augment prompt byte-identical"

    # and the guard is a no-op with nothing injected
    phases = [{"phase": "recon", "steps": [
        {"id": "recon-1", "title": "t", "entry_id": "", "ai_suggested": True,
         "from_writeup": False, "why": "reach 10.10.10.161",
         "commands": [{"lang": "bash", "cmd": "nmap 10.10.10.161"}]}]}]
    hosts, secrets = CC.collect_literals([], "goal")
    out, leaks = CC.scrub_phases(phases, hosts, secrets, "1.2.3.4")
    assert leaks == 0 and out is phases
    assert out[0]["steps"][0]["commands"][0]["cmd"] == "nmap 10.10.10.161", (
        "nothing injected → nothing scrubbed"
    )
    print("  no writeup + no methodology: byte-identical prompts, no scrubbing: PASS")


# --------------------------------------------------------------------------- #
# 5 — the budget is bounded
# --------------------------------------------------------------------------- #
def test_budget_bounded() -> None:
    huge = _entry(
        id="big", title="Big writeup", category="writeup",
        body_md="\n\n".join(
            f"# Section {i}\nrecon enumeration exploitation privesc " + ("x " * 400)
            for i in range(200)
        ),
    )
    src = CC.writeup_context(huge, "recon enumeration exploitation privesc")
    assert src is not None and src["chars"] <= CC.WRITEUP_CHARS, "writeup excerpt uncapped"
    assert len(huge["body_md"]) > 50 * CC.WRITEUP_CHARS, "fixture should dwarf the cap"

    many = [dict(src, id=f"m{i}", kind="methodology") for i in range(20)]
    block = CC.build_context_block([src] + many)
    assert len(block) <= CC.MAX_BLOCK_CHARS, (
        f"injected block {len(block)} exceeds the ceiling {CC.MAX_BLOCK_CHARS}"
    )
    # relevance-gated, not padded: an excerpt with nothing matching stays small
    off = CC.writeup_context(huge, "completely unrelated knitting patterns")
    assert off is None or off["chars"] <= CC.WRITEUP_CHARS
    print("  excerpt + block budgets bounded (cap holds against a huge doc): PASS")


# --------------------------------------------------------------------------- #
# 6 — composition still produces grounded + ai_suggested steps
# --------------------------------------------------------------------------- #
def test_composer_still_yields_grounded_and_ai() -> None:
    kerb = _entry(id="kerb", title="Kerberoasting", category="active-directory",
                  steps=[{"n": 1, "code": [{"lang": "bash", "cmd": "GetUserSPNs.py dom/u:p"}]}])
    by_id = {"kerb": kerb}
    parsed = {"phases": [{"phase": "enumeration", "steps": [
        {"entry_id": "kerb", "why": "roastable SPNs"},
        {"ai_suggested": True, "title": "Check SMB signing", "why": "gap",
         "commands": [{"lang": "bash", "cmd": "nmap --script smb2-security-mode TARGET"}]},
    ]}]}
    phases = AP._ground(parsed, by_id, "10.0.0.5", None)
    steps = phases[0]["steps"]
    assert steps[0]["ai_suggested"] is False and steps[0]["entry_id"] == "kerb"
    assert steps[1]["ai_suggested"] is True and steps[1]["entry_id"] == ""
    # grounded step uses the KB's real commands, not the model's
    assert steps[0]["commands"][0]["cmd"] == "GetUserSPNs.py dom/u:p"
    print("  composer still yields grounded + ai_suggested steps: PASS")


if __name__ == "__main__":
    test_channel1_filters_unchanged()
    test_leakage_guard()
    test_goal_identifiers_are_not_leaks()
    test_executor_backstop_still_refuses_off_target()
    test_no_op_when_nothing_matches()
    test_budget_bounded()
    test_composer_still_yields_grounded_and_ai()
    print("ALL Channel-2 context-grounding tests pass")
