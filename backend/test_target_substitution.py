"""Target-substitution polish: the CIDR rewrite, the foreign-host flag, and the backstop.

A grounded step carries its KB entry's commands VERBATIM, and those commands were written
against somebody else's environment. Two things follow, and they are different problems:

  1. SUBSTITUTABLE — an example RANGE (10.0.0.0/24) has an obvious correct replacement:
     the engagement's scope range, or failing that the target host. Rewrite it.
  2. NOT SUBSTITUTABLE — a foreign AD domain (MARVEL.local) has nothing to be rewritten
     TO; we may not know the target's domain at all. Do not guess one, and do not leave
     it silently either. FLAG it.

Both are PLAN QUALITY. The last test here asserts the thing that actually keeps a foreign
host from being contacted — the executor's target lock — is untouched and still refuses
one, so the polish is an honesty improvement sitting on top of a backstop, not a
replacement for it.

Self-contained (stdlib only). Run:  python test_target_substitution.py
"""
from __future__ import annotations

import attack_path as AP


# --------------------------------------------------------------------------- #
# SP1 — an example range becomes the engagement's range
# --------------------------------------------------------------------------- #
def test_example_range_is_rewritten_to_the_scope_range() -> None:
    """Scoped to a range: that range is what the example range becomes."""
    out = AP.substitute_target("nmap -sn 10.0.0.0/24", "10.10.14.9", "192.168.50.0/24")
    assert out == "nmap -sn 192.168.50.0/24", out

    # …and it must SURVIVE the example-IP rule that runs after it. The scope range is
    # itself a private range, so an unguarded implementation rewrites it right back and
    # yields "10.10.14.9/24" — a range that was never in scope.
    assert "10.10.14.9/24" not in out
    assert "\x00" not in out, "the internal sentinel leaked into a rendered command"

    # every recognised example prefix, and a non-/24 width
    assert AP.substitute_target("nxc smb 192.168.1.0/24", "dc01.corp.io", "10.5.0.0/16") == \
        "nxc smb 10.5.0.0/16"
    assert AP.substitute_target("nmap 172.16.5.0/16", "10.10.14.9", "10.9.0.0/8") == \
        "nmap 10.9.0.0/8"
    print("  an example range is rewritten to the engagement's scope range: PASS")


def test_without_a_scope_range_the_example_range_becomes_the_target() -> None:
    """No range in scope: the target host is the only other thing we actually know."""
    assert AP.substitute_target("nmap -sn 10.0.0.0/24", "10.10.14.9") == "nmap -sn 10.10.14.9"
    assert AP.substitute_target("nmap -sn 172.16.5.0/16", "scanme.sh") == "nmap -sn scanme.sh"
    # a foreign range must never survive untouched just because scope is empty
    assert "10.0.0.0/24" not in AP.substitute_target("nmap 10.0.0.0/24", "10.10.14.9")
    print("  with no scope range it becomes the target host, never the foreign range: PASS")


def test_scope_cidr_reads_a_range_out_of_pasted_scope_text() -> None:
    assert AP.scope_cidr("In scope: 192.168.50.0/24 plus app.example.org") == "192.168.50.0/24"
    assert AP.scope_cidr("hosts only, no range here") is None
    assert AP.scope_cidr(None) is None
    # a malformed range is skipped rather than trusted
    assert AP.scope_cidr("bad 999.1.1.1/24 then good 10.2.0.0/16") == "10.2.0.0/16"
    assert AP.scope_cidr("bad prefix 10.0.0.0/33") is None
    print("  scope_cidr reads the first VALID range, skipping malformed ones: PASS")


# --------------------------------------------------------------------------- #
# SP1 — and nothing legitimate is mangled
# --------------------------------------------------------------------------- #
# Literals that LOOK addressy but are not somebody else's network. Every one of these
# must come back byte-for-byte identical, with a scope range set (the aggressive case).
_MUST_NOT_TOUCH = [
    "ip addr add 127.0.0.0/8 dev lo",            # loopback network
    "python3 -m http.server --bind 127.0.0.1",   # loopback host
    "ping -c 1 127.0.0.1",
    "nc -lvnp 4444 -s 0.0.0.0",                  # bind-all
    "ip route add default via 0.0.0.0/0",        # default route
    "ifconfig eth0 netmask 255.255.255.0",       # a netmask, not a range
    "openssl version 1.1.1",                     # version literal
    "curl -s http://169.254.169.254/latest/meta-data/",   # link-local metadata
    "chmod 755 /tmp/loot",                       # mode bits
    "tar -xzf backup.tar.gz",
    "cp .env.example .env",                      # filename, not a host
    "<script>alert('XSS')</script>",             # payload, not a host
    "hashcat -m 13100 -a 0 hashes.txt rockyou.txt",
]


def test_legitimate_literals_are_never_mangled() -> None:
    for cmd in _MUST_NOT_TOUCH:
        for scope in (None, "192.168.50.0/24"):
            got = AP.substitute_target(cmd, "10.10.14.9", scope)
            assert got == cmd, f"mangled (scope={scope}): {cmd!r} -> {got!r}"
    print(f"  all {len(_MUST_NOT_TOUCH)} legitimate literals survive untouched: PASS")


def test_existing_substitution_behaviour_is_unchanged() -> None:
    """The endpoint-faithful behaviour SP1 sits on top of, re-asserted verbatim."""
    host = "scanme.sh"
    assert AP.substitute_target("curl https://example.com/api", host) == \
        "curl https://scanme.sh/api"
    assert AP.substitute_target("-H 'Host: example.com'", host) == "-H 'Host: scanme.sh'"
    assert AP.substitute_target("nmap example.com", host) == "nmap scanme.sh"
    assert AP.substitute_target("ssh user@target.htb", host) == "ssh user@scanme.sh"
    assert AP.substitute_target("nmap 10.10.11.5", "10.10.14.9") == "nmap 10.10.14.9"
    # an unrelated real host is not a target and is left alone
    assert "github.com" in AP.substitute_target("wget https://github.com/a/b", host)
    # adding the new parameter changes nothing for a caller that does not pass it
    for cmd in ("curl https://example.com/api", "nmap 10.10.11.5", "nmap example.com"):
        assert AP.substitute_target(cmd, host) == AP.substitute_target(cmd, host, None)
    print("  pre-existing endpoint-faithful substitution is byte-for-byte unchanged: PASS")


# --------------------------------------------------------------------------- #
# SP2 — what cannot be substituted is FLAGGED, never guessed
# --------------------------------------------------------------------------- #
def test_a_foreign_ad_domain_is_flagged_and_not_substituted() -> None:
    cmd = "GetUserSPNs.py MARVEL.local/hawkeye:pass -dc-ip 192.168.1.10 -request"
    target = "dc01.corp.io"

    out = AP.substitute_target(cmd, target)
    # NOT wrongly substituted — we do not know this engagement's domain, so nothing is
    # invented in its place. The literal is still there…
    assert "MARVEL.local" in out, "a foreign AD domain must not be silently rewritten"

    # …and NOT silently left: it is reported.
    refs = AP.foreign_refs(out, target)
    assert "MARVEL.local" in refs, refs
    assert "192.168.1.10" in refs, f"the foreign DC address must be flagged too: {refs}"
    print("  a foreign AD domain is flagged, not guessed at and not left silent: PASS")


def test_the_flag_does_not_fire_on_the_engagements_own_target() -> None:
    """The target is not foreign, and neither is an address inside the scope range."""
    assert AP.foreign_refs("nmap -sCV dc01.corp.io", "dc01.corp.io") == []
    assert AP.foreign_refs("nmap 10.10.14.9", "10.10.14.9") == []
    assert AP.foreign_refs("curl http://dc01.corp.io:8080/x", "dc01.corp.io") == []
    # inside the engagement's own range -> not foreign
    assert AP.foreign_refs("nxc smb 10.5.0.7", "10.5.0.7", "10.5.0.0/16") == []
    # outside it -> foreign
    assert AP.foreign_refs("nxc smb 192.168.99.4", "10.5.0.7", "10.5.0.0/16") == ["192.168.99.4"]
    # legitimate literals are not "foreign hosts"
    for cmd in ("ping 127.0.0.1", "nc -lvnp 4444 -s 0.0.0.0", "ifconfig eth0 netmask 255.255.255.0",
                "cp .env.example .env", "openssl version 1.1.1"):
        assert AP.foreign_refs(cmd, "dc01.corp.io") == [], cmd
    print("  the flag never fires on the target, the scope range or a legit literal: PASS")


def test_flagging_annotates_steps_without_changing_them() -> None:
    phases = [{
        "phase": "enumeration",
        "steps": [
            {"title": "roast", "commands": [{"cmd": "GetUserSPNs.py MARVEL.local/u:p -request"}],
             "ai_suggested": False, "from_writeup": False, "entry_id": "e1"},
            {"title": "scan", "commands": [{"cmd": "nmap -sCV dc01.corp.io"}],
             "ai_suggested": False, "from_writeup": False, "entry_id": "e2"},
            {"title": "mine", "commands": [{"cmd": "nmap devhub.htb"}],
             "ai_suggested": False, "from_writeup": True, "entry_id": "e3"},
        ],
    }]
    before = [dict(s) for s in phases[0]["steps"]]
    AP.flag_foreign_refs(phases, "dc01.corp.io", None)
    steps = phases[0]["steps"]

    assert steps[0]["foreign_refs"] == ["MARVEL.local"]
    assert "foreign_refs" not in steps[1], "a clean step must not be flagged"
    # the user's OWN writeup for THIS box is skipped — its hostname is the target under
    # another name, exactly as the Channel-2 leakage guard treats it
    assert "foreign_refs" not in steps[2], "a writeup step must not be flagged"

    # ADDITIVE ONLY: commands, grounding labels and citations are untouched
    for old, new in zip(before, steps):
        assert new["commands"] == old["commands"]
        assert new["ai_suggested"] == old["ai_suggested"]
        assert new["entry_id"] == old["entry_id"]
        assert new["title"] == old["title"]
    print("  flagging is additive — commands, labels and citations untouched: PASS")


# --------------------------------------------------------------------------- #
# THE BACKSTOP — the polish did not become the safety mechanism
# --------------------------------------------------------------------------- #
def test_the_executor_target_lock_still_refuses_a_foreign_host() -> None:
    """The plan is now honest about a foreign host. What STOPS one is unchanged.

    Asserted directly rather than taken on trust: whatever the displayed plan says, a
    command pointed at a host that is not the lab target is refused at the target gate.
    """
    from cockpit import executor as E
    from cockpit.models import ExecRequest

    for args in (["-sCV", "MARVEL.local"], ["-sn", "10.0.0.0/24"], ["-sCV", "192.168.1.10"]):
        r = E.validate_request(ExecRequest(command="nmap", args=args, approved=True))
        assert r is not None and r.gate == "target", (
            f"a foreign host must still be refused at the target gate: {args} -> "
            f"{getattr(r, 'gate', None)}"
        )

    # and the lock's own wording is unchanged
    ok, reason = E.check_target_lock(["-sV", "scanme.nmap.org"])
    assert not ok and "not the lab" in reason
    print("  the executor target-lock still refuses every foreign host: PASS")


if __name__ == "__main__":
    test_example_range_is_rewritten_to_the_scope_range()
    test_without_a_scope_range_the_example_range_becomes_the_target()
    test_scope_cidr_reads_a_range_out_of_pasted_scope_text()
    test_legitimate_literals_are_never_mangled()
    test_existing_substitution_behaviour_is_unchanged()
    test_a_foreign_ad_domain_is_flagged_and_not_substituted()
    test_the_flag_does_not_fire_on_the_engagements_own_target()
    test_flagging_annotates_steps_without_changing_them()
    test_the_executor_target_lock_still_refuses_a_foreign_host()
    print("ALL target-substitution polish tests pass")
