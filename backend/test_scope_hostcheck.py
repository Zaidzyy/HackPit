"""Phase 3 step 12 — the target-lock host check no longer false-rejects file/version args.

`_looks_like_host` used to assume every dotted token was a host unless its last segment was
in a 30-item file-extension list. That rejected legitimate, human-approved arguments as
"out of scope": a wordlist name with dots (`directory-list-2.3-medium`), a version string,
`-oA scan.1.2`, `--user-agent Mozilla/5.0`. The fix recognises a host POSITIVELY — a dotted
token is a host only if its last label is a plausible alphabetic TLD and not a file
extension. This pins both directions so the check cannot silently regress either way.

This matters beyond convenience: the assessment flagged it as the prerequisite for any
auto-run tier, since the scope check becomes load-bearing the moment a command auto-runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit import executor as E  # noqa: E402
from cockpit.models import ExecRequest  # noqa: E402


def test_real_hosts_are_still_recognised() -> None:
    for tok in (
        "evil.com",
        "dc01.corp.local",
        "10.10.10.5",
        "http://scanme.nmap.org/",
        "app.corp.local:8080",
        "sub.example.co.uk",
        "https://target/api?id=1",
    ):
        assert E._looks_like_host(tok), f"{tok!r} is a host and must still be caught"
    print("  real hosts (domains, IPs, URLs, host:port) still recognised: PASS")


def test_files_and_versions_are_no_longer_hosts() -> None:
    """The exact false-positives the assessment listed, plus their neighbours."""
    for tok in (
        "directory-list-2.3-medium",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium",
        "scan.1.2",
        "Mozilla/5.0",
        "words.txt",
        "raft-large-words.txt",
        "config.yaml",
        "v1.2.3",
        "backup.2024",
        "directory-list-2.3",
        "GET",
    ):
        assert not E._looks_like_host(tok), f"{tok!r} is NOT a host and must not be rejected"
    print("  wordlists, versions, filenames and bare words are no longer 'hosts': PASS")


def test_a_wordlist_arg_no_longer_false_rejects_a_lab_command() -> None:
    """End to end through the lab target-lock: a real command with a dotted wordlist name
    used to be refused at the target gate. It must pass now (the lab target is still
    required and still present)."""
    ok, reason = E.check_target_lock(
        ["-w", "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium",
         "-u", "http://hackpit-lab-target:3000/FUZZ"]
    )
    assert ok, f"a dotted wordlist name must not fail the target-lock — got: {reason}"
    print("  ffuf with a dotted wordlist + a lab URL passes the lab target-lock: PASS")


def test_an_actually_off_target_host_is_still_refused() -> None:
    """The fix must not open the gate — a genuine foreign host is still rejected in lab mode."""
    ok, reason = E.check_target_lock(["-sV", "scanme.nmap.org"])
    assert not ok and "lab" in reason, f"a foreign host must still be refused, got: {reason!r}"

    # and via the request path
    r = E.validate_request(ExecRequest(command="nmap", args=["evil.com"], approved=True))
    assert r is not None and r.gate == "target", "a foreign host must still hit the target gate"
    print("  a genuine off-target host is still refused — the gate did not widen: PASS")


def test_a_version_string_arg_does_not_get_read_as_a_foreign_host() -> None:
    """`-oA scan.1.2` against the lab must pass — scan.1.2 must not read as a foreign host."""
    ok, reason = E.check_target_lock(
        ["-sV", "-oA", "scan.1.2", "hackpit-lab-target"]
    )
    assert ok, f"a version-style output name must not be a foreign host — got: {reason}"
    print("  -oA scan.1.2 against the lab passes (version name is not a foreign host): PASS")


if __name__ == "__main__":
    test_real_hosts_are_still_recognised()
    test_files_and_versions_are_no_longer_hosts()
    test_a_wordlist_arg_no_longer_false_rejects_a_lab_command()
    test_an_actually_off_target_host_is_still_refused()
    test_a_version_string_arg_does_not_get_read_as_a_foreign_host()
    print("ALL scope host-check tests pass")
