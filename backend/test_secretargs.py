"""Credential values must not survive into a PERSISTED run record.

Build #9's live fire ran a real BloodHound collection against a real domain and then read the
run back: the domain administrator's cleartext password was sitting in the stored record's
args. The hermetic suite could not have caught it — every WinRM test monkeypatches the
transport and the AD graph runs on sample_data, so no test had ever put a real credential on a
real command line. This file is the regression lock so it cannot come back.

The paired risk is the OPPOSITE mistake: redacting too much. `-p` is a password to netexec and
a PORT LIST to nmap, so a blanket flag rule would rewrite `nmap -p 445` into
`nmap -p <redacted>` and destroy the audit trail this is meant to protect. The negative
controls below are as load-bearing as the positive ones.

Hermetic: no network, no docker, no VM.
"""

from cockpit import secretargs
from cockpit.secretargs import REDACTED, redact_argv

PASSWORD = "Sup3rS3cret!DAPass"


def test_collector_password_is_redacted() -> None:
    """The exact shape build #9 leaked: bloodhound-python's `-p <password>`."""
    argv = ["-u", "Administrator", "-d", "corp.local", "-dc", "dc01.corp.local",
            "-c", "All", "-p", PASSWORD, "-ns", "192.168.13.140", "--zip"]
    out = redact_argv("bloodhound-python", argv)
    assert PASSWORD not in out, "the collector password MUST NOT survive into the record"
    assert out[out.index("-p") + 1] == REDACTED
    # Everything that is NOT the secret must be preserved byte-for-byte — a record that loses
    # the DC, the domain or the collection method is not an audit trail.
    assert out[:9] == ["-u", "Administrator", "-d", "corp.local", "-dc", "dc01.corp.local",
                       "-c", "All", "-p"]
    assert out[-3:] == ["-ns", "192.168.13.140", "--zip"]
    print("  bloodhound-python -p <password> is redacted, everything else preserved: PASS")


def test_hashes_and_equals_forms() -> None:
    """Pass-the-hash and `--password=value` are the same leak in a different shape."""
    nt = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    out = redact_argv("bloodhound-python", ["--hashes", nt, "-d", "corp.local"])
    assert nt not in out and out[1] == REDACTED

    out = redact_argv("netexec", ["smb", "10.0.0.1", "-u", "bob", f"--password={PASSWORD}"])
    assert PASSWORD not in " ".join(out), out
    assert "--password=" + REDACTED in out
    # the target and the user survive
    assert "10.0.0.1" in out and "bob" in out
    print("  --hashes and --password=<value> forms are redacted: PASS")


def test_impacket_positional_credential() -> None:
    """impacket's `DOMAIN/user:password@host` — only the password span is masked, so the record
    still records WHO ran against WHAT."""
    tok = f"CORP/Administrator:{PASSWORD}@192.168.13.140"
    out = redact_argv("impacket-secretsdump", [tok, "-just-dc"])
    assert PASSWORD not in out[0], out
    assert out[0] == f"CORP/Administrator:{REDACTED}@192.168.13.140"
    assert out[1] == "-just-dc"
    # The Kali `secretsdump.py` spelling resolves to the same family.
    assert redact_argv("secretsdump.py", [tok])[0] == out[0]
    print("  impacket DOMAIN/user:password@host masks only the secret span: PASS")


def test_a_password_containing_an_at_sign_is_fully_masked() -> None:
    """PASSWORDS CONTAIN `@`. The first cut of this redactor split on the FIRST `@`, so the
    rest of the password rode along in the "host" tail and was written to the record in the
    clear. Build #9's live DCSync run against the real DC stored
    `Administrator:<redacted>@2005@WIN-990RALNGERV.corp.local` — leaking `2005` out of an
    8-character password, while a naive `secret not in record` check still passed because the
    WHOLE string was absent. A hostname cannot contain `@`, so the LAST one is the separator.
    """
    for password in ("Pa55@2005", "@@Zx9leading", "Qw7trailing@", "Kd3@Mv8@Rt2", "no-at-here"):
        tok = f"CORP.LOCAL/Administrator:{password}@WIN-990RALNGERV.corp.local"
        out = redact_argv("impacket-secretsdump", [tok, "-just-dc"])[0]
        # Exact equality IS the proof: one `<redacted>` span, host intact, nothing else left.
        assert out == f"CORP.LOCAL/Administrator:{REDACTED}@WIN-990RALNGERV.corp.local", out
        # And no distinctive FRAGMENT survives — the failure mode was a partial leak that a
        # whole-string `secret not in record` check happily reported as clean. Fragments of
        # 3+ chars only; single characters collide with the scaffold text by chance.
        for chunk in password.split("@"):
            if len(chunk) >= 3:
                assert chunk not in out, f"fragment {chunk!r} of {password!r} leaked into {out!r}"
    print("  a password containing '@' is masked whole, fragments and all: PASS")


def test_nmap_ports_are_NOT_redacted() -> None:
    """THE NEGATIVE CONTROL. `-p` means ports here. If this ever fails, the redaction has been
    made global and every scan record in the store has been corrupted."""
    argv = ["-sV", "-p", "445,3389", "-oA", "scan", "192.168.13.140"]
    assert redact_argv("nmap", argv) == argv, "nmap -p is a PORT LIST and must be preserved"
    assert secretargs.secret_flags_for("nmap") == frozenset(), "nmap takes no credential flag"
    # Same for the other `-p`-using tools that do not take credentials.
    for tool in ("ffuf", "masscan", "rustscan", "hydra"):
        assert redact_argv(tool, ["-p", "8080"]) == ["-p", "8080"], tool
    print("  nmap/ffuf/masscan -p is NOT touched (negative control): PASS")


def test_unknown_tools_pass_through_verbatim() -> None:
    """An unrecognised tool's argv is stored exactly as before — empty is the safe default."""
    argv = ["--weird", "value", "user:notapassword@host", "-p", "x"]
    assert redact_argv("some-unknown-binary", argv) == argv
    print("  an unknown tool's argv is stored verbatim: PASS")


def test_url_and_bare_user_at_host_are_not_mangled() -> None:
    """The positional regex must not chew ordinary arguments."""
    for tok in ("http://example.com/a", "https://u.example.com:8443/x",
                "administrator@corp.local", "/loot/out.txt"):
        assert redact_argv("impacket-wmiexec", [tok]) == [tok], tok
    print("  URLs and bare user@host are left alone: PASS")


def test_executor_persists_redacted_args() -> None:
    """The wiring, not just the helper: the RunRecord the executor builds must be redacted."""
    import inspect

    from cockpit import executor

    src = inspect.getsource(executor)
    # Both RunRecord constructions (docker path + windows path) must go through the redactor.
    assert src.count("args=secretargs.redact_argv(request.command, request.args)") == 2, (
        "BOTH RunRecord constructions must redact — a record path that skips it is the leak"
    )
    assert "args=request.args," not in src, (
        "a RunRecord is still being built from the raw argv somewhere"
    )
    print("  both executor RunRecord paths persist redacted args: PASS")


if __name__ == "__main__":
    test_collector_password_is_redacted()
    test_hashes_and_equals_forms()
    test_impacket_positional_credential()
    test_a_password_containing_an_at_sign_is_fully_masked()
    test_nmap_ports_are_NOT_redacted()
    test_unknown_tools_pass_through_verbatim()
    test_url_and_bare_user_at_host_are_not_mangled()
    test_executor_persists_redacted_args()
    print("ALL credential-redaction invariants hold")
