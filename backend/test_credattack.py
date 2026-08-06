"""Credential-attack planner + correlator tests.  Run:  python test_credattack.py

The behaviour half of the credential surface: hashes map to the right hashcat mode, argv is
built from state with NO secret on the command line, netexec `[+]` hits and hashcat
`hash:plain` lines turn back into typed state, and a crack recovers the ACCOUNT (from the
submitted hashes) not just the plaintext. The safety half — that this module executes nothing
and the routes are gated — is in test_credattack_safety.py.
"""

from __future__ import annotations

from cockpit import credattack
from state import parsers
from state.models import Credential


# --------------------------------------------------------------------------- #
# hash-mode detection
# --------------------------------------------------------------------------- #
def test_hash_mode_detection_covers_the_common_shapes() -> None:
    cases = {
        "e19ccf75ee54e06b06a5907af13cef42": (1000, "ntlm"),          # NTLM / 32-hex
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d": (100, ""),        # SHA1
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": (1400, ""),  # SHA256
        "$2b$12$abcdefghijklmnopqrstuv": (3200, ""),                  # bcrypt
        "$6$salt$hashhashhash": (1800, ""),                           # sha512crypt
        "$1$salt$hash": (500, ""),                                    # md5crypt
    }
    for secret, (mode, kind) in cases.items():
        got = credattack.detect_hash_mode(secret, kind)
        assert got.mode == mode, f"{secret[:12]}… -> {got.mode}, expected {mode}"
    print("  common hash shapes map to the right hashcat -m: PASS")


def test_kerberos_tickets_are_detected_by_their_tag() -> None:
    assert credattack.detect_hash_mode("$krb5tgs$23$*svc$REALM$...*", "ticket").mode == 13100
    assert credattack.detect_hash_mode("$krb5asrep$23$user@REALM:...", "ticket").mode == 18200
    print("  kerberoast (13100) + AS-REP roast (18200) detected from the ticket tag: PASS")


def test_netntlmv2_is_5600_not_a_bare_ntlm() -> None:
    v2 = "admin::CORP:1122334455667788:" + "a" * 32 + ":" + "b" * 40
    assert credattack.detect_hash_mode(v2).mode == 5600
    print("  a NetNTLMv2 capture resolves to 5600, not misread as NTLM: PASS")


def test_an_unrecognised_shape_returns_no_mode_with_a_reason() -> None:
    """A wrong mode silently cracks nothing and reads as 'the password held' — so a miss must
    be a miss, never a guess."""
    got = credattack.detect_hash_mode("not-a-hash", "hash")
    assert got.mode is None and got.reason
    print("  an unrecognised hash returns mode=None with a reason, never a wrong guess: PASS")


def test_crackable_gates_on_kind_and_a_detectable_mode() -> None:
    assert credattack.crackable(Credential(session_id="s", kind="ntlm", principal="a",
                                           secret="e19ccf75ee54e06b06a5907af13cef42"))
    assert not credattack.crackable(Credential(session_id="s", kind="password", principal="a",
                                               secret="hunter2"))          # already plaintext
    assert not credattack.crackable(Credential(session_id="s", kind="hash", principal="a",
                                               secret=""))                 # nothing to crack
    assert not credattack.crackable(Credential(session_id="s", kind="hash", principal="a",
                                               secret="zzz"))              # no detectable mode
    print("  crackable() needs a hash/ticket kind AND a detectable mode AND no plaintext: PASS")


# --------------------------------------------------------------------------- #
# argv building — secrets never on the command line
# --------------------------------------------------------------------------- #
def test_spray_argv_is_netexec_with_files_and_no_secret_on_the_line() -> None:
    req = credattack.SprayRequest(service="smb", target="10.10.10.5",
                                  usernames=["a", "b"], passwords=["S3cret!"], domain="CORP")
    argv, warn = credattack.spray_argv(req, users_path="/loot/s/u.txt", pass_path="/loot/s/p.txt")
    assert argv[:2] == ["netexec", "smb"], argv
    assert "10.10.10.5" in argv and "/loot/s/u.txt" in argv and "/loot/s/p.txt" in argv
    assert argv[argv.index("-d") + 1] == "CORP"
    assert "S3cret!" not in argv, "a password must NEVER be on the argv"
    print("  spray argv references user/pass FILES, target is present, secret is not: PASS")


def test_spray_unknown_service_warns_and_builds_nothing() -> None:
    req = credattack.SprayRequest(service="telnet", target="h", usernames=["a"], passwords=["b"])
    argv, warn = credattack.spray_argv(req, users_path="u", pass_path="p")
    assert argv == [] and any("unknown spray service" in w for w in warn)
    print("  an unknown spray service warns and builds no argv: PASS")


def test_kerberos_spray_fills_the_domain_via_credvault() -> None:
    """The <domain> placeholder is filled by state.credvault.fill — the ONE placeholder mapping,
    reused rather than re-implemented."""
    req = credattack.SprayRequest(service="kerberos", target="dc01", usernames=["a"],
                                  passwords=["b"], domain="corp.local")
    argv, _ = credattack.spray_argv(req, users_path="/loot/u.txt", pass_path="/loot/p.txt")
    assert argv[0] == "kerbrute" and "corp.local" in argv and "<domain>" not in argv
    print("  kerberos spray uses kerbrute and fills the realm, no stray placeholder: PASS")


def test_crack_argv_puts_the_hash_in_a_file_and_carries_the_mode() -> None:
    req = credattack.CrackRequest(wordlist="/usr/share/wordlists/rockyou.txt")
    argv = credattack.crack_argv(req, hash_path="/loot/s/m1000.txt", mode=1000)
    assert argv[0] == "hashcat"
    assert argv[argv.index("-m") + 1] == "1000"
    assert "/loot/s/m1000.txt" in argv and "/usr/share/wordlists/rockyou.txt" in argv
    assert "--potfile-disable" in argv, "a stale pot must not make a fresh crack look empty"
    print("  crack argv is hashcat -m <mode> <hashfile> <wordlist>, no hash inline: PASS")


# --------------------------------------------------------------------------- #
# planning from state
# --------------------------------------------------------------------------- #
def _state_creds() -> list[Credential]:
    return [
        Credential(session_id="s", kind="ntlm", principal="administrator",
                   secret="e19ccf75ee54e06b06a5907af13cef42", domain="CORP"),
        Credential(session_id="s", kind="ntlm", principal="jsmith",
                   secret="209c6174da490caeb422f3fa5a7ae634", domain="CORP"),
        Credential(session_id="s", kind="ticket", principal="svc_sql",
                   secret="$krb5tgs$23$*svc_sql$CORP$MSSQL*..."),
        Credential(session_id="s", kind="password", principal="guest", secret="already-known"),
    ]


def test_plan_crack_groups_hashes_by_mode() -> None:
    plan = credattack.plan_crack(credattack.CrackRequest(session_id="s"), _state_creds())
    by_mode = {g.mode: g for g in plan.crack}
    assert 1000 in by_mode and by_mode[1000].hashes == 2          # two NTLM
    assert 13100 in by_mode and by_mode[13100].hashes == 1        # one TGS ticket
    assert "guest" not in [p for g in plan.crack for p in g.principals]  # plaintext excluded
    print("  plan_crack groups NTLM together, tickets separately, skips plaintext: PASS")


def test_plan_crack_honours_a_principal_selection() -> None:
    plan = credattack.plan_crack(
        credattack.CrackRequest(session_id="s", principals=["jsmith"]), _state_creds()
    )
    picked = [p for g in plan.crack for p in g.principals]
    assert picked == ["jsmith"], picked
    print("  plan_crack cracks only the selected principals: PASS")


def test_plan_spray_warns_when_a_list_is_missing() -> None:
    plan = credattack.plan_spray(
        credattack.SprayRequest(service="smb", target="h", usernames=[], passwords=["x"])
    )
    assert any("no usernames" in w for w in plan.warnings)
    print("  plan_spray warns (does not refuse) when the user list is empty: PASS")


def test_state_helpers_extract_usernames_and_known_passwords() -> None:
    creds = _state_creds()
    assert credattack.state_usernames(creds) == ["administrator", "jsmith", "svc_sql", "guest"]
    assert credattack.state_passwords(creds) == ["already-known"]   # only plaintext kinds
    print("  state helpers seed the user list and the known-password list: PASS")


# --------------------------------------------------------------------------- #
# parsing + correlation
# --------------------------------------------------------------------------- #
NXC_OUTPUT = """\
SMB         10.10.10.5      445    DC01             [*] Windows 10 x64
SMB         10.10.10.5      445    DC01             [-] CORP.local\\bob:wrong STATUS_LOGON_FAILURE
SMB         10.10.10.5      445    DC01             [+] CORP.local\\Administrator:Passw0rd! (Pwn3d!)
SSH         10.10.10.6      22     10.10.10.6       [+] root:toor
SMB         10.10.10.5      445    DC01             [+] Enumerated shares
"""


def test_parse_netexec_takes_only_valid_login_lines() -> None:
    parsed = parsers.parse_netexec(NXC_OUTPUT, "s", "run1")
    principals = sorted(c.principal for c in parsed.credentials)
    assert principals == ["Administrator", "root"], principals   # not bob (failed), not "Enumerated"
    admin = next(c for c in parsed.credentials if c.principal == "Administrator")
    assert admin.domain == "CORP.local" and admin.secret == "Passw0rd!" and admin.validated is True
    assert "Pwn3d" in admin.note
    print("  parse_netexec keeps [+] logins (Pwn3d! noted), drops [-] and informational: PASS")


def test_correlate_spray_marks_validated_and_raises_a_high_finding() -> None:
    req = credattack.SprayRequest(service="smb", target="10.10.10.5", usernames=["Administrator"],
                                  passwords=["Passw0rd!"])
    creds, findings = credattack.correlate_spray(req, NXC_OUTPUT, "s", "run1")
    assert any(c.validated and "sprayed OK on 10.10.10.5" in c.note for c in creds)
    assert findings and findings[0].severity == "high" and findings[0].tool == "netexec"
    print("  a spray hit becomes a validated cred + a high 'valid credential' finding: PASS")


def test_parse_hashcat_pairs_maps_lines_to_the_submitted_hash() -> None:
    known = {"e19ccf75ee54e06b06a5907af13cef42", "$krb5tgs$23$*svc$R$x*:body:withcolons"}
    text = (
        "E19CCF75EE54E06B06A5907AF13CEF42:Winter2024!\n"         # uppercase (hashcat lowercases)
        "$krb5tgs$23$*svc$R$x*:body:withcolons:Summer2024!\n"    # colons inside the hash body
        "deadbeef:not-a-known-hash\n"
    )
    out = parsers.parse_hashcat_pairs(text, known)
    assert out["e19ccf75ee54e06b06a5907af13cef42"] == "Winter2024!"
    assert out["$krb5tgs$23$*svc$R$x*:body:withcolons"] == "Summer2024!"
    assert "deadbeef" not in out            # a line matching no submitted hash is ignored
    print("  hashcat lines map back to the submitted hash, case-folded, colon-safe: PASS")


def test_correlate_crack_recovers_the_account_and_keeps_the_hash() -> None:
    """The plaintext is a NEW password credential for the same principal — the NT hash stays for
    pass-the-hash, and the account is recovered from the submitted hash, not from the bare line."""
    before = _state_creds()
    text = "e19ccf75ee54e06b06a5907af13cef42:Winter2024!\n"
    creds, findings = credattack.correlate_crack(text, before, "s", "run1")
    assert len(creds) == 1
    got = creds[0]
    assert got.kind == "password" and got.principal == "administrator" and got.domain == "CORP"
    assert got.secret == "Winter2024!" and got.validated is True
    assert findings and findings[0].severity == "high" and "administrator" in findings[0].title
    print("  a crack recovers the account (from the hash) as a password cred + high finding: PASS")


def test_gate_equivalent_request_names_the_real_tool() -> None:
    spray = credattack.SprayRequest(service="smb", target="10.10.10.5", usernames=["a"],
                                    passwords=["b"], engagement_id="e1")
    er = credattack.spray_exec_request(spray, users_path="/loot/u", pass_path="/loot/p")
    assert er.command == "netexec" and "10.10.10.5" in er.args and er.engagement_id == "e1"
    crack = credattack.CrackRequest(engagement_id="e1")
    cr = credattack.crack_exec_request(crack, hash_path="/loot/h", mode=1000)
    assert cr.command == "hashcat" and "1000" in cr.args
    print("  the gate-equivalent ExecRequest names the real tool + carries the engagement: PASS")


if __name__ == "__main__":
    test_hash_mode_detection_covers_the_common_shapes()
    test_kerberos_tickets_are_detected_by_their_tag()
    test_netntlmv2_is_5600_not_a_bare_ntlm()
    test_an_unrecognised_shape_returns_no_mode_with_a_reason()
    test_crackable_gates_on_kind_and_a_detectable_mode()
    test_spray_argv_is_netexec_with_files_and_no_secret_on_the_line()
    test_spray_unknown_service_warns_and_builds_nothing()
    test_kerberos_spray_fills_the_domain_via_credvault()
    test_crack_argv_puts_the_hash_in_a_file_and_carries_the_mode()
    test_plan_crack_groups_hashes_by_mode()
    test_plan_crack_honours_a_principal_selection()
    test_plan_spray_warns_when_a_list_is_missing()
    test_state_helpers_extract_usernames_and_known_passwords()
    test_parse_netexec_takes_only_valid_login_lines()
    test_correlate_spray_marks_validated_and_raises_a_high_finding()
    test_parse_hashcat_pairs_maps_lines_to_the_submitted_hash()
    test_correlate_crack_recovers_the_account_and_keeps_the_hash()
    test_gate_equivalent_request_names_the_real_tool()
    print("\ncredattack: all tests passed.")
