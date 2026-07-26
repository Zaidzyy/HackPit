"""Phase 3 step 14 — the credential vault fills placeholders from captured credentials.

The AD templates carry <user>/<password>/<ntlm-hash>/<domain> placeholders the operator used
to retype every time. This maps a stored credential onto them. The mapping lives ONLY here
(state/credvault.py) so front and back cannot drift.

Pins the rules that matter:
  * a password credential fills <password>, an ntlm credential fills <hash> — never the wrong one
  * a credential fills only the fields it HAS; an unmatched placeholder stays visible, never blanked
  * case-insensitive on the placeholder name (<PASSWORD> and <password> both fill)
  * it touches only credential placeholders — <target> and operational ones are left alone
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from state import credvault  # noqa: E402
from state.models import Credential  # noqa: E402


def _pw() -> Credential:
    return Credential(session_id="s", kind="password", principal="svc_sql",
                      domain="corp.local", secret="S3cr3t!")


def _nt() -> Credential:
    return Credential(session_id="s", kind="ntlm", principal="Administrator",
                      domain="corp.local", secret="64f12cddaa88057e06a81b54e73b949b")


def test_password_fills_password_not_hash() -> None:
    cmd = "evil-winrm -i 10.0.0.5 -u <user> -p <password>"
    filled, used = credvault.fill(cmd, _pw())
    assert filled == "evil-winrm -i 10.0.0.5 -u svc_sql -p S3cr3t!", filled
    assert set(used) == {"<user>", "<password>"}
    # A password credential must NOT fill a hash placeholder.
    hashcmd, used2 = credvault.fill("tool -H <ntlm-hash>", _pw())
    assert hashcmd == "tool -H <ntlm-hash>" and used2 == [], "password must not fill a hash"
    print("  a password fills <user>/<password>, never <hash>: PASS")


def test_ntlm_fills_hash_not_password() -> None:
    cmd = "impacket-secretsdump <domain>/<user>@<dc-ip> -hashes :<ntlm-hash>"
    filled, used = credvault.fill(cmd, _nt())
    assert "64f12cddaa88057e06a81b54e73b949b" in filled
    assert "corp.local/Administrator@<dc-ip>" in filled, "<dc-ip> is a host, must stay unfilled"
    assert "<ntlm-hash>" not in filled and set(used) == {"<domain>", "<user>", "<ntlm-hash>"}
    # An ntlm credential must NOT fill a cleartext password placeholder.
    pwcmd, used2 = credvault.fill("tool -p <password>", _nt())
    assert pwcmd == "tool -p <password>" and used2 == [], "a hash must not fill <password>"
    print("  an ntlm credential fills <hash>, never <password>; <dc-ip> untouched: PASS")


def test_case_insensitive_and_unmatched_stays_visible() -> None:
    filled, used = credvault.fill("x -u <USER> -p <Password> -d <DOMAIN> -k <apikey>", _pw())
    assert "svc_sql" in filled and "S3cr3t!" in filled and "corp.local" in filled
    assert "<apikey>" in filled, "a placeholder the credential can't fill must stay visible"
    assert set(used) == {"<USER>", "<Password>", "<DOMAIN>"}
    print("  case-insensitive fill; an unmatched placeholder is never blanked: PASS")


def test_only_credential_placeholders_are_touched() -> None:
    """<target>, <lport>, <listener> etc. are NOT the vault's job — it must leave them alone."""
    cmd = "nc <target> <lport>; scan <url>"
    filled, used = credvault.fill(cmd, _pw())
    assert filled == cmd and used == [], "the vault must not touch non-credential placeholders"
    ph = credvault.credential_placeholders("x <user> <target> <password> <lport>")
    assert set(ph) == {"<user>", "<password>"}, f"only cred placeholders, got {ph}"
    print("  only credential placeholders are filled; target/operational ones untouched: PASS")


def test_best_matches_ranks_by_coverage() -> None:
    cmd = "impacket-secretsdump <domain>/<user>@<dc-ip> -hashes :<ntlm-hash>"
    ranked = credvault.best_matches(cmd, [_pw(), _nt()])
    assert [c.principal for c in ranked] == ["Administrator", "svc_sql"], (
        "the ntlm cred fills more placeholders (incl. <ntlm-hash>) so it must rank first"
    )
    # A command needing no credential yields no matches.
    assert credvault.best_matches("nmap -sV <target>", [_pw(), _nt()]) == []
    print("  best_matches ranks by how many placeholders each credential fills: PASS")


def test_no_value_is_never_substituted_as_empty() -> None:
    """A credential with no domain must not blank a <domain> placeholder to empty string."""
    c = Credential(session_id="s", kind="password", principal="bob", domain="", secret="pw")
    filled, used = credvault.fill("x -u <user> -d <domain>", c)
    assert filled == "x -u bob -d <domain>", "an empty field must leave its placeholder visible"
    assert used == ["<user>"]
    print("  an empty credential field leaves its placeholder visible, not blank: PASS")


if __name__ == "__main__":
    test_password_fills_password_not_hash()
    test_ntlm_fills_hash_not_password()
    test_case_insensitive_and_unmatched_stays_visible()
    test_only_credential_placeholders_are_touched()
    test_best_matches_ranks_by_coverage()
    test_no_value_is_never_substituted_as_empty()
    print("ALL credential-vault tests pass")
