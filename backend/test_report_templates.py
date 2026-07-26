"""Exam-mode report templates + proof.txt as per-host state (Phase 4 item 5).

Pins the properties that matter for exam reporting:

  * proof/local flags are captured ONLY when the command read a flag file (a stray 32-hex hash
    is never mistaken for a flag), attributed to the run's target host
  * a manual set path (paste) upserts the flag; ownership is derived, never assumed
  * the OSCP proof table is built from STATE, not written by the model — no hash retyped
  * CVSS 3.1 base scores are computed (arithmetic), matching the official calculator
  * the template selector shapes the sections; an unknown template is refused
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import report as R  # noqa: E402
from state import parsers, store  # noqa: E402
from state.models import Host  # noqa: E402


# --------------------------------------------------------------------------- #
# proof-flag capture
# --------------------------------------------------------------------------- #
_FLAG = "0123456789abcdef0123456789abcdef"


def test_flag_captured_only_when_command_read_a_flag_file() -> None:
    # proof.txt read -> proof flag on the target
    p = parsers.parse_proof_flags("cat proof.txt", _FLAG, "10.10.10.5", "s", "r")
    assert len(p.hosts) == 1 and p.hosts[0].proof_txt == _FLAG and p.hosts[0].local_txt == ""
    assert p.hosts[0].address == "10.10.10.5"

    # local.txt / user.txt -> local flag
    p2 = parsers.parse_proof_flags("type local.txt", _FLAG, "10.10.10.5", "s", "r")
    assert p2.hosts[0].local_txt == _FLAG and p2.hosts[0].proof_txt == ""

    # a 32-hex hash in unrelated output (no flag file in the command) is NOT a flag
    p3 = parsers.parse_proof_flags("secretsdump.py corp/u:p@dc", _FLAG, "10.10.10.5", "s", "r")
    assert p3.hosts == [], "a bare 32-hex hash must not be captured as a flag"

    # no target -> nothing to attribute
    p4 = parsers.parse_proof_flags("cat proof.txt", _FLAG, "", "s", "r")
    assert p4.hosts == []
    print("  flags captured only when the command read a flag file, attributed to the host: PASS")


def test_manual_set_and_ownership() -> None:
    store.init_db()
    sid = "test-proof-session"
    store.clear(sid)
    # foothold: local only
    h = store.set_proof(sid, "10.10.10.5", "local", _FLAG)
    assert h.local_txt == _FLAG and h.ownership() == "foothold"
    # owned: add proof
    h = store.set_proof(sid, "10.10.10.5", "proof", "f" * 32)
    assert h.proof_txt == "f" * 32 and h.ownership() == "owned"
    # the local flag was preserved (upsert, not overwrite-to-blank)
    assert h.local_txt == _FLAG, "setting proof must not blank the local flag"
    # bad kind refused
    try:
        store.set_proof(sid, "10.10.10.5", "bogus", "x")
        assert False, "bad kind must raise"
    except ValueError:
        pass
    store.clear(sid)
    print("  manual set upserts flags; ownership derived; local preserved when proof added: PASS")


# --------------------------------------------------------------------------- #
# OSCP proof table — built from state, not the model
# --------------------------------------------------------------------------- #
def test_proof_table_renders_from_state() -> None:
    session = {"state_hosts": [
        {"address": "10.10.10.5", "hostname": "dc01", "local_txt": "a" * 32,
         "proof_txt": "b" * 32, "ownership": "owned"},
        {"address": "10.10.10.6", "hostname": "", "local_txt": "c" * 32,
         "proof_txt": "", "ownership": "foothold"},
        {"address": "10.10.10.7", "local_txt": "", "proof_txt": "", "ownership": ""},  # no flags
    ]}
    table = R.build_proof_table(session)
    assert "1/2 host(s) fully owned" in table, table
    assert "10.10.10.5" in table and "dc01" in table
    assert "a" * 32 in table and "b" * 32 in table, "flags come straight from state"
    assert "OWNED" in table and "foothold" in table
    assert "10.10.10.7" not in table, "a host with no flags is not a proof row"
    # empty state -> a clear placeholder, not a broken table
    assert "No local.txt" in R.build_proof_table({"state_hosts": []})
    print("  the OSCP proof table renders per-host flags from state, no retyping: PASS")


def test_proof_marker_is_replaced_not_left() -> None:
    md = f"## High-Level Summary\n\nfoo\n\n{R._OSCP_PROOF_MARKER}\n\nbar"
    session = {"state_hosts": [{"address": "10.0.0.1", "local_txt": "x" * 32,
                                "proof_txt": "", "ownership": "foothold"}]}
    out = R._insert_proof_table(md, session)
    assert R._OSCP_PROOF_MARKER not in out, "the marker must be replaced"
    assert "x" * 32 in out
    print("  the proof-table marker is replaced with the authoritative table: PASS")


# --------------------------------------------------------------------------- #
# CVSS 3.1 — computed, matches the official calculator
# --------------------------------------------------------------------------- #
def test_cvss31_matches_reference_scores() -> None:
    cases = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
        ("AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.6, "Low"),
        ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
    ]
    for vector, score, sev in cases:
        r = R.cvss31_base(vector)
        assert r is not None, vector
        assert r["score"] == score, f"{vector}: got {r['score']}, want {score}"
        assert r["severity"] == sev, f"{vector}: got {r['severity']}, want {sev}"
    assert R.cvss31_base("garbage") is None
    assert R.cvss31_base("AV:N/AC:L") is None, "an incomplete vector must not score"
    print("  CVSS 3.1 base scores are computed and match the official calculator: PASS")


def test_cvss_block_is_computed_not_written() -> None:
    block = R.build_cvss_block({"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert "9.8" in block and "Critical" in block and "computed" in block.lower()
    assert R.build_cvss_block({}) == "", "no vector -> no block"
    print("  the CVSS block is computed from the vector, not asserted by the model: PASS")


# --------------------------------------------------------------------------- #
# template selection
# --------------------------------------------------------------------------- #
def test_templates_shape_sections_and_reject_unknown() -> None:
    assert set(R.TEMPLATES) == {"standard", "oscp", "cpts", "bugbounty"}
    # OSCP is per-host + carries the proof-table marker; CPTS has an exec summary + findings
    assert R._OSCP_PROOF_MARKER in R.TEMPLATES["oscp"]
    assert "Per-Target" in R.TEMPLATES["oscp"]
    assert "Executive Summary" in R.TEMPLATES["cpts"] and "Findings" in R.TEMPLATES["cpts"]
    assert "Steps to Reproduce" in R.TEMPLATES["bugbounty"] and "Impact" in R.TEMPLATES["bugbounty"]
    # every template still carries the shared grounding + evidence marker
    for name, sys_prompt in R.TEMPLATES.items():
        assert R._EVIDENCE_MARKER in sys_prompt, f"{name} lost the evidence marker"
        assert "NEVER invent" in sys_prompt, f"{name} lost the grounding rule"

    # compose_report refuses an unknown template (before hitting the model)
    try:
        R.compose_report({"goal": "x"}, template="nope")
        assert False, "unknown template must raise"
    except ValueError as e:
        assert "unknown report template" in str(e)
    print("  templates shape the sections, keep grounding, and reject an unknown name: PASS")


if __name__ == "__main__":
    test_flag_captured_only_when_command_read_a_flag_file()
    test_manual_set_and_ownership()
    test_proof_table_renders_from_state()
    test_proof_marker_is_replaced_not_left()
    test_cvss31_matches_reference_scores()
    test_cvss_block_is_computed_not_written()
    test_templates_shape_sections_and_reject_unknown()
    print("ALL report-template tests pass")
