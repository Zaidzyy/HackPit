"""Authenticated scanning — the operator's attached session (session_store) reaches every scan
surface, and the token VALUE never lands in a persisted argv / job record.

Hermetic (no Docker): asserts the pure argv/spec builders + the shared masker directly.

  * session_store helpers: header_pairs, additional_session_headers (typed wins), mask_header_flag_values.
  * nuclei: -H when attached, MASKED in the record, none without.
  * discover: ffuf/feroxbuster -H, arjun --headers, all masked, none without.
  * jsrecon: the session rides in the STDIN job spec, NEVER the approved gate argv.

Run:  python test_authenticated_scanning.py
"""
from __future__ import annotations

from cockpit import discover as d, jsrecon as j, nuclei, session_store as ss

SESSION = [("Cookie", "session_key=SUPER-SECRET-TOKEN")]


def _has_token(parts) -> bool:
    return "SUPER-SECRET-TOKEN" in " ".join(parts)


def test_session_store_helpers() -> None:
    ss.set_session("e", SESSION, "A")
    assert ss.header_pairs("e") == SESSION
    assert ss.header_pairs("nope") == []
    # typed header wins: a name already present is not re-added; an absent one is
    assert ss.additional_session_headers(["cookie"], SESSION) == []
    assert ss.additional_session_headers(["x"], SESSION) == SESSION
    masked = ss.mask_header_flag_values(["nuclei", "-H", "Cookie: session_key=SUPER-SECRET-TOKEN"])
    assert not _has_token(masked) and any("Cookie:" in a for a in masked)
    ss.clear_session("e")
    print("  session_store helpers + masker: PASS")


def test_nuclei_auth_argv_and_mask() -> None:
    req = nuclei.NucleiRequest(targets=["https://x"], attach_session=True, engagement_id="e")
    real = nuclei.nuclei_argv(["https://x"], req, extra_headers=SESSION)
    assert "-H" in real and _has_token(real)
    assert not _has_token(ss.mask_header_flag_values(real))
    assert "-H" not in nuclei.nuclei_argv(["https://x"], req)  # none without a session
    print("  nuclei: -H when attached, masked in record, none without: PASS")


def test_discover_auth_flags_and_mask() -> None:
    ff = d.ffuf_argv("http://x/FUZZ", "/w", "/o", [], None, extra_headers=SESSION)
    fx = d.feroxbuster_argv("http://x", "/w", "/o", [], None, extra_headers=SESSION)
    aj = d.arjun_argv("http://x", "GET", "/o", extra_headers=SESSION)
    assert "-H" in ff and _has_token(ff)
    assert "-H" in fx and _has_token(fx)
    assert "--headers" in aj and _has_token(aj)
    for argv in (ff, fx, aj):
        assert not _has_token(ss.mask_header_flag_values(argv))
    assert "-H" not in d.ffuf_argv("http://x/FUZZ", "/w", "/o", [], None)  # none without a session
    print("  discover: ffuf/ferox -H, arjun --headers, all masked, none without: PASS")


def test_jsrecon_spec_headers_stdin_not_argv() -> None:
    req = j.JsReconRequest(target="https://x", attach_session=True, engagement_id="e")
    spec = j.mine_job_spec(["https://x/a.js"], req, extra_headers=SESSION)
    assert spec.get("headers") == [["Cookie", "session_key=SUPER-SECRET-TOKEN"]]
    assert not _has_token(j.gate_argv(req))                 # never in the approved argv
    assert "headers" not in j.mine_job_spec(["https://x/a.js"], req)  # none without a session
    print("  jsrecon: session in the STDIN spec, never the gate argv: PASS")


if __name__ == "__main__":
    test_session_store_helpers()
    test_nuclei_auth_argv_and_mask()
    test_discover_auth_flags_and_mask()
    test_jsrecon_spec_headers_stdin_not_argv()
    print("ALL authenticated-scanning tests pass")
