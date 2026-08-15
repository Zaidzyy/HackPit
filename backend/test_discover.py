"""Parameter / content discovery tests.  Run:  python test_discover.py

Covers the halves the :discover feature rests on:

  * PARSERS: arjun/feroxbuster output -> Endpoint rows with discovered param/path NAMES (never values).
  * ARGV: each mode builds the correct command; the CONTENT word list is in the gate surface WHOLE
    (intruder-style, nothing truncated); ffuf gets a FUZZ keyword.
  * SCOPE: filter_endpoints_in_scope keeps in-scope + drops/collects out-of-scope, with a control.
  * HAND-OFF: a discovered param produces a valid pre-filled intruder position; interesting params
    and sensitive endpoints become low findings, boring ones do not.

Hermetic: no Docker, no network, no DB — every function under test is pure.
"""
from __future__ import annotations

from cockpit import discover
from cockpit import scope as SC
from state.models import Endpoint
from state.parsers import parse_arjun, parse_feroxbuster

_SID = "s-discover-0001"
_SCOPE = SC.parse_scope("example.com, *.example.com", resolve=False)


# --------------------------------------------------------------------------- #
# parsers
# --------------------------------------------------------------------------- #
def test_parse_arjun_map_and_flat_shapes() -> None:
    # map shape: URL -> {method, params}
    mp = '{"https://api.example.com/x": {"method": "GET", "params": ["id", "debug"]}}'
    parsed = parse_arjun(mp, _SID, "r1")
    assert len(parsed.endpoints) == 1
    assert parsed.endpoints[0].url == "https://api.example.com/x"
    assert parsed.endpoints[0].params == ["id", "debug"], parsed.endpoints[0].params
    # flat shape: an object naming its own url
    flat = '{"url": "https://api.example.com/y", "params": ["user"]}'
    p2 = parse_arjun(flat, _SID, "r1")
    assert p2.endpoints[0].url == "https://api.example.com/y"
    assert p2.endpoints[0].params == ["user"], p2.endpoints[0].params
    print("  arjun: both JSON shapes -> Endpoint with discovered param NAMES: PASS")


def test_parse_feroxbuster_only_response_lines() -> None:
    text = (
        '{"type":"configuration","wordlist":"x"}\n'
        '{"type":"response","url":"https://api.example.com/admin","status":200,"content_length":42}\n'
        '{"type":"response","url":"https://api.example.com/admin","status":200,"content_length":42}\n'  # dup
        '{"type":"statistics","total":10}\n'
    )
    parsed = parse_feroxbuster(text, _SID, "r1")
    urls = [e.url for e in parsed.endpoints]
    assert urls == ["https://api.example.com/admin"], urls  # config/statistics dropped, dup collapsed
    assert parsed.endpoints[0].status == 200 and parsed.endpoints[0].length == 42
    print("  feroxbuster: only response lines become Endpoints, dup collapses, config/stats dropped: PASS")


# --------------------------------------------------------------------------- #
# argv — per mode; the content word list is in the surface WHOLE
# --------------------------------------------------------------------------- #
def test_arjun_argv_targets_one_url() -> None:
    argv = discover.arjun_argv("https://api.example.com/x", "POST", "/loot/e/out.json")
    assert argv[:2] == ["arjun", "-u"] and argv[2] == "https://api.example.com/x"
    assert "-m" in argv and argv[argv.index("-m") + 1] == "POST"
    assert "-oJ" in argv
    print("  arjun argv: -u <url> -m <method> -oJ <loot>, url is the only host on the line: PASS")


def test_ffuf_argv_gets_a_fuzz_keyword() -> None:
    argv = discover.ffuf_argv("https://api.example.com/", "/loot/e/w.txt", "/loot/e/out.json", [])
    url = argv[argv.index("-u") + 1]
    assert url == "https://api.example.com/FUZZ", url  # FUZZ appended when absent
    kept = discover.ffuf_argv("https://api.example.com/FUZZ", "/loot/e/w.txt", "/loot/e/o.json", [])
    assert kept[kept.index("-u") + 1] == "https://api.example.com/FUZZ"  # existing FUZZ untouched
    print("  ffuf argv: a FUZZ keyword is ensured, an existing one is left alone: PASS")


def test_content_gate_argv_carries_every_word_not_truncated() -> None:
    req = discover.DiscoverRequest(
        mode="content", url="https://api.example.com/",
        words=["admin", "login", "backup", "| sh"],  # a dangerous one in the middle
    )
    argv = discover.content_gate_argv(req)
    # every word rides on the gated line so the danger heuristic reads the same bytes that get sent
    for w in ("admin", "login", "backup", "| sh"):
        assert w in argv, f"{w!r} must be in the approved surface, not summarised"
    assert argv.count("-w") == 4, argv
    print("  content gate argv: the WHOLE word list is in the approved surface (intruder-style): PASS")


def test_paramspider_argv_is_domain_only() -> None:
    argv = discover.paramspider_argv("example.com")
    assert argv == ["paramspider", "-d", "example.com"], argv
    print("  paramspider argv: -d <domain>, passive, one host on the line: PASS")


# --------------------------------------------------------------------------- #
# scope discipline — the correctness property
# --------------------------------------------------------------------------- #
def test_filter_endpoints_in_scope_keeps_in_drops_out() -> None:
    eps = [
        Endpoint(session_id=_SID, url="https://api.example.com/x?id=1", params=["id"]),
        Endpoint(session_id=_SID, url="https://evil.com/x?id=1", params=["id"]),          # OUT
        Endpoint(session_id=_SID, url="https://cdn.partner.net/y", params=[]),            # OUT
    ]
    kept, out_hosts = discover.filter_endpoints_in_scope(eps, _SCOPE)
    assert [e.url for e in kept] == ["https://api.example.com/x?id=1"], [e.url for e in kept]
    assert "evil.com" in out_hosts and "cdn.partner.net" in out_hosts
    # CONTROL: the in-scope host is NEVER in the out list.
    assert "api.example.com" not in out_hosts
    print("  filter_endpoints_in_scope keeps in-scope, drops+collects out-of-scope, with a control: PASS")


# --------------------------------------------------------------------------- #
# hand-off + findings
# --------------------------------------------------------------------------- #
def test_mark_param_builds_a_valid_intruder_position() -> None:
    # no query string yet -> ?param=[[FUZZ]]
    m = discover._mark_param("https://api.example.com/x", "id")
    assert m == "https://api.example.com/x?id=[[FUZZ]]", m
    # existing query string -> &param=[[FUZZ]]
    m2 = discover._mark_param("https://api.example.com/x?a=1", "id")
    assert m2 == "https://api.example.com/x?a=1&id=[[FUZZ]]", m2
    # and the whole discovered-param row carries it
    dp = discover._to_discovered_param(
        Endpoint(session_id=_SID, url="https://api.example.com/x", params=["id", "lang"])
    )
    assert dp.intruder_url == "https://api.example.com/x?id=[[FUZZ]]"
    assert dp.nuclei_target == "https://api.example.com/x"
    assert "id" in dp.interesting  # id is an IDOR magnet, lang is not
    assert "lang" not in dp.interesting
    print("  a discovered param yields a valid [[FUZZ]] intruder position + nuclei/repeater hand-offs: PASS")


def test_findings_only_for_interesting_discoveries() -> None:
    # params mode: an interesting param name -> a low finding; a boring one -> none
    hot = discover._findings_from(
        "params",
        [Endpoint(session_id=_SID, url="https://api.example.com/x", params=["debug", "lang"])],
        _SID, "r1",
    )
    assert len(hot) == 1 and hot[0].severity == "low" and hot[0].vuln_class == "param-discovery"
    boring = discover._findings_from(
        "params", [Endpoint(session_id=_SID, url="https://api.example.com/x", params=["lang"])], _SID, "r1"
    )
    assert boring == [], "a plain ?lang= param is surface, not a finding"
    # content mode: a sensitive URL -> a finding; a plain one -> none
    sens = discover._findings_from(
        "content", [Endpoint(session_id=_SID, url="https://api.example.com/admin")], _SID, "r1"
    )
    assert len(sens) == 1 and sens[0].vuln_class == "content-discovery"
    plain = discover._findings_from(
        "content", [Endpoint(session_id=_SID, url="https://api.example.com/about")], _SID, "r1"
    )
    assert plain == [], "a plain /about path is surface, not a finding"
    print("  only interesting discoveries (admin endpoint / debug param) become low findings: PASS")


def test_impersonate_routes_active_tools_through_the_ja3_proxy() -> None:
    """The WAF fix for :discover: impersonate=True routes each active tool through the in-sandbox
    JA3 MITM proxy (feroxbuster also gets -k for the proxy's cert). Default off leaves the argv
    byte-for-byte as before. paramspider is passive (archives) and takes no impersonate."""
    px = discover.IMPERSONATE_PROXY

    a = discover.arjun_argv("https://cf.example.com/x", "GET", "/loot/o.json", impersonate=True)
    assert "--proxy" in a and px in a, a
    assert "--proxy" not in discover.arjun_argv("https://cf.example.com/x", "GET", "/loot/o.json"), "default off"

    f = discover.ffuf_argv("https://cf.example.com/", "/loot/w.txt", "/loot/o.json", [], impersonate=True)
    assert "-x" in f and px in f, f
    assert "-x" not in discover.ffuf_argv("https://cf.example.com/", "/loot/w.txt", "/loot/o.json", []), "default off"

    x = discover.feroxbuster_argv("https://cf.example.com/", "/loot/w.txt", "/loot/o.json", [], impersonate=True)
    assert "--proxy" in x and px in x and "-k" in x, x
    print("  impersonate routes arjun/ffuf/feroxbuster through the JA3 proxy; default off unchanged: PASS")


if __name__ == "__main__":
    test_parse_arjun_map_and_flat_shapes()
    test_parse_feroxbuster_only_response_lines()
    test_arjun_argv_targets_one_url()
    test_ffuf_argv_gets_a_fuzz_keyword()
    test_content_gate_argv_carries_every_word_not_truncated()
    test_paramspider_argv_is_domain_only()
    test_filter_endpoints_in_scope_keeps_in_drops_out()
    test_mark_param_builds_a_valid_intruder_position()
    test_findings_only_for_interesting_discoveries()
    test_impersonate_routes_active_tools_through_the_ja3_proxy()
    print("\nall discover tests pass.")
