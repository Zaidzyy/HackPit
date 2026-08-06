"""Guided recon -> ranked surface tests.  Run:  python test_recon.py

Covers the two halves the :recon feature rests on:

  * PARSERS: subfinder/dnsx/naabu/url-lister output -> Host/Service/Endpoint, params mined.
  * SCOPE + RANK: filter_in_scope keeps in-scope and drops out-of-scope records; rank_surface
    orders a session's state by likely-exploitable, deterministically.

Hermetic: no Docker, no network. State goes to a throwaway temp DB.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from cockpit import recon
from cockpit import scope as SC
from exploits.index import ExploitIndex
from state import store as state_store
from state.models import Endpoint, Finding, Host, Service
from state.parsers import parse_dnsx, parse_naabu, parse_subfinder, parse_urls

_SID = "s-recon-0001"
_SCOPE = SC.parse_scope("example.com, *.example.com", resolve=False)


# --------------------------------------------------------------------------- #
# parsers
# --------------------------------------------------------------------------- #
def test_parse_subfinder_one_host_per_line() -> None:
    text = "api.example.com\nwww.example.com\napi.example.com\n# comment\nnot a host line\n"
    parsed = parse_subfinder(text, _SID, "r1")
    got = {h.address for h in parsed.hosts}
    assert got == {"api.example.com", "www.example.com"}, got
    assert all(h.status == "" for h in parsed.hosts), "discovery is not liveness"
    print("  subfinder: one Host per unique subdomain, noise dropped, status blank: PASS")


def test_parse_dnsx_marks_resolved_up() -> None:
    text = '{"host":"api.example.com","a":["1.2.3.4"]}\n{"host":"www.example.com","a":["5.6.7.8"]}\n'
    parsed = parse_dnsx(text, _SID, "r1")
    assert {h.address for h in parsed.hosts} == {"api.example.com", "www.example.com"}
    assert all(h.status == "up" for h in parsed.hosts), "a resolved name is up"
    print("  dnsx: resolved names become up Hosts: PASS")


def test_parse_naabu_open_services() -> None:
    text = '{"host":"api.example.com","ip":"1.2.3.4","port":443}\n{"ip":"1.2.3.4","port":80}\n'
    parsed = parse_naabu(text, _SID, "r1")
    ports = sorted(s.port for s in parsed.services)
    assert ports == [80, 443], ports
    assert all(s.state == "open" for s in parsed.services)
    assert any(s.address == "1.2.3.4" for s in parsed.services)
    assert any(h.address == "api.example.com" for h in parsed.hosts)
    print("  naabu: open ports -> Services on the IP + the name as an up Host: PASS")


def test_parse_urls_mines_param_names_not_values() -> None:
    text = (
        "https://api.example.com/v2/users?id=1&team=7\n"
        "https://api.example.com/login\n"
        "https://api.example.com/v2/users?id=1&team=7\n"  # dup collapses
        "garbage line\n"
    )
    parsed = parse_urls(text, _SID, "r1")
    urls = [e.url for e in parsed.endpoints]
    assert len(urls) == 2, urls
    users = next(e for e in parsed.endpoints if "users" in e.url)
    assert users.params == ["id", "team"], users.params
    assert "1" not in "".join(users.params) or "team" in users.params  # names, never values
    print("  url lister: one Endpoint per URL, query param NAMES mined (not values): PASS")


# --------------------------------------------------------------------------- #
# scope discipline — the correctness property
# --------------------------------------------------------------------------- #
def test_filter_in_scope_keeps_in_drops_out() -> None:
    from state.parsers import Parsed

    p = Parsed()
    p.hosts = [
        Host(session_id=_SID, address="api.example.com"),
        Host(session_id=_SID, address="evil.com"),           # OUT
    ]
    p.services = [
        Service(session_id=_SID, address="api.example.com", port=443),
        Service(session_id=_SID, address="cdn.partner.net", port=80),  # OUT
    ]
    p.endpoints = [
        Endpoint(session_id=_SID, url="https://www.example.com/x?id=1"),
        Endpoint(session_id=_SID, url="https://evil.com/x"),  # OUT
    ]
    kept, out_hosts = recon.filter_in_scope(p, _SCOPE)
    assert {h.address for h in kept.hosts} == {"api.example.com"}
    assert {s.address for s in kept.services} == {"api.example.com"}
    assert [e.url for e in kept.endpoints] == ["https://www.example.com/x?id=1"]
    assert "evil.com" in out_hosts and "cdn.partner.net" in out_hosts
    # CONTROL: an in-scope host is NEVER in the out list.
    assert "api.example.com" not in out_hosts
    print("  filter_in_scope keeps in-scope records, drops+collects out-of-scope, with a control: PASS")


# --------------------------------------------------------------------------- #
# ranking — deterministic order by likely-exploitable
# --------------------------------------------------------------------------- #
def _seed_state() -> None:
    # A: rich (3 services + 2 param endpoints + an auth surface + a High finding)
    state_store.upsert_hosts([Host(session_id=_SID, address="a.example.com", status="up")])
    state_store.upsert_services([
        Service(session_id=_SID, address="a.example.com", port=p) for p in (80, 443, 8080)
    ])
    state_store.upsert_endpoints([
        Endpoint(session_id=_SID, url="https://a.example.com/api/users?id=1", params=["id"]),
        Endpoint(session_id=_SID, url="https://a.example.com/api/orders?oid=2", params=["oid"]),
        Endpoint(session_id=_SID, url="https://a.example.com/admin/login"),
    ])
    state_store.upsert_findings([
        Finding(session_id=_SID, title="SQLi", severity="high", target="https://a.example.com/api/users?id=1")
    ])
    # C: mid (3 param endpoints, no services)
    state_store.upsert_hosts([Host(session_id=_SID, address="c.example.com", status="up")])
    state_store.upsert_endpoints([
        Endpoint(session_id=_SID, url=f"https://c.example.com/q?p={i}", params=["p"]) for i in range(3)
    ])
    # B: low (one bare service)
    state_store.upsert_hosts([Host(session_id=_SID, address="b.example.com", status="up")])
    state_store.upsert_services([Service(session_id=_SID, address="b.example.com", port=22, name="ssh")])


def test_rank_surface_orders_and_is_deterministic() -> None:
    tmp = Path(tempfile.mkdtemp()) / "state.db"
    orig = state_store.DB_PATH
    state_store.DB_PATH = tmp
    try:
        state_store.init_db()
        _seed_state()
        empty_index = ExploitIndex()  # ready == False -> CVE signal off, fully deterministic
        surface = recon.rank_surface(_SID, index=empty_index)
        order = [t.address for t in surface.targets]
        assert order[0] == "a.example.com", order
        assert set(order) == {"a.example.com", "b.example.com", "c.example.com"}, order
        # a (services+params+auth+High) > c (3 params) > b (one bare service)
        rank = {t.address: t.score for t in surface.targets}
        assert rank["a.example.com"] > rank["c.example.com"] > rank["b.example.com"], rank
        # every target states WHY, and A hands off endpoints to nuclei
        top = surface.targets[0]
        assert top.reasons and any("finding" in r for r in top.reasons), top.reasons
        assert top.nuclei_targets, "the top target must hand off endpoints to :nuclei"
        # determinism: same state -> byte-identical order + scores
        again = recon.rank_surface(_SID, index=empty_index)
        assert [(t.address, t.score) for t in again.targets] == [
            (t.address, t.score) for t in surface.targets
        ]
        print("  rank_surface orders by likely-exploitable, states the WHY, is deterministic: PASS")
    finally:
        state_store.DB_PATH = orig


if __name__ == "__main__":
    test_parse_subfinder_one_host_per_line()
    test_parse_dnsx_marks_resolved_up()
    test_parse_naabu_open_services()
    test_parse_urls_mines_param_names_not_values()
    test_filter_in_scope_keeps_in_drops_out()
    test_rank_surface_orders_and_is_deterministic()
    print("\nall recon tests pass.")
