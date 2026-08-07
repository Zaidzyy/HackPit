"""Unconstrained delegation edge + golden/silver ticket forging — the delegation-family closer.

Two claims, tested rather than asserted:

  1. UNCONSTRAINED DELEGATION IS A ROUTABLE EDGE. A host flagged ``unconstraineddelegation``
     synthesizes a ``TrustedForDelegation`` edge to Domain Admins (own the host, coerce a DC,
     capture its TGT, DCSync), and an owned low-priv user who is local admin on it routes all the
     way to DA. Its technique has a Linux template AND a native Windows variant, both destructive
     and both tripping the danger gate — the same oracle every other abusable edge passes.

  2. GOLDEN / SILVER TICKET FORGING IS PERSISTENCE, NOT A ROUTE. Golden is offered on the domain
     node only once krbtgt is held; silver on a service node only once its hash is held; and
     NEITHER is ever traversed by the path engine or the orchestrator frontier. Forging a ticket
     presupposes the compromise it would otherwise be used to "reach", so it must stay out of the
     route-to-DA search entirely.

Hermetic: no Docker, no LLM, no network. Run:  python test_deleg_tickets.py
"""
from __future__ import annotations

from adgraph import parser as P
from adgraph import paths as PATHS
from adgraph import persistence as PERS
from adgraph import sample_data as S
from adgraph import schema as SC
from adgraph.orchestrator import AdState, frontier, proposal_for_edge
from cockpit import allowlist as A


def _deleg_fixture() -> dict:
    """A minimal BloodHound collection: one unconstrained-delegation host + a domain object."""
    dom = "S-1-5-21-9-9-9"
    return {
        "domains": {"data": [{"ObjectIdentifier": dom,
                              "Properties": {"name": "EXAMPLE.LOCAL", "highvalue": True},
                              "Aces": [], "ChildObjects": [], "Links": [], "Trusts": []}],
                    "meta": {"type": "domains", "version": 5}},
        "groups": {"data": [{"ObjectIdentifier": f"{dom}-512",
                             "Properties": {"name": "DOMAIN ADMINS@EXAMPLE.LOCAL", "highvalue": True},
                             "Members": [], "Aces": []}],
                   "meta": {"type": "groups", "version": 5}},
        "computers": {"data": [{"ObjectIdentifier": f"{dom}-1201",
                                "Properties": {"name": "SRV01.EXAMPLE.LOCAL",
                                               "unconstraineddelegation": True, "highvalue": False},
                                "Aces": [], "AllowedToDelegate": [], "AllowedToAct": [],
                                "Sessions": {"Results": []}, "LocalAdmins": {"Results": []},
                                "RemoteDesktopUsers": {"Results": []}, "PSRemoteUsers": {"Results": []},
                                "DcomUsers": {"Results": []}, "PrimaryGroupSID": f"{dom}-515"}],
                      "meta": {"type": "computers", "version": 5}},
        "users": {"data": [], "meta": {"type": "users", "version": 5}},
    }


# --------------------------------------------------------------------------- #
# 1. unconstrained delegation is a routable edge
# --------------------------------------------------------------------------- #
def test_unconstrained_flag_synthesizes_the_edge() -> None:
    g = P.parse_collection(_deleg_fixture())
    tfd = [e for e in g.edges if e.kind == "TrustedForDelegation"]
    assert len(tfd) == 1, f"expected exactly one TrustedForDelegation edge, got {len(tfd)}"
    e = tfd[0]
    assert e.source.endswith("-1201"), "the edge must start at the unconstrained host"
    assert e.target.endswith("-512"), "and target the Domain Admins objective"
    assert e.abusable, "TrustedForDelegation must be an abusable (traversable) edge"
    assert e.props.get("requires_owned_host") is True, "the edge notes the host must be owned first"
    print("  an unconstrained-delegation host synthesizes a routable TrustedForDelegation edge "
          "to Domain Admins: PASS")


def test_no_flag_no_edge() -> None:
    """A host WITHOUT the flag must not get a delegation edge — the predicate is the flag."""
    fx = _deleg_fixture()
    fx["computers"]["data"][0]["Properties"]["unconstraineddelegation"] = False
    g = P.parse_collection(fx)
    assert not any(e.kind == "TrustedForDelegation" for e in g.edges), (
        "no unconstrained flag => no TrustedForDelegation edge"
    )
    print("  a host without the unconstrained flag gets no delegation edge: PASS")


def test_owned_user_routes_to_da_through_the_delegation_host() -> None:
    """The headline: owned PODRICK --AdminTo--> APP01 --TrustedForDelegation--> Domain Admins."""
    g = P.parse_collection(S.sample_collection())
    da = PATHS.default_high_value_target(g)
    res = PATHS.paths_to_target(g, S.DELEG_SAMPLE_START, da)
    assert res["found"], f"no route from PODRICK to DA: {res['reason']}"
    kinds = [h["kind"] for h in res["path"]["edges"]]
    assert "AdminTo" in kinds and "TrustedForDelegation" in kinds, kinds
    assert kinds[-1] == "TrustedForDelegation", (
        f"the route's last hop into DA must be the delegation edge, got {kinds}"
    )
    print(f"  PODRICK routes to Domain Admins via {' -> '.join(kinds)}: PASS")


def test_delegation_technique_has_both_transports_and_is_destructive() -> None:
    """The edge's technique must carry a Linux template AND a native Windows variant, be marked
    destructive, and BOTH first-runnable commands must trip the danger gate (the catalog oracle)."""
    g = P.parse_collection(S.sample_collection())
    edge = next(e for e in g.edges if e.kind == "TrustedForDelegation")
    prop = proposal_for_edge(g, edge, "coerce a DC, capture its TGT, DCSync")
    assert prop["destructive_technique"], "unconstrained delegation abuse is destructive"
    # Linux: krbrelayx is the first runnable line -> credential capture -> danger gate
    assert prop["command"] == "krbrelayx.py", prop["command"]
    assert prop["dangerous_flags"], "the Linux command must trip the danger heuristic"
    # Windows: Rubeus monitor is the first runnable line -> ticket capture -> danger gate
    assert prop["windows_command"] == "Rubeus.exe", prop["windows_command"]
    assert prop["windows_dangerous_flags"], "the Windows variant must trip the danger heuristic"
    print("  the delegation technique has Linux + Windows variants, both destructive and both "
          "tripping the danger gate: PASS")


def test_coercion_and_capture_tools_all_trip_the_gate() -> None:
    """Every tool the delegation abuse leans on — the listener, the coercers, the DCSync — must
    demand the red confirm, on both transports."""
    for command, args in (
        ("krbrelayx.py", ["-t", "ldap://dc01", "--no-dump"]),
        ("printerbug.py", ["example.local/u:p@dc01", "srv01"]),
        ("PetitPotam.py", ["attacker", "dc01"]),
        ("SpoolSample.exe", ["dc01", "srv01"]),
        ("Rubeus.exe", ["monitor", "/interval:1", "/nowrap"]),
    ):
        assert A.dangerous_command_heuristic(command, args), f"{command} must be flagged dangerous"
    # and Rubeus read-only enumeration is NOT flagged — the confirm keeps its meaning
    assert A.dangerous_command_heuristic("Rubeus.exe", ["triage"]) == []
    print("  krbrelayx / printerbug / PetitPotam / SpoolSample / Rubeus monitor all trip the "
          "danger gate; Rubeus triage stays clean: PASS")


# --------------------------------------------------------------------------- #
# 2. golden / silver forging is persistence, not a route
# --------------------------------------------------------------------------- #
def test_forging_kinds_are_not_abusable_edges() -> None:
    for kind in PERS.KINDS:
        assert kind not in SC.ABUSABLE_EDGES, f"{kind} must never be an abusable edge"
        assert not SC.is_abusable(kind), f"{kind} must not be traversable"
    print("  GoldenTicket / SilverTicket are not abusable edges — the path engine cannot walk "
          "them: PASS")


def test_golden_is_gated_on_krbtgt_held() -> None:
    """Golden is offered on the domain node ONLY after krbtgt is held (DCSync / captured DC TGT /
    DA owned) — never before."""
    g = P.parse_collection(S.sample_collection())

    # before: owning only the low-priv start does NOT offer golden
    early = PERS.persistence_actions(g, AdState(owned=(S.DELEG_SAMPLE_START,)))
    assert not any(a["kind"] == "GoldenTicket" for a in early), (
        "golden must not be offered before krbtgt is held"
    )

    # after a DCSync traversal: golden IS offered on the domain node
    dcsync_key = f"a|{S.DOMAIN_ADMINS}|DCSync"
    held = PERS.persistence_actions(g, AdState(owned=(S.DELEG_SAMPLE_START,), traversed=(dcsync_key,)))
    golden = [a for a in held if a["kind"] == "GoldenTicket"]
    assert golden, "golden must be offered once a DCSync has been walked"
    assert golden[0]["node_type"] == "domain", "golden is offered on the domain node"
    assert golden[0]["destructive"] and golden[0]["commands"][0]["cmd"], "with a forging command"

    # a captured DC TGT via unconstrained delegation also yields krbtgt -> golden offered
    tfd_key = f"{S.APP01}|{S.DOMAIN_ADMINS}|TrustedForDelegation"
    via_deleg = PERS.persistence_actions(g, AdState(owned=(S.DELEG_SAMPLE_START,), traversed=(tfd_key,)))
    assert any(a["kind"] == "GoldenTicket" for a in via_deleg), (
        "capturing a DC TGT via unconstrained delegation also unlocks golden"
    )
    print("  golden ticket is offered on the domain node ONLY after krbtgt is held "
          "(DCSync / captured DC TGT): PASS")


def test_silver_is_gated_on_a_held_service_hash() -> None:
    """Silver is offered on a computer/service node only once you own it (its hash is held)."""
    g = P.parse_collection(S.sample_collection())

    none_owned = PERS.persistence_actions(g, AdState(owned=(S.DELEG_SAMPLE_START,)))
    assert not any(a["kind"] == "SilverTicket" for a in none_owned), (
        "silver must not be offered before a service account's hash is held"
    )

    owns_app01 = PERS.persistence_actions(g, AdState(owned=(S.DELEG_SAMPLE_START, S.APP01)))
    silver = [a for a in owns_app01 if a["kind"] == "SilverTicket"]
    assert silver, "silver must be offered once you own the service host"
    assert silver[0]["node_id"] == S.APP01 and silver[0]["node_type"] == "computer"
    assert "cifs/APP01" in silver[0]["commands"][0]["cmd"], "the SPN is templated for the host"
    print("  silver ticket is offered on a service node ONLY once its hash is held (host owned): "
          "PASS")


def test_forging_never_enters_the_frontier_or_the_route() -> None:
    """The load-bearing separation: even with EVERYTHING owned, the orchestrator frontier and the
    path engine only ever surface abusable edges — never a forging action."""
    g = P.parse_collection(S.sample_collection())
    all_owned = AdState(owned=tuple(g.nodes.keys()))
    for e in frontier(g, all_owned):
        assert not PERS.is_persistence(e.kind), f"a forging action reached the frontier: {e.kind}"
    # and no edge of a forging kind exists in the graph at all
    assert not any(PERS.is_persistence(e.kind) for e in g.edges), (
        "no GoldenTicket/SilverTicket edge may exist in the graph"
    )
    # the route to DA is made of abusable edges only, none of them forging
    res = PATHS.paths_to_target(g, S.DELEG_SAMPLE_START, PATHS.default_high_value_target(g))
    if res["found"]:
        for hop in res["path"]["edges"]:
            assert not PERS.is_persistence(hop["kind"]), hop["kind"]
    print("  ticket forging never enters the orchestrator frontier, the graph edges, or a route: "
          "PASS")


def test_forging_commands_trip_the_danger_gate() -> None:
    """A forging command is a real domain change — both transports must demand the red confirm."""
    g = P.parse_collection(S.sample_collection())
    actions = PERS.persistence_actions(g, AdState(owned=S.DELEG_DEMO_OWNED))
    assert actions, "the demo-owned state should offer both golden and silver"
    for a in actions:
        for cmd_set in ("commands", "windows_commands"):
            cmd = a[cmd_set][0]["cmd"]
            first = next(ln for ln in cmd.splitlines() if ln.strip() and not ln.strip().startswith("#"))
            parts = first.split()
            assert A.dangerous_command_heuristic(parts[0], parts[1:]), (
                f"{a['kind']} {cmd_set} must trip the danger gate: {first}"
            )
    print("  golden + silver forging commands trip the danger gate on both transports: PASS")


if __name__ == "__main__":
    test_unconstrained_flag_synthesizes_the_edge()
    test_no_flag_no_edge()
    test_owned_user_routes_to_da_through_the_delegation_host()
    test_delegation_technique_has_both_transports_and_is_destructive()
    test_coercion_and_capture_tools_all_trip_the_gate()
    test_forging_kinds_are_not_abusable_edges()
    test_golden_is_gated_on_krbtgt_held()
    test_silver_is_gated_on_a_held_service_hash()
    test_forging_never_enters_the_frontier_or_the_route()
    test_forging_commands_trip_the_danger_gate()
    print("ALL unconstrained-delegation + ticket-forging tests pass")
