"""Regression-lock for the AD graph parser + path engine (adgraph/).

The parser turns a BloodHound collection into a typed graph; the path engine finds the route
to Domain Admin over abusable edges. These tests fail loudly if either drifts:

  PARSER
  1. every object becomes a typed node; the domain is detected; high-value (RID 512 etc.) fires.
  2. ACEs become directed Principal->object edges of the right kind (across v4/v5/CE naming).
  3. group Members become MemberOf; computer local-admins/sessions/RDP become the right edges.
  4. DCSync is synthesized from GetChanges + GetChangesAll on the same target.
  5. partial collections parse (missing methods -> warnings, not a crash); empty -> ParseError.
  6. input-shape agnostic: combined mapping, list of files, a .zip and a directory all parse
     to the same graph.

  PATH ENGINE
  7. the known GOAD-style ACL chain resolves to the exact 5-hop route to Domain Admins.
  8. no-path is reported cleanly (found=False + reason), not raised.
  9. only ABUSABLE edges are traversed (a structural-only route is not a path).
 10. equal-length ties break toward the cheaper (lower-rank) abuse.

Hermetic: no network, no Docker, no LLM. Run:  python test_adgraph.py
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import zipfile

from adgraph import sample_data as S
from adgraph.parser import ParseError, parse_collection
from adgraph.paths import (
    default_high_value_target,
    paths_to_target,
    shortest_path,
)
from adgraph.schema import Edge, Graph, Node


def _graph():
    return parse_collection(S.sample_collection())


def _edge_kinds(g, source, target):
    return {e.kind for e in g.edges if e.source == source and e.target == target}


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def test_nodes_typed_domain_and_highvalue() -> None:
    g = _graph()
    assert g.domain == "SEVENKINGDOMS.LOCAL"
    assert g.node(S.TYWIN).type == "user"
    assert g.node(S.DC01).type == "computer"
    assert g.node(S.SMALL_COUNCIL).type == "group"
    da = g.node(S.DOMAIN_ADMINS)
    assert da.high_value, "Domain Admins (RID 512) must be high-value"
    assert not g.node(S.TYWIN).high_value, "a low-priv user is not high-value"
    print("  nodes typed, domain detected, high-value (RID 512) fires: PASS")


def test_aces_become_directed_edges() -> None:
    g = _graph()
    assert "ForceChangePassword" in _edge_kinds(g, S.TYWIN, S.JAIME)
    assert "GenericWrite" in _edge_kinds(g, S.JAIME, S.JOFFREY)
    assert "WriteDacl" in _edge_kinds(g, S.JOFFREY, S.TYRION)
    assert "GenericAll" in _edge_kinds(g, S.SMALL_COUNCIL, S.DOMAIN_ADMINS)
    # direction matters: the ACE holder is the SOURCE
    assert not _edge_kinds(g, S.JAIME, S.TYWIN), "an ACE edge must not be reversed"
    print("  ACEs -> directed Principal->object edges of the right kind: PASS")


def test_membership_and_computer_edges() -> None:
    g = _graph()
    assert "MemberOf" in _edge_kinds(g, S.CERSEI, S.DOMAIN_ADMINS), "group Members -> MemberOf"
    assert "AddSelf" in _edge_kinds(g, S.TYRION, S.SMALL_COUNCIL)
    assert "AdminTo" in _edge_kinds(g, S.DOMAIN_ADMINS, S.DC01), "LocalAdmins -> AdminTo"
    assert "HasSession" in _edge_kinds(g, S.DC01, S.CERSEI), "Sessions -> HasSession (comp->user)"
    print("  Members/local-admins/sessions map to MemberOf/AdminTo/HasSession: PASS")


def test_dcsync_is_synthesized() -> None:
    g = _graph()
    assert "DCSync" in _edge_kinds(g, S.DOMAIN_ADMINS, S.DOMAIN_SID), \
        "GetChanges + GetChangesAll on the domain must synthesize a DCSync edge"
    # a principal with only ONE of the two rights must NOT get a DCSync edge
    coll = S.sample_collection()
    coll["domains"]["data"][0]["Aces"] = [
        {"PrincipalSID": S.TYRION, "PrincipalType": "User", "RightName": "GetChanges"}
    ]
    g2 = parse_collection(coll)
    assert "DCSync" not in _edge_kinds(g2, S.TYRION, S.DOMAIN_SID), \
        "one replication right alone is not DCSync"
    print("  DCSync synthesized only from BOTH replication rights: PASS")


def test_partial_and_empty_collections() -> None:
    # a collection with no ACLs still parses, with a warning
    coll = S.sample_collection()
    for f in coll.values():
        for obj in f["data"]:
            obj["Aces"] = []
    g = parse_collection(coll)
    assert any("ACL" in w or "abuse" in w for w in g.warnings), g.warnings
    # empty -> ParseError
    try:
        parse_collection({"users": {"data": [], "meta": {"type": "users"}}})
    except ParseError:
        print("  partial collection warns; empty collection raises ParseError: PASS")
        return
    raise AssertionError("an empty collection must raise ParseError")


def test_input_shapes_agree() -> None:
    coll = S.sample_collection()
    base = parse_collection(coll).stats()

    # list of file objects
    as_list = parse_collection(list(coll.values())).stats()
    assert as_list == base, "a list of files must parse the same as the combined mapping"

    # a directory of *.json files
    with tempfile.TemporaryDirectory() as d:
        for mtype, fileobj in coll.items():
            with open(os.path.join(d, f"20260101_{mtype}.json"), "w", encoding="utf-8") as fh:
                json.dump(fileobj, fh)
        as_dir = parse_collection(d).stats()
    assert as_dir == base, "a directory of files must parse the same"

    # a .zip of *.json files
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for mtype, fileobj in coll.items():
            zf.writestr(f"20260101_{mtype}.json", json.dumps(fileobj))
    as_zip = parse_collection(buf.getvalue()).stats()
    assert as_zip == base, "a .zip must parse the same"
    print("  combined / list / directory / .zip inputs all agree: PASS")


# --------------------------------------------------------------------------- #
# path engine
# --------------------------------------------------------------------------- #
def test_known_route_to_domain_admins() -> None:
    g = _graph()
    res = paths_to_target(g, S.OWNED_START, S.HIGH_VALUE_TARGET)
    assert res["found"], res["reason"]
    kinds = [e["kind"] for e in res["path"]["edges"]]
    assert kinds == [
        "ForceChangePassword", "GenericWrite", "WriteDacl", "AddSelf", "GenericAll",
    ], kinds
    assert res["path"]["node_ids"][0] == S.TYWIN
    assert res["path"]["node_ids"][-1] == S.DOMAIN_ADMINS
    print("  known GOAD-style chain resolves to the exact 5-hop route to DA: PASS")


def test_auto_high_value_target_is_domain_admins() -> None:
    g = _graph()
    assert default_high_value_target(g) == S.DOMAIN_ADMINS
    print("  the auto high-value target is Domain Admins (RID 512): PASS")


def test_no_path_is_clean() -> None:
    g = _graph()
    res = paths_to_target(g, S.CERSEI, S.TYWIN)  # DA -> low-priv: no abusable route
    assert res["found"] is False and res["path"] is None
    assert "no abusable path" in res["reason"]
    # unknown endpoints too
    assert paths_to_target(g, "S-1-nope", S.TYWIN)["found"] is False
    print("  no-path + unknown-endpoint report found=False with a reason (no raise): PASS")


def test_only_abusable_edges_are_traversed() -> None:
    # A graph joined ONLY by a structural Contains edge has no abusable path.
    g = Graph()
    g.add_node(Node(id="A", type="ou", label="A"))
    g.add_node(Node(id="B", type="user", label="B", high_value=True))
    g.add_edge(Edge(source="A", target="B", kind="Contains"))
    assert shortest_path(g, "A", "B") is None, "structural edges must not be traversable"
    g.add_edge(Edge(source="A", target="B", kind="GenericAll"))
    assert shortest_path(g, "A", "B") is not None, "an abusable edge makes it reachable"
    print("  only abusable edges are traversed (structural edges are inert): PASS")


def test_tie_breaks_toward_cheaper_abuse() -> None:
    # Two equal-length routes A->goal: one via MemberOf (rank 0), one via HasSession (high).
    g = Graph()
    for nid in ("A", "M", "S", "G"):
        g.add_node(Node(id=nid, type="user", label=nid))
    g.add_edge(Edge(source="A", target="M", kind="MemberOf"))
    g.add_edge(Edge(source="M", target="G", kind="GenericAll"))
    g.add_edge(Edge(source="A", target="S", kind="HasSession"))
    g.add_edge(Edge(source="S", target="G", kind="GenericAll"))
    p = shortest_path(g, "A", "G")
    assert p is not None and p.node_ids[1] == "M", "the cheaper (MemberOf) hop must win the tie"
    print("  equal-length ties break toward the cheaper abuse: PASS")


if __name__ == "__main__":
    test_nodes_typed_domain_and_highvalue()
    test_aces_become_directed_edges()
    test_membership_and_computer_edges()
    test_dcsync_is_synthesized()
    test_partial_and_empty_collections()
    test_input_shapes_agree()
    test_known_route_to_domain_admins()
    test_auto_high_value_target_is_domain_admins()
    test_no_path_is_clean()
    test_only_abusable_edges_are_traversed()
    test_tie_breaks_toward_cheaper_abuse()
    print("ALL adgraph parser + path tests pass")
