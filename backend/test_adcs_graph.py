"""Regression-lock for the AD CS (ESC1-8) graph synthesis (adgraph/parser.ingest_certipy).

certipy `find -json` output is folded into the SAME graph as the BloodHound collection: it adds
`certtemplate` / `certauthority` nodes and synthesizes composite ESC abuse edges the exact way
DCSync is synthesized — a predicate over a template's vulnerability AND an enrollee's enroll
right collapses to one edge from a low-priv enrollee to Domain Admins. These tests fail loudly
if that drifts:

  1. cert nodes are typed; the CA/template misconfigs land in props.
  2. a directly-vulnerable template + a low-priv enrollee => one composite ESC1 edge => the
     enrollee reaches Domain Admins over it.
  3. ESC4 (write over a template) and ESC7 (ManageCA) emit the TWO-HOP reconfigure-then-abuse
     shape (principal -> template/CA node -> objective).
  4. ESC2 / ESC3 / ESC6 / ESC8 are modeled from their own predicates.
  5. every ESC edge resolves to a runnable technique (a Linux command AND a native Windows
     `win_template`), and carries template_name / ca_name / esc_variant / eku in props that
     survive serialization.
  6. a non-vulnerable template you may enrol is CONTEXT (a structural CanEnroll edge), never a
     traversable abuse.
  7. the BloodHound-only graph is unchanged (no certipy => no cert nodes / ESC edges).

Hermetic: no network, no Docker, no LLM. Run:  python test_adcs_graph.py
"""
from __future__ import annotations

from adgraph import sample_data as S
from adgraph import techniques as T
from adgraph.parser import ingest_certipy, parse_collection
from adgraph.paths import default_high_value_target, paths_to_target
from adgraph.schema import ABUSABLE_EDGES, STRUCTURAL_EDGES, Graph


def _g() -> Graph:
    return parse_collection(S.sample_collection(), certipy=S.sample_certipy())


def _kinds(g, source, target):
    return {e.kind for e in g.edges if e.source == source and e.target == target}


def _edge(g, kind):
    return next(e for e in g.edges if e.kind == kind)


_TID = "CERTTEMPLATE:VulnTemplate"
_CID = "CERTAUTHORITY:SEVENKINGDOMS-CA"


# --------------------------------------------------------------------------- #
# nodes + the taxonomy
# --------------------------------------------------------------------------- #
def test_cert_nodes_typed_with_props() -> None:
    g = _g()
    ca = g.node(_CID)
    assert ca is not None and ca.type == "certauthority", "the CA must be a certauthority node"
    assert ca.props.get("user_specified_san") is True, "the EDITF SAN flag must be captured"
    assert ca.props.get("web_enrollment") is True
    t = g.node(_TID)
    assert t is not None and t.type == "certtemplate"
    templates = [n.label for n in g.nodes.values() if n.type == "certtemplate"]
    assert "UserAuthESC1" in templates and "EnrollmentAgent" in templates, templates
    print("  certtemplate / certauthority nodes are typed and carry the misconfig props: PASS")


def test_esc_kinds_are_abusable_and_context_is_structural() -> None:
    for k in ("ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7", "ESC8"):
        assert k in ABUSABLE_EDGES, f"{k} must be an abusable (traversable) edge"
    for k in ("PublishedTo", "CanEnroll"):
        assert k in STRUCTURAL_EDGES, f"{k} must be structural (context, not traversed)"
    print("  ESC1-8 are abusable; PublishedTo/CanEnroll are structural context: PASS")


# --------------------------------------------------------------------------- #
# synthesis + routing
# --------------------------------------------------------------------------- #
def test_direct_esc1_enrollee_reaches_domain_admins() -> None:
    g = _g()
    da = default_high_value_target(g)
    assert g.node(da).id.endswith("-512"), "the objective is Domain Admins (RID 512)"
    # BRAN is a direct ESC1 enrollee (UserAuthESC1: enrollee-supplied SAN + client auth).
    assert "ESC1" in _kinds(g, S.BRAN, da), "a directly-vulnerable template => a composite ESC1 edge"
    res = paths_to_target(g, S.BRAN, da)
    assert res["found"], res["reason"]
    assert res["path"]["edges"][0]["kind"] == "ESC1"
    assert res["path"]["node_ids"][-1] == da
    print("  a low-priv enrollee reaches Domain Admins via a synthesized ESC1 edge: PASS")


def test_esc4_is_a_two_hop_reconfigure_then_abuse() -> None:
    g = _g()
    da = default_high_value_target(g)
    # HODOR can WRITE VulnTemplate (ESC4) -> the template node -> ESC1 -> DA.
    assert "ESC4" in _kinds(g, S.HODOR, _TID), "ESC4 targets the template node"
    assert "ESC1" in _kinds(g, _TID, da), "the follow-on ESC1 abuse runs from the template node"
    res = paths_to_target(g, S.HODOR, da)
    assert res["found"], res["reason"]
    kinds = [e["kind"] for e in res["path"]["edges"]]
    assert kinds == ["ESC4", "ESC1"], kinds
    mids = res["path"]["node_ids"]
    assert g.node(mids[1]).type == "certtemplate", "the middle hop is the cert TEMPLATE node"
    print("  ESC4 is a two-hop reconfigure-then-abuse through the template node: PASS")


def test_esc7_is_a_two_hop_through_the_ca() -> None:
    g = _g()
    da = default_high_value_target(g)
    # BRAN has ManageCA (ESC7) -> the CA node -> ESC6 (enable SAN + issue) -> DA.
    assert "ESC7" in _kinds(g, S.BRAN, _CID), "ESC7 targets the CA node"
    assert "ESC6" in _kinds(g, _CID, da), "the follow-on issue runs from the CA node"
    print("  ESC7 is a two-hop reconfigure-then-abuse through the CA node: PASS")


def test_esc2_esc3_esc6_esc8_modeled() -> None:
    g = _g()
    da = default_high_value_target(g)
    esc_kinds = {e.kind for e in g.edges if e.kind.startswith("ESC")}
    for k in ("ESC2", "ESC3", "ESC6", "ESC8"):
        assert k in esc_kinds, f"{k} must be synthesized from the sample"
    # ESC8: the coerced/relayed machine -> the CA node.
    assert "ESC8" in _kinds(g, S.WKSTN01, _CID), "ESC8 is computer -> certauthority (relay)"
    # ESC3: bran holds an Enrollment-Agent template right.
    assert "ESC3" in _kinds(g, S.BRAN, da)
    print("  ESC2 / ESC3 / ESC6 / ESC8 are all modeled (incl. ESC8 computer->CA): PASS")


def test_publishedto_wires_template_to_ca() -> None:
    g = _g()
    assert "PublishedTo" in _kinds(g, _TID, _CID), "a template publishes to its CA (structural)"
    # structural edges are not abusable, so they are not traversed
    assert not any(e.abusable for e in g.edges if e.kind == "PublishedTo")
    print("  PublishedTo wires the template to its CA and is not traversable: PASS")


def test_canenroll_is_context_only_for_a_non_vulnerable_template() -> None:
    # A CA WITHOUT the EDITF flag + a client-auth template that is NOT enrollee-supplied-SAN and
    # NOT any-purpose is not abusable: the enrollee gets a structural CanEnroll edge, no ESC.
    g = Graph(domain="LAB.LOCAL")
    from adgraph.schema import Node
    g.add_node(Node(id="S-1-5-21-9-9-9-512", type="group", label="DOMAIN ADMINS@LAB.LOCAL",
                    high_value=True))
    g.add_node(Node(id="S-1-5-21-9-9-9-1001", type="user", label="BOB@LAB.LOCAL"))
    certipy = {
        "Certificate Authorities": {"0": {"CA Name": "LAB-CA", "Web Enrollment": "Disabled",
                                          "User Specified SAN": "Disabled"}},
        "Certificate Templates": {"0": {
            "Template Name": "PlainUser",
            "Enabled": True,
            "Extended Key Usage": ["Client Authentication"],
            "Enrollee Supplies Subject": False,
            "Requires Manager Approval": False,
            "Enrollment Rights": ["LAB.LOCAL\\bob"],
            "Certificate Authorities": ["LAB-CA"],
        }},
    }
    ingest_certipy(g, certipy)
    bob = "S-1-5-21-9-9-9-1001"
    tid = "CERTTEMPLATE:PlainUser"
    assert "CanEnroll" in _kinds(g, bob, tid), "a non-vulnerable enrollable template => CanEnroll"
    assert not any(e.kind.startswith("ESC") for e in g.edges), "no ESC edge for a clean template"
    print("  a non-vulnerable enrollable template is CanEnroll context, not an abuse: PASS")


# --------------------------------------------------------------------------- #
# every ESC edge is runnable + carries its props
# --------------------------------------------------------------------------- #
def test_every_esc_edge_has_a_runnable_technique_and_props() -> None:
    g = _g()
    esc_edges = [e for e in g.edges if e.kind.startswith("ESC")]
    assert esc_edges, "the sample must synthesize ESC edges"
    for e in esc_edges:
        tech = T.technique_for_edge(e, g)
        cmds = tech.get("commands") or []
        assert cmds and cmds[0]["cmd"].strip(), f"{e.kind} must resolve to a Linux command"
        assert tech.get("windows_commands"), f"{e.kind} must have a native Windows variant"
        assert tech["destructive"], f"{e.kind} issues/mints a cert — it must be destructive"
        # props carry the AD CS context and survive serialization
        d = e.to_dict()
        assert d["props"].get("esc_variant"), f"{e.kind} must carry esc_variant in props"
        if e.kind not in ("ESC8",):  # ESC8 targets the CA, not template-bound
            assert "ca_name" in d["props"] or "template_name" in d["props"], d["props"]
    print(f"  every ESC edge ({len(esc_edges)}) resolves to a runnable Linux + Windows technique "
          "and carries its props: PASS")


def test_esc1_technique_is_certipy_req_then_auth() -> None:
    g = _g()
    tech = T.technique_for_edge(_edge(g, "ESC1"), g, dc="10.0.0.5")
    cmd = tech["commands"][0]["cmd"]
    assert cmd.splitlines()[0].startswith("certipy req"), cmd
    assert "certipy auth" in cmd, "ESC1 must recover creds via certipy auth"
    assert tech["windows_commands"][0]["cmd"].startswith("Certify.exe request"), tech
    print("  ESC1 resolves to certipy req -> auth (Linux) + Certify.exe request (Windows): PASS")


# --------------------------------------------------------------------------- #
# the BloodHound-only graph is unchanged
# --------------------------------------------------------------------------- #
def test_bloodhound_only_graph_has_no_cert_nodes() -> None:
    g = parse_collection(S.sample_collection())  # NO certipy
    assert not any(n.type in ("certtemplate", "certauthority") for n in g.nodes.values())
    assert not any(e.kind.startswith("ESC") for e in g.edges)
    # and TYWIN's classic 5-hop ACL route is intact
    res = paths_to_target(g, S.OWNED_START, S.HIGH_VALUE_TARGET)
    assert [e["kind"] for e in res["path"]["edges"]] == [
        "ForceChangePassword", "GenericWrite", "WriteDacl", "AddSelf", "GenericAll"]
    print("  the BloodHound-only graph is unchanged — no cert nodes, no ESC, ACL route intact: PASS")


if __name__ == "__main__":
    test_cert_nodes_typed_with_props()
    test_esc_kinds_are_abusable_and_context_is_structural()
    test_direct_esc1_enrollee_reaches_domain_admins()
    test_esc4_is_a_two_hop_reconfigure_then_abuse()
    test_esc7_is_a_two_hop_through_the_ca()
    test_esc2_esc3_esc6_esc8_modeled()
    test_publishedto_wires_template_to_ca()
    test_canenroll_is_context_only_for_a_non_vulnerable_template()
    test_every_esc_edge_has_a_runnable_technique_and_props()
    test_esc1_technique_is_certipy_req_then_auth()
    test_bloodhound_only_graph_has_no_cert_nodes()
    print("ALL AD CS (ESC1-8) graph tests pass")
