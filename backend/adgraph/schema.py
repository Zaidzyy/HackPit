"""The normalized AD graph schema the parser produces and the UI + path engine consume.

Deliberately independent of BloodHound's on-disk shape (which differs across v4 / v5 / CE):
the parser (``parser.py``) is the ONLY thing that knows the wire format; everything downstream
speaks this stable schema. A node is a typed principal/object; an edge is a directed
relationship whose ``kind`` names the AD right or abuse that connects them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# --- node types (BloodHound's object taxonomy, lower-cased + stable) -------- #
# `certtemplate` / `certauthority` are AD CS objects: they come from a certipy `find` ingest
# (see parser._ingest_certipy), not from BloodHound's core files, but they live in the SAME
# graph so the same path engine can walk an ESC chain (enrollee → vulnerable template → DA).
NODE_TYPES = ("user", "group", "computer", "domain", "ou", "gpo", "container",
              "certtemplate", "certauthority")

# --- edge taxonomy ---------------------------------------------------------- #
# Every edge kind the parser can emit. Split into structural (how the directory is wired)
# and ABUSABLE (a path an attacker can traverse). The path engine walks ONLY abusable
# edges; the UI renders all of them but lights the route over the abusable set.
STRUCTURAL_EDGES = frozenset({
    "Contains",     # OU/container -> child object
    "GpLink",       # GPO -> OU/domain it is linked to
    "TrustedBy",    # domain trust direction
    # AD CS context (NOT traversed — they wire the cert objects into the graph so the drawer can
    # show where a template is published and who may enrol, without inventing an abuse path):
    "PublishedTo",  # certtemplate -> certauthority it is published on
    "CanEnroll",    # principal -> certtemplate it may enrol (when the template is NOT vulnerable)
})

# Abusable edges — the traversable set BloodHound uses to reach Domain Admin. Each maps to a
# concrete abuse technique (see techniques.py). Order here is also a rough "directness" rank
# used only for tie-breaking equal-length paths (a cheaper/quieter abuse wins).
ABUSABLE_EDGES: tuple[str, ...] = (
    "MemberOf",              # principal -> group (inherits the group's rights)
    "DCSync",                # principal -> domain (replicate secrets => full compromise)
    # --- AD CS (ESC1-8) -------------------------------------------------------- #
    # Synthesized from a certipy `find` ingest exactly like DCSync is synthesized from the two
    # replication rights: a (template-vuln x enroll-right) predicate collapses to one composite
    # edge from a low-priv enrollee to the domain's Domain Admins. ESC1/ESC6/ESC8 are the direct,
    # most-common wins, so they rank high (near DCSync) for the equal-length tie-break; ESC4/ESC7
    # are reconfigure-then-abuse and target the template/CA node (a two-hop shape), so they sit a
    # little lower. See techniques.py for each one's abuse command.
    "ESC1",                  # enrollee -> DA : enrollee-supplied SAN + client-auth EKU + enroll
    "ESC6",                  # enrollee -> DA : CA EDITF_ATTRIBUTESUBJECTALTNAME2 (any template)
    "ESC8",                  # computer -> CA : NTLM relay to web enrollment (certsrv)
    "ESC2",                  # enrollee -> DA : Any-Purpose (or no) EKU
    "ESC3",                  # enrollee -> DA : Enrollment Agent template (enroll on behalf of)
    "ESC4",                  # principal -> certtemplate : write over the template (-> ESC1)
    "ESC7",                  # principal -> certauthority : ManageCA / ManageCertificates
    "AllExtendedRights",     # -> user/domain (incl. the DCSync/GetChanges rights)
    "GenericAll",            # full control over the target object
    "GenericWrite",          # write any non-protected attribute
    "WriteDacl",             # rewrite the target's DACL (grant yourself rights)
    "WriteOwner",            # take ownership, then grant yourself rights
    "Owns",                  # already owner -> can rewrite the DACL
    "AddMember",             # add a principal to a group
    "AddSelf",               # add yourself to a group
    "ForceChangePassword",   # reset the target user's password
    "AddKeyCredentialLink",  # shadow-credentials the target (msDS-KeyCredentialLink)
    "AddAllowedToAct",       # write msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
    "ReadLAPSPassword",      # read the local admin password
    "ReadGMSAPassword",      # read a gMSA's managed password
    "AllowedToDelegate",     # constrained delegation (S4U) to a target service
    "AllowedToAct",          # resource-based constrained delegation on the target
    "HasSIDHistory",         # SID history grants the referenced principal's access
    "AdminTo",               # local admin on a computer
    "CanRDP",                # interactive logon via RDP
    "CanPSRemote",           # PowerShell Remoting (WinRM)
    "ExecuteDCOM",           # code exec via DCOM
    "HasSession",            # a session whose token/creds can be harvested
    "SQLAdmin",              # sysadmin on a SQL instance the computer hosts
)

_ABUSABLE_SET = frozenset(ABUSABLE_EDGES)
_ABUSE_RANK = {k: i for i, k in enumerate(ABUSABLE_EDGES)}


def is_abusable(kind: str) -> bool:
    return kind in _ABUSABLE_SET


def abuse_rank(kind: str) -> int:
    """Lower = preferred when two paths are the same length (quieter/more-direct abuse)."""
    return _ABUSE_RANK.get(kind, len(ABUSABLE_EDGES))


@dataclass
class Node:
    """One AD object. ``id`` is the BloodHound ObjectIdentifier (a SID, or a GUID for
    GPO/OU/container). ``label`` is the display name (``user@DOMAIN`` style)."""

    id: str
    type: str                                   # one of NODE_TYPES
    label: str
    props: dict[str, Any] = field(default_factory=dict)

    # convenience flags the UI + path engine lean on (derived at parse time)
    high_value: bool = False                    # Domain Admins, the domain, DCs, etc.
    owned: bool = False                         # marked as an owned/start principal

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "high_value": self.high_value,
            "owned": self.owned,
            "props": self.props,
        }


@dataclass
class Edge:
    """A directed relationship ``source -> target`` of a given ``kind`` (an edge taxonomy
    name). ``abusable`` is precomputed. ``props`` carries edge-specific detail (e.g. the SPN
    for AllowedToDelegate, whether an ACE was inherited)."""

    source: str
    target: str
    kind: str
    abusable: bool = False
    props: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str, str]:
        return (self.source, self.target, self.kind)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "abusable": self.abusable,
            "props": self.props,
        }


@dataclass
class Graph:
    """A parsed AD graph: nodes keyed by id + a de-duplicated edge list, plus the domain
    context and any collection warnings the parser surfaced."""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    domain: str | None = None
    warnings: list[str] = field(default_factory=list)
    _edge_keys: set[tuple[str, str, str]] = field(default_factory=set, repr=False)

    # -- mutation (parser-side) ------------------------------------------- #
    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        # merge: keep the richer record, OR the derived flags together
        existing.props.update({k: v for k, v in node.props.items() if v not in (None, "")})
        if node.type != "container" or existing.type == "container":
            existing.type = node.type or existing.type
        if node.label and (not existing.label or existing.label == existing.id):
            existing.label = node.label
        existing.high_value = existing.high_value or node.high_value
        existing.owned = existing.owned or node.owned
        return existing

    def add_edge(self, edge: Edge) -> bool:
        """Add an edge unless an identical (source,target,kind) already exists. Returns
        True if it was added. Self-loops are dropped."""
        if edge.source == edge.target:
            return False
        edge.abusable = is_abusable(edge.kind)
        k = edge.key()
        if k in self._edge_keys:
            return False
        self._edge_keys.add(k)
        self.edges.append(edge)
        return True

    # -- queries (engine + UI) -------------------------------------------- #
    def outgoing(self, node_id: str, abusable_only: bool = False) -> Iterable[Edge]:
        for e in self.edges:
            if e.source != node_id:
                continue
            if abusable_only and not e.abusable:
                continue
            yield e

    def node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def high_value_nodes(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.high_value]

    def stats(self) -> dict[str, int]:
        by_type: dict[str, int] = {}
        for n in self.nodes.values():
            by_type[n.type] = by_type.get(n.type, 0) + 1
        abusable = sum(1 for e in self.edges if e.abusable)
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "abusable_edges": abusable,
            **{f"node_{t}": c for t, c in by_type.items()},
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "stats": self.stats(),
            "warnings": self.warnings,
        }
