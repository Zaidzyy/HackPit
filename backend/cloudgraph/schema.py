"""The normalized cloud IAM graph schema the parser produces and the UI + path engine consume.

The cloud parallel to ``adgraph/schema.py``. Deliberately independent of any one tool's on-disk
shape (ScoutSuite's results tree, Prowler's OCSF findings, pacu's session db, cloudfox's loot):
the parser (``parser.py``) is the ONLY thing that speaks those wire formats; everything
downstream speaks this stable schema. A node is a typed principal or resource; an edge is a
directed relationship whose ``kind`` names the IAM right or privilege-escalation an attacker can
abuse to move from one to the next.

Multi-cloud by construction: every node carries a ``provider`` (aws | azure | gcp), so ONE engine
routes an AWS, Azure or GCP privesc path with no per-cloud branching in the path engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# --- providers -------------------------------------------------------------- #
PROVIDERS = ("aws", "azure", "gcp")

# --- node types (principals + the resources a privesc chain touches) -------- #
# Principals: user, role, group, serviceaccount (GCP SA / Azure service principal / managed
# identity). Resources: bucket, function, secret, kmskey, policy, and the account/subscription/
# project root. ``resource`` is the neutral fallback for anything referenced but not typed.
NODE_TYPES = (
    "user", "role", "group", "serviceaccount",
    "bucket", "function", "secret", "kmskey", "policy", "account", "resource",
)
PRINCIPAL_TYPES = frozenset({"user", "role", "group", "serviceaccount"})

# --- edge taxonomy ---------------------------------------------------------- #
# Structural edges wire the account together (who is in what, what holds what). The path engine
# never traverses these; the UI renders them but lights the route over the ABUSABLE set only.
STRUCTURAL_EDGES = frozenset({
    "Contains",     # account/subscription/project -> a resource it owns
    "HasPolicy",    # principal -> a policy attached to it (context, not a step)
    "Trusts",       # role trust policy: which principals MAY assume it (context)
})

# Abusable edges — the traversable set an attacker walks toward an admin/owner principal. Each
# maps to a concrete abuse technique (see techniques.py). Order here is also a rough "directness"
# rank used to break ties between equal-length paths (a quieter / more direct abuse wins).
ABUSABLE_EDGES: tuple[str, ...] = (
    # inherited — you already hold the target's rights (no command; see techniques.no_command)
    "MemberOf",                 # user/SA -> group : you already inherit the group's permissions
    # --- AWS IAM privilege escalation ------------------------------------- #
    "AssumeRole",               # sts:AssumeRole -> role : become a more-privileged role
    "AddUserToGroup",           # iam:AddUserToGroup -> group : add yourself, inherit its policies
    "AttachUserPolicy",         # iam:AttachUserPolicy -> principal : attach AdministratorAccess
    "AttachRolePolicy",         # iam:AttachRolePolicy -> role
    "AttachGroupPolicy",        # iam:AttachGroupPolicy -> group
    "PutUserPolicy",            # iam:PutUserPolicy -> principal : inline an allow-* policy
    "PutRolePolicy",            # iam:PutRolePolicy -> role
    "CreatePolicyVersion",      # iam:CreatePolicyVersion -> policy : rewrite an attached policy
    "SetDefaultPolicyVersion",  # iam:SetDefaultPolicyVersion -> policy : roll back to an admin ver
    "UpdateAssumeRolePolicy",   # iam:UpdateAssumeRolePolicy -> role : let yourself assume it
    "CreateAccessKey",          # iam:CreateAccessKey -> user : mint long-lived creds as them
    "CreateLoginProfile",       # iam:CreateLoginProfile / UpdateLoginProfile -> user : console pw
    "PassRole",                 # iam:PassRole (+ a service that runs it) -> role
    "UpdateFunctionCode",       # lambda:UpdateFunctionCode -> function : run code as its role
    "CreateFunction",           # lambda:CreateFunction + PassRole -> function
    "RunInstances",             # ec2:RunInstances + PassRole -> role (instance profile)
    "ReadSecret",               # secretsmanager:GetSecretValue / ssm:GetParameter -> secret
    "DecryptKey",               # kms:Decrypt -> kmskey : unwrap a data key / stored secret
    # --- Azure ------------------------------------------------------------- #
    "OwnerOnSelf",              # Microsoft.Authorization/roleAssignments/write -> grant self Owner
    "AddAppCredential",         # add a password/cert to an app registration -> auth as its SP
    "RunCommandVM",             # Microsoft.Compute/.../runCommand -> code as the VM's identity
    "AKSAdminCreds",            # listClusterAdminCredential -> cluster-admin on AKS
    # --- GCP --------------------------------------------------------------- #
    "ServiceAccountTokenCreator",  # iam.serviceAccounts.getAccessToken -> impersonate the SA
    "ActAs",                       # iam.serviceAccounts.actAs (+ deploy) -> run as the SA
    "SetIamPolicy",                # *.setIamPolicy -> grant yourself a role on a resource
    "DeployFunctionAs",            # cloudfunctions deploy --service-account -> run as the SA
)

_ABUSABLE_SET = frozenset(ABUSABLE_EDGES)
_ABUSE_RANK = {k: i for i, k in enumerate(ABUSABLE_EDGES)}


def is_abusable(kind: str) -> bool:
    return kind in _ABUSABLE_SET


def abuse_rank(kind: str) -> int:
    """Lower = preferred when two paths are the same length (quieter / more direct abuse)."""
    return _ABUSE_RANK.get(kind, len(ABUSABLE_EDGES))


@dataclass
class Node:
    """One cloud principal or resource. ``id`` is the stable identity — an ARN (AWS), an object
    id / resource id (Azure), or a full resource name (GCP). ``label`` is the display name."""

    id: str
    type: str                                   # one of NODE_TYPES
    label: str
    provider: str = ""                          # aws | azure | gcp | "" (unknown)
    props: dict[str, Any] = field(default_factory=dict)

    # convenience flags the UI + path engine lean on (derived at parse time)
    high_value: bool = False                    # admin/owner-equivalent — reaching it is the win
    owned: bool = False                         # a principal we already control (start / captured)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "provider": self.provider,
            "high_value": self.high_value,
            "owned": self.owned,
            "props": self.props,
        }


@dataclass
class Edge:
    """A directed relationship ``source -> target`` of a given ``kind`` (an edge-taxonomy name).
    ``abusable`` is precomputed. ``props`` carries edge-specific detail (the service that runs a
    PassRole, the permission that granted the edge, whether it came from an inline policy)."""

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
    """A parsed cloud IAM graph: nodes keyed by id + a de-duplicated edge list, plus the account
    context (account id / subscription / project) and any collection warnings the parser raised."""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    provider: str | None = None
    account: str | None = None
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
        if node.type != "resource" or existing.type == "resource":
            existing.type = node.type or existing.type
        if node.label and (not existing.label or existing.label == existing.id):
            existing.label = node.label
        if node.provider and not existing.provider:
            existing.provider = node.provider
        existing.high_value = existing.high_value or node.high_value
        existing.owned = existing.owned or node.owned
        return existing

    def add_edge(self, edge: Edge) -> bool:
        """Add an edge unless an identical (source,target,kind) already exists. Returns True if
        it was added. Self-loops are dropped."""
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
            "provider": self.provider,
            "account": self.account,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "stats": self.stats(),
            "warnings": self.warnings,
        }
