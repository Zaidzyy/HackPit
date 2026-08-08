"""A self-contained SYNTHETIC three-lane kill chain — one web foothold, one cloud IAM enumeration,
one on-prem AD graph, stitched by the cross-domain seams into a single route to Domain Admin. Used
by the tests and by the UI's ``?demo=1`` so the kill-chain graph renders end-to-end with NO live
data — no real host, account, ARN, tenant, or domain appears here.

*** SYNTHETIC ONLY. ***

Each lane is expressed in the SAME public-dict shape the real graphs emit (``Graph.to_dict()`` —
nodes/edges with a precomputed ``abusable`` flag), so the merge path exercises the exact contract a
live lane would. The lit route the merge produces:

    web SSRF finding  --SsrfToImds-->  cloud ci-deployer  --ReadSecret-->  cloud app/prod secret
        --CloudToOnprem-->  on-prem SVC-SQL  --GenericAll-->  BACKUPADMIN  --MemberOf-->  Domain Admins

with a parallel web-RCE→host seam (WebToHost) converging on SVC-SQL, a cloud admin branch
(AttachRolePolicy → break-glass-admin), and two more seams modeled off the lit route (NodeToCloud,
OnpremToCloud) so every bridge kind is represented.
"""

from __future__ import annotations

from typing import Any

from .merge import merge_lanes
from .schema import Graph, qualify

# --- lane-local ids (all synthetic) ---------------------------------------- #
ACCOUNT = "123456789012"
REGION = "us-east-1"
DOM_SID = "S-1-5-21-1111111111-2222222222-3333333333"
DC_HOST = "dc01.sevenkingdoms.local"

# web lane
WEB_SSRF = "finding:ssrf-metadata"
WEB_RCE = "finding:rce-upload"
# cloud lane
CI_DEPLOYER = f"arn:aws:iam::{ACCOUNT}:role/ci-deployer"
BREAK_GLASS = f"arn:aws:iam::{ACCOUNT}:role/break-glass-admin"
APP_SECRET = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:app/prod-Ab12Cd"
K8S_NODE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0deadbeefeksnode"
# on-prem lane
SVC_SQL = f"{DOM_SID}-1201"
BACKUP = f"{DOM_SID}-1202"
DOMAIN_ADMINS = f"{DOM_SID}-512"
WKSTN01 = f"{DOM_SID}-1301"
APP01 = f"{DOM_SID}-1302"

# --- the merged, domain-qualified anchors the UI + tests use --------------- #
OWNED_START = qualify("web", WEB_SSRF)
HIGH_VALUE_TARGET = qualify("onprem", DOMAIN_ADMINS)


def _node(nid: str, ntype: str, label: str, *, owned: bool = False, high_value: bool = False,
          props: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"id": nid, "type": ntype, "label": label, "owned": owned,
            "high_value": high_value, "props": props or {}}


def _edge(src: str, dst: str, kind: str) -> dict[str, Any]:
    # Within-lane sample edges are ABUSABLE by construction (each is a real abuse in its own lane).
    return {"source": src, "target": dst, "kind": kind, "abusable": True, "props": {}}


def sample_web() -> dict[str, Any]:
    """The web lane: two footholds from engagement findings, each declaring a seam into another
    lane. The SSRF reaches cloud metadata (→ cloud principal); the RCE lands on a host (→ on-prem)."""
    return {
        "nodes": [
            _node(WEB_SSRF, "finding", "SSRF @ /api/fetch?url=", owned=True, props={
                "severity": "high",
                "seams": [{"kind": "SsrfToImds", "to": qualify("cloud", CI_DEPLOYER)}],
            }),
            _node(WEB_RCE, "finding", "RCE @ /upload (deserialization)", owned=True, props={
                "severity": "critical",
                "seams": [{"kind": "WebToHost", "to": qualify("onprem", WKSTN01)}],
            }),
        ],
        "edges": [],
        "warnings": [],
    }


def sample_cloud() -> dict[str, Any]:
    """The cloud lane: the IMDS-reached ci-deployer role, its admin-granting edge, and a secret it
    can read whose value is reused on-prem (CloudToOnprem seam)."""
    return {
        "nodes": [
            _node(CI_DEPLOYER, "role", "ci-deployer"),
            _node(BREAK_GLASS, "role", "break-glass-admin", high_value=True),
            _node(APP_SECRET, "secret", "app/prod", props={
                # the secret's value is an AD credential — the seam into the on-prem lane
                "seams": [{"kind": "CloudToOnprem", "to": qualify("onprem", SVC_SQL),
                           "props": {"dc_host": DC_HOST}}],
            }),
            _node(K8S_NODE, "resource", "eks-node-1", props={
                # a compute/K8s node whose instance role is ci-deployer (NodeToCloud seam)
                "seams": [{"kind": "NodeToCloud", "to": qualify("cloud", CI_DEPLOYER)}],
            }),
        ],
        "edges": [
            _edge(CI_DEPLOYER, BREAK_GLASS, "AttachRolePolicy"),
            _edge(CI_DEPLOYER, APP_SECRET, "ReadSecret"),
        ],
        "warnings": [],
    }


def sample_onprem() -> dict[str, Any]:
    """The on-prem AD lane: the reused SVC-SQL credential routes to Domain Admins; a host reached
    from the web RCE has a SVC-SQL session (WebToHost converges here); one box bridges back to the
    cloud (OnpremToCloud seam)."""
    return {
        "nodes": [
            _node(SVC_SQL, "user", "SVC-SQL@SEVENKINGDOMS.LOCAL", props={"dc_host": DC_HOST}),
            _node(BACKUP, "user", "BACKUPADMIN@SEVENKINGDOMS.LOCAL"),
            _node(DOMAIN_ADMINS, "group", "DOMAIN ADMINS@SEVENKINGDOMS.LOCAL", high_value=True),
            _node(WKSTN01, "computer", "WKSTN01.SEVENKINGDOMS.LOCAL"),
            _node(APP01, "computer", "APP01.SEVENKINGDOMS.LOCAL", props={
                "seams": [{"kind": "OnpremToCloud", "to": qualify("cloud", BREAK_GLASS)}],
            }),
        ],
        "edges": [
            _edge(SVC_SQL, BACKUP, "GenericAll"),
            _edge(BACKUP, DOMAIN_ADMINS, "MemberOf"),
            _edge(WKSTN01, SVC_SQL, "HasSession"),
        ],
        "warnings": [],
    }


def sample_lanes() -> dict[str, Any]:
    """The three lane dicts, keyed by domain — the exact input the merge (and the app layer) take."""
    return {"web": sample_web(), "cloud": sample_cloud(), "onprem": sample_onprem()}


def sample_graph() -> Graph:
    """The merged, stitched three-lane graph the demo route + the tests run over."""
    lanes = sample_lanes()
    return merge_lanes(web=lanes["web"], cloud=lanes["cloud"], onprem=lanes["onprem"])
