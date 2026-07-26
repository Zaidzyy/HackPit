"""State -> prompt text.

This is the payoff for the whole package. The orchestrator used to be handed the last
12-20 runs at 600-1600 characters each and asked to "adapt to prior results", which in
practice meant re-reading stdout tails and hoping the important line was inside the window.
It now gets the ACCUMULATED, DEDUPLICATED, STRUCTURED picture: what is up, what is
listening, what is reachable, what credentials exist, what is already known to be wrong.

The difference is not cosmetic. A tail window forgets: a service found on run 3 is gone by
run 20. State does not forget, and it costs a fraction of the tokens because each fact
appears once instead of once per run that mentioned it.

CREDENTIALS IN THE PROMPT
`INCLUDE_CREDENTIAL_SECRETS` decides whether real secret values reach the model. It is True
by default — Zaid's explicit decision, so the planner can write fully-formed commands with
no substitution step. Note what that means operationally: every captured credential is sent
to whatever LLM endpoint is configured, including a remote one. Flip this single constant
to False to send only the fact that a credential exists and what it is for; the planner can
still reason "I have creds for that account" and placeholders get filled locally instead.
"""

from __future__ import annotations

from . import tasks as task_tree
from .models import StateSummary, severity_rank

INCLUDE_CREDENTIAL_SECRETS = True

# Bounds. The point of state is that it is SMALLER than the stdout tails it replaces; an
# unbounded inventory on a /16 would be worse than what it replaced.
MAX_HOSTS = 40
MAX_SERVICES_PER_HOST = 14
MAX_ENDPOINTS = 30
MAX_FINDINGS = 25
MAX_CREDENTIALS = 25


def _host_block(state: StateSummary) -> list[str]:
    if not state.hosts and not state.services:
        return []
    by_host: dict[str, list[str]] = {}
    for svc in state.services:
        by_host.setdefault(svc.address.lower(), []).append(svc.label())

    # Hosts the services reference but that no host record exists for still matter — a
    # service is evidence the host is up.
    addresses = [h.address for h in state.hosts]
    for addr in by_host:
        if not any(a.lower() == addr for a in addresses):
            addresses.append(addr)

    lines = ["", "## Hosts and services (accumulated — this is what you actually know)"]
    for addr in addresses[:MAX_HOSTS]:
        host = next((h for h in state.hosts if h.address.lower() == addr.lower()), None)
        bits = [addr]
        if host is not None:
            if host.hostname and host.hostname.lower() != addr.lower():
                bits.append(f"({host.hostname})")
            if host.os:
                bits.append(f"os={host.os}")
        svcs = by_host.get(addr.lower(), [])
        head = " ".join(bits)
        if svcs:
            shown = svcs[:MAX_SERVICES_PER_HOST]
            more = f" +{len(svcs) - len(shown)} more" if len(svcs) > len(shown) else ""
            lines.append(f"- {head}: {', '.join(shown)}{more}")
        else:
            lines.append(f"- {head}: no services recorded yet")
    if len(addresses) > MAX_HOSTS:
        lines.append(f"- … {len(addresses) - MAX_HOSTS} more hosts")
    return lines


def _endpoint_block(state: StateSummary) -> list[str]:
    if not state.endpoints:
        return []
    lines = ["", "## HTTP endpoints seen"]
    # Interesting first: something that answered beats something that 404'd.
    ordered = sorted(
        state.endpoints,
        key=lambda e: (0 if (e.status or 0) < 400 else 1, e.status or 999, e.url),
    )
    for ep in ordered[:MAX_ENDPOINTS]:
        bits = [ep.url]
        if ep.status is not None:
            bits.append(f"[{ep.status}]")
        if ep.title:
            bits.append(f'"{ep.title[:60]}"')
        if ep.tech:
            bits.append(f"tech={ep.tech[:60]}")
        if ep.params:
            bits.append(f"params={','.join(ep.params[:6])}")
        lines.append(f"- {' '.join(bits)}")
    if len(ordered) > MAX_ENDPOINTS:
        lines.append(f"- … {len(ordered) - MAX_ENDPOINTS} more endpoints")
    return lines


def _credential_block(state: StateSummary) -> list[str]:
    if not state.credentials:
        return []
    lines = ["", "## Credentials captured"]
    for cred in state.credentials[:MAX_CREDENTIALS]:
        status = (
            "VALIDATED" if cred.validated is True
            else "failed" if cred.validated is False
            else "untested"
        )
        if INCLUDE_CREDENTIAL_SECRETS and cred.secret:
            lines.append(f"- {cred.label()} = {cred.secret} ({status})")
        else:
            lines.append(f"- {cred.label()} — value withheld ({status})")
    if len(state.credentials) > MAX_CREDENTIALS:
        lines.append(f"- … {len(state.credentials) - MAX_CREDENTIALS} more")
    if not INCLUDE_CREDENTIAL_SECRETS:
        lines.append(
            "  (Secrets are withheld from this prompt. Use the placeholder <PASSWORD> / "
            "<HASH> in your command and it is filled in locally before the command runs.)"
        )
    return lines


def _finding_block(state: StateSummary) -> list[str]:
    if not state.findings:
        return []
    lines = ["", "## Findings already established (do NOT re-discover these)"]
    ordered = sorted(state.findings, key=lambda f: (severity_rank(f.severity), f.title))
    for f in ordered[:MAX_FINDINGS]:
        where = f" on {f.target}" if f.target else ""
        ref = f" [{f.reference}]" if f.reference else ""
        lines.append(f"- {f.severity.upper()}: {f.title}{where}{ref}")
    if len(ordered) > MAX_FINDINGS:
        lines.append(f"- … {len(ordered) - MAX_FINDINGS} more findings")
    return lines


def render_state(state: StateSummary, session_id: str = "") -> str:
    """The full state block for the proposer prompt.

    Returns "" when there is nothing known, so a session with no state produces
    byte-for-byte the prompt it produced before this package existed. That property is what
    makes this safe to add to a working loop.
    """
    blocks: list[str] = []
    blocks += _host_block(state)
    blocks += _endpoint_block(state)
    blocks += _credential_block(state)
    blocks += _finding_block(state)

    tree = task_tree.render(session_id) if session_id else ""
    if tree:
        blocks += [
            "",
            "## Task tree — the live plan. [ ] to-do, [x] done, [-] not applicable.",
            tree,
            "",
            "Update it with your response: mark what this run completed, mark branches that "
            "the evidence has ruled out as not applicable, and add sub-tasks for what the "
            "results have newly opened up. Only reference task ids that exist above.",
        ]

    if not blocks:
        return ""
    counts = state.counts()
    header = (
        "",
        "ENGAGEMENT STATE — the accumulated, deduplicated picture built from every run so "
        f"far ({counts['hosts']} hosts, {counts['services']} services, "
        f"{counts['endpoints']} endpoints, {counts['credentials']} credentials, "
        f"{counts['findings']} findings). This is authoritative and it does not forget: "
        "prefer it over the raw output excerpts, and do not re-run something whose answer "
        "is already here.",
    )
    return "\n".join([*header, *blocks])
