"""2.5 — the skeptic pass. A second look that tries to REFUTE a proposal before a human sees it.

Confident hallucination is the top hard-box failure mode: the model cites a CVE that does not
apply to the version actually observed, or targets a service that is not in state at all, and
says it with total confidence. A generalist proposer cannot catch itself doing this; a dedicated
critic can, cheaply, because the checks are concrete:

* Does the cited CVE actually apply to the version in STATE? This reuses the CVE->exploit
  index's rule that the VERSION VERDICT OUTRANKS TOKEN SIMILARITY — a CVE whose exploit targets
  Apache 2.4.49 does not apply to an observed 2.4.58, no matter how well the words match. That is
  the single check that kills the most confident wrong answers.
* Does the service the proposal leans on actually EXIST in state, or is it invented?
* Is the target host one we have actually seen?

The critic never blocks and never executes: it returns a verdict — pass, or downrank with the
concerns spelled out — so the UI can show the human WHY a proposal is shaky. Downrank, not kill,
because a critic that silently deletes proposals is its own failure mode; the human still decides.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_CVE_RE = re.compile(r"CVE[-\s]?\d{4}[-\s]?\d{4,7}", re.IGNORECASE)


@dataclass
class Critique:
    ok: bool = True                       # passed every check it could run
    downrank: bool = False                # keep it, but de-prioritise + flag
    confidence: float = 1.0               # 0..1, dropped by each concern
    concerns: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)   # what actually ran (evidence, per the rule)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "downrank": self.downrank,
            "confidence": round(self.confidence, 2),
            "concerns": list(self.concerns),
            "checks": list(self.checks),
        }


def _cves(proposal: dict[str, Any]) -> list[str]:
    """Every CVE the proposal leans on — in its citations, its reference, or its command."""
    blob = " ".join(
        [
            str(proposal.get("command") or ""),
            " ".join(str(a) for a in (proposal.get("args") or [])),
            str(proposal.get("reference") or ""),
            str(proposal.get("hypothesis") or ""),
            str(proposal.get("rationale") or ""),
            " ".join(
                str(c.get("id") or "") for c in (proposal.get("citations") or [])
                if isinstance(c, dict)
            ),
        ]
    )
    out: list[str] = []
    for m in _CVE_RE.finditer(blob):
        cve = re.sub(r"\s+", "-", m.group(0).upper())
        if cve not in out:
            out.append(cve)
    return out


def _shares_token(product: str, tokens: list[str]) -> bool:
    p = (product or "").lower()
    return any(t and t.lower() in p for t in tokens)


def _cve_applies(index: Any, cve: str, state: Any) -> tuple[str, str]:
    """Best verdict of a CVE against the versions actually in STATE.

    Returns (verdict, detail) where verdict is one of the index's tiers ("exact"/"in-range"/
    "line"/"product-only"/"different") or "no-service" when nothing in state shares the CVE's
    product. This is where the version-verdict-outranks-token rule does its work.
    """
    try:
        entries = index.for_cve(cve)
    except Exception:  # noqa: BLE001 — a missing/odd index must never break the loop
        return "no-index", "exploit index unavailable"
    if not entries:
        return "unknown-cve", "the CVE is not in the exploit index"

    best_rank = -1
    best = ("no-service", "the cited CVE's product is not among the observed services")
    order = {"different": 0, "product-only": 1, "line": 2, "in-range": 3, "exact": 4}
    for svc in getattr(state, "services", []) or []:
        version = (getattr(svc, "version", "") or "").strip()
        product = getattr(svc, "product", "") or getattr(svc, "name", "")
        for e in entries:
            if not _shares_token(product, e.get("tokens", [])):
                continue
            if not version:
                verdict, detail = "product-only", f"{product} present, version unknown"
            else:
                try:
                    from exploits.index import version_tuple

                    verdict, _s, why = index._version_verdict(e, version, version_tuple(version))
                except Exception:  # noqa: BLE001
                    continue
                detail = f"observed {product} {version}: {why}"
            r = order.get(verdict, 0)
            if r > best_rank:
                best_rank, best = r, (verdict, detail)
    return best


def critique(proposal: dict[str, Any], state: Any, index: Any = None) -> Critique:
    """Refute-first review of one proposal against the accumulated state.

    ``index`` is the CVE->exploit index (exploits.index.ExploitIndex); pass None to skip the CVE
    checks. Pure and read-only — it inspects data and returns a verdict.
    """
    c = Critique()

    # --- CVE ↔ observed version (the load-bearing check) ------------------- #
    if index is not None:
        for cve in _cves(proposal):
            verdict, detail = _cve_applies(index, cve, state)
            c.checks.append(f"CVE {cve} vs state: {verdict} ({detail})")
            if verdict == "different":
                c.ok = False
                c.downrank = True
                c.confidence -= 0.6
                c.concerns.append(
                    f"{cve} does not apply to the observed version — {detail}. The version "
                    "verdict outranks the keyword match; this is likely a confident mismatch."
                )
            elif verdict in ("no-service", "unknown-cve"):
                c.confidence -= 0.2
                c.concerns.append(
                    f"{cve}: {detail} — the exploit cannot be tied to anything in state yet."
                )

    # --- service existence ------------------------------------------------- #
    # A PORT is a colon-prefixed number (host:8080, url :8443) or a -p/-port flag value — NEVER a
    # bare number, so an IP octet ("10.10.10.5") and a query value ("?id=1") are not misread as
    # ports (that false positive showed up in the first live run against Ollama).
    argline = " ".join(str(a) for a in (proposal.get("args") or []))
    port_toks = re.findall(r":(\d{2,5})\b", argline) + re.findall(r"-p(?:ort)?\s+(\d{2,5})\b", argline)
    named_ports = {int(p) for p in port_toks if 0 < int(p) <= 65535}
    state_ports = {int(getattr(s, "port", 0)) for s in getattr(state, "services", []) or []}
    # Only a concern when the proposal explicitly leans on a service (an exploit hypothesis),
    # not for recon that is trying to DISCOVER ports.
    hypothesis = str(proposal.get("hypothesis") or "").lower()
    leans_on_service = any(w in hypothesis for w in ("exploit", "vulnerab", "inject", "rce", "auth", "bypass"))
    if leans_on_service and state_ports and named_ports and not (named_ports & state_ports):
        c.confidence -= 0.15
        c.concerns.append(
            "the proposal targets a port that is not among the services recorded in state — "
            "confirm the service exists before exploiting it."
        )
        c.checks.append(f"service check: proposal ports {sorted(named_ports)} vs state {sorted(state_ports)}")
    elif state_ports:
        c.checks.append("service check: state has recorded services to ground against")

    c.confidence = max(0.0, min(1.0, c.confidence))
    if not c.concerns:
        c.checks.append("no refutation found — proposal is consistent with the evidence")
    return c
