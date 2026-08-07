"""Pluggable severity rankers — open·kritt's ``severityRankers.js`` + ``defaultSeverityRankers.js``.

WHAT THIS IS
A **ranker** is a small, per-engagement-selectable rule set that (re)scores a finding's severity.
The producer states a severity; the ranker gives the *operator's engagement* the final word — a
bug-bounty engagement weights RCE / auth-bypass / loss-of-funds up and best-practice noise down,
a compliance engagement weights crypto / missing-controls up regardless of exploitability. Same
findings, different lens.

A ranker is DATA: an ordered list of rules, each a keyword match over the finding's class / title /
reference that sets a severity. First match wins; no match keeps the producer's (normalized)
severity. This module executes nothing — it maps a finding dict to a severity string.

Ported: the pluggable-ranker registry + the shipped defaults. HackPit's twist over open·kritt is
that the rules are grounded in what HackPit's own surfaces actually emit (nuclei tags, ai-audit
vuln classes, AD/cloud edge names).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .schema import SEVERITY_LEVELS, normalize_severity

_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_LEVELS)}


@dataclass
class Rule:
    """One rescoring rule. Matches when ANY keyword appears in the finding's class/title/
    reference (word-ish, case-insensitive). ``severity`` is the level it assigns."""

    keywords: list[str]
    severity: str
    note: str = ""

    def matches(self, haystack: str) -> bool:
        return any(re.search(rf"(?<![a-z0-9]){re.escape(k)}", haystack) for k in self.keywords)


@dataclass
class Ranker:
    """A named, ordered rule set. ``clamp`` (optional) caps every finding at a ceiling — a
    compliance ranker never wants a raw 'critical' from an exploitation tool to dominate its
    control-focused view; a bug-bounty ranker leaves it uncapped."""

    id: str
    label: str
    description: str
    rules: list[Rule] = field(default_factory=list)
    clamp: str = ""            # "" = no cap

    def rescore(self, finding: dict[str, Any]) -> tuple[str, str]:
        """Return (severity, note). First matching rule wins; else the producer's severity."""
        hay = " ".join(str(finding.get(k) or "") for k in
                       ("vuln_class", "title", "reference", "tool")).lower()
        base = normalize_severity(finding.get("severity"))
        chosen, note = base, ""
        for rule in self.rules:
            if rule.matches(hay):
                chosen, note = normalize_severity(rule.severity), rule.note
                break
        if self.clamp and _SEV_RANK.get(chosen, 99) < _SEV_RANK.get(self.clamp, 99):
            chosen = self.clamp
            note = (note + " · " if note else "") + f"capped at {self.clamp} by ranker"
        return chosen, note

    def meta(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "description": self.description,
                "rules": len(self.rules), "clamp": self.clamp or None}


# --------------------------------------------------------------------------- #
# the shipped defaults (defaultSeverityRankers.js)
# --------------------------------------------------------------------------- #
# High-impact classes worth promoting on an offensive engagement.
_LOSS_OF_FUNDS = ["loss-of-funds", "loss of funds", "fund", "reentrancy", "price-manipulation",
                  "consensus", "double-spend"]
_RCE = ["rce", "remote-code-execution", "code-execution", "deserialization", "deserialisation",
        "ssti", "command-injection", "os-command", "template-injection"]
_CRITICAL_WEB = ["sqli", "sql-injection", "auth-bypass", "authentication-bypass",
                 "account-takeover", "ato", "dcsync", "golden-ticket", "domain-admin",
                 "privilege-escalation", "privesc", "imds", "metadata-service"]
_HIGH_WEB = ["ssrf", "idor", "insecure-direct-object", "xxe", "path-traversal", "lfi", "rfi",
             "file-upload", "csrf", "open-redirect", "stored-xss", "jwt", "graphql"]
_NOISE = ["informational", "best-practice", "best practice", "missing-header",
          "missing header", "security-header", "verbose-error", "banner", "version-disclosure",
          "cookie-flag", "clickjacking", "cache-control", "autocomplete"]
_CRYPTO_CONTROLS = ["tls", "ssl", "weak-cipher", "cipher", "hsts", "certificate", "crypto",
                    "hash", "md5", "sha1", "insecure-transport", "mixed-content"]
_MISCONFIG = ["misconfiguration", "misconfig", "default-credential", "directory-listing",
              "exposed", "debug-mode", "cors", "permission"]


DEFAULT_RANKERS: dict[str, Ranker] = {
    "default": Ranker(
        id="default", label="Producer severity",
        description="Keep each producer's own severity, normalized. No re-weighting — the "
                    "neutral baseline every surface has always used.",
        rules=[],
    ),
    "bug-bounty-payout": Ranker(
        id="bug-bounty-payout", label="Bug-bounty payout",
        description="Weight by what a program actually pays: RCE / loss-of-funds / auth-bypass to "
                    "the top, exploitable web classes high, best-practice noise down to info.",
        rules=[
            Rule(_LOSS_OF_FUNDS, "critical", "loss-of-funds — top payout tier"),
            Rule(_RCE, "critical", "remote code execution"),
            Rule(_CRITICAL_WEB, "critical", "auth/SQLi/takeover/DA — critical payout class"),
            Rule(_HIGH_WEB, "high", "high-impact web class"),
            Rule(_NOISE, "info", "best-practice / informational — rarely paid"),
        ],
    ),
    "compliance": Ranker(
        id="compliance", label="Compliance / audit",
        description="Weight by control coverage, not exploitability: crypto, header and "
                    "configuration gaps — the things a bug-bounty payout ranker discards as "
                    "noise — rise to medium here, and raw exploitation criticals are capped so a "
                    "control view is not dominated by a single popped host.",
        clamp="high",
        rules=[
            # the SAME missing-header the payout ranker sends to info is a control gap here.
            Rule(_CRYPTO_CONTROLS + ["missing-header", "missing header", "security-header",
                                     "cookie-flag", "clickjacking"], "medium",
                 "cryptographic / header control gap"),
            Rule(_MISCONFIG, "medium", "configuration / hardening gap"),
            Rule(["banner", "version-disclosure", "verbose-error", "autocomplete"], "low",
                 "informational control note"),
        ],
    ),
}

DEFAULT_RANKER_ID = "default"


def list_rankers() -> list[dict[str, Any]]:
    """Metadata for every registered ranker — the picker's data. Default first."""
    order = [DEFAULT_RANKER_ID] + [k for k in DEFAULT_RANKERS if k != DEFAULT_RANKER_ID]
    return [DEFAULT_RANKERS[k].meta() for k in order if k in DEFAULT_RANKERS]


def get_ranker(ranker_id: str | None) -> Ranker:
    """Resolve a ranker id to a Ranker. Unknown / blank -> the default (never raises)."""
    return DEFAULT_RANKERS.get((ranker_id or "").strip() or DEFAULT_RANKER_ID,
                               DEFAULT_RANKERS[DEFAULT_RANKER_ID])
