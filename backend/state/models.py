"""The structured engagement state — what HackPit KNOWS, as objects rather than text.

WHY THIS EXISTS
Before this package, every result was a text blob. The orchestrator's "adapt to prior
results" was really "re-read the tail of the last twelve stdout buffers", and there was no
host inventory, no service list, no endpoint list, no credential store and no findings
model. You cannot reason over an attack surface when no attack surface object exists.

These are the five things a pentest actually accumulates:

    Host        something addressable    10.10.10.5, dc01.corp.local
    Service     something listening      445/tcp smb, Windows Server 2019
    Endpoint    something reachable      https://app/api/v2/users?id=1
    Credential  something you can use    svc_sql:S3cr3t! / an NTLM hash / a TGT
    Finding     something that is wrong  ESC1 on the CA, SQLi in ?id=

Everything is scoped to a ``session_id`` — the same key run records already use — so an
engagement's state is a self-contained slice and two engagements never see each other's.

DESIGN NOTES
* Every record carries ``source_run_id``. State that cannot be traced back to the command
  that produced it is not evidence, and a report built on it would be unciteable.
* ``first_seen`` / ``last_seen`` are kept so re-running a scan updates rather than
  duplicates, and so "this appeared only after we got creds" stays visible.
* These are plain dataclasses with no persistence logic — store.py owns SQLite, parsers.py
  owns tool output. Keeping them separate is what lets a parser be tested without a
  database and the store without a parser.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


def _norm(value: str | None) -> str:
    return (value or "").strip()


@dataclass
class Host:
    """Something addressable. ``address`` is the identity — an IP or a hostname."""

    session_id: str
    address: str
    hostname: str = ""
    os: str = ""
    # "up" | "down" | "" (unknown). Only ever set from evidence, never assumed.
    status: str = ""
    # Exam proof flags (OSCP/HTB). Set when the operator pastes one, or auto-captured when a
    # command's output contains one (state/parsers.py). local.txt = user/low-priv foothold;
    # proof.txt = root/SYSTEM. A host with local but not proof is "half-owned".
    local_txt: str = ""
    proof_txt: str = ""
    source_run_id: str | None = None
    first_seen: str = ""
    last_seen: str = ""

    def key(self) -> tuple[str, str]:
        return (self.session_id, _norm(self.address).lower())

    def ownership(self) -> str:
        """'' (none) | 'foothold' (local only) | 'owned' (proof captured)."""
        if self.proof_txt.strip():
            return "owned"
        if self.local_txt.strip():
            return "foothold"
        return ""


@dataclass
class Service:
    """Something listening on a host. Identity is (host, port, protocol)."""

    session_id: str
    address: str
    port: int
    proto: str = "tcp"
    name: str = ""          # "http", "microsoft-ds"
    product: str = ""       # "nginx", "Microsoft Windows RPC"
    version: str = ""
    state: str = "open"     # open | closed | filtered
    banner: str = ""
    source_run_id: str | None = None
    first_seen: str = ""
    last_seen: str = ""

    def key(self) -> tuple[str, str, int, str]:
        return (self.session_id, _norm(self.address).lower(), int(self.port), _norm(self.proto).lower())

    def label(self) -> str:
        bits = [f"{self.port}/{self.proto}"]
        if self.name:
            bits.append(self.name)
        detail = " ".join(x for x in (self.product, self.version) if x)
        if detail:
            bits.append(f"({detail})")
        return " ".join(bits)


@dataclass
class Endpoint:
    """Something reachable over HTTP. Identity is (url, method)."""

    session_id: str
    url: str
    method: str = "GET"
    status: int | None = None
    title: str = ""
    length: int | None = None
    tech: str = ""                                  # fingerprinted stack, when known
    params: list[str] = field(default_factory=list)  # discovered parameter names
    source_run_id: str | None = None
    first_seen: str = ""
    last_seen: str = ""

    def key(self) -> tuple[str, str, str]:
        return (self.session_id, _norm(self.url), _norm(self.method).upper() or "GET")


@dataclass
class Credential:
    """Something you can authenticate with.

    Identity is (kind, principal, domain) — one account can hold a password AND a hash AND
    a ticket, and those are three usable credentials, not one that keeps changing.

    `secret` holds the real value. It lives in the local, gitignored SQLite file alongside
    the run records that already contain it in plaintext output anyway. See
    state/render.py for the one switch that decides whether it reaches an LLM prompt.
    """

    session_id: str
    kind: str            # password | ntlm | hash | ticket | key | token
    principal: str       # username / account / key id
    secret: str = ""
    domain: str = ""
    # None = never tested. True/False = we have evidence either way.
    validated: bool | None = None
    note: str = ""
    source_run_id: str | None = None
    first_seen: str = ""
    last_seen: str = ""

    def key(self) -> tuple[str, str, str, str]:
        return (
            self.session_id,
            _norm(self.kind).lower(),
            _norm(self.principal).lower(),
            _norm(self.domain).lower(),
        )

    def label(self) -> str:
        who = f"{self.principal}@{self.domain}" if self.domain else self.principal
        return f"{self.kind} for {who}"


@dataclass
class Finding:
    """Something that is wrong. Identity is a fingerprint of what + where.

    Fingerprinting rather than a running id means the same issue re-detected by a later
    scan updates in place instead of appearing three times in the report.
    """

    session_id: str
    title: str
    severity: str = "info"   # info | low | medium | high | critical
    target: str = ""         # host, url or account the finding is about
    evidence: str = ""
    tool: str = ""
    reference: str = ""      # CVE, template id, technique id
    source_run_id: str | None = None
    first_seen: str = ""
    last_seen: str = ""

    def fingerprint(self) -> str:
        raw = "|".join(
            (_norm(self.title).lower(), _norm(self.target).lower(), _norm(self.reference).lower())
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def key(self) -> tuple[str, str]:
        return (self.session_id, self.fingerprint())


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(_norm(severity).lower(), 5)


@dataclass
class StateSummary:
    """Everything known for one session, ready to render."""

    hosts: list[Host] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(
            (self.hosts, self.services, self.endpoints, self.credentials, self.findings)
        )

    def counts(self) -> dict[str, int]:
        return {
            "hosts": len(self.hosts),
            "services": len(self.services),
            "endpoints": len(self.endpoints),
            "credentials": len(self.credentials),
            "findings": len(self.findings),
        }

    def to_dict(self, include_secrets: bool = False) -> dict[str, Any]:
        return {
            "counts": self.counts(),
            "hosts": [{**vars(h), "ownership": h.ownership()} for h in self.hosts],
            "services": [vars(s) for s in self.services],
            "endpoints": [vars(e) for e in self.endpoints],
            "credentials": [
                {**vars(c), **({} if include_secrets else {"secret": ""})}
                for c in self.credentials
            ],
            "findings": [{**vars(f), "fingerprint": f.fingerprint()} for f in self.findings],
        }
