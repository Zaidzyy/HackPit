"""G1 — the BloodHound collector, wired to run THROUGH the gated cockpit executor.

``bloodhound-python`` (the Linux ingestor) enumerates the domain over LDAP/SMB and writes a set
of JSON files. It is read-only, but on a real domain it is still a command against a real host,
so it runs like EVERY other cockpit command: as an argv-only ``ExecRequest`` that the human
approves, in engagement mode, where the scope-lock refuses a DC outside the engagement scope.
This module never execs anything itself — it only *builds the request* and *ingests the output*.

Two halves:
  * :func:`build_collector_request` — turn collector params + an engagement into the exact
    ``ExecRequest`` the operator approves at ``POST /cockpit/exec``. The DC/domain appear as
    argv tokens so the executor's scope-aware target-lock covers them.
  * :func:`ingest_collection` — parse a captured collection (zip / dir / json / bytes) into the
    graph and persist it against the session/engagement. :func:`classify_failure` turns a failed
    collector run (bad creds, DC unreachable, DNS) into a clean, human message.

On this branch the collector is BUILT + unit-tested against captured/sample output but not run
against a live AD lab (there is none) — see docs/AD-GRAPH.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from cockpit.models import ExecRequest

from . import store
from .parser import ParseError, parse_collection

# The collector binary. bloodhound-python (legacy) and bloodhound-ce-python (CE) share flags;
# the operator's sandbox provides whichever their BloodHound version needs.
COLLECTOR_BIN = "bloodhound-python"

# Collection methods we ask for by default: everything queryable, incl. ACLs (needed for the
# abuse edges) + sessions. "DCOnly" is offered for a quieter, DC-only pass.
DEFAULT_METHODS = "All"


@dataclass
class CollectorParams:
    """Everything needed to build a collector invocation against a real domain."""

    domain: str                                  # e.g. sevenkingdoms.local
    username: str                                # a low-priv domain user (the owned principal)
    # The DC to query, and it must be the FQDN — bloodhound-python rejects a bare IP here
    # ("looks like an IP address, but requires a hostname"). Point `nameserver` at the DC's IP
    # so the FQDN resolves. Whichever form is used, it must be inside the engagement scope.
    dc: str
    password: str | None = None                  # OR a hash / kerberos
    nthash: str | None = None                    # -hashes :NTHASH  (pass-the-hash)
    nameserver: str | None = None                # -ns  (usually the DC's IP; must be in scope)
    collection_methods: str = DEFAULT_METHODS    # -c
    use_zip: bool = True                         # --zip the JSON output set
    dns_tcp: bool = False                         # --dns-tcp (when UDP/53 is filtered)
    extra_args: list[str] = field(default_factory=list)  # escape hatch (operator-supplied)

    def redacted(self) -> dict[str, Any]:
        """A log/telemetry-safe view — the secret is never echoed."""
        return {
            "domain": self.domain,
            "username": self.username,
            "dc": self.dc,
            "auth": "nthash" if self.nthash else ("password" if self.password else "none"),
            "nameserver": self.nameserver,
            "collection_methods": self.collection_methods,
        }


def _validate(p: CollectorParams) -> None:
    for name, val in (("domain", p.domain), ("username", p.username), ("dc", p.dc)):
        if not (val or "").strip():
            raise ValueError(f"collector needs a {name}")
        if any(c.isspace() for c in val.strip()):
            raise ValueError(f"collector {name} must be a single token (no spaces)")
    if not (p.password or p.nthash):
        raise ValueError("collector needs a password or an NT hash for the domain user")
    if p.nthash and not re.fullmatch(r"[0-9a-fA-F]{32}", p.nthash.strip()):
        raise ValueError("nthash must be 32 hex chars (the NT half of the NTLM hash)")


def build_collector_argv(p: CollectorParams) -> list[str]:
    """The full argv for ``bloodhound-python`` (command first). Argv-only — no shell, so the
    executor runs it token-for-token and the DC/domain/nameserver are inspectable tokens the
    scope-lock checks."""
    _validate(p)
    args: list[str] = [
        "-u", p.username,
        "-d", p.domain,
        "-dc", p.dc,
        "-c", p.collection_methods,
    ]
    if p.nthash:
        args += ["--hashes", f":{p.nthash.strip()}"]
    elif p.password:
        args += ["-p", p.password]
    if p.nameserver:
        args += ["-ns", p.nameserver]
    if p.dns_tcp:
        args.append("--dns-tcp")
    if p.use_zip:
        args.append("--zip")
    args += [a for a in p.extra_args if isinstance(a, str)]
    return [COLLECTOR_BIN, *args]


def build_collector_request(
    p: CollectorParams, engagement_id: str, session_id: str | None = None
) -> ExecRequest:
    """The ``ExecRequest`` the operator approves to run the collector in ENGAGEMENT mode.

    ``engagement_id`` is REQUIRED — collection runs against a real domain, so it must be a
    scoped engagement (the executor refuses an unknown/exited id and scope-locks the DC). This
    returns the request UNAPPROVED: nothing runs until the human sets approved=true at the
    exec endpoint, exactly like every other cockpit command. There is no batch path.
    """
    if not (engagement_id or "").strip():
        raise ValueError(
            "the collector runs against a real domain — it requires an active engagement "
            "(enter engagement mode + set the scope to the AD hosts/CIDR first)"
        )
    argv = build_collector_argv(p)
    return ExecRequest(
        command=argv[0],
        args=argv[1:],
        approved=False,                 # NEVER pre-approved — the human approves at exec time
        engagement_id=engagement_id.strip(),
        session_id=session_id,
    )


# --- failure classification ------------------------------------------------- #
# Signatures in bloodhound-python's stderr for the common, actionable failure modes.
_FAILURE_SIGNS = [
    # FIRST, deliberately. bloodhound-python refuses an IP for -dc, and the very message it
    # prints also says "Use the -ns flag to specify a DNS server IP" — which the generic DNS
    # signature below matches. Ordered after it, the operator would be told to fix their
    # nameserver when the actual problem is the -dc value. Build #9's first live collection
    # against a real domain failed exactly here, and the classifier had nothing to say about it.
    (re.compile(r"looks like an IP address, but requires a hostname", re.I),
     "bloodhound-python needs the DC's FQDN for -dc, not its IP (e.g. dc01.corp.local) — keep "
     "-ns pointed at the DC's IP so that name resolves"),
    (re.compile(r"STATUS_LOGON_FAILURE|invalid credentials|authenticationexception", re.I),
     "authentication failed — check the username / password / hash and the domain"),
    (re.compile(r"STATUS_ACCOUNT_LOCKED_OUT", re.I),
     "the domain account is locked out"),
    (re.compile(r"STATUS_PASSWORD_EXPIRED|password.*expired", re.I),
     "the domain account's password is expired"),
    (re.compile(r"clock skew|KRB_AP_ERR_SKEW", re.I),
     "kerberos clock skew — sync the sandbox clock to the DC"),
    (re.compile(r"could not resolve|name or service not known|dns", re.I),
     "DNS/name resolution failed — point -ns at the DC's IP (and try --dns-tcp)"),
    (re.compile(r"connection refused|timed out|no route to host|unreachable|errno", re.I),
     "the DC was unreachable — check the -dc host, the network route, and the scope"),
]


def classify_failure(exit_code: int | None, stdout: str, stderr: str) -> tuple[bool, str]:
    """(failed, reason) for a finished collector run. A non-zero exit OR no output files is a
    failure; the reason names the most likely actionable cause when a signature matches."""
    blob = f"{stdout}\n{stderr}"
    for rx, msg in _FAILURE_SIGNS:
        if rx.search(blob):
            return True, msg
    if exit_code not in (0, None):
        return True, f"collector exited {exit_code} — see the run output for details"
    return False, ""


# --- ingest a captured collection ------------------------------------------- #
def ingest_collection(
    source: Any,
    session_id: str | None,
    engagement_id: str | None = None,
    origin: str = "collector",
) -> dict[str, Any]:
    """Parse a captured BloodHound collection and persist it against the session/engagement.

    ``source`` is anything :func:`parse_collection` accepts (zip / dir / json path / bytes /
    decoded mapping). Returns ``{graph_id, domain, stats, warnings}``. Raises
    :class:`ParseError` if the collection can't be parsed (the caller maps that to a clean
    HTTP error).
    """
    graph = parse_collection(source)          # raises ParseError on junk
    graph_dict = graph.to_dict()
    graph_id = store.save_graph(graph_dict, session_id, engagement_id, source=origin)
    return {
        "graph_id": graph_id,
        "domain": graph.domain,
        "stats": graph.stats(),
        "warnings": graph.warnings,
    }


__all__ = [
    "COLLECTOR_BIN",
    "CollectorParams",
    "ParseError",
    "build_collector_argv",
    "build_collector_request",
    "classify_failure",
    "ingest_collection",
]
