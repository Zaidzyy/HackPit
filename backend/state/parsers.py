"""Tool output -> typed state records.

Each parser is a pure function: text in, records out. No database, no network, no
subprocess — which means every one is testable against a captured sample with nothing
mocked, and a parser bug can never affect a run that already happened.

WHAT IS PARSED, AND FROM WHERE
Two sources, because tools split into two camps:

  * STDOUT — httpx, nuclei, ffuf and dalfox emit JSON (one object per line, or one array)
    straight to the terminal. secretsdump prints a well-known credential format.
  * LOOT FILES — nmap's real output is XML behind `-oX`/`-oA`; its stdout is a lossy human
    summary. Phase 1's loot mount is what makes this half possible: ingest.py diffs the
    run's loot directory and feeds any new file here.

DELIBERATELY NOT PARSED
BloodHound. `adgraph/` already ingests it into a typed graph with its own store, and a
second ingestion path would give two sources of truth for the same data.

EVERY PARSER MUST FAIL SOFT. Tools change their output formats, and a parser that raises
would break ingestion for a run that already completed successfully — losing the result
entirely rather than just failing to structure it. Every entry point catches broadly and
returns what it managed to extract.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable
from xml.etree import ElementTree

from .models import Credential, Endpoint, Finding, Host, Service


class Parsed:
    """What one parser extracted. Records are unsaved; ingest.py persists them."""

    def __init__(self) -> None:
        self.hosts: list[Host] = []
        self.services: list[Service] = []
        self.endpoints: list[Endpoint] = []
        self.credentials: list[Credential] = []
        self.findings: list[Finding] = []

    def extend(self, other: "Parsed") -> "Parsed":
        self.hosts += other.hosts
        self.services += other.services
        self.endpoints += other.endpoints
        self.credentials += other.credentials
        self.findings += other.findings
        return self

    def is_empty(self) -> bool:
        return not any(
            (self.hosts, self.services, self.endpoints, self.credentials, self.findings)
        )

    def counts(self) -> dict[str, int]:
        return {
            "hosts": len(self.hosts), "services": len(self.services),
            "endpoints": len(self.endpoints), "credentials": len(self.credentials),
            "findings": len(self.findings),
        }


def _json_objects(text: str) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from JSONL, a JSON array, or a single object.

    Tools are inconsistent: httpx and nuclei emit one object per line, ffuf writes an
    object containing a "results" array, dalfox writes an array. Handling all three here
    keeps every caller from re-implementing the guesswork.
    """
    text = (text or "").strip()
    if not text:
        return
    # Whole-document parse first — an array or single object.
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        doc = None
    if isinstance(doc, dict):
        yield doc
        return
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, dict):
                yield item
        return
    # Fall back to line-delimited.
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            yield obj
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    yield item


# --------------------------------------------------------------------------- #
# nmap — XML (the real output; stdout is a lossy summary)
# --------------------------------------------------------------------------- #
def parse_nmap_xml(text: str, session_id: str, run_id: str | None = None) -> Parsed:
    out = Parsed()
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return out
    if root.tag != "nmaprun":
        return out

    for host_el in root.findall("host"):
        addr = ""
        # Prefer IPv4/IPv6 over MAC — a MAC is not something you can point a tool at.
        for a in host_el.findall("address"):
            kind = a.get("addrtype", "")
            if kind in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        if not addr:
            continue
        hostname = ""
        hn = host_el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        status_el = host_el.find("status")
        status = status_el.get("state", "") if status_el is not None else ""
        os_name = ""
        osmatch = host_el.find("os/osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name", "")

        out.hosts.append(
            Host(
                session_id=session_id, address=addr, hostname=hostname, os=os_name,
                status=status, source_run_id=run_id,
            )
        )

        for port_el in host_el.findall("ports/port"):
            try:
                portno = int(port_el.get("portid", "0"))
            except ValueError:
                continue
            if not portno:
                continue
            st = port_el.find("state")
            state = st.get("state", "") if st is not None else ""
            # Closed/filtered ports are noise at scale — a -p- scan would write 65k rows.
            if state != "open":
                continue
            svc = port_el.find("service")
            out.services.append(
                Service(
                    session_id=session_id, address=addr, port=portno,
                    proto=port_el.get("protocol", "tcp"),
                    name=svc.get("name", "") if svc is not None else "",
                    product=svc.get("product", "") if svc is not None else "",
                    version=svc.get("version", "") if svc is not None else "",
                    state=state,
                    banner=svc.get("extrainfo", "") if svc is not None else "",
                    source_run_id=run_id,
                )
            )
    return out


# --------------------------------------------------------------------------- #
# httpx — JSONL of live HTTP endpoints
# --------------------------------------------------------------------------- #
def parse_httpx(text: str, session_id: str, run_id: str | None = None) -> Parsed:
    out = Parsed()
    for obj in _json_objects(text):
        url = obj.get("url") or obj.get("input") or ""
        if not isinstance(url, str) or not url.startswith("http"):
            continue
        tech = obj.get("tech") or obj.get("technologies") or []
        out.endpoints.append(
            Endpoint(
                session_id=session_id, url=url, method=str(obj.get("method") or "GET"),
                status=obj.get("status_code") if isinstance(obj.get("status_code"), int) else None,
                title=str(obj.get("title") or ""),
                length=obj.get("content_length") if isinstance(obj.get("content_length"), int) else None,
                tech=", ".join(tech) if isinstance(tech, list) else str(tech),
                source_run_id=run_id,
            )
        )
        host = obj.get("host") or ""
        if isinstance(host, str) and host and not host.startswith("http"):
            out.hosts.append(
                Host(session_id=session_id, address=host, status="up", source_run_id=run_id)
            )
    return out


# --------------------------------------------------------------------------- #
# ffuf — JSON with a "results" array
# --------------------------------------------------------------------------- #
def parse_ffuf(text: str, session_id: str, run_id: str | None = None) -> Parsed:
    out = Parsed()
    for obj in _json_objects(text):
        results = obj.get("results")
        rows = results if isinstance(results, list) else [obj]
        for row in rows:
            if not isinstance(row, dict):
                continue
            url = row.get("url") or ""
            if not isinstance(url, str) or not url.startswith("http"):
                continue
            out.endpoints.append(
                Endpoint(
                    session_id=session_id, url=url,
                    status=row.get("status") if isinstance(row.get("status"), int) else None,
                    length=row.get("length") if isinstance(row.get("length"), int) else None,
                    source_run_id=run_id,
                )
            )
    return out


# --------------------------------------------------------------------------- #
# nuclei — JSONL findings
# --------------------------------------------------------------------------- #
def parse_nuclei(text: str, session_id: str, run_id: str | None = None) -> Parsed:
    out = Parsed()
    for obj in _json_objects(text):
        info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
        template = obj.get("template-id") or obj.get("templateID") or ""
        name = info.get("name") or template
        if not name:
            continue
        matched = obj.get("matched-at") or obj.get("host") or ""
        out.findings.append(
            Finding(
                session_id=session_id, title=str(name),
                severity=str(info.get("severity") or "info").lower(),
                target=str(matched), tool="nuclei", reference=str(template),
                evidence=str(obj.get("extracted-results") or obj.get("matcher-name") or "")[:2000],
                source_run_id=run_id,
            )
        )
        if isinstance(matched, str) and matched.startswith("http"):
            out.endpoints.append(
                Endpoint(session_id=session_id, url=matched, source_run_id=run_id)
            )
    return out


# --------------------------------------------------------------------------- #
# secretsdump — the impacket credential dump format
# --------------------------------------------------------------------------- #
# user:rid:lmhash:nthash:::            (SAM / NTDS dump)
_SECRETSDUMP_NTLM = re.compile(
    r"^(?P<principal>[^:\s]+):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):(?P<nt>[a-fA-F0-9]{32}):::"
)
# DOMAIN\user:plaintext_password    (cleartext from LSA secrets)
_SECRETSDUMP_PLAIN = re.compile(
    r"^(?:(?P<domain>[^\\\s:]+)\\)?(?P<principal>[^:\s]+):(?P<secret>[^:]{1,120})\s*$"
)
# Blank NTLM hash — an account with no password set. Recording it as a usable credential
# would send you off chasing an empty hash.
_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


def parse_secretsdump(text: str, session_id: str, run_id: str | None = None) -> Parsed:
    out = Parsed()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("[") or line.startswith("*"):
            continue
        m = _SECRETSDUMP_NTLM.match(line)
        if m:
            nt = m.group("nt").lower()
            if nt == _EMPTY_NT:
                continue
            principal = m.group("principal")
            domain = ""
            if "\\" in principal:
                domain, principal = principal.split("\\", 1)
            out.credentials.append(
                Credential(
                    session_id=session_id, kind="ntlm", principal=principal, domain=domain,
                    secret=nt, note="secretsdump NT hash", source_run_id=run_id,
                )
            )
            continue
        # Only treat a line as cleartext when it looks like one — hash-shaped and
        # colon-heavy lines are handled above and must not fall through to here.
        if line.count(":") == 1 and not re.search(r"[a-fA-F0-9]{32}", line):
            m2 = _SECRETSDUMP_PLAIN.match(line)
            if m2 and m2.group("secret") not in ("", "(null)"):
                out.credentials.append(
                    Credential(
                        session_id=session_id, kind="password",
                        principal=m2.group("principal"), domain=m2.group("domain") or "",
                        secret=m2.group("secret"), note="secretsdump cleartext",
                        source_run_id=run_id,
                    )
                )
    return out


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #
#: filename suffix -> parser, for files that appear in a run's loot directory.
FILE_PARSERS = {
    ".xml": parse_nmap_xml,
}

#: tool program name -> parser, for a run's stdout.
STDOUT_PARSERS = {
    "httpx": parse_httpx,
    "httpx-toolkit": parse_httpx,
    "ffuf": parse_ffuf,
    "nuclei": parse_nuclei,
    "secretsdump.py": parse_secretsdump,
    "secretsdump": parse_secretsdump,
}


# --------------------------------------------------------------------------- #
# proof / local.txt flags (Phase 4 item 5) — captured for the OSCP report
# --------------------------------------------------------------------------- #
# HTB/OSCP flags are 32 hex chars. We only capture one when the COMMAND read a flag file
# (proof.txt/root.txt = proof; local.txt/user.txt = local), so a random 32-hex string in
# other output is never mistaken for a flag. The flag is attributed to the run's target host.
_FLAG_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_PROOF_FILE_RE = re.compile(r"\b(?:proof|root)\.txt\b", re.I)
_LOCAL_FILE_RE = re.compile(r"\b(?:local|user)\.txt\b", re.I)


def parse_proof_flags(
    command: str, text: str, target: str, session_id: str, run_id: str | None = None
) -> Parsed:
    """Capture a proof/local flag when the command read a flag file. Never raises.

    Conservative by design: the command must name the flag file, so an unrelated 32-hex hash
    (an NTLM hash, a checksum) in some other output is never captured as a flag.
    """
    out = Parsed()
    cmd = command or ""
    addr = (target or "").strip()
    if not (session_id and addr):
        return out
    reads_proof = bool(_PROOF_FILE_RE.search(cmd))
    reads_local = bool(_LOCAL_FILE_RE.search(cmd))
    if not (reads_proof or reads_local):
        return out
    m = _FLAG_RE.search(text or "")
    if not m:
        return out
    flag = m.group(0).lower()
    host = Host(session_id=session_id, address=addr, source_run_id=run_id)
    if reads_proof:
        host.proof_txt = flag
    else:
        host.local_txt = flag
    out.hosts.append(host)
    return out


def parse_stdout(program: str, text: str, session_id: str, run_id: str | None = None) -> Parsed:
    """Parse a run's stdout using the parser for that program. Never raises."""
    fn = STDOUT_PARSERS.get((program or "").strip().lower())
    if fn is None:
        return Parsed()
    try:
        return fn(text, session_id, run_id)
    except Exception:  # noqa: BLE001 - a parser must never break a completed run
        return Parsed()


def parse_file(name: str, text: str, session_id: str, run_id: str | None = None) -> Parsed:
    """Parse one loot file by extension. Never raises."""
    lowered = (name or "").lower()
    for suffix, fn in FILE_PARSERS.items():
        if lowered.endswith(suffix):
            try:
                return fn(text, session_id, run_id)
            except Exception:  # noqa: BLE001
                return Parsed()
    return Parsed()
