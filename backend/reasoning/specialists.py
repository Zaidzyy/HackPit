"""2.6 — domain-specialist routing. One generalist prompt is shallower than four specialists.

A web finding, an AD state, a binary to pwn and a privesc foothold call for different knowledge,
different tools and a different KB slice. Routing the proposal to a domain-specialized prompt +
KB filter (the offensive-* skill families) instead of one generalist raises the ceiling on each.

This module classifies the current engagement situation into a domain from the EVIDENCE — the
services in state, the findings, the last command — and returns the specialist to consult: its
prompt fragment, its KB search tags, and the offensive-* skill it corresponds to. It proposes
nothing and runs nothing; it selects which expert voice the proposer speaks in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Specialist:
    domain: str                       # web | active-directory | binary-pwn | privesc | generalist
    skill: str                        # the offensive-* skill family this maps to
    kb_tags: tuple[str, ...] = ()     # tags/terms to bias KB retrieval toward
    prompt: str = ""                  # the specialist framing appended to the proposer prompt


_WEB = Specialist(
    "web", "offensive-xss / offensive-sqli / offensive-idor / offensive-ssrf",
    ("web", "http", "injection", "idor", "ssrf", "xss", "sqli", "auth-bypass"),
    "SPECIALIST — WEB: reason as a web-app tester. Enumerate endpoints and parameters first, "
    "fingerprint the stack, then test one bug class at a time against a parameter you actually "
    "SAW (SQLi/XSS/IDOR/SSRF/auth). Prefer a targeted probe over a broad scanner once you have a "
    "candidate.",
)
_AD = Specialist(
    "active-directory", "offensive-active-directory",
    ("active directory", "kerberos", "smb", "ldap", "ntlm", "bloodhound", "domain"),
    "SPECIALIST — ACTIVE DIRECTORY: reason as an AD operator. Enumerate the domain (users, "
    "SPNs, shares, delegation), harvest and validate credentials, and think in terms of the "
    "attack PATH to Domain Admin (Kerberoast -> crack -> lateral -> DCSync), one approved step "
    "at a time.",
)
_PWN = Specialist(
    "binary-pwn", "offensive-exploit-development / offensive-basic-exploitation",
    ("binary", "buffer overflow", "rop", "pwn", "gdb", "reverse engineering"),
    "SPECIALIST — BINARY: reason as an exploit developer. Triage the binary (checksec, strings, "
    "objdump), find the vulnerable primitive, then build the exploit incrementally — a crash "
    "before control, control before a shell.",
)
_PRIVESC = Specialist(
    "privesc", "offensive-windows-boundaries / privesc",
    ("privilege escalation", "linpeas", "winpeas", "suid", "sudo", "kernel", "misconfiguration"),
    "SPECIALIST — PRIVESC: reason as a post-exploitation operator on a foothold. Enumerate the "
    "local surface (SUID, sudo rules, services, scheduled tasks, kernel), match it to a known "
    "vector, and propose the single escalation step that the enumeration actually supports.",
)
_GENERALIST = Specialist(
    "generalist", "bug-bounty / recon",
    ("recon", "enumeration"),
    "",
)

_ALL = (_WEB, _AD, _PWN, _PRIVESC)


def _text(*parts: Any) -> str:
    return " ".join(str(p or "") for p in parts).lower()


def route(state: Any, last_command: str = "", finding: dict[str, Any] | None = None) -> Specialist:
    """Pick the specialist for the current situation from the evidence.

    Scoring, not first-match: each specialist accrues signal from the services, findings and the
    last command, and the strongest wins. Ties and no-signal fall back to the generalist — the
    honest answer when the engagement has not yet declared its shape.
    """
    scores: dict[str, int] = {s.domain: 0 for s in _ALL}
    blob_parts: list[str] = [last_command]

    for svc in getattr(state, "services", []) or []:
        blob_parts.append(_text(getattr(svc, "name", ""), getattr(svc, "product", ""),
                                getattr(svc, "port", "")))
    for f in getattr(state, "findings", []) or []:
        blob_parts.append(_text(getattr(f, "title", ""), getattr(f, "reference", "")))
    for h in getattr(state, "hosts", []) or []:
        # a captured foothold (local/proof flag) is the strongest privesc signal there is
        if (getattr(h, "local_txt", "") or getattr(h, "proof_txt", "")):
            scores["privesc"] += 2
    if finding:
        blob_parts.append(_text(finding.get("title"), finding.get("reference"), finding.get("target")))
    # credentials in play push toward AD/privesc reasoning
    if getattr(state, "credentials", None):
        scores["active-directory"] += 1
        scores["privesc"] += 1

    blob = " ".join(blob_parts)
    _WEB_SIG = ("http", "https", "web", "80", "443", "8080", "8443", "url", "sqlmap", "nikto",
                "gobuster", "ffuf", "wordpress", "apache", "nginx")
    _AD_SIG = ("smb", "445", "ldap", "389", "kerberos", "88", "domain", "netexec", "bloodhound",
               "microsoft-ds", "msrpc", "135", "active directory")
    _PWN_SIG = ("gdb", "checksec", "binary", "elf", "overflow", "rop", "pwn", "objdump")
    _PRIVESC_SIG = ("linpeas", "winpeas", "suid", "sudo", "privilege", "kernel", "gtfobins")
    for w in _WEB_SIG:
        if w in blob:
            scores["web"] += 1
    for w in _AD_SIG:
        if w in blob:
            scores["active-directory"] += 1
    for w in _PWN_SIG:
        if w in blob:
            scores["binary-pwn"] += 1
    for w in _PRIVESC_SIG:
        if w in blob:
            scores["privesc"] += 1

    best_domain = max(scores, key=lambda d: scores[d])
    if scores[best_domain] == 0:
        return _GENERALIST
    return next(s for s in _ALL if s.domain == best_domain)


def prompt_fragment(specialist: Specialist) -> str:
    """The specialist framing for the proposer prompt. "" for the generalist (prompt unchanged)."""
    if not specialist.prompt:
        return ""
    return "\n" + specialist.prompt
