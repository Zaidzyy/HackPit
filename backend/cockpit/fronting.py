"""Is this host behind a CDN, and what might be behind it? PASSIVE LOOKUPS ONLY.

*** WHY THIS EXISTS, IN ONE MEASUREMENT. ***
Build #17 established that an Akamai-fronted host is TWO walls: Bot Manager refuses the CLIENT
(a bare curl/ffuf/nuclei never reaches request one) and the WAF refuses the REQUEST CONTENT (36
of 39 scanner payloads came back `403 AkamaiGHost`). Everything else in build #18 is an answer to
one wall or the other. This module answers the question that comes BEFORE all of them: *which of
these hosts is actually fronted?* Two of the eleven in a live program might need none of it.

*** IT ANSWERS A QUESTION. IT DOES NOT ATTACK. ***
Everything here is a lookup:

  * CNAME chain, A records, SPF (TXT) and MX — DNS.
  * ASN and its owner — DNS, via Team Cymru's `origin.asn.cymru.com` / `asn.cymru.com` zones.
  * Certificate transparency — a query to crt.sh, a public log of certificates already issued.
  * The `Server` header — ONE `HEAD` request per host.

The `HEAD` is the only thing that touches the target at all, and it is one request that any
browser makes on any page load. There is no scanning, no brute force, no subdomain guessing and
no port sweep. That is a deliberate boundary and not an accident of what was easy.

*** A DISCOVERED ORIGIN IP IS OUT OF SCOPE UNTIL THE SCOPE SAYS OTHERWISE. ***
This module REPORTS candidate origins and adds nothing. `engagement.add_pivot_subnet` is the one
deliberate, audited widening path in this codebase and a human uses it. An origin IP found here
is a lead for that human, and routing a request to it before the scope covers it would be the
recon-driven-expansion rule broken by the module that most looks like it should be allowed to.

*** IT RUNS FROM INSIDE THE ENGAGE SANDBOX, LIKE THE REPEATER. ***
`docker exec` into the fully-open sandbox, argv-only, no shell — so NO NEW EGRESS PATH is created
from the Windows host. That is repeater.py's rule #1 restated: the alternative, resolving from the
backend process, would have made the operator's own machine the origin of every lookup and given
it reach to host-local services.

*** UNKNOWN IS A REAL ANSWER AND IS USED FREELY. ***
A failed lookup reports `unknown`, never `not-fronted`. This is build #17's most repeated lesson —
an error path that returns empty reads as a confident zero — applied before it can happen: "we
could not tell" and "it is not behind a CDN" are different facts and the verdict says which.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from typing import Any

from pydantic import BaseModel, Field

from . import config

#: How long any single lookup may take. Short: this is a sweep over a scope, and one host with a
#: broken resolver must not hold up the other ten.
LOOKUP_TIMEOUT = 15
#: How far a CNAME chain is followed. Real chains are 1-3 links; a longer one is a loop.
MAX_CNAME_DEPTH = 6

#: CNAME suffixes that NAME the provider. The strongest single signal there is — a CNAME to
#: `e1234.dscx.akamaiedge.net` is not circumstantial evidence, it is the delegation itself.
CDN_CNAME_SUFFIXES: dict[str, str] = {
    "akamaiedge.net": "Akamai",
    "akamai.net": "Akamai",
    "akamaized.net": "Akamai",
    "edgekey.net": "Akamai",
    "edgesuite.net": "Akamai",
    "akadns.net": "Akamai",
    "cloudfront.net": "Amazon CloudFront",
    "cloudflare.net": "Cloudflare",
    "cdn.cloudflare.net": "Cloudflare",
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "azureedge.net": "Azure CDN",
    "azurefd.net": "Azure Front Door",
    "incapdns.net": "Imperva Incapsula",
    "impervadns.net": "Imperva",
    "sucuri.net": "Sucuri",
    "stackpathdns.com": "StackPath",
    "b-cdn.net": "BunnyCDN",
    "cdn77.org": "CDN77",
    "llnwd.net": "Limelight",
    "gcdn.co": "G-Core",
    "awsglobalaccelerator.com": "AWS Global Accelerator",
    "vercel-dns.com": "Vercel",
    "netlify.app": "Netlify",
}

#: `Server` header values. Weaker than a CNAME — a header can be set by anything — but it is the
#: header build #17 read `AkamaiGHost` out of, so it earns its place.
CDN_SERVER_MARKERS: dict[str, str] = {
    "akamaighost": "Akamai",
    "akamainetstorage": "Akamai",
    "cloudflare": "Cloudflare",
    "cloudfront": "Amazon CloudFront",
    "sucuri": "Sucuri",
    "incapsula": "Imperva Incapsula",
    "imperva": "Imperva",
    "bunnycdn": "BunnyCDN",
    "ecacc": "Edgecast",
    "ecs (": "Edgecast",
}

#: ASN owner substrings. The weakest of the three and deliberately last: plenty of origins live
#: in AMAZON-02 without a CDN in front of them, which is exactly why this alone never decides.
CDN_ASN_MARKERS: dict[str, str] = {
    "AKAMAI": "Akamai",
    "CLOUDFLARENET": "Cloudflare",
    "FASTLY": "Fastly",
    "INCAPSULA": "Imperva Incapsula",
    "SUCURI": "Sucuri",
    "CDN77": "CDN77",
    "BUNNY": "BunnyCDN",
}


class FrontingEvidence(BaseModel):
    """One piece of evidence, with WHERE it came from — so a verdict can be argued with."""

    source: str = Field(description="cname | server-header | asn")
    detail: str
    provider: str = ""


class HostFronting(BaseModel):
    """Everything this module learned about one host."""

    host: str
    verdict: str = Field(
        "unknown",
        description="fronted | not-fronted | unknown. UNKNOWN when the lookups failed — which "
        "is a different fact from 'no CDN' and is never reported as one.",
    )
    provider: str = ""
    cname_chain: list[str] = Field(default_factory=list)
    addresses: list[str] = Field(default_factory=list)
    server_header: str = ""
    asn: str = ""
    asn_org: str = ""
    evidence: list[FrontingEvidence] = Field(default_factory=list)
    #: Candidate origins from passive sources. REPORTED, NEVER ADDED — see the module docstring.
    candidate_origins: list[str] = Field(default_factory=list)
    spf: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# classification — PURE. Everything above the network line, testable with no Docker.
# --------------------------------------------------------------------------- #
def _suffix_provider(name: str) -> str:
    """The CDN a hostname's SUFFIX names, or "".

    Matched on a dot-anchored suffix, never on a substring: `notakamai.net.example.com` contains
    `akamai.net` and is not Akamai. This is the same class of mistake as `pkill -f` matching a
    fragment, which this repo has been bitten by in both directions.
    """
    low = (name or "").strip().rstrip(".").lower()
    for suffix, provider in CDN_CNAME_SUFFIXES.items():
        if low == suffix or low.endswith("." + suffix):
            return provider
    return ""


def classify(host: str, cname_chain: list[str], server_header: str,
             asn_org: str, addresses: list[str], reachable: bool) -> tuple[str, str, list[FrontingEvidence]]:
    """``(verdict, provider, evidence)``. PURE — no lookups, no sockets, no Docker.

    Split out so the decision can be tested hermetically against fixed inputs, which is the only
    way to know the "unknown" branch works: a live host that happens to resolve proves nothing
    about the case where nothing does.

    UNKNOWN wins whenever there was nothing to judge. Evidence is collected from all three
    sources even after the first hit, because a host fronted by two providers (a WAF in front of
    a CDN) is a real arrangement and reporting only the first would hide it.
    """
    evidence: list[FrontingEvidence] = []
    providers: list[str] = []

    for name in cname_chain:
        provider = _suffix_provider(name)
        if provider:
            evidence.append(FrontingEvidence(
                source="cname", detail=f"CNAME chain reaches {name}", provider=provider))
            providers.append(provider)

    server_low = (server_header or "").lower()
    for marker, provider in CDN_SERVER_MARKERS.items():
        if marker in server_low:
            evidence.append(FrontingEvidence(
                source="server-header", detail=f"Server: {server_header}", provider=provider))
            providers.append(provider)

    org_up = (asn_org or "").upper()
    for marker, provider in CDN_ASN_MARKERS.items():
        if marker in org_up:
            evidence.append(FrontingEvidence(
                source="asn", detail=f"addresses live in {asn_org}", provider=provider))
            providers.append(provider)

    if evidence:
        # Preserve first-seen order while de-duplicating: CNAME evidence is the strongest and is
        # collected first, so the leading provider is the best-supported one.
        seen = list(dict.fromkeys(providers))
        return "fronted", " + ".join(seen), evidence

    # NOTHING FOUND. That is only "not fronted" if the lookups actually worked. With no addresses
    # and no reachable host there was nothing to look at, and saying "not fronted" would be a
    # confident answer drawn from a failed measurement — build #17's whole lesson.
    if not addresses and not reachable:
        return "unknown", "", evidence
    return "not-fronted", "", evidence


# --------------------------------------------------------------------------- #
# lookups — IMPURE. argv-only `docker exec` into the open sandbox, never a shell.
# --------------------------------------------------------------------------- #
def _run(argv: list[str], timeout: int = LOOKUP_TIMEOUT) -> str:
    """One command inside the open sandbox. Returns stdout, or "" on any failure.

    Bytes then an explicit UTF-8 decode, for the reason proxy.py's `_api_get` records: `text=True`
    decodes with the ambient locale codec (cp1252 here), and a TXT record or a `Server` header
    carrying one byte outside that codepage would raise inside subprocess's own reader thread and
    leave stdout as None.
    """
    full = ["docker", "exec", config.KALI_OPEN_CONTAINER, *argv]
    try:
        out = subprocess.run(full, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ""
    return (out.stdout or b"").decode("utf-8", "replace")


def _dig(record: str, name: str) -> list[str]:
    """``dig +short <record> <name>`` -> non-empty lines. Argv-only: no shell parses ``name``."""
    raw = _run(["dig", "+short", "+time=5", "+tries=2", record, name])
    return [line.strip() for line in raw.splitlines() if line.strip()]


def cname_chain(host: str) -> list[str]:
    """Follow the CNAME chain from ``host``. Bounded, and a loop terminates rather than hangs."""
    chain: list[str] = []
    current = host
    for _ in range(MAX_CNAME_DEPTH):
        answers = _dig("CNAME", current)
        if not answers:
            break
        nxt = answers[0].rstrip(".")
        if not nxt or nxt.lower() in {c.lower() for c in chain} or nxt.lower() == current.lower():
            break
        chain.append(nxt)
        current = nxt
    return chain


def addresses_for(host: str) -> list[str]:
    """A records for ``host``, ignoring anything that is not an address (a chain's CNAME lines)."""
    out: list[str] = []
    for line in _dig("A", host):
        try:
            out.append(str(ipaddress.ip_address(line)))
        except ValueError:
            continue
    return out


def asn_for(ip: str) -> tuple[str, str]:
    """``(asn, owner)`` for an address, via Team Cymru's DNS zones. ``("", "")`` when unknown.

    A DNS lookup, not a probe: nothing is sent to the address itself. The reversed-octet form is
    Cymru's own interface, and the answer is a quoted TXT record of pipe-separated fields.
    """
    try:
        octets = str(ipaddress.ip_address(ip)).split(".")
    except ValueError:
        return "", ""
    if len(octets) != 4:  # IPv6 uses a different zone; reported as unknown rather than guessed
        return "", ""
    answers = _dig("TXT", ".".join(reversed(octets)) + ".origin.asn.cymru.com")
    if not answers:
        return "", ""
    asn = answers[0].strip('"').split("|")[0].strip().split()[0] if answers[0].strip('"') else ""
    if not asn:
        return "", ""
    org_answers = _dig("TXT", f"AS{asn}.asn.cymru.com")
    org = ""
    if org_answers:
        parts = org_answers[0].strip('"').split("|")
        org = parts[-1].strip() if parts else ""
    return asn, org


def server_header_for(host: str) -> tuple[str, bool]:
    """``(server_header, reachable)`` from ONE ``HEAD`` request. The only thing here that is not
    a lookup, and it is one request — the same one a browser makes opening the page.

    ``reachable`` is returned separately because it is what tells :func:`classify` apart from a
    host that answered without a `Server` header and a host that never answered at all.
    """
    raw = _run([
        "curl", "-s", "-I", "-m", "10", "-o", "/dev/null",
        "-w", "%{http_code}\n%{header_json}",
        f"https://{host}/",
    ], timeout=20)
    lines = raw.splitlines()
    if not lines:
        return "", False
    code = lines[0].strip()
    reachable = code.isdigit() and code != "000"
    header = ""
    try:
        parsed = json.loads("\n".join(lines[1:]) or "{}")
        for name, values in parsed.items():
            if name.lower() == "server" and values:
                header = str(values[0])
                break
    except (ValueError, AttributeError, TypeError):
        header = ""
    return header, reachable


_CT_NAME = re.compile(r"[A-Za-z0-9*_.-]+")


def ct_names(domain: str) -> list[str]:
    """Hostnames certificate transparency has seen for ``domain``. A PUBLIC LOG, not a probe.

    Returns [] on any failure — and the caller SAYS SO in `notes` rather than treating an empty
    list as "the log holds nothing". Same distinction as the verdict's `unknown`.
    """
    raw = _run([
        "curl", "-s", "-m", "20", "-H", "Accept: application/json",
        f"https://crt.sh/?q=%25.{domain}&output=json",
    ], timeout=30)
    try:
        rows = json.loads(raw or "[]")
    except (ValueError, TypeError):
        return []
    if not isinstance(rows, list):
        return []
    out: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for value in str(row.get("name_value") or "").split("\n"):
            name = value.strip().lower()
            if name and _CT_NAME.fullmatch(name) and name not in out:
                out.append(name)
    return out


def analyse(host: str, *, with_ct: bool = False) -> HostFronting:
    """Everything this module can passively learn about ``host``. Never raises.

    ``with_ct`` is off by default because crt.sh is a third-party service and a sweep over eleven
    hosts would query it eleven times for what is usually one answer about one registrable domain.
    """
    clean = (host or "").strip().rstrip(".")
    result = HostFronting(host=clean)
    if not clean:
        result.notes.append("empty host")
        return result

    result.cname_chain = cname_chain(clean)
    result.addresses = addresses_for(clean)
    result.server_header, reachable = server_header_for(clean)
    if result.addresses:
        result.asn, result.asn_org = asn_for(result.addresses[0])
    result.spf = [t for t in _dig("TXT", clean) if "v=spf1" in t.lower()]
    result.mx = _dig("MX", clean)

    verdict, provider, evidence = classify(
        clean, result.cname_chain, result.server_header, result.asn_org,
        result.addresses, reachable,
    )
    result.verdict, result.provider, result.evidence = verdict, provider, evidence

    if verdict == "unknown":
        result.notes.append(
            "no addresses and no answer to a HEAD request — this is 'we could not tell', NOT "
            "'not behind a CDN'. Check the open sandbox is up and that dig/curl are in it."
        )

    # CANDIDATE ORIGINS — reported, never added to any scope. An MX host and an SPF `ip4:` are
    # the classic leaks: mail is rarely proxied through the CDN that fronts the website, so the
    # address a domain sends mail from is often the address the website is really on.
    for record in result.mx:
        parts = record.split()
        if len(parts) >= 2:
            result.candidate_origins.append(f"mx:{parts[-1].rstrip('.')}")
    for record in result.spf:
        for token in record.replace('"', "").split():
            if token.lower().startswith(("ip4:", "ip6:")):
                result.candidate_origins.append(f"spf:{token.split(':', 1)[1]}")

    if with_ct:
        labels = clean.split(".")
        registrable = ".".join(labels[-2:]) if len(labels) >= 2 else clean
        names = ct_names(registrable)
        if names:
            result.candidate_origins += [f"ct:{n}" for n in names[:50]]
        else:
            result.notes.append(
                f"certificate transparency returned nothing for {registrable} — that is a FAILED "
                "or empty query, not a statement that no certificates exist"
            )

    if result.candidate_origins:
        result.notes.append(
            "candidate origins are REPORTED ONLY. They are out of scope until the scope says "
            "otherwise — engagement.add_pivot_subnet is the one audited widening path, and a "
            "human uses it."
        )
    return result


def sweep(hosts: list[str], *, with_ct: bool = False) -> dict[str, Any]:
    """Analyse several hosts and summarise. Never raises; a host that fails reports `unknown`."""
    results = [analyse(h, with_ct=with_ct) for h in hosts if (h or "").strip()]
    return {
        "hosts": results,
        "fronted": [r.host for r in results if r.verdict == "fronted"],
        "not_fronted": [r.host for r in results if r.verdict == "not-fronted"],
        "unknown": [r.host for r in results if r.verdict == "unknown"],
        "note": "PASSIVE ONLY — DNS lookups, public CT logs and one HEAD request per host. "
                "Nothing here scans, brute-forces or adds anything to a scope.",
    }


__all__ = [
    "CDN_ASN_MARKERS", "CDN_CNAME_SUFFIXES", "CDN_SERVER_MARKERS",
    "FrontingEvidence", "HostFronting", "analyse", "classify", "sweep",
]
