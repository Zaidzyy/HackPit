"""Tests for the SSRF -> IMDS bridge parser (``cloudgraph/imds.py``).

Covers all three clouds — AWS (IMDSv1 credentials, the IMDSv2 token PUT + creds GET, the role
listing, the instance-identity doc), Azure (a managed-identity JWT), GCP (an SA token / email / ID
token) — plus malformed / truncated bodies (blind-SSRF reads). The invariants that matter:

  * a real credential body yields an ``owned=True`` node with the provider set;
  * the SECRET is NEVER present in ``finding_evidence`` (it goes to the vault/loot);
  * a partial / garbage body degrades to ``warnings`` and never raises.

*** All fixtures are SYNTHETIC — fake account ids, ARNs, tenants and tokens. ***

Hermetic: no Docker, no LLM, no network. Run:  python test_cloud_imds.py
"""
from __future__ import annotations

import base64
import json

from cloudgraph import imds
from cloudgraph.schema import Node


# --------------------------------------------------------------------------- #
# synthetic fixtures
# --------------------------------------------------------------------------- #
AWS_CREDS_V1 = json.dumps({
    "Code": "Success",
    "LastUpdated": "2026-08-07T00:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAEXAMPLE0SYNTHETIC",
    "SecretAccessKey": "wSyntheticSecretKeyMaterialDoNotUseFAKE1234567890",
    "Token": "SyntheticSessionTokenAAAABBBBCCCCDDDDEEEEFFFF==",
    "Expiration": "2026-08-07T06:00:00Z",
})

AWS_INSTANCE_DOC = json.dumps({
    "accountId": "123456789012", "region": "us-east-1",
    "instanceId": "i-0synthetic0abc123", "imageId": "ami-0synthetic",
})

AWS_ROLE_LISTING = "ci-deployer"
AWS_V2_TOKEN = "AQAEAFAKEsyntheticIMDSv2SessionToken1234567890abcdef==="


def _jwt(payload: dict) -> str:
    def seg(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    header = seg({"alg": "RS256", "typ": "JWT"})
    body = seg(payload)
    return f"{header}.{body}.c3ludGhldGljc2ln"  # 'syntheticsig'


AZURE_TOKEN = json.dumps({
    "access_token": _jwt({
        "oid": "00000000-0000-0000-0000-00000000dead",
        "appid": "11111111-2222-3333-4444-555555555555",
        "tid": "99999999-8888-7777-6666-555555555555",
        "exp": 1900000000,
    }),
    "expires_on": "1900000000",
    "resource": "https://management.azure.com/",
    "token_type": "Bearer",
})

GCP_TOKEN = json.dumps({
    "access_token": "ya29.SYNTHETICgcpAccessTokenDoNotUseFAKE",
    "expires_in": 3599,
    "token_type": "Bearer",
})
GCP_EMAIL = "svc-deploy@synthetic-project.iam.gserviceaccount.com"


def _no_secret_leaks(result: imds.SeedResult) -> None:
    """The secret material must not appear in anything the finding/UI is allowed to show."""
    ev = result.finding_evidence
    resp = json.dumps(result.to_response())
    for secret in result.creds.values():
        if not secret:
            continue
        assert secret not in ev, f"SECRET leaked into finding_evidence: {result.creds!r}"
        assert secret not in resp, f"SECRET leaked into the API response: {result.creds!r}"


# --------------------------------------------------------------------------- #
# AWS
# --------------------------------------------------------------------------- #
def test_aws_imds_v1_credentials() -> None:
    r = imds.parse(AWS_CREDS_V1, "aws", role_hint="ci-deployer")
    assert isinstance(r.node, Node) and r.node.owned is True, "the seed must be an owned node"
    assert r.node.provider == "aws"
    assert r.node.type == "role"
    assert r.node.props.get("via") == "ssrf-imds"
    assert "ci-deployer" in r.node.id, r.node.id
    assert r.creds["SecretAccessKey"].startswith("wSynthetic")
    assert r.identity == "ci-deployer"
    assert "ci-deployer" in r.aliases
    _no_secret_leaks(r)
    print("  AWS IMDSv1 credentials -> owned role node, secret kept out of the finding: PASS")


def test_aws_imds_v2_token_then_creds() -> None:
    # the bare PUT token: recognised, but no identity to own (names the next step).
    tok = imds.parse(AWS_V2_TOKEN, "aws")
    assert tok.node is None and tok.imds_version == "IMDSv2", tok
    assert any("IMDSv2 session token" in w for w in tok.warnings)
    # the creds GET, with the token header pasted in front -> version hint flips to IMDSv2.
    body = "X-aws-ec2-metadata-token: " + AWS_V2_TOKEN + "\n\n" + AWS_CREDS_V1
    creds = imds.parse(body, "aws", role_hint="ci-deployer")
    assert creds.node is not None and creds.node.owned
    assert creds.imds_version == "IMDSv2", creds.imds_version
    _no_secret_leaks(creds)
    print("  AWS IMDSv2 token PUT recognised (no node); creds GET -> owned node, v2 detected: PASS")


def test_aws_role_listing_and_identity_doc() -> None:
    listing = imds.parse(AWS_ROLE_LISTING, "aws")
    assert listing.node is None and listing.identity == "ci-deployer"
    assert "ci-deployer" in listing.aliases
    doc = imds.parse(AWS_INSTANCE_DOC, "aws")
    assert doc.node is None and doc.account == "123456789012"
    assert any("instance-identity" in w for w in doc.warnings)
    print("  AWS role listing -> identity+alias, no node; identity doc -> account context: PASS")


def test_aws_credentials_without_role_hint_still_owns() -> None:
    r = imds.parse(AWS_CREDS_V1, "aws")  # no role_hint
    assert r.node is not None and r.node.owned, "must still seed an owned node"
    assert any("role_hint" in w for w in r.warnings), "should warn that no role name was given"
    _no_secret_leaks(r)
    print("  AWS creds with no role_hint still seed an owned node (with a warning): PASS")


# --------------------------------------------------------------------------- #
# Azure
# --------------------------------------------------------------------------- #
def test_azure_managed_identity_jwt() -> None:
    r = imds.parse(AZURE_TOKEN, "azure")
    assert r.node is not None and r.node.owned and r.node.provider == "azure"
    assert r.node.type == "serviceaccount"
    assert r.node.props.get("appid") == "11111111-2222-3333-4444-555555555555"
    assert r.node.props.get("oid") == "00000000-0000-0000-0000-00000000dead"
    assert r.account == "99999999-8888-7777-6666-555555555555", "tenant from the JWT tid claim"
    assert r.creds["access_token"].count(".") == 2
    _no_secret_leaks(r)
    print("  Azure managed-identity JWT -> owned SP node, oid/appid/tenant decoded, token hidden: "
          "PASS")


# --------------------------------------------------------------------------- #
# GCP
# --------------------------------------------------------------------------- #
def test_gcp_service_account_token() -> None:
    r = imds.parse(GCP_TOKEN, "gcp", role_hint=GCP_EMAIL)
    assert r.node is not None and r.node.owned and r.node.provider == "gcp"
    assert r.node.type == "serviceaccount"
    assert GCP_EMAIL in r.aliases
    assert r.creds["access_token"].startswith("ya29.")
    assert any("Metadata-Flavor" in w for w in r.warnings), "must note GCP's header requirement"
    _no_secret_leaks(r)
    print("  GCP SA token -> owned SA node, Metadata-Flavor caveat noted, token hidden: PASS")


def test_gcp_email_only() -> None:
    r = imds.parse(GCP_EMAIL, "gcp")
    assert r.node is None and r.identity == GCP_EMAIL and GCP_EMAIL in r.aliases
    print("  GCP SA email (identity only) -> alias, no node: PASS")


# --------------------------------------------------------------------------- #
# malformed / partial — never crash
# --------------------------------------------------------------------------- #
def test_malformed_and_partial_bodies_never_raise() -> None:
    cases = [
        ("aws", '{"AccessKeyId": "ASIA'),                     # truncated JSON (blind-SSRF cut)
        ("aws", "<html>403 Forbidden</html>"),                # a WAF/error page, not IMDS
        ("azure", '{"token_type": "Bearer"}'),                # JSON but no access_token
        ("azure", "not json at all"),
        ("gcp", '{"expires_in": 3599}'),                      # no access_token
        ("aws", "   "),                                        # whitespace -> parse raises cleanly
    ]
    for provider, body in cases:
        try:
            r = imds.parse(body, provider)
        except imds.ImdsParseError:
            continue  # empty body is the one input that (correctly) raises
        assert isinstance(r, imds.SeedResult)
        assert r.warnings, f"a malformed body should carry warnings: {provider} {body!r}"
        # partial AWS creds: SecretAccessKey missing -> still no crash, warns about truncation
        if r.node is not None:
            _no_secret_leaks(r)
    # a truncated AWS creds body that still has both keys must not leak and must own
    partial = '{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"wPARTIALsecretFAKE"}'
    r = imds.parse(partial, "aws", role_hint="ci-deployer")
    assert r.node is not None and r.node.owned
    _no_secret_leaks(r)
    print("  malformed / truncated bodies degrade to warnings, never crash, never leak: PASS")


def test_unknown_provider_and_empty_raise() -> None:
    for bad in ("k8s", "", "  "):
        try:
            imds.parse(AWS_CREDS_V1, bad)
            assert False, f"provider {bad!r} should raise"
        except imds.ImdsParseError:
            pass
    try:
        imds.parse("", "aws")
        assert False, "empty body should raise"
    except imds.ImdsParseError:
        pass
    print("  an unknown provider and an empty body raise ImdsParseError, loudly: PASS")


def test_request_catalog_is_data_only() -> None:
    for prov in imds.PROVIDERS:
        cat = imds.request_catalog(prov)
        assert cat and all("cmd" in c and "label" in c for c in cat)
    # AWS catalog covers the IMDSv2 two-step
    aws = " ".join(c["cmd"] for c in imds.request_catalog("aws"))
    assert "PUT" in aws and "X-aws-ec2-metadata-token" in aws, "IMDSv2 two-step must be in the set"
    assert imds.request_catalog("nonsense") == []
    print("  the IMDS request catalog is per-provider data incl. the IMDSv2 two-step: PASS")


if __name__ == "__main__":
    test_aws_imds_v1_credentials()
    test_aws_imds_v2_token_then_creds()
    test_aws_role_listing_and_identity_doc()
    test_aws_credentials_without_role_hint_still_owns()
    test_azure_managed_identity_jwt()
    test_gcp_service_account_token()
    test_gcp_email_only()
    test_malformed_and_partial_bodies_never_raise()
    test_unknown_provider_and_empty_raise()
    test_request_catalog_is_data_only()
    print("ALL cloud IMDS-bridge parser tests pass")
