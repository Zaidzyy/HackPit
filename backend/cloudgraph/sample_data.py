"""A small, self-contained SYNTHETIC cloud enumeration — a ScoutSuite-shaped AWS IAM tree with a
real multi-hop privilege-escalation route to an admin role, plus a handful of Prowler-shaped
misconfiguration findings. Used by the tests and available to the UI as a demo so the cloud graph
renders end-to-end with NO live cloud credentials and NO real account.

*** SYNTHETIC ONLY — no real account id, ARN partition, tenant or project appears here. ***

The route (owned low-priv `dev-alice` → the `break-glass-admin` role, which holds
AdministratorAccess):

    dev-alice --MemberOf--> [developers] --AssumeRole--> ci-deployer
              --AttachRolePolicy--> break-glass-admin            (== win, admin)

with a parallel Lambda branch:  ci-deployer --UpdateFunctionCode--> deploy-fn's role
(break-glass-admin), and a side branch:  ci-deployer --ReadSecret--> app/prod secret.

The shape mirrors ScoutSuite's ``services.iam`` results (users / roles / groups keyed by id, each
carrying ``inline_policies`` with a ``PolicyDocument``; managed policies under ``policies`` with an
``attached_to``). SIDs are fake but ARN-shaped so the parser's high-value detection
(AdministratorAccess == admin) fires exactly as it would on a real account.
"""

from __future__ import annotations

ACCOUNT = "123456789012"
REGION = "us-east-1"

# --- ARNs (all synthetic) --------------------------------------------------- #
ALICE = f"arn:aws:iam::{ACCOUNT}:user/dev-alice"
BUILD_BOT = f"arn:aws:iam::{ACCOUNT}:user/build-bot"
DEVELOPERS = f"arn:aws:iam::{ACCOUNT}:group/developers"
CI_DEPLOYER = f"arn:aws:iam::{ACCOUNT}:role/ci-deployer"
BREAK_GLASS = f"arn:aws:iam::{ACCOUNT}:role/break-glass-admin"
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
DEPLOY_FN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:deploy-fn"
APP_SECRET = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:app/prod-Ab12Cd"
PUBLIC_BUCKET = f"arn:aws:s3:::app-public-assets-{ACCOUNT}"


def _stmt(actions, resource="*", effect="Allow") -> dict:
    return {"Effect": effect, "Action": actions, "Resource": resource}


def _doc(*stmts) -> dict:
    return {"Version": "2012-10-17", "Statement": list(stmts)}


def sample_scoutsuite() -> dict:
    """A ScoutSuite-shaped results mapping the parser consumes (services.iam + a lambda + s3)."""
    return {
        "provider_code": "aws",
        "account_id": ACCOUNT,
        "services": {
            "iam": {
                "users": {
                    "AIDAALICE": {
                        "name": "dev-alice", "id": "AIDAALICE", "arn": ALICE,
                        "groups": {"developers": {"name": "developers", "arn": DEVELOPERS}},
                        "inline_policies": {}, "policies": {},
                    },
                    "AIDABUILDBOT": {
                        "name": "build-bot", "id": "AIDABUILDBOT", "arn": BUILD_BOT,
                        # a dead-end principal, so the graph is not a single line
                        "inline_policies": {
                            "read-only": {"PolicyDocument": _doc(_stmt(["s3:GetObject"], "*"))}
                        },
                        "groups": {}, "policies": {},
                    },
                },
                "groups": {
                    "developers": {
                        "name": "developers", "id": "developers", "arn": DEVELOPERS,
                        "users": {"AIDAALICE": {"name": "dev-alice"}},
                        "inline_policies": {
                            "dev-assume": {"PolicyDocument": _doc(
                                _stmt(["sts:AssumeRole"], CI_DEPLOYER)
                            )}
                        },
                        "policies": {},
                    },
                },
                "roles": {
                    "AROACIDEPLOYER": {
                        "name": "ci-deployer", "id": "AROACIDEPLOYER", "arn": CI_DEPLOYER,
                        "inline_policies": {
                            "ci-perms": {"PolicyDocument": _doc(
                                _stmt(["iam:AttachRolePolicy"], BREAK_GLASS),
                                _stmt(["lambda:UpdateFunctionCode"], DEPLOY_FN),
                                _stmt(["secretsmanager:GetSecretValue"], APP_SECRET),
                            )}
                        },
                        "policies": {},
                        "trust_policy": {"Statement": [
                            {"Effect": "Allow", "Principal": {"AWS": DEVELOPERS},
                             "Action": "sts:AssumeRole"}
                        ]},
                    },
                    "AROABREAKGLASS": {
                        "name": "break-glass-admin", "id": "AROABREAKGLASS", "arn": BREAK_GLASS,
                        "inline_policies": {},
                        # attached managed AdministratorAccess -> the parser marks it admin
                        "policies": {ADMIN_POLICY: {"name": "AdministratorAccess",
                                                    "arn": ADMIN_POLICY}},
                        "trust_policy": {"Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                             "Action": "sts:AssumeRole"}
                        ]},
                    },
                },
                "policies": {
                    ADMIN_POLICY: {
                        "name": "AdministratorAccess", "id": "ANPAADMIN", "arn": ADMIN_POLICY,
                        "PolicyDocument": _doc(_stmt(["*"], "*")),
                        "attached_to": {"roles": {"break-glass-admin": {}}},
                    },
                },
            },
            "awslambda": {
                "functions": {
                    DEPLOY_FN: {"name": "deploy-fn", "arn": DEPLOY_FN, "role": BREAK_GLASS,
                                "region": REGION},
                },
            },
            "s3": {
                "buckets": {
                    "app-public-assets": {"name": "app-public-assets", "arn": PUBLIC_BUCKET,
                                          "public": True},
                },
            },
        },
    }


def sample_prowler() -> list[dict]:
    """Prowler-shaped misconfiguration findings (native JSON output shape). FAIL rows become
    engagement-state ``Finding``s; PASS rows are ignored by the parser."""
    return [
        {
            "CheckID": "iam_root_mfa_enabled", "Status": "FAIL", "Severity": "high",
            "CheckTitle": "Ensure MFA is enabled for the root account",
            "ResourceId": f"arn:aws:iam::{ACCOUNT}:root", "ServiceName": "iam",
            "StatusExtended": "Root account does not have MFA enabled.",
        },
        {
            "CheckID": "s3_bucket_public_access", "Status": "FAIL", "Severity": "critical",
            "CheckTitle": "S3 bucket is publicly accessible",
            "ResourceId": PUBLIC_BUCKET, "ServiceName": "s3",
            "StatusExtended": "Bucket app-public-assets grants READ to AllUsers.",
        },
        {
            "CheckID": "iam_policy_no_privilege_escalation", "Status": "FAIL", "Severity": "high",
            "CheckTitle": "IAM policy permits privilege escalation",
            "ResourceId": CI_DEPLOYER, "ServiceName": "iam",
            "StatusExtended": "ci-deployer may iam:AttachRolePolicy an admin policy to a role.",
        },
        {
            "CheckID": "iam_password_policy_minimum_length", "Status": "PASS", "Severity": "medium",
            "CheckTitle": "Password policy minimum length is 14 or more",
            "ResourceId": f"arn:aws:iam::{ACCOUNT}:account", "ServiceName": "iam",
        },
    ]


def sample_collection() -> dict:
    """The combined synthetic enumeration the ingest endpoint accepts: the ScoutSuite tree plus
    the Prowler findings under one mapping (the parser reads whichever keys are present)."""
    return {"scoutsuite": sample_scoutsuite(), "prowler": sample_prowler()}


# The canonical owned start + the high-value target for the demo/tests.
OWNED_START = ALICE
HIGH_VALUE_TARGET = BREAK_GLASS
