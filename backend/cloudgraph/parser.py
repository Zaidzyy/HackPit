"""Cloud enumeration → normalized :class:`Graph`.

This is the ONLY module that understands the enumeration tools' on-disk shapes. It accepts the
JSON that **ScoutSuite** emits (the ``services.iam`` results tree — users / roles / groups keyed
by id, each with ``inline_policies`` + attached managed ``policies``, and a top-level managed
``policies`` map) and turns the IAM policy statements into a typed privilege-escalation graph.
It also reads **Prowler** findings (native JSON or OCSF) into misconfiguration ``Finding`` rows.
Nothing here runs anything; it only reads captured output.

Provider focus: the privesc-edge extraction is AWS-first (the richest, and what pacu/cloudfox
target). Azure and GCP enumerations still parse into principal/resource nodes + their findings via
the same tolerant reader, and the schema + technique catalog already carry their edge kinds — the
deep policy-statement → edge mapping for those two is the documented follow-on (see the PR notes).
"""

from __future__ import annotations

import json
from typing import Any

from .schema import Edge, Graph, Node

# Fan-out bound for a wildcard (``Resource: "*"``) target, so one over-broad statement cannot
# explode the graph. Truncation is recorded in ``graph.warnings``.
_WILDCARD_FANOUT = 30


class ParseError(ValueError):
    """An enumeration that could not be parsed into a graph (empty, wrong shape, unreadable)."""


# --- IAM action -> (edge kind, the node type its Resource ARNs resolve to) --- #
# Lower-cased action string -> the abusable edge it grants and what its target is. A privesc
# action on a resource of the right type becomes one traversable edge.
_ACTION_EDGES: dict[str, tuple[str, str]] = {
    "sts:assumerole": ("AssumeRole", "role"),
    "iam:addusertogroup": ("AddUserToGroup", "group"),
    "iam:attachuserpolicy": ("AttachUserPolicy", "user"),
    "iam:attachrolepolicy": ("AttachRolePolicy", "role"),
    "iam:attachgrouppolicy": ("AttachGroupPolicy", "group"),
    "iam:putuserpolicy": ("PutUserPolicy", "user"),
    "iam:putrolepolicy": ("PutRolePolicy", "role"),
    "iam:createpolicyversion": ("CreatePolicyVersion", "policy"),
    "iam:setdefaultpolicyversion": ("SetDefaultPolicyVersion", "policy"),
    "iam:updateassumerolepolicy": ("UpdateAssumeRolePolicy", "role"),
    "iam:createaccesskey": ("CreateAccessKey", "user"),
    "iam:createloginprofile": ("CreateLoginProfile", "user"),
    "iam:updateloginprofile": ("CreateLoginProfile", "user"),
    "iam:passrole": ("PassRole", "role"),
    "lambda:updatefunctioncode": ("UpdateFunctionCode", "function"),
    "lambda:createfunction": ("CreateFunction", "function"),
    "ec2:runinstances": ("RunInstances", "role"),
    "secretsmanager:getsecretvalue": ("ReadSecret", "secret"),
    "ssm:getparameter": ("ReadSecret", "secret"),
    "ssm:getparameters": ("ReadSecret", "secret"),
    "kms:decrypt": ("DecryptKey", "kmskey"),
}
# Which services carry mapped privesc actions (so ``iam:*`` / ``sts:*`` expand correctly).
_SERVICE_ACTIONS: dict[str, list[str]] = {}
for _act in _ACTION_EDGES:
    _SERVICE_ACTIONS.setdefault(_act.split(":", 1)[0], []).append(_act)


# --------------------------------------------------------------------------- #
# input normalization
# --------------------------------------------------------------------------- #
def _as_obj(source: Any) -> Any:
    """Decode ``source`` (a dict/list, or JSON bytes/str, possibly a ScoutSuite ``foo = {…};``
    assignment) into a Python object. Never touches the filesystem — the worker reads files."""
    if isinstance(source, (dict, list)):
        return source
    if isinstance(source, (bytes, bytearray)):
        source = source.decode("utf-8", "replace")
    if isinstance(source, str):
        text = source.strip()
        # ScoutSuite writes `scoutsuite_results = { ... };` — strip the JS assignment wrapper.
        if "=" in text and not text.startswith("{") and not text.startswith("["):
            text = text.split("=", 1)[1].strip()
        if text.endswith(";"):
            text = text[:-1].strip()
        try:
            return json.loads(text)
        except ValueError as exc:
            raise ParseError(f"could not decode enumeration JSON: {exc}")
    raise ParseError(f"unsupported enumeration source type: {type(source).__name__}")


def _scoutsuite_root(obj: Any) -> dict | None:
    """The ScoutSuite results mapping, wherever it sits in the accepted inputs."""
    if isinstance(obj, dict):
        if "scoutsuite" in obj and isinstance(obj["scoutsuite"], dict):
            return obj["scoutsuite"]
        if "services" in obj or "provider_code" in obj or "account_id" in obj:
            return obj
    return None


# --------------------------------------------------------------------------- #
# statement helpers
# --------------------------------------------------------------------------- #
def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [str(v)]


def _statements(doc: Any) -> list[dict]:
    """Every statement dict in a policy document (``{Statement: [...]}`` or a bare list)."""
    if isinstance(doc, dict):
        st = doc.get("Statement") or doc.get("statement")
    else:
        st = doc
    if isinstance(st, dict):
        return [st]
    return [s for s in st if isinstance(s, dict)] if isinstance(st, list) else []


def _is_admin_doc(doc: Any) -> bool:
    """A policy that grants ``Allow`` ``*`` on ``*`` — administrator-equivalent."""
    for s in _statements(doc):
        if str(s.get("Effect", "Allow")).lower() != "allow":
            continue
        actions = [a.lower() for a in _as_list(s.get("Action"))]
        resources = _as_list(s.get("Resource")) or ["*"]
        if "*" in actions and "*" in resources:
            return True
    return False


def _expand_actions(actions: list[str]) -> tuple[list[str], bool]:
    """Resolve action strings (incl. ``service:*`` and ``*``) to mapped privesc actions. Returns
    (mapped_actions, is_admin) — ``is_admin`` is True when a full ``*`` action appeared."""
    out: list[str] = []
    is_admin = False
    for raw in actions:
        a = raw.strip().lower()
        if a == "*":
            is_admin = True
            continue
        if a.endswith(":*"):
            out.extend(_SERVICE_ACTIONS.get(a.split(":", 1)[0], []))
        elif a in _ACTION_EDGES:
            out.append(a)
    return out, is_admin


# --------------------------------------------------------------------------- #
# node construction
# --------------------------------------------------------------------------- #
def _label_of(rec: dict, fallback: str) -> str:
    return str(rec.get("name") or rec.get("Name") or fallback)


def _arn_of(rec: dict, fallback: str) -> str:
    return str(rec.get("arn") or rec.get("Arn") or rec.get("id") or fallback)


class _Builder:
    """Turns a ScoutSuite IAM tree into a :class:`Graph`. Two passes: nodes, then edges (so edge
    endpoints always resolve). Wildcard targets fan out over the nodes of that type."""

    def __init__(self, provider: str, account: str | None) -> None:
        self.g = Graph(provider=provider, account=account)
        self.provider = provider
        # arn/id -> the resolved policy document(s) for a managed policy (for admin detection)
        self.managed: dict[str, dict] = {}
        # function arn -> its execution role arn (UpdateFunctionCode reaches the ROLE)
        self.fn_role: dict[str, str] = {}

    # -- node passes ------------------------------------------------------- #
    def add_principal(self, ntype: str, rec: dict) -> str:
        arn = _arn_of(rec, "")
        if not arn:
            return ""
        node = Node(id=arn, type=ntype, label=_label_of(rec, arn), provider=self.provider,
                    props={"name": _label_of(rec, arn), "id": rec.get("id")})
        self.g.add_node(node)
        return arn

    def index_managed(self, policies: dict) -> None:
        for pid, rec in (policies or {}).items():
            if not isinstance(rec, dict):
                continue
            arn = _arn_of(rec, str(pid))
            doc = rec.get("PolicyDocument") or rec.get("policy_document") or {}
            admin = _is_admin_doc(doc) or _label_of(rec, "").lower() == "administratoraccess"
            self.g.add_node(Node(id=arn, type="policy", label=_label_of(rec, str(pid)),
                                 provider=self.provider, high_value=admin,
                                 props={"name": _label_of(rec, str(pid)), "admin": admin}))
            self.managed[arn] = doc
            self.managed[_label_of(rec, "")] = doc  # also resolvable by name

    def add_resource(self, ntype: str, arn: str, label: str, props: dict | None = None) -> str:
        if not arn:
            return ""
        self.g.add_node(Node(id=arn, type=ntype, label=label or arn, provider=self.provider,
                             props=props or {}))
        return arn

    def ensure(self, arn: str, ntype: str = "resource") -> None:
        if arn and arn not in self.g.nodes:
            self.g.add_node(Node(id=arn, type=ntype, label=_short(arn), provider=self.provider))

    # -- target resolution ------------------------------------------------- #
    def resolve_targets(self, target_kind: str, resource: Any) -> list[str]:
        """The node ids a statement's Resource points at, for a target of ``target_kind``. A
        ``*`` resource fans out over every node of that type (bounded)."""
        out: list[str] = []
        for res in _as_list(resource) or ["*"]:
            if res == "*" or res.endswith(":*") or res.endswith("/*"):
                same = [n.id for n in self.g.nodes.values() if n.type == target_kind]
                out.extend(same[:_WILDCARD_FANOUT])
                if len(same) > _WILDCARD_FANOUT:
                    self.g.warnings.append(
                        f"a wildcard {target_kind} target was capped at {_WILDCARD_FANOUT} of "
                        f"{len(same)} {target_kind}s"
                    )
            else:
                node = self.g.nodes.get(res)
                if node is not None:
                    out.append(node.id)
                elif _looks_like(res, target_kind):
                    self.ensure(res, target_kind)
                    out.append(res)
        return list(dict.fromkeys(out))  # de-dupe, preserve order

    # -- statement -> edges ------------------------------------------------ #
    def emit_statements(self, source_arn: str, docs: list[Any]) -> None:
        admin = False
        for doc in docs:
            for s in _statements(doc):
                if str(s.get("Effect", "Allow")).lower() != "allow":
                    continue
                actions, is_admin = _expand_actions(_as_list(s.get("Action")))
                admin = admin or is_admin
                resource = s.get("Resource", "*")
                for act in actions:
                    kind, tkind = _ACTION_EDGES[act]
                    for tid in self.resolve_targets(tkind, resource):
                        self._emit_edge(source_arn, tid, kind, act)
        if admin:  # a principal that can do *:* is itself an admin objective
            node = self.g.node(source_arn)
            if node is not None:
                node.high_value = True

    def _emit_edge(self, source: str, target: str, kind: str, permission: str) -> None:
        props: dict[str, Any] = {"permission": permission}
        # A Lambda/EC2 abuse reaches the compute's EXECUTION ROLE, not the resource itself: that
        # is where the privilege lands. Redirect the edge to the role when we know it.
        if kind in ("UpdateFunctionCode", "CreateFunction") and target in self.fn_role:
            props["via_function"] = target
            target = self.fn_role[target]
        self.g.add_edge(Edge(source=source, target=target, kind=kind, props=props))


def _short(arn: str) -> str:
    """A readable label from an ARN — the last path/name segment."""
    tail = arn.rsplit(":", 1)[-1]
    return tail.rsplit("/", 1)[-1] or arn


def _looks_like(res: str, target_kind: str) -> bool:
    """Whether an unmatched Resource ARN plausibly names a node of ``target_kind`` (so we stub
    it rather than dropping the edge)."""
    r = res.lower()
    hints = {
        "role": ":role/", "user": ":user/", "group": ":group/", "policy": ":policy/",
        "function": ":function:", "secret": ":secret:", "kmskey": ":key/",
    }
    hint = hints.get(target_kind)
    return bool(res.startswith("arn:") and (hint is None or hint in r))


# --------------------------------------------------------------------------- #
# the parse
# --------------------------------------------------------------------------- #
def parse_collection(source: Any) -> Graph:
    """Parse a ScoutSuite enumeration (or a combined ``{scoutsuite, prowler}`` mapping) into a
    :class:`Graph`. Raises :class:`ParseError` if no IAM data is found."""
    obj = _as_obj(source)
    root = _scoutsuite_root(obj)
    if root is None:
        raise ParseError(
            "no ScoutSuite IAM enumeration found — expected a results tree with services.iam "
            "(run `scout aws` / import its scoutsuite_results JSON)"
        )
    provider = str(root.get("provider_code") or root.get("provider") or "aws").lower()
    account = str(root.get("account_id") or root.get("account") or "") or None
    services = root.get("services") or {}
    iam = services.get("iam") or {}
    users = iam.get("users") or {}
    roles = iam.get("roles") or {}
    groups = iam.get("groups") or {}
    policies = iam.get("policies") or {}
    if not (users or roles or groups):
        raise ParseError("the IAM enumeration has no users, roles or groups")

    b = _Builder(provider, account)
    if account:
        b.add_resource("account", f"{provider}:{account}", f"{provider} account {account}")

    # PASS 1a: managed policies (so admin detection + attach targets resolve).
    b.index_managed(policies)

    # PASS 1b: principals.
    for rec in _values(users):
        b.add_principal("user", rec)
    for rec in _values(roles):
        b.add_principal("role", rec)
    for rec in _values(groups):
        b.add_principal("group", rec)

    # PASS 1c: resources referenced by privesc edges (lambda functions, s3, secrets, kms).
    _add_lambda(b, services)
    _add_simple_resources(b, services)

    # PASS 2a: group membership (user/SA -> group), from either side of the relation.
    _emit_memberships(b, users, groups)

    # PASS 2b: role trust policies -> structural Trusts edges (who MAY assume the role).
    for rec in _values(roles):
        _emit_trust(b, rec)

    # PASS 2c: policy statements -> abusable privesc edges. Mark a principal high-value when it
    # holds an attached admin (AdministratorAccess) managed policy.
    for ntype, coll in (("user", users), ("role", roles), ("group", groups)):
        for rec in _values(coll):
            arn = _arn_of(rec, "")
            docs = _principal_docs(b, rec)
            b.emit_statements(arn, docs)
            if _has_admin_managed(b, rec):
                node = b.g.node(arn)
                if node is not None:
                    node.high_value = True

    _warnings(b.g)
    return b.g


def _values(coll: Any) -> list[dict]:
    if isinstance(coll, dict):
        return [v for v in coll.values() if isinstance(v, dict)]
    if isinstance(coll, list):
        return [v for v in coll if isinstance(v, dict)]
    return []


def _principal_docs(b: _Builder, rec: dict) -> list[Any]:
    """Every policy document that applies to a principal: its inline policies plus the documents
    of the managed policies attached to it."""
    docs: list[Any] = []
    inline = rec.get("inline_policies") or rec.get("InlinePolicies") or {}
    for v in _values_or_docs(inline):
        docs.append(v.get("PolicyDocument") or v.get("policy_document") or v)
    for arn, name in _attached_managed(rec):
        doc = b.managed.get(arn) or b.managed.get(name)
        if doc:
            docs.append(doc)
    return docs


def _values_or_docs(inline: Any) -> list[dict]:
    """inline_policies is {name: {PolicyDocument}} or {name: PolicyDocument} or a list."""
    if isinstance(inline, dict):
        return [v for v in inline.values() if isinstance(v, dict)]
    if isinstance(inline, list):
        return [v for v in inline if isinstance(v, dict)]
    return []


def _attached_managed(rec: dict) -> list[tuple[str, str]]:
    """(arn, name) for each managed policy attached to a principal, across the key spellings
    ScoutSuite versions use (``policies`` dict/list, ``managed_policies``)."""
    out: list[tuple[str, str]] = []
    for key in ("policies", "managed_policies", "Policies", "AttachedManagedPolicies"):
        pol = rec.get(key)
        if isinstance(pol, dict):
            for pid, v in pol.items():
                if isinstance(v, dict):
                    out.append((str(v.get("arn") or pid), str(v.get("name") or pid)))
                else:
                    out.append((str(pid), str(pid)))
        elif isinstance(pol, list):
            for v in pol:
                if isinstance(v, dict):
                    out.append((str(v.get("PolicyArn") or v.get("arn") or ""),
                                str(v.get("PolicyName") or v.get("name") or "")))
                elif isinstance(v, str):
                    out.append((v, v))
    return out


def _has_admin_managed(b: _Builder, rec: dict) -> bool:
    for arn, name in _attached_managed(rec):
        if name.lower() == "administratoraccess":
            return True
        node = b.g.node(arn)
        if node is not None and node.high_value and node.type == "policy":
            return True
    return False


def _emit_memberships(b: _Builder, users: Any, groups: Any) -> None:
    for rec in _values(users):
        uarn = _arn_of(rec, "")
        for _gid, g in _member_groups(rec):
            garn = str(g.get("arn") or "") or _find_group_arn(groups, g.get("name"))
            if garn:
                b.ensure(garn, "group")
                b.g.add_edge(Edge(source=uarn, target=garn, kind="MemberOf"))
    # from the group side (Members / users on the group record)
    for rec in _values(groups):
        garn = _arn_of(rec, "")
        for _uid, u in _member_users(rec):
            uarn = str(u.get("arn") or "")
            if uarn:
                b.ensure(uarn, "user")
                b.g.add_edge(Edge(source=uarn, target=garn, kind="MemberOf"))


def _member_groups(rec: dict) -> list[tuple[str, dict]]:
    grp = rec.get("groups") or rec.get("Groups") or {}
    if isinstance(grp, dict):
        return [(k, v if isinstance(v, dict) else {"name": v}) for k, v in grp.items()]
    if isinstance(grp, list):
        return [(str(i), v if isinstance(v, dict) else {"name": v}) for i, v in enumerate(grp)]
    return []


def _member_users(rec: dict) -> list[tuple[str, dict]]:
    us = rec.get("users") or rec.get("Users") or rec.get("Members") or {}
    if isinstance(us, dict):
        return [(k, v if isinstance(v, dict) else {"name": v}) for k, v in us.items()]
    if isinstance(us, list):
        return [(str(i), v if isinstance(v, dict) else {"name": v}) for i, v in enumerate(us)]
    return []


def _find_group_arn(groups: Any, name: Any) -> str:
    if not name:
        return ""
    for rec in _values(groups):
        if _label_of(rec, "") == str(name):
            return _arn_of(rec, "")
    return ""


def _emit_trust(b: _Builder, rec: dict) -> None:
    role_arn = _arn_of(rec, "")
    trust = rec.get("trust_policy") or rec.get("AssumeRolePolicyDocument") or {}
    for s in _statements(trust):
        principal = s.get("Principal") or {}
        if isinstance(principal, dict):
            for arn in _as_list(principal.get("AWS")):
                if arn.startswith("arn:") and "iam:" in arn:
                    b.ensure(arn, "role" if ":role/" in arn else "user")
                    b.g.add_edge(Edge(source=arn, target=role_arn, kind="Trusts",
                                      props={"via": "trust-policy"}))


def _add_lambda(b: _Builder, services: dict) -> None:
    lam = services.get("awslambda") or services.get("lambda") or {}
    funcs = lam.get("functions") or {}
    for rec in _values(funcs) if not isinstance(funcs, dict) else funcs.values():
        if not isinstance(rec, dict):
            continue
        arn = _arn_of(rec, "")
        role = str(rec.get("role") or rec.get("Role") or "")
        b.add_resource("function", arn, _label_of(rec, _short(arn)),
                       {"name": _label_of(rec, _short(arn)), "role": role})
        if arn and role:
            b.fn_role[arn] = role
            b.ensure(role, "role")


def _add_simple_resources(b: _Builder, services: dict) -> None:
    for svc, ntype, key in (("s3", "bucket", "buckets"),
                            ("secretsmanager", "secret", "secrets"),
                            ("kms", "kmskey", "keys")):
        coll = (services.get(svc) or {}).get(key) or {}
        for rec in coll.values() if isinstance(coll, dict) else _values(coll):
            if isinstance(rec, dict):
                arn = _arn_of(rec, "")
                b.add_resource(ntype, arn, _label_of(rec, _short(arn)),
                               {k: v for k, v in rec.items() if k in ("public", "name")})


def _warnings(g: Graph) -> None:
    if not any(e.abusable for e in g.edges):
        g.warnings.append(
            "no privilege-escalation edges found — the enumeration may lack IAM policy detail "
            "(run scoutsuite with IAM, or add pacu/cloudfox permission mapping)"
        )
    if not g.high_value_nodes():
        g.warnings.append(
            "no admin/owner-equivalent principal detected — the objective picker has no default "
            "target; name one explicitly"
        )


# --------------------------------------------------------------------------- #
# Prowler findings
# --------------------------------------------------------------------------- #
_SEV_MAP = {
    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
    "informational": "info", "info": "info",
    # OCSF severity_id
    "1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical", "6": "critical",
}


def parse_prowler_findings(source: Any) -> list[dict]:
    """Prowler output (native JSON list or OCSF) -> a list of finding dicts
    ``{title, severity, target, evidence, reference}`` for the failed checks only. Tolerant of the
    shape differences between Prowler's ``json`` and ``json-ocsf`` outputs."""
    obj = _as_obj(source)
    if isinstance(obj, dict):
        obj = obj.get("prowler") if "prowler" in obj else obj.get("findings") or [obj]
    rows = obj if isinstance(obj, list) else []
    out: list[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        status = str(_first(r, "Status", "status", "status_code") or "").upper()
        # OCSF nests status under status_code; treat FAIL / ALARM / anything not PASS-ok as failed
        if status in ("PASS", "MANUAL", "MUTED", "INFO", ""):
            if status != "FAIL" and status != "ALARM":
                # OCSF: status_code FAIL lives here too; only skip clear passes
                if status in ("PASS", "MANUAL", "MUTED"):
                    continue
        if status not in ("FAIL", "ALARM"):
            continue
        title = str(_first(r, "CheckTitle", "check_title", "title")
                    or (r.get("finding_info") or {}).get("title") or "cloud misconfiguration")
        sev = str(_first(r, "Severity", "severity", "severity_id") or "medium").lower()
        target = str(_first(r, "ResourceId", "resource_id", "resource_uid")
                     or _first_resource(r) or "")
        evidence = str(_first(r, "StatusExtended", "status_detail", "risk_details") or "")
        ref = str(_first(r, "CheckID", "check_id", "metadata_uid") or "")
        out.append({
            "title": title, "severity": _SEV_MAP.get(sev, "medium"),
            "target": target, "evidence": evidence, "reference": ref,
        })
    return out


def _first(d: dict, *keys: str) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _first_resource(r: dict) -> str:
    res = r.get("resources") or r.get("Resources") or []
    if isinstance(res, list) and res and isinstance(res[0], dict):
        return str(res[0].get("uid") or res[0].get("name") or res[0].get("Id") or "")
    return ""


__all__ = ["ParseError", "parse_collection", "parse_prowler_findings"]
