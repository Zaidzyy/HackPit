"""BloodHound collection → normalized :class:`Graph`.

This is the ONLY module that understands BloodHound's on-disk shape. It accepts the JSON that
``bloodhound-python`` / SharpHound emit — the per-type files (``*_users.json``,
``*_groups.json``, ``*_computers.json``, ``*_domains.json``, ``*_gpos.json``, ``*_ous.json``,
``*_containers.json``), a combined mapping of them, or a directory / .zip of them — across the
v4, v5 and Community-Edition variants, and produces the stable schema everything downstream
consumes. Nothing here runs anything; it only reads captured output.

References for the wire format: BloodHound.py `enumeration/*` (the object dicts) and SharpHound's
documented JSON. Where the variants differ (ACE right names, `Members` vs `Results`, `Owner`
vs `Owns`) the mapping below reconciles them.
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from typing import Any

from .schema import Edge, Graph, Node


class ParseError(ValueError):
    """A collection that could not be parsed into a graph (empty, wrong shape, unreadable)."""


# --- well-known SIDs / RIDs that mark high-value targets -------------------- #
# High-value RIDs (suffix of the domain SID) — the accounts/groups that ARE effective
# domain compromise, so the path engine treats reaching any of them as "win".
_HIGH_VALUE_RIDS = frozenset({
    "512",  # Domain Admins
    "516",  # Domain Controllers
    "518",  # Schema Admins
    "519",  # Enterprise Admins
    "521",  # Read-only Domain Controllers
})
# High-value well-known (domain-independent) SIDs.
_HIGH_VALUE_WELLKNOWN = frozenset({
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-551",  # Backup Operators
})

# --- ACE RightName -> our edge kind ----------------------------------------- #
# Reconciles v4/v5/CE naming. Anything not here is ignored (structural/noise).
_ACE_MAP = {
    "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite",
    "WriteDacl": "WriteDacl",
    "WriteOwner": "WriteOwner",
    "Owns": "Owns",
    "Owner": "Owns",
    "AddMember": "AddMember",
    "AddSelf": "AddSelf",
    "ForceChangePassword": "ForceChangePassword",
    "AllExtendedRights": "AllExtendedRights",
    "ReadLAPSPassword": "ReadLAPSPassword",
    "ReadGMSAPassword": "ReadGMSAPassword",
    "AddKeyCredentialLink": "AddKeyCredentialLink",
    "AddAllowedToAct": "AddAllowedToAct",
    "WriteAccountRestrictions": "GenericWrite",  # abusable the same way (RBCD/props)
    "WriteSPN": "GenericWrite",
    "DCSync": "DCSync",  # CE emits this directly
}
# The two replication rights that TOGETHER equal DCSync (v4/v5 emit them separately).
_GETCHANGES = "GetChanges"
_GETCHANGES_ALL = "GetChangesAll"

# Computer membership lists -> edge kind (principal -> computer).
_COMPUTER_MEMBER_EDGES = {
    "LocalAdmins": "AdminTo",
    "RemoteDesktopUsers": "CanRDP",
    "PSRemoteUsers": "CanPSRemote",
    "DcomUsers": "ExecuteDCOM",
}

# meta.type -> node type for the file-level object taxonomy.
_TYPE_SINGULAR = {
    "users": "user",
    "groups": "group",
    "computers": "computer",
    "domains": "domain",
    "gpos": "gpo",
    "ous": "ou",
    "containers": "container",
}


def _rid(sid: str) -> str | None:
    return sid.rsplit("-", 1)[-1] if sid and sid.startswith("S-1-5-21-") else None


def _is_high_value(sid: str) -> bool:
    if sid in _HIGH_VALUE_WELLKNOWN:
        return True
    if sid.endswith("-S-1-5-32-544"):  # domain-prefixed BUILTIN\Administrators
        return True
    rid = _rid(sid)
    return rid in _HIGH_VALUE_RIDS


def _label(props: dict[str, Any], oid: str, node_type: str) -> str:
    name = props.get("name") or props.get("distinguishedname") or oid
    return str(name)


def _member_type(raw: str | None, default: str = "") -> str:
    return (raw or default).strip().lower()


class _Loader:
    """Collects the per-type object lists from whatever input shape we were handed."""

    def __init__(self) -> None:
        self.buckets: dict[str, list[dict]] = {t: [] for t in _TYPE_SINGULAR}
        self.meta_versions: set[int] = set()

    def add_file_obj(self, obj: dict, hint: str | None = None) -> None:
        """One decoded BloodHound file: {"data": [...], "meta": {"type": ..., "version": ...}}."""
        if not isinstance(obj, dict):
            return
        meta = obj.get("meta") or {}
        mtype = str(meta.get("type") or "").lower()
        if isinstance(meta.get("version"), int):
            self.meta_versions.add(meta["version"])
        data = obj.get("data")
        if not isinstance(data, list):
            return
        # trust meta.type; fall back to the filename hint (e.g. "..._users.json")
        if mtype not in self.buckets and hint:
            for key in self.buckets:
                if hint.lower().endswith(f"{key}.json") or f"_{key}." in hint.lower():
                    mtype = key
                    break
        if mtype in self.buckets:
            self.buckets[mtype].extend(d for d in data if isinstance(d, dict))

    def add_combined(self, obj: dict) -> None:
        """A single mapping like {"users": {...file...}, "groups": {...}} or type->list."""
        for key, val in obj.items():
            k = key.lower()
            if k in self.buckets and isinstance(val, dict) and "data" in val:
                self.add_file_obj(val, hint=k)
            elif k in self.buckets and isinstance(val, list):
                self.buckets[k].extend(d for d in val if isinstance(d, dict))


def _load(source: Any) -> _Loader:
    """Normalize any accepted input into a :class:`_Loader`."""
    loader = _Loader()

    def feed_bytes(name: str, raw: bytes) -> None:
        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            return
        if isinstance(obj, dict) and "data" in obj:
            loader.add_file_obj(obj, hint=name)
        elif isinstance(obj, dict):
            loader.add_combined(obj)

    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.filename.lower().endswith(".json"):
                        feed_bytes(info.filename, zf.read(info))
        elif os.path.isdir(path):
            for fn in sorted(os.listdir(path)):
                if fn.lower().endswith(".json"):
                    with open(os.path.join(path, fn), "rb") as fh:
                        feed_bytes(fn, fh.read())
        elif os.path.isfile(path):
            with open(path, "rb") as fh:
                feed_bytes(os.path.basename(path), fh.read())
        else:
            raise ParseError(f"collection path not found: {path}")
    elif isinstance(source, (bytes, bytearray)):
        if zipfile.is_zipfile(io.BytesIO(bytes(source))):
            with zipfile.ZipFile(io.BytesIO(bytes(source))) as zf:
                for info in zf.infolist():
                    if info.filename.lower().endswith(".json"):
                        feed_bytes(info.filename, zf.read(info))
        else:
            feed_bytes("<bytes>", bytes(source))
    elif isinstance(source, dict):
        if "data" in source:
            loader.add_file_obj(source)
        else:
            loader.add_combined(source)
    elif isinstance(source, (list, tuple)):
        for item in source:  # a list of decoded file objects
            if isinstance(item, dict):
                loader.add_file_obj(item)
    else:
        raise ParseError(f"unsupported collection source type: {type(source).__name__}")
    return loader


def parse_collection(source: Any, certipy: Any | None = None) -> Graph:
    """Parse a BloodHound collection into a :class:`Graph`.

    ``source`` may be a path to a .zip / directory / single .json file, raw bytes of a zip or
    a json file, a decoded file mapping, a combined mapping, or a list of decoded file objects.
    Raises :class:`ParseError` if nothing parseable is found. Missing collection methods (e.g.
    no ACLs, no sessions) are tolerated and noted in ``graph.warnings`` — a partial collection
    still yields a partial graph.

    ``certipy`` (optional) is decoded ``certipy find -json`` output — the authoritative AD CS
    enumeration. When present it is folded into the SAME graph as ``certtemplate`` /
    ``certauthority`` nodes plus synthesized ESC1-8 abuse edges (see :func:`ingest_certipy`), so
    the path engine can walk an enrollee → vulnerable template → Domain Admin chain.
    """
    loader = _load(source)
    total = sum(len(v) for v in loader.buckets.values())
    if total == 0:
        raise ParseError(
            "no BloodHound objects found — expected users/groups/computers/domains JSON "
            "(a SharpHound/bloodhound-python collection)"
        )

    g = Graph()

    # first pass: every object becomes a typed node so edge endpoints always resolve.
    for mtype, items in loader.buckets.items():
        ntype = _TYPE_SINGULAR[mtype]
        for obj in items:
            oid = str(obj.get("ObjectIdentifier") or obj.get("objectid") or "").strip()
            if not oid:
                continue
            props = dict(obj.get("Properties") or {})
            node = Node(id=oid, type=ntype, label=_label(props, oid, ntype), props=props)
            node.high_value = bool(props.get("highvalue")) or _is_high_value(oid)
            if ntype == "domain" and g.domain is None:
                g.domain = str(props.get("name") or props.get("domain") or "") or None
            g.add_node(node)

    # second pass: edges.
    for mtype, items in loader.buckets.items():
        for obj in items:
            _emit_edges(g, mtype, obj)

    # Unconstrained delegation: synthesize the routable TrustedForDelegation edge from the
    # `unconstraineddelegation` flag — the parallel to the RBCD / DCSync synthesis (a composite
    # abuse edge emitted when a predicate over collected facts holds), needs all nodes present.
    _synthesize_unconstrained_delegation(g)

    # collection-method coverage warnings (so a thin graph explains itself).
    _acl_kinds = set(_ACE_MAP.values()) | {"DCSync"}
    if not any(e.kind in _acl_kinds for e in g.edges):
        g.warnings.append(
            "no ACL/abuse edges found — the collection may lack the Acl method "
            "(bloodhound-python -c All / DCOnly includes it)"
        )
    if not any(e.kind == "HasSession" for e in g.edges):
        g.warnings.append("no sessions collected (Session method) — HasSession edges absent")
    if loader.meta_versions and max(loader.meta_versions) < 5:
        g.warnings.append(
            f"BloodHound legacy schema (v{max(loader.meta_versions)}) — parsed with the "
            "v4/v5 mapping"
        )

    if certipy is not None:
        ingest_certipy(g, certipy)
    return g


def _ensure(g: Graph, oid: str, node_type: str = "container") -> None:
    """Reference to an object we didn't get a full record for (e.g. a foreign-domain SID):
    create a stub so the edge resolves. Type defaults to a neutral container."""
    if oid and oid not in g.nodes:
        g.add_node(Node(id=oid, type=node_type, label=oid, props={}, high_value=_is_high_value(oid)))


def _member_list(raw: Any) -> list[dict]:
    """Both ``[...]`` and ``{"Results": [...], "Collected": true}`` shapes flatten to a list."""
    if isinstance(raw, dict):
        raw = raw.get("Results")
    return [x for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []


def _emit_edges(g: Graph, mtype: str, obj: dict) -> None:
    oid = str(obj.get("ObjectIdentifier") or obj.get("objectid") or "").strip()
    if not oid:
        return

    # -- ACEs: every ACE on THIS object is an edge Principal -> this object --- #
    _emit_aces(g, oid, obj.get("Aces") or [])

    # -- MemberOf via PrimaryGroupSID (users + computers) -------------------- #
    pgs = obj.get("PrimaryGroupSID")
    if isinstance(pgs, str) and pgs:
        _ensure(g, pgs, "group")
        g.add_edge(Edge(source=oid, target=pgs, kind="MemberOf", props={"via": "primarygroup"}))

    # -- group membership (Members are on the GROUP object) ------------------ #
    if mtype == "groups":
        for m in _member_list(obj.get("Members")):
            msid = str(m.get("ObjectIdentifier") or "").strip()
            if msid:
                _ensure(g, msid, _member_type(m.get("ObjectType"), "user"))
                g.add_edge(Edge(source=msid, target=oid, kind="MemberOf"))

    # -- delegation + SID history (users + computers) ------------------------ #
    for d in _member_list(obj.get("AllowedToDelegate")):
        tsid = str(d.get("ObjectIdentifier") or "").strip()
        if tsid:
            _ensure(g, tsid, "computer")
            g.add_edge(Edge(source=oid, target=tsid, kind="AllowedToDelegate"))
    for s in _member_list(obj.get("HasSIDHistory")):
        tsid = str(s.get("ObjectIdentifier") or "").strip()
        if tsid:
            _ensure(g, tsid)
            g.add_edge(Edge(source=oid, target=tsid, kind="HasSIDHistory"))

    # -- computer-specific edges --------------------------------------------- #
    if mtype == "computers":
        for field_name, kind in _COMPUTER_MEMBER_EDGES.items():
            for m in _member_list(obj.get(field_name)):
                psid = str(m.get("ObjectIdentifier") or "").strip()
                if psid:
                    _ensure(g, psid, _member_type(m.get("ObjectType"), "group"))
                    g.add_edge(Edge(source=psid, target=oid, kind=kind))
        # Sessions: computer -> user (a token/cred is harvestable there)
        for sess in _member_list(obj.get("Sessions")):
            usid = str(sess.get("UserSID") or "").strip()
            csid = str(sess.get("ComputerSID") or oid).strip()
            if usid:
                _ensure(g, usid, "user")
                _ensure(g, csid, "computer")
                g.add_edge(Edge(source=csid, target=usid, kind="HasSession"))
        # RBCD: principals allowed to act on behalf of others on THIS computer
        for m in _member_list(obj.get("AllowedToAct")):
            psid = str(m.get("ObjectIdentifier") or "").strip()
            if psid:
                _ensure(g, psid, "computer")
                g.add_edge(Edge(source=psid, target=oid, kind="AllowedToAct"))

    # -- domain / OU / container structure ----------------------------------- #
    for child in _member_list(obj.get("ChildObjects")):
        csid = str(child.get("ObjectIdentifier") or "").strip()
        if csid:
            _ensure(g, csid, _member_type(child.get("ObjectType"), "container"))
            g.add_edge(Edge(source=oid, target=csid, kind="Contains"))
    for link in _member_list(obj.get("Links")):
        gsid = str(link.get("GUID") or link.get("ObjectIdentifier") or "").strip()
        if gsid:
            _ensure(g, gsid, "gpo")
            g.add_edge(Edge(source=gsid, target=oid, kind="GpLink",
                            props={"enforced": bool(link.get("IsEnforced"))}))
    for tr in _member_list(obj.get("Trusts")):
        tsid = str(tr.get("TargetDomainSid") or tr.get("ObjectIdentifier") or "").strip()
        if tsid:
            _ensure(g, tsid, "domain")
            g.add_edge(Edge(source=oid, target=tsid, kind="TrustedBy",
                            props={"trusttype": tr.get("TrustType"),
                                   "transitive": bool(tr.get("IsTransitive"))}))


def _emit_aces(g: Graph, target_oid: str, aces: Any) -> None:
    """Turn an object's ACE list into edges (Principal -> object), and synthesize the DCSync
    composite (GetChanges + GetChangesAll on the same target by the same principal)."""
    if not isinstance(aces, list):
        return
    getchanges: dict[str, set[str]] = {}
    for ace in aces:
        if not isinstance(ace, dict):
            continue
        psid = str(ace.get("PrincipalSID") or "").strip()
        right = str(ace.get("RightName") or "").strip()
        if not psid or not right:
            continue
        _ensure(g, psid, _member_type(ace.get("PrincipalType"), "group"))
        if right in (_GETCHANGES, _GETCHANGES_ALL):
            getchanges.setdefault(psid, set()).add(right)
            continue
        kind = _ACE_MAP.get(right)
        if kind is None:
            continue
        g.add_edge(Edge(source=psid, target=target_oid, kind=kind,
                        props={"inherited": bool(ace.get("IsInherited"))}))
    # DCSync = both replication rights on the target (typically the domain object).
    for psid, rights in getchanges.items():
        if _GETCHANGES in rights and _GETCHANGES_ALL in rights:
            g.add_edge(Edge(source=psid, target=target_oid, kind="DCSync",
                            props={"via": "GetChanges+GetChangesAll"}))


def _synthesize_unconstrained_delegation(g: Graph) -> None:
    """Synthesize the routable ``TrustedForDelegation`` edge from BloodHound's
    ``unconstraineddelegation`` flag — the unconstrained-delegation parallel to the RBCD /
    DCSync synthesis.

    A host TRUSTED FOR (unconstrained) DELEGATION caches the full TGT of every principal that
    authenticates to it. So for each such non-DC computer/user we emit one composite edge
    ``host --TrustedForDelegation--> <Domain Admins objective>``: own that host (the walk reaches
    it via AdminTo), coerce a DC to authenticate to it (printerbug / PetitPotam), capture the DC's
    TGT, and DCSync ⇒ krbtgt ⇒ full compromise. The abuse REQUIRES owning the host first, which
    the BFS supplies via the inbound AdminTo edge — the composite edge itself only encodes the
    win. Idempotent (``Graph.add_edge`` de-dups). Uses the same objective terminus as the ESC
    synthesis so the enrollee lands on the real Domain Admins node the path engine picks.
    """
    objective = _esc_objective(g)
    if not objective:
        return
    for node in list(g.nodes.values()):
        if node.type not in ("computer", "user") or node.id == objective:
            continue
        if not _truthy(node.props.get("unconstraineddelegation")):
            continue
        # A DC is unconstrained by design and already domain-controlling — that is game over,
        # not a route to it. We still emit the edge (owning a DC IS the win) but flag it so the
        # UI/technique can say so rather than proposing a coerce-a-DC dance you don't need.
        is_dc = node.type == "computer" and node.high_value
        g.add_edge(Edge(source=node.id, target=objective, kind="TrustedForDelegation", props={
            "is_dc": is_dc,
            "requires_owned_host": True,      # the BFS supplies this via the inbound AdminTo edge
            "coerce": "printerbug / PetitPotam / Coercer",
        }))


# =========================================================================== #
# AD CS (certipy find -json) — cert nodes + synthesized ESC1-8 abuse edges.
#
# This mirrors the DCSync synthesis above EXACTLY: DCSync is one composite edge emitted when a
# predicate over two facts holds (GetChanges AND GetChangesAll on the same target). An ESC edge
# is one composite edge emitted when a predicate over a template's vulnerability AND an
# enrollee's enroll-right holds — a low-privileged enrollee to the domain's Domain Admins. The
# certtemplate / certauthority nodes carry the misconfiguration; the ESC edge carries the abuse.
#
# certipy's own field names drift across versions, so every read goes through a case-insensitive
# getter and tolerates both dict-keyed ({"0": {...}}) and list-shaped containers. Nothing here
# runs anything — it reads captured `certipy find` output, exactly like the BloodHound parser.
# =========================================================================== #

# Client-authentication-capable EKUs — the ones that let a cert log a user on to the domain.
_CLIENT_AUTH_EKUS = frozenset({
    "client authentication", "smart card logon", "pkinit client authentication",
    "any purpose", "certificate request agent",
})
_ANY_PURPOSE_EKUS = frozenset({"any purpose"})
_ENROLL_AGENT_EKUS = frozenset({"certificate request agent", "enrollment agent"})
# Names that denote a GROUP rather than a user, for stub principals certipy references by name.
_GROUPISH = ("users", "computers", "admins", "everyone", "authenticated", "operators", "guests")


def _ci_get(d: dict, *keys: str, default: Any = None) -> Any:
    """Case-insensitive first-match getter over a certipy object (its keys vary by version)."""
    if not isinstance(d, dict):
        return default
    low = {str(k).strip().lower(): v for k, v in d.items()}
    for k in keys:
        v = low.get(k.strip().lower())
        if v is not None:
            return v
    return default


def _rows(container: Any) -> list[dict]:
    """certipy emits ``{"0": {...}, "1": {...}}`` or a plain list — flatten either to a list."""
    if isinstance(container, dict):
        return [v for v in container.values() if isinstance(v, dict)]
    if isinstance(container, list):
        return [v for v in container if isinstance(v, dict)]
    return []


def _listify(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v]
    if isinstance(v, dict):  # {"right": [principals]} — flatten the principal lists
        out: list[str] = []
        for val in v.values():
            out.extend(_listify(val))
        return out
    return [str(v)]


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "yes", "enabled", "enforce")


def _sam_key(name: str) -> str:
    """A principal name from certipy (``DOMAIN\\user`` / ``user@dom`` / ``Domain Users``) → the
    bare, lower-cased sam used to match it back to a BloodHound node."""
    v = str(name or "").strip()
    v = v.split("@", 1)[0]
    if "\\" in v:
        v = v.rsplit("\\", 1)[-1]
    return v.strip().lower()


def _principal_index(g: Graph) -> dict[str, str]:
    """{sam_lower: node_id} over the existing principals, so a certipy enrollee named
    ``SEVENKINGDOMS.LOCAL\\hodor`` resolves to the same node BloodHound already created."""
    idx: dict[str, str] = {}
    for n in g.nodes.values():
        if n.type in ("user", "group", "computer"):
            idx.setdefault(_sam_key(n.label), n.id)
    return idx


def _resolve_principal(g: Graph, idx: dict[str, str], name: str) -> str | None:
    """Resolve a certipy principal name to a node id, creating a typed stub if unknown."""
    sam = _sam_key(name)
    if not sam:
        return None
    if sam in idx:
        return idx[sam]
    ntype = "group" if any(tok in sam for tok in _GROUPISH) else "user"
    nid = f"CERTPRINCIPAL:{sam}"
    if nid not in g.nodes:
        g.add_node(Node(id=nid, type=ntype, label=str(name), props={"source": "certipy"}))
    idx[sam] = nid
    return nid


def _esc_objective(g: Graph) -> str | None:
    """The node an ESC chain escalates TO: Domain Admins (RID 512) if collected, else the domain
    object, else any high-value node. Same 'reaching this is the win' terminus the path engine
    uses, so a synthesized ESC edge lands the enrollee on the real objective."""
    for n in g.nodes.values():
        if n.type == "group" and n.id.endswith("-512"):
            return n.id
    for n in g.nodes.values():
        if n.type == "domain":
            return n.id
    hv = g.high_value_nodes()
    return hv[0].id if hv else None


def _certtemplate_id(name: str) -> str:
    return f"CERTTEMPLATE:{name}"


def _certauthority_id(name: str) -> str:
    return f"CERTAUTHORITY:{name}"


def ingest_certipy(g: Graph, data: Any) -> Graph:
    """Fold decoded ``certipy find -json`` into ``g``: add certtemplate / certauthority nodes and
    synthesize the composite ESC1-8 abuse edges (predicate over template-vuln x enroll-right),
    the AD CS parallel to the DCSync synthesis above. Idempotent (Graph.add_edge de-dups).

    Returns ``g`` for chaining. Tolerates certipy's version-to-version key drift and missing
    sections. A ``certipy`` blob with no CA/template data adds a warning rather than raising.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            data = json.loads(bytes(data).decode("utf-8", "replace"))
        except ValueError:
            data = None
    if not isinstance(data, dict):
        g.warnings.append("certipy data was not a JSON object — no AD CS nodes added")
        return g

    cas = _rows(_ci_get(data, "Certificate Authorities", "certificate_authorities", default={}))
    templates = _rows(_ci_get(data, "Certificate Templates", "certificate_templates", default={}))
    if not cas and not templates:
        g.warnings.append(
            "certipy output had no Certificate Authorities / Templates — nothing to ingest "
            "(run `certipy find -json` and pass the resulting .json)"
        )
        return g

    idx = _principal_index(g)
    objective = _esc_objective(g)

    # --- certificate authorities ------------------------------------------- #
    ca_nodes: dict[str, str] = {}          # ca_name -> node id
    ca_editf_san: dict[str, bool] = {}     # ca_name -> EDITF_ATTRIBUTESUBJECTALTNAME2 set?
    for ca in cas:
        ca_name = str(_ci_get(ca, "CA Name", "ca_name", "name", default="") or "").strip()
        if not ca_name:
            continue
        editf = _truthy(_ci_get(ca, "User Specified SAN", "user_specified_san",
                                "EDITF_ATTRIBUTESUBJECTALTNAME2", default=False))
        web = _truthy(_ci_get(ca, "Web Enrollment", "web_enrollment", default=False))
        cid = _certauthority_id(ca_name)
        g.add_node(Node(id=cid, type="certauthority", label=ca_name, props={
            "dns": _ci_get(ca, "DNS Name", "dns_name", default=""),
            "web_enrollment": web,
            "user_specified_san": editf,
            "vulnerabilities": _ci_get(ca, "[!] Vulnerabilities", "Vulnerabilities", default={}),
        }))
        ca_nodes[ca_name] = cid
        ca_editf_san[ca_name] = editf

        # ESC7 — ManageCA / ManageCertificates over the CA: reconfigure it (enable a SAN-abusable
        # template / approve requests), then issue. Two-hop, targeting the CA node.
        officers = _listify(_ci_get(ca, "Manage CA Principals", "manage_ca_principals", default=[]))
        officers += _listify(_ci_get(ca, "Manage Certificates Principals",
                                     "manage_certificates_principals", default=[]))
        for name in officers:
            pid = _resolve_principal(g, idx, name)
            if pid:
                g.add_edge(Edge(source=pid, target=cid, kind="ESC7",
                                props={"ca_name": ca_name, "esc_variant": "ESC7",
                                       "enrollee_sam": _sam_key(name)}))
        if officers and objective:
            g.add_edge(Edge(source=cid, target=objective, kind="ESC6",
                            props={"ca_name": ca_name, "esc_variant": "ESC7-then-issue",
                                   "via": "ManageCA-enable-SAN"}))

        # ESC8 — NTLM relay to web enrollment. The relay SOURCE is a coerced computer, which
        # certipy does not name (it is operator-chosen), so it is taken from an explicit
        # "Relay Sources" list when present. computer -> CA.
        if web:
            for name in _listify(_ci_get(ca, "Relay Sources", "relay_sources", default=[])):
                pid = _resolve_principal(g, idx, name)
                if pid:
                    if g.nodes[pid].type != "computer":
                        g.nodes[pid].type = "computer"
                    g.add_edge(Edge(source=pid, target=cid, kind="ESC8",
                                    props={"ca_name": ca_name, "esc_variant": "ESC8",
                                           "via": "relay-to-certsrv"}))

    # --- certificate templates --------------------------------------------- #
    for t in templates:
        name = str(_ci_get(t, "Template Name", "template_name", "name", default="") or "").strip()
        if not name:
            continue
        enabled = _truthy(_ci_get(t, "Enabled", "enabled", default=True))
        ekus = [str(e).strip().lower() for e in _listify(_ci_get(t, "Extended Key Usage",
                                                                 "EKUs", "ekus", default=[]))]
        name_flags = [str(f).upper() for f in _listify(_ci_get(t, "Certificate Name Flag",
                                                               "msPKI-Certificate-Name-Flag",
                                                               default=[]))]
        ess = _truthy(_ci_get(t, "Enrollee Supplies Subject", "enrollee_supplies_subject",
                              default=False)) or any("ENROLLEE" in f and "SUBJECT" in f
                                                     for f in name_flags)
        manager = _truthy(_ci_get(t, "Requires Manager Approval", "requires_manager_approval",
                                  "Manager Approval", default=False))
        client_auth = (not ekus) or bool(set(ekus) & _CLIENT_AUTH_EKUS)
        any_purpose = (not ekus) or bool(set(ekus) & _ANY_PURPOSE_EKUS)
        enroll_agent = bool(set(ekus) & _ENROLL_AGENT_EKUS)
        eku_disp = ", ".join(e for e in _listify(_ci_get(t, "Extended Key Usage", "EKUs",
                                                         "ekus", default=[]))) or "(any)"

        enrollees = _listify(_ci_get(t, "Enrollment Rights", "enrollment_rights", default=[]))
        # object-control writers over the template (ESC4): Write Owner / Write Dacl / GenericAll.
        writers = _listify(_ci_get(t, "Object Control Permissions", "object_control_permissions",
                                   "Write Owner Principals", "Write Dacl Principals",
                                   "Full Control Principals", default=[]))
        ca_list = [str(c).strip() for c in _listify(_ci_get(t, "Certificate Authorities",
                                                            "certificate_authorities", "CA",
                                                            default=[])) if str(c).strip()]

        tid = _certtemplate_id(name)
        g.add_node(Node(id=tid, type="certtemplate", label=name, props={
            "enabled": enabled,
            "ekus": eku_disp,
            "enrollee_supplies_subject": ess,
            "requires_manager_approval": manager,
            "cas": ca_list,
            "vulnerabilities": _ci_get(t, "[!] Vulnerabilities", "Vulnerabilities", default={}),
        }))
        for ca_name in ca_list:
            cid = ca_nodes.get(ca_name) or _certauthority_id(ca_name)
            if cid not in g.nodes:
                g.add_node(Node(id=cid, type="certauthority", label=ca_name, props={}))
            g.add_edge(Edge(source=tid, target=cid, kind="PublishedTo",
                            props={"template_name": name}))

        eku_prop = eku_disp
        ca_for_props = ca_list[0] if ca_list else ""

        def _esc_edge(src: str, variant: str) -> None:
            if objective:
                g.add_edge(Edge(source=src, target=objective, kind=variant,
                                props={"template_name": name, "ca_name": ca_for_props,
                                       "esc_variant": variant, "eku": eku_prop,
                                       "enrollee_sam": _sam_key(g.nodes[src].label)}))

        esc1_vuln = enabled and client_auth and ess and not manager
        esc2_vuln = enabled and any_purpose
        esc3_vuln = enabled and enroll_agent
        esc6_vuln = enabled and client_auth and not manager and any(
            ca_editf_san.get(c) for c in ca_list)

        vulnerable_here = esc1_vuln or esc2_vuln or esc3_vuln or esc6_vuln
        for name_p in enrollees:
            pid = _resolve_principal(g, idx, name_p)
            if not pid:
                continue
            if esc1_vuln:
                _esc_edge(pid, "ESC1")
            if esc2_vuln and not esc1_vuln:
                _esc_edge(pid, "ESC2")
            if esc3_vuln:
                _esc_edge(pid, "ESC3")
            if esc6_vuln and not esc1_vuln:
                _esc_edge(pid, "ESC6")
            if not vulnerable_here:
                # context only — a template you may enrol but cannot abuse (not traversed).
                g.add_edge(Edge(source=pid, target=tid, kind="CanEnroll",
                                props={"template_name": name}))

        # ESC4 — write control over the template: reconfigure it into ESC1, then abuse. Two-hop,
        # targeting the template node, then a follow-on ESC1 from the (now-vulnerable) template.
        for name_p in writers:
            pid = _resolve_principal(g, idx, name_p)
            if not pid:
                continue
            g.add_edge(Edge(source=pid, target=tid, kind="ESC4",
                            props={"template_name": name, "ca_name": ca_for_props,
                                   "esc_variant": "ESC4", "enrollee_sam": _sam_key(name_p)}))
            if objective:
                g.add_edge(Edge(source=tid, target=objective, kind="ESC1",
                                props={"template_name": name, "ca_name": ca_for_props,
                                       "esc_variant": "ESC1", "eku": eku_prop,
                                       "via": "ESC4-reconfigure",
                                       "enrollee_sam": _sam_key(name_p)}))

    return g
