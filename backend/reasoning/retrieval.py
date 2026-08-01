"""2.7 — fingerprint-keyed KB retrieval: "this exact stack was solved by X" ranked ahead of token soup.

Generic KB search ranks by token similarity, which is why a query about "Apache 2.4.49" surfaces
a pile of loosely-Apache-flavoured prose before the one write-up that names 2.4.49. Case-based
retrieval flips that: an EXACT service+version fingerprint match is ranked above every token
match, because a write-up that solved this precise stack is worth more than ten that mention the
words.

This module builds the plumbing: a fingerprint from a state Service, and a re-rank that floats
fingerprint hits to the top of whatever the base KB search returned. GROWING the exploitation-
write-up corpus that this retrieval keys into is a FOLLOW-ON build — noted honestly, not faked
here: the ranker works the day the corpus lands, and on today's KB it degrades to the base order.

Read-only and executes nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

# Single-token normalisations: a scanner spelling on the left, the corpus's service key on the
# right. NB: no ``httpd -> apache`` here — that generic web-server word is handled structurally
# below (dropping it leaves the vendor ``apache`` as the head), which is what keeps
# ``Apache httpd`` (-> apache) and ``Apache Tomcat`` (-> tomcat) on DIFFERENT keys.
_ALIASES = {
    "apache2": "apache", "iis": "microsoft-iis",
    "mysqld": "mysql", "postgres": "postgresql", "smbd": "samba",
}
# Irreducible multi-word product names where no single token is the service key. Matched as a
# substring of the whole product string, so ``Microsoft SQL Server 2022`` resolves to ``mssql``.
_PHRASE_ALIASES = {
    "sql server": "mssql",
    "internet information services": "microsoft-iis",
}
# Umbrella orgs that PREFIX a product in an nmap banner ("Apache Tomcat", "Oracle WebLogic").
# When a vendor is the first token AND a more specific product token follows, the product wins.
# Small and stable by design — the anti-collision regression test (test_fingerprint_norm.py) is
# the real guard, so an omission here surfaces as a failing test, not a silent wrong key.
_VENDORS = {"apache", "microsoft", "oracle", "atlassian", "eclipse", "sun",
            "ibm", "vmware", "adobe", "redhat", "canonical", "isc", "the"}
# Generic descriptors that are never the product — the words around the real name in a banner.
_GENERIC = {"httpd", "http", "server", "daemon", "service", "engine", "framework",
            "software", "jsp", "coyote", "the"}


def fingerprint(product: str, version: str = "") -> str:
    """A normalized ``product/version`` key: ``("Apache httpd","2.4.49") -> "apache/2.4.49"``.

    Resolves a vendor-prefixed banner to the PRODUCT, not the vendor, so ``Apache Tomcat`` keys
    on ``tomcat`` (was ``apache``, colliding with ``Apache httpd``). The rule, from real nmap
    ``-sV`` product strings rather than a per-product special-case list:

      * drop generic descriptors (``httpd``, ``server``, ``engine`` …) and pure-numeric tokens
        (edition years like ``2022``) — what remains are the "specific" tokens;
      * if the first specific token is an umbrella VENDOR and another specific token follows, the
        product is that following token (``Apache Tomcat`` -> ``tomcat``, ``Oracle WebLogic`` ->
        ``weblogic``); otherwise the head is the first specific token (``Redis key-value store``
        -> ``redis``, ``vsftpd`` -> ``vsftpd``);
      * a vendor with only a generic descriptor after it IS the product (``Apache httpd`` ->
        ``apache``), which is exactly what keeps it distinct from ``Apache Tomcat``.

    The version is kept verbatim (it is the selective part).
    """
    p = (product or "").strip().lower()
    ver = (version or "").strip().lower()

    def _key(head: str) -> str:
        head = _ALIASES.get(head, head)
        return f"{head}/{ver}" if ver else head

    for phrase, key in _PHRASE_ALIASES.items():
        if phrase in p:
            return _key(key)

    toks = [t for t in re.split(r"[\s/_-]+", p) if t]
    specific = [t for t in toks if t not in _GENERIC and not t[0].isdigit()]
    if specific and specific[0] in _VENDORS and len(specific) > 1:
        head = specific[1]
    elif specific:
        head = specific[0]
    else:
        head = toks[0] if toks else ""
    return _key(head)


def service_fingerprint(service: Any) -> str:
    product = getattr(service, "product", "") or getattr(service, "name", "")
    return fingerprint(product, getattr(service, "version", "") or "")


@dataclass
class Ranked:
    entry: Any
    base_rank: int
    fingerprint_match: bool
    why: str


def _entry_blob(entry: Any) -> str:
    if isinstance(entry, dict):
        return " ".join(
            str(entry.get(k, "")) for k in ("title", "text", "body", "summary", "tags", "product")
        ).lower()
    return " ".join(
        str(getattr(entry, k, "")) for k in ("title", "text", "body", "summary", "tags")
    ).lower()


def _structured_fp(entry: Any) -> dict | None:
    """A structured ``meta.fingerprint`` block (service + version_kind + versions), or None.

    The exploitation-writeup corpus carries this so retrieval can range-match a version rather
    than substring-match it — the shape mirrors the CVE->exploit index's ``version_kind`` +
    ``versions`` exactly, so the version verdict stays the authoritative signal.
    """
    meta = entry.get("meta") if isinstance(entry, dict) else getattr(entry, "meta", None)
    fp = (meta or {}).get("fingerprint") if isinstance(meta, dict) else None
    return fp if isinstance(fp, dict) and fp.get("service") else None


def _structured_match(sfp: dict, product: str, version: str) -> tuple[bool, str]:
    """Does a corpus entry's structured fingerprint cover the queried service+version?

    Reuses the CVE index's own ``_version_verdict`` on the entry's ``version_kind``/``versions``,
    so an in-range version matches and an OUT-OF-RANGE one does NOT — the version verdict
    outranks token similarity, and a wrong version cannot ride a product-name match to the top.

    The fingerprint corpus stores the **last vulnerable** version (unlike the CVE index, which
    stores the fix version), so the boundary is INCLUSIVE: a scan reporting exactly the stored
    version is a hit. ``inclusive=True`` states that convention explicitly rather than leaning on
    the predicate's default — the two callers genuinely need opposite boundaries.
    """
    service = str(sfp.get("service") or "").lower()
    if product and product not in service and service not in product:
        return False, f"different product ({service})"
    if not version:
        return True, f"names {service} (no version queried)"
    kind = str(sfp.get("version_kind") or "none")
    versions = [str(v) for v in (sfp.get("versions") or [])]
    if kind == "none" or not versions:
        return True, f"{service} (product-only fingerprint)"
    try:
        from exploits.index import ExploitIndex, version_tuple

        verdict = ExploitIndex()._version_verdict(
            {"version_kind": kind, "versions": versions}, version, version_tuple(version),
            inclusive=True,
        )[0]
    except Exception:  # noqa: BLE001 — fall back to a plain product match if the index is odd
        return True, f"{service} (version verdict unavailable)"
    if verdict == "different":
        return False, f"{service} but {version} is out of range {versions}"
    return True, f"{service} {version}: {verdict}"


def rerank(entries: list[Any], fp: str) -> list[Ranked]:
    """Re-rank base KB results so exact fingerprint matches lead, preserving base order within
    each group. A fingerprint like ``apache/2.4.49`` matches an entry that names BOTH the product
    and the exact version — the version is what makes it a case match rather than a topic match.

    Two matching paths: an entry carrying a STRUCTURED ``meta.fingerprint`` is range-matched via
    the CVE index verdict (so an out-of-range version is correctly NOT a match); any other entry
    falls back to the substring product+version test (backward-compatible with plain KB entries).
    """
    if not fp:
        return [Ranked(e, i, False, "no fingerprint") for i, e in enumerate(entries)]
    parts = fp.split("/", 1)
    product = parts[0]
    version = parts[1] if len(parts) > 1 else ""
    ranked: list[Ranked] = []
    for i, e in enumerate(entries):
        sfp = _structured_fp(e)
        if sfp is not None:
            match, why = _structured_match(sfp, product, version)
            ranked.append(Ranked(e, i, match, why))
            continue
        blob = _entry_blob(e)
        has_product = bool(product) and product in blob
        has_version = bool(version) and version in blob
        if has_product and has_version:
            ranked.append(Ranked(e, i, True, f"names {product} and version {version}"))
        elif has_product and not version:
            ranked.append(Ranked(e, i, True, f"names {product}"))
        else:
            ranked.append(Ranked(e, i, False, "token match only"))
    # fingerprint matches first, then original order within each bucket
    ranked.sort(key=lambda r: (0 if r.fingerprint_match else 1, r.base_rank))
    return ranked


def retrieve(
    service: Any,
    kb_search: Callable[[str], list[Any]],
    limit: int = 8,
    get_entry: Callable[[str], Any] | None = None,
) -> list[Ranked]:
    """Fingerprint-keyed retrieval for a discovered service.

    ``kb_search`` is the base retriever (title/token search) — injected so this stays decoupled
    from whichever KB backend is wired. The query is ``product version``; results are re-ranked
    by fingerprint. Returns [] when there is nothing to search on.

    ``get_entry`` optionally hydrates each lightweight search result into its FULL KB entry by id
    (``STATE.by_id.get``). This matters for the exploitation-writeup corpus: the search index
    returns only title/snippet, but the STRUCTURED ``meta.fingerprint`` — which is what lets a
    version RANGE (``lte`` / ``range``) match rather than a substring — lives on the full entry.
    Without it, only exact versions present in the title/snippet fingerprint-match (still useful,
    just narrower). Best-effort: a hydrator miss falls back to the lightweight result.
    """
    product = getattr(service, "product", "") or getattr(service, "name", "")
    version = getattr(service, "version", "") or ""
    if not product.strip():
        return []
    query = f"{product} {version}".strip()
    try:
        base = list(kb_search(query))[: max(limit * 3, limit)]
    except Exception:  # noqa: BLE001 — retrieval must never break the loop
        return []
    if get_entry is not None:
        hydrated = []
        for r in base:
            eid = r.get("id") if isinstance(r, dict) else getattr(r, "id", None)
            full = get_entry(eid) if eid else None
            hydrated.append(full if full is not None else r)
        base = hydrated
    return rerank(base, service_fingerprint(service))[:limit]
