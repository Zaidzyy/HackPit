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

_ALIASES = {
    "httpd": "apache", "apache2": "apache", "iis": "microsoft-iis",
    "mysqld": "mysql", "postgres": "postgresql", "smbd": "samba",
}


def fingerprint(product: str, version: str = "") -> str:
    """A normalized ``product/version`` key: ``("Apache httpd","2.4.49") -> "apache/2.4.49"``.

    The product is reduced to its first meaningful token and de-aliased so a banner and a KB
    entry agree; the version is kept verbatim (it is the selective part).
    """
    toks = [t for t in re.split(r"[\s/_-]+", (product or "").strip().lower()) if t]
    head = ""
    for t in toks:
        if t in ("httpd", "server", "http", "the"):
            continue
        head = _ALIASES.get(t, t)
        break
    head = head or (toks[0] if toks else "")
    ver = (version or "").strip().lower()
    return f"{head}/{ver}" if ver else head


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


def rerank(entries: list[Any], fp: str) -> list[Ranked]:
    """Re-rank base KB results so exact fingerprint matches lead, preserving base order within
    each group. A fingerprint like ``apache/2.4.49`` matches an entry that names BOTH the product
    and the exact version — the version is what makes it a case match rather than a topic match.
    """
    if not fp:
        return [Ranked(e, i, False, "no fingerprint") for i, e in enumerate(entries)]
    parts = fp.split("/", 1)
    product = parts[0]
    version = parts[1] if len(parts) > 1 else ""
    ranked: list[Ranked] = []
    for i, e in enumerate(entries):
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
) -> list[Ranked]:
    """Fingerprint-keyed retrieval for a discovered service.

    ``kb_search`` is the base retriever (title/token search) — injected so this stays decoupled
    from whichever KB backend is wired. The query is ``product version``; results are re-ranked
    by fingerprint. Returns [] when there is nothing to search on.
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
    return rerank(base, service_fingerprint(service))[:limit]
