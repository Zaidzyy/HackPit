"""Tie a finding to the KB technique behind it.

A scanner tells you *there is an SQL injection on line 41*. The KB knows *what an SQL
injection is and how it gets exploited*. Linking the two turns a lint result into something
a reviewer can actually learn from — the defensive finding points at the offensive technique
that would abuse it.

**Never fabricated.** A link is only attached when the KB genuinely has a matching technique:
the candidate must be step-eligible (a real technique page, not a writeup or a grab-bag) and
its title or summary must actually contain one of the category's own words. No confident
match → no link, and the finding stands on its own. That is the same discipline the attack
path uses for grounded vs ai_suggested steps: a citation is real or it is absent.

This module imports nothing from the engagement / executor / scope / isolation model. It is
handed a search callable and the KB index, so it stays a pure lookup.
"""

from __future__ import annotations

from typing import Any, Callable

# category -> (search seed, tokens that must appear in the matched entry)
#
# The required tokens are what stop a loose semantic hit from becoming a bogus citation: a
# search for "path traversal" that returns a generic web-recon page fails the token check and
# the finding is simply left unlinked.
_CATEGORY_KB: dict[str, tuple[str, tuple[str, ...]]] = {
    "injection": (
        "sql injection command injection exploitation sqlmap payload",
        ("sql", "inject", "sqli", "command exec", "rce"),
    ),
    "xss": (
        "cross site scripting xss payload dom stored reflected",
        ("xss", "cross-site script", "cross site script"),
    ),
    "ssrf": (
        "server side request forgery ssrf cloud metadata internal",
        ("ssrf", "request forgery"),
    ),
    "xxe": (
        "xxe xml external entity injection file read",
        ("xxe", "xml external", "external entity"),
    ),
    "path-traversal": (
        "path traversal directory traversal local file inclusion lfi",
        ("traversal", "lfi", "file inclusion", "../"),
    ),
    "deserialization": (
        "insecure deserialization pickle gadget chain remote code execution",
        ("deserial", "pickle", "gadget", "unserialize"),
    ),
    "secrets": (
        "hardcoded credentials secrets api key leak exposed",
        ("secret", "credential", "api key", "hardcoded", "token"),
    ),
    "auth": (
        "jwt token forgery authentication bypass signature none algorithm",
        ("jwt", "auth bypass", "authentication bypass", "token forg"),
    ),
    "csrf": (
        "cross site request forgery csrf token bypass",
        ("csrf", "request forgery"),
    ),
    "open-redirect": (
        "open redirect oauth token theft redirect_uri",
        ("open redirect", "redirect"),
    ),
    # Deliberately narrow. A loose "tls" token matched "Evil Twin EAP-TLS" — a WiFi attack,
    # not a weak-crypto technique. The tokens must name the CLASS, not merely a protocol the
    # page mentions; an unlinked finding is the correct outcome when the KB has no fit.
    "crypto": (
        "weak hashing algorithm password cracking hashcat certificate validation bypass",
        ("hash crack", "hashcat", "john the ripper", "weak cipher", "weak hash",
         "certificate valid", "padding oracle", "md5", "sha1"),
    ),
    "misconfiguration": (
        "security misconfiguration cors debug exposed admin interface",
        ("cors", "misconfig", "debug", "exposed"),
    ),
}

_SEARCH_K = 8


def _matches(entry: dict, tokens: tuple[str, ...]) -> bool:
    """The candidate must actually be ABOUT this class — not merely nearby in vector space."""
    hay = f"{entry.get('title') or ''} {entry.get('summary') or ''}".lower()
    return any(tok in hay for tok in tokens)


def _best_entry(
    category: str,
    by_id: dict[str, dict],
    search_fn: Callable[[str, int, str], list[dict]],
    eligible: Callable[[dict], bool] | None,
    focused: Callable[[dict], bool] | None = None,
) -> tuple[str, str] | None:
    """(entry_id, title) of a genuinely matching technique for this category, or None.

    Two passes: a FOCUSED single-technique page wins over a broad cheatsheet/resource page,
    so "SQL Injection" beats "sql injection resource" when both match. The broad page is
    still better than nothing, so it is the fallback rather than being excluded.
    """
    spec = _CATEGORY_KB.get(category)
    if not spec:
        return None
    seed, tokens = spec
    try:
        hits = search_fn(seed, _SEARCH_K, "hybrid")
    except Exception:  # noqa: BLE001 - the tie-in is a bonus; a search failure never fails a scan
        return None

    candidates: list[dict] = []
    for hit in hits or []:
        entry = by_id.get(hit.get("id") or "")
        if not entry:
            continue
        if eligible is not None and not eligible(entry):
            continue  # writeup / grab-bag / meta doc — not a technique to point at
        if not _matches(entry, tokens):
            continue
        candidates.append(entry)

    if focused is not None:
        for entry in candidates:
            if focused(entry):
                return entry["id"], str(entry.get("title") or "")
    for entry in candidates:
        return entry["id"], str(entry.get("title") or "")
    return None


def link(
    findings: list[Any],
    by_id: dict[str, dict],
    search_fn: Callable[[str, int, str], list[dict]] | None,
    eligible: Callable[[dict], bool] | None = None,
    focused: Callable[[dict], bool] | None = None,
) -> int:
    """Attach ``kb_entry_id`` / ``kb_title`` to findings whose category maps to a real KB
    technique. Returns how many were linked.

    One search per distinct CATEGORY, not per finding — a hundred SQLi findings share one
    lookup. Mutates the findings in place and is a no-op when no search is available, so a
    KB-less deployment scans exactly the same, just without the links.
    """
    if not findings or not by_id or search_fn is None:
        return 0
    resolved: dict[str, tuple[str, str] | None] = {}
    linked = 0
    for finding in findings:
        category = getattr(finding, "category", "") or ""
        if category not in resolved:
            resolved[category] = _best_entry(category, by_id, search_fn, eligible, focused)
        hit = resolved[category]
        if hit:
            finding.kb_entry_id, finding.kb_title = hit
            linked += 1
    return linked
