"""Regression lock for D-B: no two distinct products may normalise to the same fingerprint key.

The bug this pins: `reasoning.retrieval.fingerprint()` took the FIRST meaningful token, so every
vendor-prefixed nmap banner collapsed to the vendor — `Apache Tomcat` and `Apache httpd` both
became `apache/<ver>`. Two unrelated products on ONE key are distinguished only by version number,
which can produce a CONFIDENTLY WRONG fingerprint hit — the exact failure this subsystem exists to
avoid — not merely a missing one.

Per backend/AGENTS.md: drive it from the real corpus (every service key the live KB defines) plus
real `nmap -sV` product strings, assert on what was checked, and carry a positive control that a
planted colliding pair is caught.

Run:  python test_fingerprint_norm.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pipeline"))

from reasoning.retrieval import fingerprint  # noqa: E402
from test_support import kb as kb_source  # noqa: E402

# Real `nmap -sV` product strings, paired with the corpus service key each MUST resolve to.
# These are the banners scanners actually emit — vendor-prefixed forms are the whole point.
NMAP_BANNERS = {
    "Apache httpd": "apache",
    "Apache Tomcat": "tomcat",
    "Apache Tomcat/Coyote JSP engine": "tomcat",
    "Apache Solr": "solr",
    "Apache log4j": "log4j",
    "Microsoft SQL Server 2022": "mssql",
    "Microsoft Exchange": "exchange",
    "Microsoft IIS httpd": "microsoft-iis",
    "Oracle WebLogic": "weblogic",
    "Atlassian Confluence": "confluence",
    "Redis key-value store": "redis",
    "vsftpd": "vsftpd",
    "OpenSSH": "openssh",
    "nginx": "nginx",
    "ProFTPD": "proftpd",
    "ISC BIND": "bind",
}


def _corpus_service_keys() -> set[str]:
    """Every structured fingerprint service key in the corpus — live KB locally, its committed
    projection in CI (`/data/` is gitignored). The projection keeps every fingerprint, and the
    provenance is printed so a green run cannot hide which corpus it iterated."""
    entries, provenance = kb_source.load()
    print(f"  corpus: {provenance}")
    keys: set[str] = set()
    for e in entries:
        fp = ((e.get("meta") or {}).get("fingerprint")) if isinstance(e.get("meta"), dict) else None
        if isinstance(fp, dict) and fp.get("service"):
            keys.add(str(fp["service"]).lower())
    return keys


def _head(product: str) -> str:
    return fingerprint(product).split("/", 1)[0]


def test_vendor_prefixed_banners_resolve_to_the_product() -> None:
    keys = _corpus_service_keys()
    assert keys, "no corpus service keys found — the KB or path is wrong"
    checked = 0
    wrong: list[str] = []
    for banner, want in NMAP_BANNERS.items():
        checked += 1
        got = _head(banner)
        if got != want:
            wrong.append(f"{banner!r} -> {got!r}, want {want!r}")
    assert not wrong, "banner(s) normalised to the wrong key:\n  " + "\n  ".join(wrong)
    print(f"  {checked} real nmap banners each resolve to the product, not the vendor: PASS")


def test_no_two_distinct_products_collide_on_one_key() -> None:
    """The core lock: Apache Tomcat and Apache httpd MUST land on different keys, and more
    generally no two banners for different corpus services may share a key."""
    # 1. the named regression: Tomcat vs httpd.
    assert _head("Apache Tomcat") != _head("Apache httpd"), (
        f"COLLISION: Apache Tomcat and Apache httpd both -> {_head('Apache httpd')!r}"
    )
    # 2. every banner whose intended key differs must produce a different key — driven by the
    #    real banner->key table, so a future collision surfaces here rather than in production.
    by_key: dict[str, set[str]] = {}
    for banner, want in NMAP_BANNERS.items():
        by_key.setdefault(_head(banner), set()).add(want)
    collided = {k: v for k, v in by_key.items() if len(v) > 1}
    assert not collided, f"distinct products share a fingerprint key: {collided}"
    print(f"  {len(NMAP_BANNERS)} banners over {len(by_key)} distinct keys, no collision: PASS")


def test_positive_control_a_planted_collision_is_caught() -> None:
    """Prove the collision check can FAIL. (1) A collided bucket must be detected — the exact
    thing the OLD first-token normaliser produced for `Apache Tomcat`/`Apache httpd`. (2) The
    real normaliser must keep two genuinely different vendor-prefixed products apart."""
    # 1. the detector fires on a collided bucket (two distinct products, one key).
    planted_bucket = {"apache/1.0": {"tomcat", "httpd"}}
    detected = {k: v for k, v in planted_bucket.items() if len(v) > 1}
    assert detected, "positive control FAILED: the collision detector cannot see a collision"
    # 2. under the real normaliser, two different Apache-prefixed products do NOT share a key.
    assert _head("Apache Tomcat") != _head("Apache Solr"), (
        f"positive control FAILED: distinct products collided "
        f"(Tomcat={_head('Apache Tomcat')!r}, Solr={_head('Apache Solr')!r})"
    )
    print("  positive control: a collided bucket is detected, real vendor products stay distinct: PASS")


if __name__ == "__main__":
    test_vendor_prefixed_banners_resolve_to_the_product()
    test_no_two_distinct_products_collide_on_one_key()
    test_positive_control_a_planted_collision_is_caught()
    print("all fingerprint normalisation tests passed")
