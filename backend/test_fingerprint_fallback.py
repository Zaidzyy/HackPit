"""Regression lock for the version-less substring fallback (the eval's last retrieval residual).

The bug this pins: `reasoning.retrieval.rerank`'s fallback path matched a scanned product as a bare
substring anywhere in a plain entry and set `fingerprint_match=True` — the SAME confidence as a
structured meta.fingerprint match. So a scan of a service the corpus does NOT cover (Pure-FTPd,
Node.js, MinIO) produced a "this exact stack was solved by X" grounding line it had not earned
(measured 20% false-fire on the eval's UNCOVERED group). The fix reserves `fingerprint_match` for
STRUCTURED hits; an unstructured product-name hit is a distinct, lower-ranked `fallback_match`,
tightened to a word boundary.

Per backend/AGENTS.md: iterate the REAL corpus plus real services it does not cover, assert the
fallback never claims a structured fingerprint match for them, and carry a positive control that
demonstrably fails.

Run:  python test_fingerprint_fallback.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pipeline"))

from reasoning import retrieval  # noqa: E402

KB_PATH = Path(__file__).resolve().parents[1] / "data" / "kb" / "entries.jsonl"

# Real services the fingerprint corpus does NOT cover — the eval's UNCOVERED group plus the three
# that actually false-fired. A hit claiming fingerprint_match for any of these is the defect.
UNCOVERED = [
    ("nginx", "1.18.0"), ("ISC BIND", "9.16.1"), ("lighttpd", "1.4.59"), ("Jetty", "9.4.43"),
    ("Dovecot pop3d", ""), ("Pure-FTPd", ""), ("Node.js Express framework", ""),
    ("Werkzeug httpd", "0.14.1"), ("Gunicorn", "20.1.0"), ("Postfix smtpd", ""),
    ("Exim smtpd", "4.94"), ("HAProxy", "2.4.0"), ("Kibana", "7.10.0"), ("RabbitMQ", "3.8.9"),
    ("MinIO object storage", ""),
]
# A covered service+version — the control that the STRUCTURED path still fires (so the test can
# distinguish "nothing claimed a match" from "the matcher is simply dead").
COVERED = ("vsftpd", "2.3.4")


def _load() -> list[dict]:
    out: list[dict] = []
    with KB_PATH.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _corpus_service_keys(entries: list[dict]) -> set[str]:
    keys: set[str] = set()
    for e in entries:
        fp = ((e.get("meta") or {}).get("fingerprint")) if isinstance(e.get("meta"), dict) else None
        if isinstance(fp, dict) and fp.get("service"):
            keys.add(str(fp["service"]).lower())
    return keys


def test_fallback_never_claims_a_structured_fingerprint_match() -> None:
    entries = _load()
    assert entries, f"no KB entries loaded from {KB_PATH}"
    keys = _corpus_service_keys(entries)
    assert keys, "no structured fingerprint service keys in the corpus"

    checked = 0
    offenders: list[str] = []
    for product, version in UNCOVERED:
        # sanity: the service really is uncovered (its normalised head is not a corpus key)
        head = retrieval.fingerprint(product).split("/", 1)[0]
        assert not any(head == k or head in k or k in head for k in keys if head), \
            f"{product!r} normalises to {head!r}, which IS a corpus key — not a valid uncovered case"
        fp = retrieval.fingerprint(product, version)
        ranked = retrieval.rerank(entries, fp)
        checked += 1
        claimed = [r for r in ranked if r.fingerprint_match]
        if claimed:
            offenders.append(f"{product} {version} -> {[r.why for r in claimed][:2]}")
    assert not offenders, (
        f"{len(offenders)} uncovered service(s) got a STRUCTURED fingerprint claim from the "
        f"fallback:\n  " + "\n  ".join(offenders)
    )
    print(f"  {checked} uncovered services, none claim a structured fingerprint match: PASS")


def test_positive_control_structured_still_fires_and_fallback_is_distinct() -> None:
    entries = _load()
    # 1. the covered service MUST still produce a structured fingerprint match — proves the check
    #    above means "no false claim", not "the matcher is dead".
    fp = retrieval.fingerprint(*COVERED)
    ranked = retrieval.rerank(entries, fp)
    top = ranked[0]
    assert top.fingerprint_match and retrieval._structured_fp(top.entry) is not None, \
        f"positive control FAILED: covered {COVERED} did not yield a structured fingerprint match"

    # 2. a planted UNSTRUCTURED entry that names the product must be a fallback_match, NOT a
    #    fingerprint_match — this is exactly what the old blind-substring rule got wrong. If this
    #    entry were marked fingerprint_match, the assertion above would have caught it; assert the
    #    labelling here so the detector's discriminator can itself fail.
    planted = {"title": "MinIO deployment notes", "text": "running minio in production"}
    r = retrieval.rerank([planted], retrieval.fingerprint("MinIO object storage", ""))[0]
    assert r.fallback_match and not r.fingerprint_match, \
        f"positive control FAILED: an unstructured product hit was mislabelled ({r.why})"

    # 3. word-boundary: a product token that only appears INSIDE another word must not even be a
    #    fallback match (the old rule matched 'pure' inside unrelated words).
    noise = {"title": "purely academic notes", "text": "a treatise on purity"}
    r2 = retrieval.rerank([noise], retrieval.fingerprint("Pure-FTPd", ""))[0]
    assert not r2.fingerprint_match and not r2.fallback_match, \
        f"positive control FAILED: 'pure' matched inside an unrelated word ({r2.why})"
    print("  positive control: structured still fires; unstructured is fallback; substring-in-word rejected: PASS")


if __name__ == "__main__":
    test_fallback_never_claims_a_structured_fingerprint_match()
    test_positive_control_structured_still_fires_and_fallback_is_distinct()
    print("all fingerprint fallback tests passed")
