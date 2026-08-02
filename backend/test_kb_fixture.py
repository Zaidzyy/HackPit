"""The fixture the fingerprint locks fall back to in CI is REAL, COMPLETE, CURRENT and EQUIVALENT.

Three regression locks (`test_fingerprint_versions`, `test_fingerprint_norm`,
`test_fingerprint_fallback`) iterate the live KB by design — backend/AGENTS.md §1 requires a
safety test to draw from the real population so a fingerprint added tomorrow is covered without
anyone editing a test. But `/data/` is gitignored, so on a clean checkout (CI) that corpus does
not exist and those locks used to crash.

`test_support/kb_fixture.jsonl` closes that without weakening the rule: it is the COMPLETE
corpus projected onto the fields the fingerprint path actually reads, not a sample and not a
hand-written example. This file is what makes that claim checkable rather than asserted:

1. **Complete** — every entry and every structured fingerprint in the live KB is present.
2. **Faithful** — the projected field list is exactly what `retrieval._entry_blob` consults,
   read out of the matcher's own source by AST. Add a field to the matcher and this FAILS,
   rather than the fixture silently going blind to it.
3. **Current** — re-deriving from the live KB reproduces the committed bytes. A fingerprint
   added without regenerating fails here, where the data exists to notice.
4. **Equivalent** — the two corpora produce byte-identical match verdicts for every probe the
   locks use. This is the claim that actually matters, and it is measured, not argued.
5. **Falsifiable** — a truncated fixture is demonstrated to be caught (§3 of the rule: a guard
   with no proof it can fail is not evidence).

Checks 1, 3 and 4 need the live KB and are reported NOT-RUN when it is absent — never silently
skipped, because a fixture that validates only itself is exactly the vacuous pass this project
refuses elsewhere (`test_proof_honesty.py`).

Run:  python test_kb_fixture.py
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pipeline"))

from reasoning import retrieval  # noqa: E402
from test_support import kb as kb_source  # noqa: E402
from test_support import make_kb_fixture as maker  # noqa: E402

# The probes the three locks actually use — the fixture only has to be equivalent for these,
# and they are imported from nowhere so this file states its own coverage.
PROBES: list[tuple[str, str]] = [
    ("nginx", "1.18.0"), ("ISC BIND", "9.16.1"), ("lighttpd", "1.4.59"), ("Jetty", "9.4.43"),
    ("Dovecot pop3d", ""), ("Pure-FTPd", ""), ("Node.js Express framework", ""),
    ("Werkzeug httpd", "0.14.1"), ("Gunicorn", "20.1.0"), ("Postfix smtpd", ""),
    ("Exim smtpd", "4.94"), ("HAProxy", "2.4.0"), ("Kibana", "7.10.0"), ("RabbitMQ", "3.8.9"),
    ("MinIO object storage", ""), ("vsftpd", "2.3.4"), ("Apache httpd", "2.4.49"),
    ("Apache Tomcat", "9.0.30"), ("OpenSSH", "8.2p1"), ("ProFTPD", "1.3.5"),
]

NOT_RUN: list[str] = []


def _blob_fields_from_source() -> tuple[str, ...]:
    """The field names `retrieval._entry_blob` really reads, taken from its AST.

    Read from the matcher instead of duplicated here on purpose: a hand-copied list is the
    'shorter list still passes' rot backend/AGENTS.md §1 describes. If someone teaches the blob
    to read `body_md`, the fixture stops being information-preserving and this must fail.
    """
    src = Path(retrieval.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name == "_entry_blob"),
        None,
    )
    assert fn is not None, "retrieval._entry_blob not found — the matcher was renamed"
    names: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Tuple):
            vals = [x.value for x in node.elts
                    if isinstance(x, ast.Constant) and isinstance(x.value, str)]
            if len(vals) >= 2:
                names.update(vals)
    assert names, "no field tuple found inside _entry_blob"
    return tuple(sorted(names))


def _verdicts(entries: list[dict], fp: str) -> dict[int, tuple[bool, bool]]:
    """base_rank -> (fingerprint_match, fallback_match). Keyed on the ORIGINAL index so the
    two corpora are compared entry-for-entry rather than by post-sort position."""
    return {r.base_rank: (r.fingerprint_match, r.fallback_match)
            for r in retrieval.rerank(entries, fp)}


def _live_entries() -> list[dict] | None:
    """The live KB, or None when this environment does not have one (CI) / is simulating that.

    Honours HACKPIT_FORCE_KB_FIXTURE so `HACKPIT_FORCE_KB_FIXTURE=1 sh backend/run_safety_tests.sh`
    reproduces a clean CI checkout exactly — including THIS file reporting its live-KB checks as
    NOT-RUN, which is the behaviour being reproduced.
    """
    if kb_source._forced() or not kb_source.LIVE_KB.exists():
        return None
    entries = maker.read_kb(kb_source.LIVE_KB)
    return entries or None


def test_fixture_is_faithful_to_the_matcher() -> None:
    """The projection keeps every field the matcher consults (check 2)."""
    blob_fields = _blob_fields_from_source()
    projected = set(maker.BLOB_FIELDS)
    missing = [f for f in blob_fields if f not in projected]
    assert not missing, (
        f"retrieval._entry_blob reads {missing} but make_kb_fixture does not project them — "
        "the fixture would go blind to those fields. Add them to BLOB_FIELDS and regenerate."
    )
    print(f"  projection covers all {len(blob_fields)} fields _entry_blob reads "
          f"({', '.join(blob_fields)}): PASS")


def test_fixture_loads_and_carries_fingerprints() -> None:
    """The fixture is a usable corpus on its own terms (check 1, self-contained half)."""
    entries = maker.read_kb(kb_source.FIXTURE)
    assert entries, f"{kb_source.FIXTURE} parsed to zero entries"
    fps = kb_source.fingerprint_count(entries)
    assert fps > 0, "the fixture carries no structured fingerprints — the locks would be vacuous"
    # Floor, not an exact number: the corpus grows, and an exact count would fail on every
    # legitimate ingest. Staleness is caught by the byte-comparison below, where it belongs.
    assert fps >= 50, f"only {fps} fingerprints in the fixture — suspiciously few, regenerate it"
    print(f"  fixture: {len(entries)} entries, {fps} structured fingerprints: PASS")


def test_fixture_is_complete_and_current() -> None:
    """Re-deriving from the live KB reproduces the committed bytes (checks 1 + 3)."""
    live = _live_entries()
    if live is None:
        NOT_RUN.append("completeness/staleness (live KB absent — expected in CI)")
        print("  NOT-RUN completeness + staleness: no live KB (expected in CI, checked locally)")
        return
    rebuilt = maker.render(live)
    committed = kb_source.FIXTURE.read_text(encoding="utf-8")
    assert rebuilt == committed, (
        "the committed fixture is STALE — the live KB no longer projects to these bytes. "
        "Regenerate: backend/.venv/Scripts/python.exe backend/test_support/make_kb_fixture.py"
    )
    fixture_entries = maker.read_kb(kb_source.FIXTURE)
    assert len(fixture_entries) == len(live), (
        f"fixture has {len(fixture_entries)} entries, live KB has {len(live)} — not complete"
    )
    assert kb_source.fingerprint_count(fixture_entries) == kb_source.fingerprint_count(live), \
        "fixture and live KB disagree on the structured fingerprint count"
    print(f"  fixture is byte-current with the live KB ({len(live)} entries, "
          f"{kb_source.fingerprint_count(live)} fingerprints): PASS")


def test_fixture_and_live_kb_reach_identical_verdicts() -> None:
    """The claim that actually matters: same match decisions, entry for entry (check 4)."""
    live = _live_entries()
    if live is None:
        NOT_RUN.append("live-vs-fixture equivalence (live KB absent — expected in CI)")
        print("  NOT-RUN equivalence: no live KB (expected in CI, checked locally)")
        return
    fixture = maker.read_kb(kb_source.FIXTURE)
    assert len(fixture) == len(live), "corpora differ in length — cannot compare entry-for-entry"

    checked = 0
    disagreements: list[str] = []
    for product, version in PROBES:
        fp = retrieval.fingerprint(product, version)
        a, b = _verdicts(live, fp), _verdicts(fixture, fp)
        checked += 1
        for idx in a:
            if a[idx] != b.get(idx):
                title = (live[idx].get("title") or "")[:60]
                disagreements.append(f"{product} {version} @ entry {idx} ({title!r}): live={a[idx]} fixture={b.get(idx)}")
    assert not disagreements, (
        f"{len(disagreements)} verdict disagreement(s) between the live KB and the fixture — "
        "the projection is NOT information-preserving:\n  " + "\n  ".join(disagreements[:10])
    )
    print(f"  {checked} probes x {len(live)} entries: live KB and fixture agree on every "
          f"match verdict: PASS")


def test_positive_control_a_truncated_fixture_is_caught() -> None:
    """The equivalence check must be able to FAIL (check 5).

    Drops the structured fingerprints from a COPY of the fixture and asserts the comparison
    notices. Without this, "no disagreements" is what a working check and a dead one both print.
    """
    fixture = maker.read_kb(kb_source.FIXTURE)
    crippled = [e for e in fixture if not isinstance((e.get("meta") or {}).get("fingerprint"), dict)]
    assert len(crippled) < len(fixture), "control is vacuous: the fixture had no fingerprints to drop"

    fp = retrieval.fingerprint("vsftpd", "2.3.4")
    intact_claims = any(r.fingerprint_match for r in retrieval.rerank(fixture, fp))
    crippled_claims = any(r.fingerprint_match for r in retrieval.rerank(crippled, fp))
    assert intact_claims, "control FAILED: the intact fixture produced no structured match to lose"
    assert not crippled_claims, "control FAILED: a fixture with no fingerprints still claimed one"
    print(f"  positive control: dropping {len(fixture) - len(crippled)} fingerprints removes the "
          f"structured match, so the check can fail: PASS")


if __name__ == "__main__":
    print("== KB fixture: real, complete, current, equivalent ==")
    test_fixture_is_faithful_to_the_matcher()
    test_fixture_loads_and_carries_fingerprints()
    test_fixture_is_complete_and_current()
    test_fixture_and_live_kb_reach_identical_verdicts()
    test_positive_control_a_truncated_fixture_is_caught()
    if NOT_RUN:
        # Loud, never silent: a fixture that only validates itself is not evidence that it
        # matches the corpus it stands in for.
        print("\n  NOT-RUN in this environment (needs the live KB):")
        for item in NOT_RUN:
            print(f"    - {item}")
    print("all KB fixture tests passed")
