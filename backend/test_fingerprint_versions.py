"""Regression lock for D-A: every fingerprint entry must match its OWN stored version.

The bug this pins: `reasoning.retrieval._structured_match` delegated to the CVE index's
`_version_verdict`, and the two subsystems used OPPOSITE boundary conventions. The CVE index
stores `versions[-1]` as the FIX version (exclusive `<`); the fingerprint corpus stores the LAST
VULNERABLE version (needs inclusive `<=`). Nothing asserted the obvious — that a corpus entry
matches the very version it was written about — so 35 of 38 testable fingerprints silently missed
their most precise possible hit. This is the third shared-predicate defect in the project
(WinRM argv[0], D22's proxychains laundering, now this).

Per backend/AGENTS.md: iterate the REAL corpus (every `meta.fingerprint` row in the live KB, not
a sample), assert on what was checked, and carry a positive control that proves the test can fail.

Run:  python test_fingerprint_versions.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pipeline"))

from reasoning.retrieval import _structured_match  # noqa: E402

KB_PATH = Path(__file__).resolve().parents[1] / "data" / "kb" / "entries.jsonl"


def _fingerprint_entries() -> list[dict]:
    """Every entry in the live KB that carries a structured meta.fingerprint. The real
    population — a fingerprint added tomorrow is covered without anyone editing this test."""
    out: list[dict] = []
    with KB_PATH.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            fp = ((e.get("meta") or {}).get("fingerprint")) if isinstance(e.get("meta"), dict) else None
            if isinstance(fp, dict) and fp.get("service"):
                out.append(fp)
    return out


def test_every_fingerprint_matches_its_own_stored_version() -> None:
    fps = _fingerprint_entries()
    assert fps, f"no fingerprint entries found in {KB_PATH} — the corpus or path is wrong"

    checked = 0
    failures: list[str] = []
    for fp in fps:
        service = str(fp.get("service") or "")
        kind = str(fp.get("version_kind") or "none")
        versions = [str(v) for v in (fp.get("versions") or [])]
        # A version-less (kind=none) fingerprint has no stored version to self-test; its
        # product-only match is exercised by the covered-service eval, not here.
        if kind == "none" or not versions:
            continue
        for v in versions:
            checked += 1
            matched, why = _structured_match(fp, service, v)
            if not matched:
                failures.append(f"{service} {kind} {versions}: {v} -> {why}")

    assert not failures, (
        f"{len(failures)} fingerprint(s) do NOT match their own stored version:\n  "
        + "\n  ".join(failures)
    )
    print(f"  every stored version of {len(fps)} fingerprints self-matches "
          f"({checked} version checks across exact/lte/range): PASS")


def test_positive_control_a_wrong_range_is_caught() -> None:
    """The test above must be able to FAIL. A planted lte fingerprint whose stored version is
    BELOW the queried one must not match — if this 'match' returned True, the check is inert."""
    planted = {"service": "acme", "version_kind": "lte", "versions": ["1.0.0"]}
    matched, why = _structured_match(planted, "acme", "9.9.9")  # 9.9.9 is above the 1.0.0 bound
    assert not matched, f"positive control FAILED: an out-of-range version matched ({why})"
    # ...and the boundary itself (the last-vulnerable version) MUST match, or 'inclusive' is dead.
    ok, _ = _structured_match(planted, "acme", "1.0.0")
    assert ok, "positive control FAILED: the inclusive boundary (1.0.0) did not match"
    print("  positive control: out-of-range rejected, exact boundary accepted: PASS")


if __name__ == "__main__":
    test_every_fingerprint_matches_its_own_stored_version()
    test_positive_control_a_wrong_range_is_caught()
    print("all fingerprint self-match tests passed")
