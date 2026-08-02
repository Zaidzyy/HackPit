"""Regenerate the committed KB fixture the fingerprint tests fall back to in CI.

WHY THIS EXISTS. `/data/` is gitignored — the KB is a rebuildable artifact and third-party
corpora never enter the repo — so a clean checkout (CI, a fresh clone) has no
`data/kb/entries.jsonl`. Three regression locks iterate that corpus by design
(`test_fingerprint_versions`, `test_fingerprint_norm`, `test_fingerprint_fallback`), and on a
clean checkout they did not skip, they CRASHED.

WHY THIS IS NOT THE THING backend/AGENTS.md §1 FORBIDS. The rule is "never hand-write an
example when the real population is enumerable", and its worst case was a test asserting on a
synthetic value the real system never produces. This fixture is NOT synthetic and NOT a sample:
it is the COMPLETE corpus — every entry, every structured fingerprint — with only the fields
the matcher never reads removed.

`reasoning.retrieval._entry_blob` reads exactly ``title, text, body, summary, tags, product``,
and `_structured_fp` reads ``meta.fingerprint``. The live KB carries no ``text``, ``body`` or
``product`` field at all (it uses ``body_md`` and ``steps``, which the blob does not consult),
so projecting to the fields below is INFORMATION-PRESERVING for these three tests. That claim
is not taken on trust: `test_kb_fixture.py` re-derives the fixture from the live KB and asserts
the projection is byte-identical to the committed file, and asserts the three tests reach the
same verdicts on both.

The projection is what makes this affordable — 22 MB of corpus becomes ~1.1 MB of fixture
without dropping a single entry or fingerprint.

Run (from the repo root, whenever the KB gains or loses a fingerprint):
    backend/.venv/Scripts/python.exe backend/test_support/make_kb_fixture.py
"""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
KB_PATH = REPO_ROOT / "data" / "kb" / "entries.jsonl"
FIXTURE_PATH = Path(__file__).resolve().parent / "kb_fixture.jsonl"

# Exactly the fields the fingerprint path consults, plus the few that make a failure message
# readable (`id`, `category`, `source`). Adding a field here is safe; REMOVING one that
# `_entry_blob` reads would silently change what the tests see, which is why
# test_kb_fixture.py asserts this list against the matcher's own tuple.
BLOB_FIELDS = ("title", "text", "body", "summary", "tags", "product")
CONTEXT_FIELDS = ("id", "category", "source")


def project(entry: dict) -> dict:
    """One KB entry reduced to what the fingerprint matcher can actually see."""
    out: dict = {k: entry[k] for k in (*CONTEXT_FIELDS, *BLOB_FIELDS) if k in entry}
    meta = entry.get("meta")
    if isinstance(meta, dict) and isinstance(meta.get("fingerprint"), dict):
        # Only the fingerprint block — the rest of `meta` is never read by this path.
        out["meta"] = {"fingerprint": meta["fingerprint"]}
    return out


def read_kb(path: Path = KB_PATH) -> list[dict]:
    entries: list[dict] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def render(entries: list[dict]) -> str:
    """The fixture's exact bytes. `sort_keys` + a trailing newline so a regeneration that
    changed nothing produces a byte-identical file and therefore an empty diff."""
    lines = [json.dumps(project(e), ensure_ascii=False, sort_keys=True) for e in entries]
    return "\n".join(lines) + "\n"


def main() -> int:
    if not KB_PATH.exists():
        print(f"FAIL  no live KB at {KB_PATH} — build it first (the fixture is DERIVED, never authored)")
        return 1
    entries = read_kb()
    if not entries:
        print(f"FAIL  {KB_PATH} parsed to zero entries")
        return 1
    text = render(entries)
    fingerprints = sum(1 for e in entries if isinstance((e.get("meta") or {}).get("fingerprint"), dict))
    before = FIXTURE_PATH.read_text(encoding="utf-8") if FIXTURE_PATH.exists() else ""
    FIXTURE_PATH.write_text(text, encoding="utf-8", newline="\n")
    changed = "unchanged" if text == before else "UPDATED"
    print(
        f"{changed}: {FIXTURE_PATH.relative_to(REPO_ROOT)} — {len(entries)} entries, "
        f"{fingerprints} structured fingerprints, {len(text.encode('utf-8')) / 1024:.0f} KB"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
