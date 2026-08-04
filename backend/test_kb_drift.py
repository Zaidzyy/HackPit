"""DRIFT DETECTION between the knowledge base and everything derived from it (D6).

`data/kb/entries.jsonl` is the source of truth. Three artefacts are built FROM it and are
useless — worse, quietly wrong — when they fall behind it:

  * `ids.json` + `embeddings.npy`  the semantic index. An entry with no embedding is
                                   invisible to semantic search; an embedding whose entry is
                                   gone is a vector pointing at nothing.
  * `scripts.json`                 the :scripts surface. Its sources are KB entry ids.
  * `corpora_report.json`          what the corpus ingest last wrote.

None of them is regenerated automatically, and nothing compared them. THE SCRIPTS INDEX SAT
STALE BY 126 ENTRIES — built against 2,617 when the KB held 2,743 — through an entire audit,
and it was found by reading a number, not by any check. A stale index does not error: it
answers, just with 126 entries' worth of the corpus missing, which is exactly the kind of
wrong answer this repo treats as worse than a crash.

WHAT IS AND IS NOT PROVEN HERE. Every check is skipped when its artefact is absent, and the
skips are REPORTED, never silent — /data/ is gitignored in its entirety, so a fresh clone or
a CI runner has none of these files and this test legitimately proves nothing there. "Not
checked" printed loudly is the honest result in that environment; a green tick would not be.

Hermetic (reads files, runs nothing). Run:  python test_kb_drift.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
KB_DIR = REPO_ROOT / "data" / "kb"
KB_PATH = KB_DIR / "entries.jsonl"

# Reported at the end, so an environment that could not run a check says so out loud.
_UNCHECKED: list[str] = []


def _kb_ids() -> list[str]:
    """Every entry id in the live KB, in file order."""
    ids: list[str] = []
    with KB_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                ids.append(json.loads(line)["id"])
    return ids


def _artefact(name: str, why: str) -> dict | None:
    path = KB_DIR / name
    if not path.is_file():
        _UNCHECKED.append(f"{name} (absent — {why})")
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _delta(expected: set[str], got: set[str]) -> str:
    """A readable summary of a set mismatch — what is missing, what is extra."""
    missing, extra = sorted(expected - got), sorted(got - expected)
    parts = []
    if missing:
        parts.append(f"{len(missing)} in the KB but NOT in the artefact (e.g. {missing[:3]})")
    if extra:
        parts.append(f"{len(extra)} in the artefact but NO LONGER in the KB (e.g. {extra[:3]})")
    return "; ".join(parts)


# --------------------------------------------------------------------------- #
# the semantic index
# --------------------------------------------------------------------------- #
def _check_embedding_index(d: dict, live: list[str]) -> None:
    """Raises AssertionError on drift. Split out so a POSITIVE CONTROL can run the real
    check against a doctored artefact — a control that exercises a helper instead of the
    check itself proves the helper works and says nothing about the check."""
    assert int(d.get("count", -1)) == len(live), (
        f"ids.json says it indexed {d.get('count')} entries; the KB holds {len(live)}. The "
        "semantic index is stale — re-run pipeline/embed.py."
    )
    # A COUNT IS NOT COVERAGE. Equal counts with different ids is drift that reads as health:
    # one entry added and another deleted between runs leaves the total untouched.
    got = set(d.get("ids") or [])
    assert got == set(live), (
        "ids.json indexes a different SET of entries than the KB contains, even where the "
        "counts agree: " + _delta(set(live), got)
    )


def _must_fail(fn, *args, label: str = "") -> None:
    """Assert that a check REJECTS a deliberately broken input."""
    try:
        fn(*args)
    except AssertionError:
        return
    raise AssertionError(f"the {label} check passed a doctored artefact — it cannot fail")


def test_the_embedding_index_covers_exactly_the_live_kb() -> None:
    d = _artefact("ids.json", "run pipeline/embed.py to build it")
    if d is None:
        print("  (embedding index: NOT CHECKED — ids.json absent)")
        return
    live = _kb_ids()
    _check_embedding_index(d, live)
    print(f"  embedding index covers exactly the live KB ({len(live)} entries): PASS")

    # POSITIVE CONTROLS — both drift shapes, against the REAL check.
    _must_fail(_check_embedding_index, {**d, "count": len(live) - 1}, live,
               label="embedding-count")
    swapped = [*live[1:], "hackpit-entry-that-does-not-exist"]
    _must_fail(_check_embedding_index, {"count": len(live), "ids": swapped}, live,
               label="embedding-id-set")
    print("  positive control: a stale count AND an equal-count id swap both fail: PASS")


# --------------------------------------------------------------------------- #
# the scripts index — the one that actually drifted
# --------------------------------------------------------------------------- #
def _check_scripts_index(d: dict, live: list[str]) -> None:
    built_against = int(d.get("kb_entries", -1))
    assert built_against == len(live), (
        f"scripts.json was built against {built_against} KB entries; the KB now holds "
        f"{len(live)} ({len(live) - built_against:+d}). THIS IS THE D6 DEFECT VERBATIM — the "
        "index sat 126 entries stale and nothing noticed. Re-run pipeline/scripts_index.py."
    )
    # ...and its citations must still resolve. A count can match while the entries a script
    # claims to come from have been renamed or dropped underneath it.
    live_set = set(live)
    dangling: set[str] = set()
    for group in d.get("groups") or []:
        for script in group.get("scripts") or []:
            for src in script.get("sources") or []:
                sid = src.get("id")
                if sid and sid not in live_set:
                    dangling.add(sid)
    assert not dangling, (
        f"{len(dangling)} entry ids cited by scripts.json no longer exist in the KB "
        f"(e.g. {sorted(dangling)[:3]}) — the index cites entries that are gone"
    )


def test_the_scripts_index_was_built_against_the_live_kb() -> None:
    d = _artefact("scripts.json", "run pipeline/scripts_index.py to build it")
    if d is None:
        print("  (scripts index: NOT CHECKED — scripts.json absent)")
        return
    live = _kb_ids()
    _check_scripts_index(d, live)
    print(f"  scripts index built against the live KB ({d['kb_entries']} entries): PASS")
    print("  every entry id it cites still resolves: PASS")

    # POSITIVE CONTROLS — the exact drift that went unnoticed, and a dangling citation.
    _must_fail(_check_scripts_index, {**d, "kb_entries": len(live) - 126}, live,
               label="scripts-staleness")
    _must_fail(
        _check_scripts_index,
        {"kb_entries": len(live),
         "groups": [{"scripts": [{"sources": [{"id": "hackpit-deleted-entry"}]}]}]},
        live,
        label="scripts-dangling-citation",
    )
    print("  positive control: a 126-entry lag AND a dangling citation both fail: PASS")


# --------------------------------------------------------------------------- #
# the corpus ingest's own record
# --------------------------------------------------------------------------- #
def test_the_corpus_report_matches_the_kb_it_last_wrote() -> None:
    d = _artefact("corpora_report.json", "run pipeline/ingest_corpora.py to build it")
    if d is None:
        print("  (corpus report: NOT CHECKED — corpora_report.json absent)")
        return
    live = _kb_ids()
    after = int(d.get("kb_lines_after", -1))
    if after < 0:
        _UNCHECKED.append("corpora_report.json (no kb_lines_after — written by --dry-run?)")
        print("  (corpus report: NOT CHECKED — no kb_lines_after recorded)")
        return
    assert after == len(live), (
        f"the last corpus ingest left {after} entries; the KB now holds {len(live)}. Another "
        "ingester has written since, which is fine — but the corpus entries may no longer be "
        "the ones this report describes. Re-run pipeline/ingest_corpora.py to resync."
    )
    print(f"  corpus report matches the live KB ({after} entries): PASS")


def test_every_derived_artefact_is_accounted_for() -> None:
    """A NEW derived artefact must be added here deliberately, not discovered later.

    The scripts index drifted for as long as it did partly because nothing enumerated what
    "derived from the KB" even meant. This fails when data/kb grows a file that no check
    above covers and that is not on the known-not-derived list, so the choice to leave it
    unchecked has to be made on purpose.
    """
    if not KB_DIR.is_dir():
        print("  (artefact inventory: NOT CHECKED — data/kb absent)")
        return
    checked = {"ids.json", "scripts.json", "corpora_report.json"}
    # Not derived FROM entries.jsonl, so drift against it is not a meaningful question:
    # inputs, one-off reports of a past run, and the binary half of the embedding index.
    not_derived = {
        "entries.jsonl",        # the source of truth itself
        "embeddings.npy",       # checked through its ids.json sidecar
        "exploitdb.json",       # an external feed, keyed by CVE, not by entry id
        "toolfiles.json",       # a file inventory of the source trees, not of the KB
        "index.json", "index.notes.json",          # hand-maintained source registry
        "curation_report.json", "curation_report.md",
        "curation_changes.json", "curation_changes.md",
        "exclusion_report.json",
    }
    seen = {p.name for p in KB_DIR.iterdir() if p.is_file()}
    # merge_report.*.json are per-source records of one past ingest, not live artefacts.
    unknown = sorted(
        n for n in seen - checked - not_derived if not n.startswith("merge_report")
    )
    assert not unknown, (
        "data/kb holds files no drift check covers and nothing has classified: "
        f"{unknown}. Either add a check above, or list it as not-derived with the reason."
    )
    print(f"  all {len(seen)} files in data/kb are classified: PASS")


if __name__ == "__main__":
    if not KB_PATH.is_file():
        print(f"  (skipped — no live KB at {KB_PATH})")
        print("ALL KB drift checks skipped (no KB present — this proves nothing here)")
        sys.exit(0)
    test_the_embedding_index_covers_exactly_the_live_kb()
    test_the_scripts_index_was_built_against_the_live_kb()
    test_the_corpus_report_matches_the_kb_it_last_wrote()
    test_every_derived_artefact_is_accounted_for()
    if _UNCHECKED:
        print("  NOT CHECKED in this environment:")
        for item in _UNCHECKED:
            print(f"    - {item}")
    print("ALL KB drift checks pass")
