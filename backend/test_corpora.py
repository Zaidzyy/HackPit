"""Phase 4 item 1 — the Route B additive corpus ingest (D11 / D12).

The KB gap this closes is that both markdown ingesters glob `**/*.md`, so PATT's payload
lists, the shodan dorks and the `oscp_tools` scripts were never seen. The fix had to be
ADDITIVE: re-running the real pipeline reverts downstream enrichment and rewrites 15 MB of
a gitignored, Defender-sensitive file that has no restore path but a rebuild.

So the properties pinned here are the ones that make an additive ingest safe to re-run:

  * existing entries are passed through as BYTES — a re-serialization that reordered a key
    or changed an escape would silently rewrite 1,601 entries this ingest never looked at
  * a re-run is byte-identical (idempotent), so it is safe to run after every source update
  * every line it owns is marked, and only marked lines are ever dropped
  * corpora carry `no_merge`, so consolidate.py can never fold a payload corpus into a
    technique page — that collapse is the original §4.4 defect
  * the entry holds a capped EXCERPT and the full corpus lives in a sidecar; an entry that
    inlined 1.8 MB would dominate BM25 and bloat the KB
  * Windows-only tool files are kept and MARKED, never advertised as runnable (D9)
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pipeline"))

import ingest_corpora as ic  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
KB_PATH = REPO_ROOT / "data" / "kb" / "entries.jsonl"
PAYLOAD_DIR = REPO_ROOT / "data" / "kb" / "payloads"


# --------------------------------------------------------------------------- #
# the additive write — the part that can destroy data if it is wrong
# --------------------------------------------------------------------------- #
def test_merge_preserves_foreign_lines_byte_for_byte() -> None:
    """Lines the ingester does not own come back byte-identical, not re-serialized."""
    with tempfile.TemporaryDirectory() as td:
        kb = Path(td) / "entries.jsonl"
        # Deliberately awkward: non-ASCII, an escape, and NON-SORTED keys. A JSON
        # round-trip would normalise all three.
        foreign = [
            b'{"id":"a","title":"caf\\u00e9","meta":{"z":1,"a":2},"body_md":"back\\\\slash"}',
            b'{"id":"b","meta":{},"title":"plain"}',
        ]
        kb.write_bytes(b"\n".join(foreign) + b"\n")

        ic.merge_into_kb(kb, [{"id": "new", "meta": {ic.CORPUS_MARK: True}}])

        out = [ln for ln in kb.read_bytes().split(b"\n") if ln.strip()]
        assert out[:2] == foreign, "existing lines must survive byte-for-byte"
        assert json.loads(out[2])["id"] == "new"
    print("  foreign KB lines survive the merge byte-for-byte: PASS")


def test_merge_replaces_only_its_own_lines() -> None:
    """A re-run drops exactly the marked lines — never a foreign one, never a leftover."""
    with tempfile.TemporaryDirectory() as td:
        kb = Path(td) / "entries.jsonl"
        kb.write_bytes(b'{"id":"keep","meta":{}}\n')

        ic.merge_into_kb(kb, [{"id": "c1", "meta": {ic.CORPUS_MARK: True}},
                              {"id": "c2", "meta": {ic.CORPUS_MARK: True}}])
        stats = ic.merge_into_kb(kb, [{"id": "c1", "meta": {ic.CORPUS_MARK: True}}])

        ids = [json.loads(l)["id"] for l in kb.read_bytes().split(b"\n") if l.strip()]
        assert ids == ["keep", "c1"], f"stale corpus line not reclaimed: {ids}"
        assert stats["previous_corpus_lines_replaced"] == 2
        assert stats["existing_kept"] == 1
    print("  a re-run replaces only marked lines, and reclaims removed ones: PASS")


def test_merge_ignores_an_unmarked_line_that_merely_mentions_the_marker() -> None:
    """The cheap byte pre-filter must not drop an entry whose BODY contains the word."""
    with tempfile.TemporaryDirectory() as td:
        kb = Path(td) / "entries.jsonl"
        decoy = json.dumps(
            {"id": "decoy", "body_md": f"a page about {ic.CORPUS_MARK}", "meta": {}}
        ).encode()
        kb.write_bytes(decoy + b"\n")

        ic.merge_into_kb(kb, [])
        out = [ln for ln in kb.read_bytes().split(b"\n") if ln.strip()]
        assert out == [decoy], "an unmarked entry mentioning the marker must be kept"
    print("  an entry that merely mentions the marker is not dropped: PASS")


def test_merge_is_atomic_and_leaves_no_temp_file() -> None:
    with tempfile.TemporaryDirectory() as td:
        kb = Path(td) / "entries.jsonl"
        kb.write_bytes(b'{"id":"keep","meta":{}}\n')
        ic.merge_into_kb(kb, [{"id": "c", "meta": {ic.CORPUS_MARK: True}}])
        leftovers = [p.name for p in Path(td).iterdir() if p.name != "entries.jsonl"]
        assert not leftovers, f"temp file left behind: {leftovers}"
    print("  the write is atomic and leaves no temp file: PASS")


# --------------------------------------------------------------------------- #
# entry shape
# --------------------------------------------------------------------------- #
def _sample_corpus(kind: str = "payload-set", lines: int = 500) -> ic.Corpus:
    raw = "\n".join(f"../" * 3 + f"etc/passwd{i}" for i in range(lines)).encode()
    return ic.Corpus(
        entry_id=f"{kind}-test-sample", title="Test — sample", source="payloadsallthethings",
        source_label="PayloadsAllTheThings", category="web", subcategory="File Inclusion",
        tags=["lfi", kind], kind=kind,
        recipe="ffuf -w {p}:FUZZ -u 'http://<target>/?page=FUZZ'",
        rel_path="File Inclusion/Intruders/sample.txt", abs_path=Path("sample.txt"),
        lines=ic._lines_from(raw), raw=raw,
    )


def test_entry_is_an_excerpt_with_a_sidecar_pointer() -> None:
    e = ic.build_entry(_sample_corpus())
    body = e["body_md"]
    assert len(body) < 6000, f"body must stay an excerpt, got {len(body)} chars"
    assert e["meta"]["corpus_lines"] == 500
    assert e["meta"]["corpus_truncated_in_body"] is True
    assert e["meta"]["corpus_file"] == "payloads/payload-set-test-sample.txt"
    # The recipe must resolve to the CONTAINER path — the sandbox cannot see the host one.
    cmd = e["steps"][0]["code"][0]["cmd"]
    assert "/payloads/payload-set-test-sample.txt" in cmd, cmd
    assert "{p}" not in cmd, "recipe placeholder left unsubstituted"
    print("  entry carries a capped excerpt + container-resolved sidecar pointer: PASS")


def test_corpora_are_no_merge_and_marked() -> None:
    """A payload corpus must never be foldable into a technique page (§4.4)."""
    for kind in ("payload-set", "dork-list"):
        e = ic.build_entry(_sample_corpus(kind))
        assert e["meta"]["no_merge"] is True, f"{kind} must be no_merge"
        assert e["meta"][ic.CORPUS_MARK] is True, f"{kind} must be marked"
        assert e["meta"]["kind"] == kind
    print("  corpora are no_merge and marked in meta: PASS")


def test_entry_validates_against_the_canonical_schema() -> None:
    from schema import Entry  # the KB schema every source normalises into

    Entry.model_validate(ic.build_entry(_sample_corpus()))
    print("  a corpus entry validates against the canonical Entry schema: PASS")


def test_sha256_and_byte_count_describe_the_real_file() -> None:
    c = _sample_corpus()
    e = ic.build_entry(c)
    assert e["meta"]["corpus_bytes"] == len(c.raw)
    assert e["meta"]["corpus_sha256"] == ic._sha256(c.raw)
    print("  entry metadata describes the real corpus bytes: PASS")


# --------------------------------------------------------------------------- #
# tool files (D12 / D9)
# --------------------------------------------------------------------------- #
def test_windows_only_tool_files_are_marked_not_advertised() -> None:
    """D9: Windows tooling is KEPT and MARKED — never listed as runnable here."""
    tf = REPO_ROOT / "data" / "kb" / "toolfiles.json"
    if not tf.is_file():
        print("  (skipped — toolfiles.json not built)")
        return
    rows = json.loads(tf.read_text(encoding="utf-8"))["files"]
    assert rows, "expected tool files"
    for r in rows:
        assert r["platform"] in ("windows", "linux", "any"), r["platform"]
        # The invariant: runs_here is FALSE for everything Windows-only.
        assert r["runs_here"] == (r["platform"] in ("linux", "any")), r["name"]
    win = [r for r in rows if r["platform"] == "windows"]
    assert win and not any(r["runs_here"] for r in win), "a windows tool claimed runs_here"
    print(f"  {len(win)} Windows-only tool files kept and marked not-runnable: PASS")


def test_tool_file_previews_are_capped_and_binaries_have_none() -> None:
    tf = REPO_ROOT / "data" / "kb" / "toolfiles.json"
    if not tf.is_file():
        print("  (skipped — toolfiles.json not built)")
        return
    rows = json.loads(tf.read_text(encoding="utf-8"))["files"]
    for r in rows:
        assert len(r["preview"]) <= ic.TOOL_PREVIEW_CHARS, r["name"]
        if r["lang"] == "binary":
            assert r["preview"] == "", f"{r['name']}: a binary must carry no preview"
    print("  tool previews are capped; binaries carry none: PASS")


# --------------------------------------------------------------------------- #
# the built artefacts on disk
# --------------------------------------------------------------------------- #
def test_every_corpus_entry_has_its_sidecar_on_disk() -> None:
    if not KB_PATH.is_file():
        print("  (skipped — no built KB)")
        return
    built = [json.loads(l) for l in KB_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    corpora = [e for e in built if (e.get("meta") or {}).get(ic.CORPUS_MARK)]
    assert corpora, "expected corpus entries in the built KB"
    for e in corpora:
        side = REPO_ROOT / "data" / "kb" / e["meta"]["corpus_file"]
        assert side.is_file(), f"missing sidecar for {e['id']}"
        raw = side.read_bytes()
        assert ic._sha256(raw) == e["meta"]["corpus_sha256"], f"sidecar drifted: {e['id']}"
    print(f"  all {len(corpora)} corpus sidecars present and hash-matched: PASS")


def test_no_orphan_sidecars() -> None:
    """A pruned source must not leave a payload file the KB no longer references."""
    if not KB_PATH.is_file() or not PAYLOAD_DIR.is_dir():
        print("  (skipped — no built KB)")
        return
    built = [json.loads(l) for l in KB_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    referenced = {
        Path(e["meta"]["corpus_file"]).name
        for e in built if (e.get("meta") or {}).get(ic.CORPUS_MARK)
    }
    on_disk = {p.name for p in PAYLOAD_DIR.glob("*.txt")}
    assert on_disk == referenced, f"orphans: {sorted(on_disk - referenced)}"
    print("  no orphan sidecars: PASS")


def test_the_ingester_executes_nothing() -> None:
    """Source-scan lock. This module reads files and writes JSON — it must never run
    a payload, and must never reach the executor or the :kali shell."""
    src = Path(ic.__file__).read_text(encoding="utf-8")
    for banned in ("cockpit", "run_kali", "docker exec", "os.system", "subprocess.Popen",
                   "shell=True", "eval(", "exec("):
        assert banned not in src, f"corpus ingester must not contain {banned!r}"
    # It does call git to recover AV-locked / dehydrated files — argv-only, never a shell.
    assert "subprocess.run(" in src, "expected the argv-only git recovery call"
    print("  the ingester executes nothing (argv-only git recovery excepted): PASS")


def test_reingest_is_byte_identical() -> None:
    """The whole point of Route B: safe to re-run. Skipped when sources are absent."""
    if not KB_PATH.is_file() or not ic.DEFAULT_PATT.is_dir():
        print("  (skipped — sources not present)")
        return
    before = KB_PATH.read_bytes()
    r = subprocess.run(
        [sys.executable, str(REPO_ROOT / "pipeline" / "ingest_corpora.py")],
        capture_output=True, text=True, timeout=600,
    )
    assert r.returncode == 0, r.stderr[-2000:]
    assert KB_PATH.read_bytes() == before, "a re-run must be byte-identical"
    print("  re-running the ingester is byte-identical: PASS")


if __name__ == "__main__":
    test_merge_preserves_foreign_lines_byte_for_byte()
    test_merge_replaces_only_its_own_lines()
    test_merge_ignores_an_unmarked_line_that_merely_mentions_the_marker()
    test_merge_is_atomic_and_leaves_no_temp_file()
    test_entry_is_an_excerpt_with_a_sidecar_pointer()
    test_corpora_are_no_merge_and_marked()
    test_entry_validates_against_the_canonical_schema()
    test_sha256_and_byte_count_describe_the_real_file()
    test_windows_only_tool_files_are_marked_not_advertised()
    test_tool_file_previews_are_capped_and_binaries_have_none()
    test_every_corpus_entry_has_its_sidecar_on_disk()
    test_no_orphan_sidecars()
    test_the_ingester_executes_nothing()
    test_reingest_is_byte_identical()
    print("ALL corpus-ingest tests pass")
