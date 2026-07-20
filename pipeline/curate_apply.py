"""Curation apply — auto-apply the mechanical, HIGH-CONFIDENCE modernizations
and cleanups from curation_report.json, preserving every original.

Correctness-first: only transforms whose modern equivalent is unambiguous are
applied automatically; anything else is FLAGGED for manual review rather than
guessed (a wrong modernization is worse than the original).

  MODERNIZE (command text rewritten, original kept in meta.modernizations):
    * crackmapexec -> nxc          (NetExec is CME's drop-in successor)
    * enum4linux   -> enum4linux-ng (compatible; `-a` -> `-A`), skipping output banners
    * dirb URL [WORDLIST]          -> feroxbuster -u URL -w WORDLIST  (SIMPLE form only)
  FLAG only (unchanged, recorded for manual review):
    * wfuzz, wmic, dirbuster, complex dirb, python2  (varied syntax / behaviour)
  LEGACY note (meta.legacy_note, unchanged commands):
    * Flash / Silverlight / BackTrack references (dead tech)
  DROP (added to pipeline/exclude.json — reversible):  the near-empty stubs
  RECLEAN: strip U+FFFD encoding damage
  MERGE: fold each same-box writeup pair (keep the fuller, note+absorb the other)
  The 111 "thin" entries and the OCR false-positives are LEFT and only reported.

Idempotent: modern tokens no longer match the old-tool patterns; merges/drops are
keyed off preserved markers, so a re-run applies nothing new.

Writes: data/kb/entries.jsonl (single atomic write), pipeline/exclude.json,
data/kb/curation_changes.{json,md}. Run:  uv run python curate_apply.py [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

import consolidate as C

REPO_ROOT = Path(__file__).resolve().parents[1]
KB = REPO_ROOT / "data" / "kb" / "entries.jsonl"
REPORT = REPO_ROOT / "data" / "kb" / "curation_report.json"
EXCLUDE = Path(__file__).with_name("exclude.json")
OUT_JSON = REPO_ROOT / "data" / "kb" / "curation_changes.json"
OUT_MD = REPO_ROOT / "data" / "kb" / "curation_changes.md"

# same-box writeup pairs (keep, drop) — keep = the fuller writeup
MERGE_PAIRS = [
    ("wu-devarea", "wu-htb-devarea"), ("wu-variatype", "wu-htb-variatype"),
    ("wu-nanocorp", "wu-htb-nanocorp"), ("wu-htb-browsed", "wu-browsed"),
    ("wu-darkzero", "wu-htb-darkzero"), ("wu-imagery", "wu-htb-imagery"),
]

_FENCE = re.compile(r"```([\w+-]*)\n(.*?)```", re.S)
_E4L_BANNER = re.compile(r"starting enum4linux|enum4linux v\d|portcullis", re.I)
_E4L = re.compile(r"enum4linux(?!-ng)")
_DIRB_SIMPLE = re.compile(r"^\s*(?:sudo\s+)?dirb\s+(https?://\S+)(?:\s+(\S+))?\s*$")
_DEFAULT_WL = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"

# flag / legacy detectors (on the ORIGINAL text, before/after modernization)
_FLAG_TOOLS = [
    ("wfuzz", re.compile(r"\bwfuzz\b", re.I)),
    ("wmic", re.compile(r"\bwmic\b", re.I)),
    ("dirbuster", re.compile(r"\bdirbuster\b", re.I)),
    ("python2", re.compile(r"\bpython2(?:\.\d)?\b|(?<!\()\bprint\s+['\"]", re.I)),
]
_LEGACY = [
    ("flash/silverlight", re.compile(r"\b(?:adobe\s*)?flash\b|\bsilverlight\b", re.I)),
    ("backtrack", re.compile(r"\bbacktrack\b", re.I)),
]


def _modernize_line(line: str) -> str:
    new = line.replace("crackmapexec", "nxc")
    if not _E4L_BANNER.search(new):
        new = _E4L.sub("enum4linux-ng", new)
        new = re.sub(r"(enum4linux-ng\s+)-a\b", r"\1-A", new)
    m = _DIRB_SIMPLE.match(new)
    if m and not (m.group(2) or "").startswith("-"):
        wl = m.group(2) or _DEFAULT_WL
        new = f"feroxbuster -u {m.group(1)} -w {wl}"
    return new


def _modernize_block(text: str) -> tuple[str, list]:
    out, changes = [], []
    for ln in text.split("\n"):
        nl = _modernize_line(ln)
        if nl != ln:
            tool = ("crackmapexec" if "crackmapexec" in ln else
                    "enum4linux" if _E4L.search(ln) and "enum4linux-ng" not in ln else
                    "dirb" if _DIRB_SIMPLE.match(ln) else "?")
            changes.append({"tool": tool, "before": ln.strip()[:200], "after": nl.strip()[:200]})
        out.append(nl)
    return "\n".join(out), changes


def _modernize_entry(e: dict) -> list:
    changes: list = []
    for s in e.get("steps", []) or []:
        for c in s.get("code", []) or []:
            nc, ch = _modernize_block(c.get("cmd", "") or "")
            if ch:
                c["cmd"] = nc
                for x in ch:
                    x["where"] = "step"
                changes += ch
    if e.get("body_md"):
        def repl(m):
            nc, ch = _modernize_block(m.group(2))
            for x in ch:
                x["where"] = "body"
            changes.extend(ch)
            return f"```{m.group(1)}\n{nc}```"
        e["body_md"] = _FENCE.sub(repl, e["body_md"])
    if changes:
        rec = e.setdefault("meta", {}).setdefault("modernizations", [])
        have = {(x["before"], x["after"]) for x in rec}
        for x in changes:
            if (x["before"], x["after"]) not in have:
                rec.append(x)
                have.add((x["before"], x["after"]))
    return changes


def _entry_text(e: dict) -> str:
    parts = [e.get("body_md", "") or ""]
    for s in e.get("steps", []) or []:
        parts.append(s.get("text", "") or "")
        for c in s.get("code", []) or []:
            parts.append(c.get("cmd", "") or "")
    return "\n".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser(description="Apply high-confidence curation fixes.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    entries = [json.loads(l) for l in KB.open(encoding="utf-8") if l.strip()]
    by_id = {e["id"]: e for e in entries}
    rep = json.loads(REPORT.read_text(encoding="utf-8"))
    f = rep["findings"]
    stub_ids = [x["id"] for x in f if "near-empty stub" in x["reason"]]
    thin_ids = [x["id"] for x in f if "thin entry" in x["reason"]]
    ocr_fp = [x["id"] for x in f if "OCR/garbled" in x["reason"]]
    ffdd_ids = [x["id"] for x in f if "FFFD" in x["reason"]]

    report: dict = {"modernized": [], "flagged_uncertain": [], "legacy_annotated": [],
                    "dropped": [], "recleaned": [], "merged": [], "ocr_false_positive": [],
                    "flagged_thin": []}

    # 1. RECLEAN U+FFFD (strip the damaged bytes; keep the entry)
    for eid in ffdd_ids:
        e = by_id.get(eid)
        if not e:
            continue
        b = (e.get("body_md", "") or "")
        n_body = b.count("�")
        e["body_md"] = b.replace("�", "")
        n_steps = 0
        for s in e.get("steps", []) or []:
            if "�" in (s.get("text", "") or ""):
                s["text"] = s["text"].replace("�", "")
            for c in s.get("code", []) or []:
                if "�" in (c.get("cmd", "") or ""):
                    n_steps += c["cmd"].count("�")
                    c["cmd"] = c["cmd"].replace("�", "")
        if n_body or n_steps:
            e.setdefault("meta", {})["recleaned"] = "stripped U+FFFD encoding damage"
            report["recleaned"].append({"id": eid, "chars_removed": n_body + n_steps,
                                        "note": "one SQLi payload had unrecoverable raw "
                                                "bytes — U+FFFD stripped, entry kept"})

    # 2. MODERNIZE + 3. FLAG + 4. LEGACY (scan every entry)
    for e in entries:
        eid = e["id"]
        pre = _entry_text(e)
        changes = _modernize_entry(e)
        if changes:
            report["modernized"].append({
                "id": eid, "count": len(changes),
                "tools": sorted({x["tool"] for x in changes}),
                "samples": [{"before": x["before"], "after": x["after"]} for x in changes[:3]],
            })
        post = _entry_text(e)  # after modernization
        flags = [name for name, rx in _FLAG_TOOLS if rx.search(post)]
        # a residual `dirb` command that wasn't the simple form is a flag too
        if re.search(r"(?:^|\n)\s*(?:sudo\s+)?dirb\s", post) and "dirbuster" not in flags:
            flags.append("dirb (complex form)")
        if flags:
            e.setdefault("meta", {})["review_flags"] = sorted(set(flags))
            report["flagged_uncertain"].append({"id": eid, "category": e.get("category", ""),
                                                "tools": sorted(set(flags))})
        legacy = [name for name, rx in _LEGACY if rx.search(pre)]
        if legacy:
            note = ("references retired tech (" + ", ".join(legacy) +
                    ") — legacy; verify relevance on current targets")
            meta = e.setdefault("meta", {})
            meta["legacy_note"] = note
            meta["legacy_kinds"] = legacy

    # 5. MERGE writeup pairs (keep fuller; absorb + drop the other)
    drop_merged: set = set()
    for keep_id, drop_id in MERGE_PAIRS:
        keep, drop = by_id.get(keep_id), by_id.get(drop_id)
        marker = f"<!-- altwriteup:{drop_id} -->"
        if keep is None:
            continue
        if drop is None or marker in (keep.get("body_md", "") or ""):
            continue  # already merged — idempotent
        keep["body_md"] = (keep.get("body_md", "") or "").rstrip() + \
            f"\n\n{marker}\n## Alternate writeup — also your own\n\n" + (drop.get("body_md", "") or "")
        mw = keep.setdefault("meta", {}).setdefault("merged_writeups", [])
        if drop_id not in mw:
            mw.append(drop_id)
        drop_merged.add(drop_id)
        report["merged"].append({"kept": keep_id, "dropped": drop_id,
                                 "note": "same box, both your writeups; folded the "
                                         "shorter into the fuller as an alternate section"})
    entries = [e for e in entries if e["id"] not in drop_merged]

    # 6. DROP near-empty stubs via exclude.json (reversible)
    excl = json.loads(EXCLUDE.read_text(encoding="utf-8"))
    existing = {x.get("id") for x in excl["exclude"] if isinstance(x, dict)}
    for eid in stub_ids:
        if eid not in existing:
            excl["exclude"].append({"id": eid,
                                    "reason": "near-empty checklist stub (no commands, "
                                              "tiny body) — curation drop"})
            existing.add(eid)
        report["dropped"].append({"id": eid, "reason": "near-empty stub"})

    # Build the change report from the FINAL applied state (so it is accurate and
    # identical on every run, not a per-invocation delta — a re-run of an already
    # applied KB must still describe everything that was done).
    report = {"modernized": [], "flagged_uncertain": [], "legacy_annotated": [],
              "dropped": [], "recleaned": [], "merged": [], "ocr_false_positive": [],
              "flagged_thin": []}
    for e in entries:
        meta = e.get("meta") or {}
        mods = meta.get("modernizations") or []
        if mods:
            report["modernized"].append({
                "id": e["id"], "count": len(mods),
                "tools": sorted({m["tool"] for m in mods}),
                "samples": [{"before": m["before"], "after": m["after"]} for m in mods[:3]]})
        for d in meta.get("merged_writeups") or []:
            report["merged"].append({"kept": e["id"], "dropped": d,
                                     "note": "same box, both your writeups; folded the "
                                             "shorter into the fuller as an alternate section"})
        if meta.get("recleaned"):
            report["recleaned"].append({"id": e["id"], "note": meta["recleaned"]})
        if meta.get("review_flags"):
            report["flagged_uncertain"].append({"id": e["id"], "category": e.get("category", ""),
                                                "tools": meta["review_flags"]})
        if meta.get("legacy_note"):
            report["legacy_annotated"].append({"id": e["id"], "kinds": meta.get("legacy_kinds", [])})
    report["dropped"] = [{"id": x["id"], "reason": "near-empty stub"}
                         for x in excl["exclude"]
                         if "curation drop" in (x.get("reason", "") or "")]
    report["ocr_false_positive"] = [
        {"id": i, "note": "flagged by the vowel-less-word heuristic but is legitimate "
                          "dense technical content (protocol/dork/payload syntax) — no change"}
        for i in ocr_fp]
    report["flagged_thin"] = [{"id": i} for i in thin_ids]

    summary = {
        "modernized_entries": len(report["modernized"]),
        "modernized_commands": sum(m["count"] for m in report["modernized"]),
        "flagged_uncertain": len(report["flagged_uncertain"]),
        "legacy_annotated": len(report["legacy_annotated"]),
        "dropped_stubs": len(report["dropped"]),
        "recleaned": len(report["recleaned"]),
        "merged_pairs": len(report["merged"]),
        "ocr_false_positive": len(report["ocr_false_positive"]),
        "flagged_thin": len(report["flagged_thin"]),
        "kb_entries_after": len(entries),
        "excluded_total": len(existing),
        "served_after": sum(1 for e in entries if e["id"] not in existing),
    }
    report_out = {"summary": summary, **report}

    if not args.dry_run:
        tmp = KB.with_suffix(".jsonl.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        os.replace(tmp, KB)  # single atomic write
        EXCLUDE.write_text(json.dumps(excl, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        OUT_JSON.write_text(json.dumps(report_out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        _write_md(report_out, OUT_MD)

    print(("DRY RUN — " if args.dry_run else "") + "curation apply")
    for k, v in summary.items():
        print(f"  {k}: {v}")


def _write_md(r: dict, path: Path) -> None:
    s = r["summary"]
    L = ["# Curation change report", "",
         f"Applied high-confidence fixes; everything else flagged. KB "
         f"{s['kb_entries_after']} entries in file, {s['served_after']} served "
         f"({s['excluded_total']} excluded).", "", "## Summary", ""]
    for k, v in s.items():
        L.append(f"- {k}: {v}")
    L += ["", "## Modernized (original preserved in meta.modernizations)", ""]
    for m in r["modernized"][:40]:
        ex = m["samples"][0] if m["samples"] else {}
        L.append(f"- **{m['id']}** ({','.join(m['tools'])}, {m['count']} cmd) — "
                 f"`{ex.get('before','')[:60]}` → `{ex.get('after','')[:60]}`")
    if len(r["modernized"]) > 40:
        L.append(f"- … +{len(r['modernized']) - 40} more")
    L += ["", "## Merged writeup pairs", ""]
    for m in r["merged"]:
        L.append(f"- kept **{m['kept']}**, folded+dropped **{m['dropped']}**")
    L += ["", "## Dropped near-empty stubs (excluded, reversible)", ""]
    for d in r["dropped"]:
        L.append(f"- {d['id']}")
    L += ["", "## Recleaned", ""]
    for d in r["recleaned"]:
        L.append(f"- {d['id']} — {d['note']}")
    L += ["", "## Flagged for manual review (NOT modernized — correctness-first)", ""]
    for m in r["flagged_uncertain"][:80]:
        L.append(f"- {m['id']} ({m['category']}) — {', '.join(m['tools'])}")
    if len(r["flagged_uncertain"]) > 80:
        L.append(f"- … +{len(r['flagged_uncertain']) - 80} more")
    L += ["", "## Legacy-annotated (dead tech)", ""]
    for m in r["legacy_annotated"]:
        L.append(f"- {m['id']} — {', '.join(m['kinds'])}")
    L += ["", "## OCR false positives (reviewed, no change)", ""]
    for m in r["ocr_false_positive"]:
        L.append(f"- {m['id']}")
    L += ["", f"## Thin entries left for later ({len(r['flagged_thin'])})", "",
          "(see curation_changes.json `flagged_thin` for the full list)"]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
