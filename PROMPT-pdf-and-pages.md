# HackPit — KB enrichment from 2 PDFs, 2 web pages, and 1 GitLab repo

Repo `C:\Users\zaid_\Downloads\HackPit`, branch `sandbox-kali-image`.
**Run LAST, after `PROMPT-kb-repo-ingest.md` and `PROMPT-gitbook-corpus.md` have both landed.**
First action: `git pull --rebase`, then re-measure the KB — by now two batches will have moved
it and every count below is stale.

---

## THE SOURCES — three different formats, three different handlers

**PDFs (2)** — use the existing PDF path; `pipeline/ingest_box_pdfs.py` already extracts PDFs
into the canonical schema, so read it before writing anything new.
```
https://elhacker.info/ebooks%20Joas/OSCP%20NOTES.pdf
https://elhacker.info/ebooks%20Joas/eLearnSecurity%20eCPPT%20Notes%20Exam.pdf
```

**Web pages (2)** — single pages, not sites. A plain fetch, not a crawl.
```
https://parzival.sh/blog/my-oscp-notes-and-resources
https://pnpt.adot8.com/
```

**Git repo (1)** — clonable; belongs to the repo-batch shape, just hosted on GitLab.
```
https://gitlab.com/parfaittolefo23/cpent-sheet-cheat
```
`git clone --depth 1 --single-branch` into `sources/repos/`. **CPENT is the highest-value
cluster available** — it covers IoT, ICS/SCADA and pivoting, and the KB holds `iot 2`,
`pivoting 6`. Give this one real attention; it is the most likely to produce something new.

---

## EXPLICITLY EXCLUDED — do not fetch

```
https://themastermindnotes.com/products/ecppt-study-notes-guide-unofficial
```
That is a **product page for notes being sold commercially**. Do not scrape it, do not fetch it,
do not work around it. If the operator has purchased it and points you at a local file they own,
that copy goes through the PDF path like any other local file — but that has to come from them,
not from this URL.

---

## HARD RULES

1. **DISTIL, never parrot (D21).** These are individuals' notes and redistributed ebooks —
   copyrighted, and in the case of the `elhacker.info/ebooks` directory of uncertain provenance.
   Extract the *technique*, write the entry from scratch, cite the source in `references`.
   No entry may carry a source's prose or structure. If you cannot write it without the source
   open, do not write it.
2. **Fetch politely.** Two pages and two PDFs is four requests — serialise them, honest
   User-Agent, check `robots.txt`. Fetch once to disk; do not re-request while iterating.
   Follow `pipeline/fetch_portswigger.py`'s pattern.
3. **Nothing raw is committed.** `sources/` and `data/` are gitignored — the PDFs, the fetched
   pages and the clone never enter git. Code and distilled entries only.
4. **Check before you write.** By now the KB has absorbed two prior batches. Cert notes are the
   most duplicated material in it. Grep every candidate first.
5. **Zero is a valid result.** `parzival.sh/blog/my-oscp-notes-and-resources` is, by its title, a
   notes-AND-RESOURCES post — expect a link list and near-zero extractable technique, exactly
   like `awesome-oscp` in the first batch. Report zero rather than padding.

---

## PIPELINE

### 1. Acquire
* PDFs → download to `sources/pdfs/`. Extract with the existing PDF tooling; if
  `ingest_box_pdfs.py` needs a second input path, extend it rather than duplicating it.
  **Note:** the venv has no pip. `pypdf` is on the **system** python — if extraction needs it,
  use system python for the extraction step and hand the text over.
* Pages → fetch to `sources/pages/` as text/markdown.
* GitLab repo → shallow clone to `sources/repos/cpent-sheet-cheat`.

### 2. TRIAGE — stop and report
Per source: size, what it actually is, KB categories touched (saturated or thin), candidate
techniques grepped against the current KB, destination (KB entry / `backend/arsenal/tools.json`
row / nothing), estimated count. Name the sources that yield zero.

If the CPENT repo carries tool invocations rather than technique prose, that is an **arsenal**
contribution — `backend/arsenal/tools.json`. **Trap: that file is CRLF**; preserve line endings
or the diff explodes. Aliases are listed `.exe`-stripped.

### 3. Distil, ingest, verify
Entries into `pipeline/authored/authored_entries.jsonl` via a re-runnable builder that validates
with `schema.Entry.model_validate` and replaces by `id`. Then:
```bash
cp data/kb/entries.jsonl <backup>          # Defender has deleted this file before
backend/.venv/Scripts/python.exe pipeline/ingest_authored.py
backend/.venv/Scripts/python.exe pipeline/embed.py
```
Verify all four: **per-source counts diffed** before/after (a total is not proof), the KB file
still exists, retrieval via `search.search(entries, query, top)` (**positional, no `k=`**), and
`sh backend/run_safety_tests.sh` all green.
**Known flake:** `test_corpora.py` can exit 1 right after a KB ingest and pass on re-run —
`ingest_corpora.py:139` shells to `git show HEAD:<file>` to "recover AV-locked / dehydrated
files", and rewriting the 22 MB KB triggers a Defender sweep that briefly locks corpus sidecars.
Re-run before investigating.

### 4. Clean up
Delete `sources/pdfs/`, `sources/pages/` and the clone. Keep one manifest line per source: URL,
date, verdict.

### 5. Commit + push, then CLOSE OUT THE SERIES
Commit with `-F`, trailer
`Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`. Push
`sandbox-kali-image`, fast-forward `main`.

This is the LAST batch in the series, so the assessment section should close it out: fold into
`docs/ASSESSMENT-2026-07-26.md` a summary of **all four batches** (transcript corpus, repos,
GitBooks, this one) — total entries added, which thin categories actually moved and which did
not, how much of the material turned out to be duplicate, and whether the exercise was worth it.
Record the two refusals explicitly: **0xdf declined** on the repo's own standing sourcing line,
and **themastermindnotes declined** as a commercial product. Add a D-entry if the series
produced a real standing decision. **No strikethrough (`~~`).** Update Verification and Status,
then `backend/.venv/Scripts/python.exe docs/build-assessment.py`, and verify the PDF with a
**positive control first** (extract with `pypdf` on system python, confirm "HackPit" is found
before trusting any "missing" result).

---

## ENVIRONMENT
* `backend/.venv/Scripts/python.exe` (no pip); system `python` has `pypdf`.
* `PYTHONIOENCODING=utf-8` before printing non-ASCII.
* If the classifier refuses git, write a self-verifying `.sh` and hand over the `! sh ...` line.
* Never report a green suite you did not see.
