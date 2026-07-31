# HackPit — KB enrichment from 7 GitBook note-spaces

Repo `C:\Users\zaid_\Downloads\HackPit`, branch `sandbox-kali-image`.
**Run AFTER `PROMPT-kb-repo-ingest.md` has landed.** First action: `git pull --rebase`, then
re-measure the real KB counts — every number below will be stale by the time you run.

---

## THE SOURCES

Seven GitBook spaces of personal certification notes:

```
https://dev-angelist.gitbook.io/ecpptv3-ptp-notes
https://dev-angelist.gitbook.io/ecpptv2-ptp-notes
https://dev-angelist.gitbook.io/crtp-notes
https://team-anonymous.gitbook.io/certified-red-team-professional-crtp-notes
https://dudisamarel.gitbook.io/crtp-notes
https://mqt.gitbook.io/oscp-notes
https://gokulkarthik.gitbook.io/pentesting-checklist
```

**Already de-duplicated for you:** `dudisamarel.gitbook.io/crtp-notes/crtp-methodology` was also
supplied — it is a subpage of the space already listed, so it is covered.

---

## WHAT BATCH 1 ALREADY PROVED — read `sources/repos-manifest.md` BEFORE fetching anything

The repo batch ran 24 repos of this exact source class and **22 yielded nothing**. Its verdicts
apply directly here, so do not re-derive them:

* **`dev-angelist.gitbook.io/ecpptv2-ptp-notes` is ALREADY MINED.** Batch 1 ingested
  `github.com/dev-angelist/eCPPTv2-PTP-Notes` at commit `a543e9167445` — 126k words, and its
  `network-security/2.2-pivoting*.md` pair was the primary source for BOTH authored pivoting
  entries, the only two the whole batch produced. The GitBook is near-certainly the same content
  published. **Verify quickly against the manifest, then skip it.** Re-fetching it is pure waste.
* **The three CRTP spaces are near-certain zeros.** Batch 1 ran two CRTP repos (~7.6k and ~7.9k
  words, 243 and 193 code blocks) and probed DCSync, silver ticket, unconstrained delegation,
  ACL abuse, GPO and SID history against the KB — all already covered by its `active-directory`
  entries. A third, fourth and fifth pass over CRTP notes is not going to find what three passes
  did not.
* **`mqt.gitbook.io/oscp-notes` is a likely zero.** All four OSCP repos in batch 1 yielded nothing.

**That leaves two genuine unknowns, and they are where your effort belongs:**
1. **`dev-angelist.gitbook.io/ecpptv3-ptp-notes`** — a *different* author's eCPPTv3 repo was a
   1.2k-word exam review and yielded zero, but dev-angelist's v2 was the one substantial source
   in the entire batch. His v3 is worth a real look.
2. **`gokulkarthik.gitbook.io/pentesting-checklist`** — a checklist is a different shape from
   cert notes and batch 1 covered nothing like it. It may yield methodology structure rather than
   techniques, which is still valuable.

**Gate cheaply before fetching in full.** For each space, pull only the sitemap and page titles
first, and apply batch 1's proof-of-saturation method — tokenise against all KB rows and check
whether anything genuinely new appears. Batch 1 found 308 terms that were "new" and all 308 were
URL slugs, hostnames and typos. If a space's index shows the same, do not fetch its pages at all;
record it as a zero and move on. **Fetching seven spaces in full and then discovering they are
duplicates is the failure mode to avoid** — it wastes your time and hammers someone's blog for
nothing.

A batch that fetches two spaces, ingests one, and reports five zeros with evidence is a
**successful** run.

---

## HARD RULES

1. **These are individuals' personal notes — copyrighted, exactly like 0xdf.** D21 governs:
   **DISTIL, never parrot.** No entry may contain a source's prose, structure, or phrasing.
   Write technique entries from scratch. If you cannot write one without the source open in
   front of you, do not write it.
2. **Fetch politely, the way `pipeline/fetch_portswigger.py` already does it** — read that file
   first and follow its pattern:
   * URLs come from the site's own **sitemap**, never from crawling links
   * check `robots.txt` and honour it
   * requests **serialised with a delay**, and an **honest User-Agent**
   * fetch once to disk; never re-hammer a site while iterating
3. **Nothing raw is committed.** Fetch into `sources/gitbooks/<space>/` — gitignored. Only
   distilled entries and code are committable.
4. **Check before you write.** Grep every candidate against the whole KB, which by now includes
   whatever the repo batch landed. These are CERT NOTES, and cert notes are the single most
   duplicated material in this KB.
5. **Zero is a valid result.** Several of these will yield nothing once the repo batch has run.
   Report zero and move on. Do not pad.

---

## EXPECTED YIELD — set expectations honestly

Before the repo batch, the KB was saturated exactly where these sources sit:

```
SATURATED  web 636 · cloud 534 · network-services 183 · active-directory 123 · privesc 116
           methodology 100 · windows 99 · writeup 173
THIN       pivoting 6 · credentials 5 · exploitation 5 · persistence 4 · fuzzing 4
           iot 2 · mobile 2 · phishing 1
```

Three of these seven spaces are **CRTP notes** — Active Directory, where the KB already held
123 entries before the repo batch added more. The realistic expectation for those three is
**near zero**, and that is fine. The eCPPT spaces are the better bet (pivoting,
post-exploitation), and the pentesting-checklist space may yield methodology structure rather
than techniques.

**Do not let a low count push you into ingesting duplicates.**

---

## PIPELINE

### 1. Write the fetcher
Add `pipeline/fetch_gitbook.py`, modelled directly on `fetch_portswigger.py`. GitBook spaces
expose a sitemap (commonly `/sitemap.xml` or `/sitemap-pages.xml`); resolve it per space rather
than assuming one path. Keep only the main content block, drop nav/footer chrome. One space per
directory under `sources/gitbooks/`. Support `--limit` for a smoke test before a full run.

### 2. Fetch, then TRIAGE — stop and report
Per space report: pages fetched, total size, what it actually covers, which KB categories it
touches (saturated or thin), candidate techniques **grepped against the current KB**, and an
estimated entry count. State plainly which spaces yield nothing.

### 3. Distil and ingest
Write entries into `pipeline/authored/authored_entries.jsonl` with a re-runnable builder that
validates each row via `schema.Entry.model_validate` and replaces by `id`. Match the existing
style exactly: numbered `steps`, optional `code` blocks, `references`, `meta.phase`,
`meta.canonical_keys`. Attribute the source space in `references` — crediting a source you
learned from is right; copying it is not.

```bash
backend/.venv/Scripts/python.exe pipeline/ingest_authored.py
backend/.venv/Scripts/python.exe pipeline/embed.py
```

### 4. Verify — four checks, real numbers
* `cp data/kb/entries.jsonl` to a backup FIRST (Defender has deleted this file before)
* **per-source counts diffed before/after** — prove no other source lost rows; a total is not proof
* confirm `data/kb/entries.jsonl` still exists afterwards
* retrieval: real natural-language queries via `search.search(entries, query, top)` —
  **positional, there is no `k=`**
* `sh backend/run_safety_tests.sh` → all files exit 0.
  **Known flake:** `test_corpora.py` can exit 1 right after a KB ingest and pass on re-run.
  `pipeline/ingest_corpora.py:139` shells to `git show HEAD:<file>` to "recover AV-locked /
  dehydrated files"; rewriting the 22 MB `entries.jsonl` triggers a Defender sweep that briefly
  locks corpus sidecars. **Re-run before investigating.**

### 5. Clean up
Delete `sources/gitbooks/` after ingest. Keep `sources/gitbooks-manifest.md`: URL, fetch date,
page count, verdict (entries produced / zero / duplicate-of-X).

### 6. Commit + push, then assessment
Multi-line message to a file, `-F`, trailer
`Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
Push `sandbox-kali-image`, fast-forward `main` if clean.

Fold a short section into `docs/ASSESSMENT-2026-07-26.md`: spaces taken, spaces that yielded
nothing and why, entries added, which thin categories moved. **No strikethrough (`~~`).** Update
Verification and Status, then `backend/.venv/Scripts/python.exe docs/build-assessment.py`.
Verify the PDF: `%PDF`, page count, and that the new text is genuinely inside it — extract with
`pypdf` on the **system** python (the venv has no pip) and **run a positive control first**
(search "HackPit"); without it a broken extractor reports false negatives.

---

## ENVIRONMENT
* `backend/.venv/Scripts/python.exe` (no pip); system `python` has `pypdf`.
* `PYTHONIOENCODING=utf-8` before printing non-ASCII or cp1252 crashes the script.
* If the classifier refuses git, write a self-verifying `.sh` to the repo root and hand over the
  exact `! sh ...` line rather than stalling.
* Never report a green suite you did not see.
