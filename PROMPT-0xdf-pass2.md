# HackPit — 0xdf pass 2: the remaining novel-CVE posts

Repo `C:\Users\zaid_\Downloads\HackPit`, branch `sandbox-kali-image`. `git pull --rebase` first.

**RUN `PROMPT-fingerprint-eval.md` BEFORE THIS ONE.** That session measures whether the 97
fingerprints actually fire on real scanner output. If it reports that retrieval is inert or has
a normalisation bug, **this batch is a waste of time until that is fixed** — more entries in a
corpus that never fires buys nothing. Read `docs/FINGERPRINT-EVAL.md` first and say in your
opening summary what it concluded and why you are proceeding anyway.

---

## WHY THERE IS A SECOND PASS

Pass 1 (`0389665`, manifest at `sources/0xdf-manifest.md`) established the numbers that justify
this one:

* The index found **614 posts / 276 CVE tags, of which 175 CVEs had never appeared anywhere in
  the KB.** That figure is what separated 0xdf from the 31 cert-note sources that produced 2
  entries between them.
* Pass 1 sampled **only 55 of those 614 posts** and wrote **19 fingerprints from 12 of them**.
* Concept-grep killed 43 of 55 as already-covered — a ~22% survival rate.

So most of the 175 novel CVEs were never looked at. At the observed survival rate another
50-60 posts plausibly yields **10-15 more fingerprints**. That is the best remaining source in
the series by a wide margin — but it is also clearly the tail, so measure as you go and stop
when the rate collapses.

---

## HARD RULES — unchanged from pass 1, all of them still apply

1. **DISTIL, never parrot.** Not one line of 0xdf's prose, headings or structure. Write from the
   technique plus public CVE facts, in HackPit's voice. If you cannot write it without the page
   open, skip it.
2. **Credit every source** — the writeup URL in `references` on every entry. This is what makes
   distillation legitimate.
3. **Fetch politely.** Reuse `pipeline/fetch_0xdf.py` exactly as pass 1 built it — sitemap and
   the site's own `/tags/` page only, serialised at ~1.8s, honest User-Agent, robots re-checked.
   This is one person's blog and it has now been fetched once already; be conservative.
4. **CONCEPT-GREP BEFORE WRITING — the token diff nominates, it never confirms.** Batch 2 proved
   this: `seshutdownprivilege` looked like a certain gap (11 occurrences, 0 of 2,714 rows) and
   was already in the KB spelled `SeShutdown`. Pass 1 caught two more (`schallenge` →
   XSSChallengeWiki, `wsrep` → wsrepl). Grep synonyms, stems, the tool name and the technique
   name — not the token.
5. **Nothing raw is committed.** Fetch to `sources/0xdf/` (gitignored), delete after, append to
   `sources/0xdf-manifest.md`.
6. **No exploit code.** Approach, tool pattern, detection footprint — the shape of the existing 97.

---

## SCOPE

**Select by novel CVE, not by recency.** Re-pull the index (2 requests) and diff its CVE tags
against both the KB and the 55 posts pass 1 already covered — the manifest records which those
were. Shortlist **50-60 unfetched posts** whose CVE tags are still absent from the KB, weighted
toward a **versioned network-service foothold** (that is what a fingerprint is for) over web-app
boxes, where the KB already holds 636 entries.

**Stop early if the rate collapses.** If the first 25 posts yield fewer than 3 entries after
concept-grep, stop, report the rate, and recommend closing the source. Do not push to a target
count — the honest tail is the finding.

---

## KNOWN FAILURE MODES FROM PASS 1 — expect these
* **Windows Defender deletes fetched pages mid-triage** (`OSError 22` → `OSError 2`). It ate 5 of
  55 in pass 1 and 2 of 113 in batch 2. Tolerate a file vanishing between listing and reading,
  re-fetch once, and report what was actually analysed rather than what was listed.
* A page can vanish twice and stay gone (pass 1 dropped CrushFTP for this). Record it and move on.

---

## PIPELINE
```bash
cp data/kb/entries.jsonl <backup>          # Defender has deleted this file before
backend/.venv/Scripts/python.exe pipeline/ingest_exploitation_writeups.py
backend/.venv/Scripts/python.exe pipeline/embed.py
```

Verify four ways, with real numbers:
* **per-source counts diffed** before/after — only `hackpit-distilled` may move; prove no other
  source lost a row
* `data/kb/entries.jsonl`, `embeddings.npy` and `ids.json` all present afterwards
* retrieval on realistic **scanner-format** banners (`Apache Tomcat/9.0.30`, not `tomcat 9.0.30`)
  via `search.search(entries, query, top)` — **positional, no `k=`**
* `sh backend/run_safety_tests.sh` → 52 files, all exit 0. `test_corpora.py` may flake after a
  KB rewrite (Defender locks corpus sidecars while `ingest_corpora.py:139` does its git
  recovery) — re-run before investigating.

---

## ONE THING TO GET RIGHT THAT PASS 1 GOT WRONG

Pass 1 reported its 19 entries as landing "in thin categories (services, pivoting, credentials,
persistence)". **They did not.** `ingest_exploitation_writeups.py` forces `category="writeup"`
(part of its `no_merge` discipline), so all 19 landed in `writeup` — which was already saturated
at 173 — and `services 9 / pivoting 8 / credentials 5 / persistence 4` did not move at all.

The entries still work, because 2.7 retrieval keys on `meta.fingerprint` rather than category.
But **report where rows actually land, measured, not where they thematically belong.** If you
think the category assignment is wrong for discoverability, say so as a finding — do not quietly
change the ingester's contract.

---

## OUTPUT
Commit with `-F` and the trailer
`Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`; push `sandbox-kali-image`,
fast-forward `main`. Append to `sources/0xdf-manifest.md`.

**Amend, do not rewrite, the assessment's series summary** — it was closed out by pass 1 and
already states the totals. Add pass 2's numbers and, if the yield rate collapsed, record that
0xdf is now exhausted. Regenerate with `backend/.venv/Scripts/python.exe docs/build-assessment.py`
and verify the PDF with a **positive control first** (`pypdf` on the system python; confirm
"HackPit" extracts before trusting any "missing" result). No strikethrough.

Never report a green suite you did not see.
