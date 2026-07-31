# HackPit — 0xdf → the service→technique fingerprint corpus

Repo `C:\Users\zaid_\Downloads\HackPit`, branch `sandbox-kali-image`.
**Run after the other batches have landed.** First action: `git pull --rebase`, then re-measure
the KB — the counts below will be stale.

---

## A POLICY CHANGE YOU MUST MAKE FIRST — DO NOT SKIP THIS

`pipeline/ingest_exploitation_writeups.py:13` currently states a HARD SOURCING LINE that names
0xdf as a source never to draw from:

> *"Not one line is a copy of a third-party writeup (0xdf / IppSec / an individual HTB
> walkthrough)."*

**The operator has reviewed and revised that rule.** The revised policy — which is the same rule
already applied to every other source in this project (D21) — is:

> **DISTIL, never parrot.** Learning a technique from a third-party writeup and writing an
> original entry about it, with the source credited in `references`, is permitted and is how
> every other source in this KB is handled. Reproducing a writeup's prose, structure, screenshots
> or phrasing is not.

**Your first task is to update that docstring so the code stops contradicting practice.** Leaving
a comment that forbids what the pipeline now does is worse than either policy. Rewrite lines
~10-20 of `pipeline/ingest_exploitation_writeups.py` to state the distil-not-copy rule and to
note that sources are credited in `references`. Keep the rest of the file's discipline intact
(additive, byte-preserving, idempotent, own marker, `no_merge`).

**Do NOT change `pipeline/consolidate.py:2324`.** That skip drops a 0xdf *link index* file as a
"pure link list, no technique" — that remains correct for the same reason `awesome-oscp` yields
nothing. A list of links carries no technique regardless of policy.

---

## THE GOAL

`hackpit-distilled` — 78 entries built by `ingest_exploitation_writeups.py` — keys a
**service + version fingerprint** to the technique that solves it (service, version range, CVE,
technique, solved_via). That corpus feeds build #8's 2.7 fingerprint retrieval, which ranks
"this exact stack was solved via X" above generic token matches. A ranker is only as good as its
corpus, and 78 entries is thin.

`https://0xdf.gitlab.io/` is the best available source for exactly this shape: several hundred
long-form HTB/CTF machine writeups, each of which starts from a scan result and ends at root.
That is a service→technique mapping in narrative form. **Distil it into fingerprints.**

Every `nmap` result the cockpit parses is a service+version pair. Today only 78 of them map to a
known approach. This is the retrieval path most likely to make the proposer feel sharp on a real
box, which is why it is worth doing properly.

---

## HARD RULES

1. **DISTIL, never parrot.** Not one line of 0xdf's prose, headings, structure or phrasing enters
   an entry. Read a writeup, understand the technique, write the entry from scratch in HackPit's
   voice from the technique plus public CVE facts. **If you cannot write the entry without the
   page open in front of you, you do not understand it well enough to write it — skip it.**
2. **Credit every source.** Each entry carries the writeup URL in `references`. Attribution is
   not optional; it is the thing that makes distillation legitimate rather than appropriation.
3. **Fetch politely — this is one person's personal blog, not a corporate docs site.**
   Follow `pipeline/fetch_portswigger.py`, which already does this correctly:
   * URLs from the site's own **sitemap**, never from crawling
   * check and honour `robots.txt`
   * **serialise requests with a real delay** (≥1-2s; this is a hobby blog on GitLab Pages)
   * honest User-Agent
   * fetch once to disk and iterate locally — never re-hammer while developing
   If `robots.txt` disallows the content paths, **stop and report** rather than working around it.
4. **No exploit code.** Entries describe the approach, the tool pattern, and the detection
   footprint — the shape of the existing 78. Not weaponised payloads.
5. **Nothing raw is committed.** Fetch into `sources/0xdf/` (gitignored). The committable
   artifacts are the ingester code, the policy fix, and the distilled entries.
6. **Check before you write.** Grep each candidate fingerprint against the existing 78 and the
   whole KB. Duplicates are skipped and reported as skipped.

---

## SCOPE — phase it, do not mirror the archive

There are several hundred posts. Fetching all of them in one pass is both impolite and
unnecessary, and mirroring an archive wholesale is a different act from distilling from it.

**Phase 1 — index only.** Pull the sitemap and the post metadata (title, date, tags/OS). That
alone is a coverage map: which services and techniques recur across real machines. Report it.

**Phase 2 — prioritised subset.** Pick posts by what the KB is MISSING, not by recency. Current
shape (re-measure — earlier batches will have moved these):

```
SATURATED  web 636 · cloud 534 · network-services 183 · active-directory 123 · privesc 116
THIN       services 9 · reversing 9 · exploit-dev 7 · pivoting 6 · credentials 5
           exploitation 5 · persistence 4 · fuzzing 4 · iot 2 · mobile 2 · phishing 1
```

`services` at 9 entries is precisely what a fingerprint corpus is for. Prioritise writeups whose
initial foothold is a **versioned network service**, and pivoting/credential/persistence chains.
Deprioritise pure web-app boxes — the KB holds 636 web entries already.

**Start with ~40-60 posts.** Report the yield, then decide with the operator whether to continue.
A second pass is cheap; an unnecessary full mirror is not.

---

## PIPELINE

### 1. Policy fix (above), then the fetcher
Add `pipeline/fetch_0xdf.py` modelled on `fetch_portswigger.py`. Support `--limit` and smoke-test
with 3 posts before any real run.

### 2. Index + TRIAGE — stop and report
Post count, tag/service distribution, which fingerprints are already covered by the existing 78,
and the prioritised shortlist with an estimated entry count.

### 3. Distil into fingerprints
Extend `ingest_exploitation_writeups.py`'s data table. Each entry needs: the fingerprint
(service, version range, CVE where one applies), what the flaw actually is, the approach, the
tool pattern, **what it leaves in logs**, and the source URL in `references`.

```bash
cp data/kb/entries.jsonl <backup>        # Defender has deleted this file before
backend/.venv/Scripts/python.exe pipeline/ingest_exploitation_writeups.py
backend/.venv/Scripts/python.exe pipeline/embed.py
```

### 4. Verify — four checks, real numbers
* **per-source counts diffed** before/after — prove no other source lost rows; a total is not proof
* `data/kb/entries.jsonl` still exists
* retrieval with realistic scan output ("vsftpd 2.3.4", "Apache 2.4.49") via
  `search.search(entries, query, top)` — **positional, there is no `k=`**
* `sh backend/run_safety_tests.sh` → all files exit 0.
  **Known flake:** `test_corpora.py` can exit 1 right after a KB ingest and pass on re-run —
  `ingest_corpora.py:139` shells to `git show HEAD:<file>` to "recover AV-locked / dehydrated
  files", and rewriting the 22 MB KB triggers a Defender sweep that briefly locks corpus
  sidecars. **Re-run before investigating.**

### 5. Clean up
Delete `sources/0xdf/`. Keep `sources/0xdf-manifest.md`: URLs fetched, date, and which produced
an entry.

### 6. Commit + push, then assessment
Commit with `-F`, trailer
`Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`. Push
`sandbox-kali-image`, fast-forward `main` if clean.

Fold into `docs/ASSESSMENT-2026-07-26.md`: **record the policy change explicitly** — the standing
rule named 0xdf as never-to-draw-from, it was reviewed by the operator and revised to the
project-wide distil-not-parrot rule, the code comment was corrected to match, and the link-index
skip in `consolidate.py` was deliberately left alone. That is a real decision, so add a
**D-entry**. Then the batch itself: fingerprints added, which thin categories moved, yield rate.
**No strikethrough (`~~`).** Update Verification and Status, then
`backend/.venv/Scripts/python.exe docs/build-assessment.py`, and verify the PDF with a
**positive control first** (extract via `pypdf` on the SYSTEM python — the venv has no pip —
confirm "HackPit" is found before trusting any "missing" result).

---

## STILL EXCLUDED
`https://themastermindnotes.com/products/ecppt-study-notes-guide-unofficial` — a product page for
notes sold commercially. Not fetched. If the operator supplies a copy they have purchased, that
local file goes through the PDF path.

---

## ENVIRONMENT
* `backend/.venv/Scripts/python.exe` (no pip); system `python` has `pypdf`.
* `PYTHONIOENCODING=utf-8` before printing non-ASCII or cp1252 crashes the script.
* If the classifier refuses git, write a self-verifying `.sh` to the repo root and hand over the
  exact `! sh ...` line rather than stalling.
* Never report a green suite you did not see.
