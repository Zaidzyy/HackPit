# HackPit — extend the service→technique fingerprint corpus

Repo `C:\Users\zaid_\Downloads\HackPit`, branch `sandbox-kali-image`.
**Run this ONLY AFTER `PROMPT-kb-repo-ingest.md` has finished, committed and pushed.**
First action: `git pull` / rebase onto whatever that session landed, and re-read the real KB
counts — the numbers below will be stale by then.

---

## WHY THIS EXISTS, AND WHAT IT IS *NOT*

The operator asked whether `https://0xdf.gitlab.io/` could be folded into the KB. **It cannot,
and this repo already decided that twice:**

* `pipeline/ingest_exploitation_writeups.py:13` states a HARD SOURCING LINE naming 0xdf
  explicitly — *"Not one line is a copy of a third-party writeup (0xdf / IppSec / an individual
  HTB walkthrough)."*
* `pipeline/consolidate.py:2324` already encountered a 0xdf link index and deliberately SKIPPED
  it as a pure link list.

The KB's current state matches that policy: of ~101 rows mentioning 0xdf, ~96 are **reference
links**, and none are 0xdf-sourced entries — the mentions come from HackTricks and others citing
him. That posture is correct and must not change. It is one person's copyrighted blog.

**Therefore: do NOT scrape, crawl, mirror, or ingest 0xdf.gitlab.io. Do not copy his prose,
his structure, his screenshots, or his phrasing into any entry.**

What you ARE doing instead is extending the corpus that already exists for this purpose:
`hackpit-distilled` (78 entries via `ingest_exploitation_writeups.py`), which keys a
**service + version fingerprint** to the technique that solves it, written from **public CVE
data and general technique knowledge**. That corpus feeds build #8's 2.7 fingerprint retrieval,
which ranks "this exact stack was solved via X" ahead of generic token matches. A ranker is only
as good as the corpus behind it, and 78 entries is thin.

If you want a list of which service fingerprints recur on real target boxes, use **public,
factual sources**: CVE databases, NVD, ExploitDB, vendor advisories, the HTB machine list
(machine names, OS, and release dates are facts). Reading a public index to learn *that*
`vsftpd 2.3.4` is a commonly-encountered service is fine. Reading someone's walkthrough and
restating their solution is not.

---

## HARD RULES

1. **No third-party prose.** Every entry is written from scratch from CVE facts and general
   technique knowledge. If you cannot write it without a walkthrough open, do not write it.
2. **Check before you write.** Grep each candidate fingerprint against the existing corpus and
   the whole KB. `meta.fingerprint` already exists on 78 rows — do not duplicate one.
3. **Zero is a valid result** for any fingerprint that turns out to be already covered.
4. **Nothing raw is committed.** `sources/` and `data/` are gitignored. The committable artifact
   is the ingester's own generated rows plus any code change.
5. **No exploit code.** Entries describe the approach, the tool pattern, and the detection
   footprint — the same shape as the existing 78. Not weaponised payloads.

---

## THE WORK

### 1. Read the existing corpus first
```bash
backend/.venv/Scripts/python.exe - <<'PY'
import json, collections
rows=[json.loads(l) for l in open('data/kb/entries.jsonl',encoding='utf-8')]
fp=[r for r in rows if r.get('meta',{}).get('exploitation_writeup')]
print('fingerprint entries:', len(fp))
svc=collections.Counter(r['meta'].get('fingerprint',{}).get('service','?') for r in fp)
print('services covered:', dict(svc.most_common()))
PY
```
Understand the exact `meta.fingerprint` shape (service, version range, CVE, technique,
solved_via) and the entry style before adding anything. Match it exactly.

### 2. Pick the gaps that matter
Target the **thin KB categories**, not the saturated ones. Current shape (re-measure — the repo
batch will have moved these):

```
SATURATED  web 636 · cloud 534 · network-services 183 · active-directory 123 · privesc 116
THIN       services 9 · reversing 9 · exploit-dev 7 · pivoting 6 · credentials 5
           exploitation 5 · persistence 4 · fuzzing 4 · iot 2 · mobile 2 · phishing 1
```

Good fingerprint candidates are **network services with a well-known versioned flaw** — the
`services` category is at 9 entries and is exactly what this corpus is for. Think in terms of
"a scan returns `<product> <version>` — what does the operator do next?"

### 3. Write the entries
Extend the generator in `pipeline/ingest_exploitation_writeups.py` (or its data table) following
its existing discipline, which is documented at the top of the file:
* additive and byte-preserving — existing lines copied through as raw bytes
* idempotent — rows carry `meta.exploitation_writeup`; a re-run replaces exactly those
* its own marker, distinct from the other ingesters, so they never collide
* `category="writeup"` + `meta.no_merge` so consolidation leaves them alone

Each entry needs: the fingerprint, what the flaw actually is (from the CVE), the approach, the
tool pattern, and **what it leaves in logs** — the detection footprint is part of the house style.

### 4. Ingest and verify — report real numbers
```bash
cp data/kb/entries.jsonl /tmp/entries.before.jsonl      # Defender has deleted this file before
backend/.venv/Scripts/python.exe pipeline/ingest_exploitation_writeups.py
backend/.venv/Scripts/python.exe pipeline/embed.py
```
Then verify all four:
* **per-source counts diffed before/after** — prove no other source lost rows, total alone is
  not enough
* `data/kb/entries.jsonl` still exists
* retrieval — query with realistic scan output ("vsftpd 2.3.4", "Apache 2.4.49 path traversal")
  through `search.search(entries, query, top)`; the signature is **positional, there is no `k=`**
* `sh backend/run_safety_tests.sh` → expected all files exit 0.
  **Known flake:** `test_corpora.py` can exit 1 right after a KB ingest and pass on re-run —
  `ingest_corpora.py:139` shells to `git show HEAD:<file>` to "recover AV-locked / dehydrated
  files", and rewriting the 22 MB `entries.jsonl` triggers a Defender sweep that briefly locks
  corpus sidecars. Re-run before investigating.

### 5. Commit + push
Multi-line message to a file, commit with `-F`, trailer:
`Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
Push `sandbox-kali-image`, fast-forward `main` if clean.

### 6. Assessment
Fold a short section into `docs/ASSESSMENT-2026-07-26.md`: how many fingerprints were added,
which services, which thin categories moved, and — importantly — **record the 0xdf decision**:
that ingesting it was proposed, declined on the repo's own standing sourcing line, and replaced
with distilled fingerprints written from public CVE data. Add a D-entry if that reads as a real
decision. **No strikethrough (`~~`).** Update Verification and Status, then:
```bash
backend/.venv/Scripts/python.exe docs/build-assessment.py
```
Verify the PDF: `%PDF` header, page count, and that the new text is genuinely **inside** it —
extract with `pypdf` on the **system** python (the venv has no pip) and **always run a positive
control first** (search for "HackPit"); without it a broken extractor reports false negatives.

---

## ENVIRONMENT NOTES
* Interpreter `backend/.venv/Scripts/python.exe` (no pip); system `python` has `pypdf`.
* `PYTHONIOENCODING=utf-8` before printing non-ASCII, or cp1252 will crash the script.
* If the classifier refuses git, write a self-verifying `.sh` to the repo root and hand over the
  exact `! sh /c/Users/zaid_/Downloads/HackPit/<name>.sh` line rather than stalling.
* Never report a green suite you did not see.
