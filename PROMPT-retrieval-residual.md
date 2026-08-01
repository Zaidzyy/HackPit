# HackPit — close the last retrieval defect, and close out the enrichment series

Repo `C:\Users\zaid_\Downloads\HackPit`, branch `sandbox-kali-image`. `git pull --rebase` first.
Read `docs/FINGERPRINT-EVAL.md` — it holds the measured baseline you must beat and the residual
you are here to fix.

Two tasks: **fix the last known retrieval defect**, then **formally close the enrichment series**
in the assessment. Do not add KB entries in this session.

---

## TASK 1 — the version-less substring fallback false-fires on uncovered services

### The defect
The eval measured **~20% false-fire on UNCOVERED services** (3/15: `pure`, `node.js`, `minio`),
and 0xdf pass 2 re-measured it at exactly **20% (3/15), zero delta** after adding 8 entries.
So it is stable, reproducible, and independent of corpus size.

It is a **different code path from the structured matcher**. `_structured_match` is now correct —
D-A and D-B are fixed, 45/45 versioned fingerprints self-match, 0/45 fire above the boundary.
This is the *version-less substring fallback* in `reasoning/retrieval.py` firing when a scanned
product merely appears as a substring somewhere in an entry, with no version check.

### Why it matters
2.7 retrieval exists to float a fingerprint hit **above** token matches, so the proposer treats
it as *"this exact stack was solved by X"*. When the fallback fires on a service the corpus does
not cover, that confidence is unearned: the operator gets a precise-looking pointer to a
technique for a different product.

Severity is bounded — every command is human-approved, so a bad pointer degrades proposal
quality rather than creating risk — but it is the last known correctness gap in the path, and
the corpus has stopped growing, so now is the time.

### What to do
Read the fallback and decide what it is *for* before changing it. It presumably exists so a
version-less scan still gets some signal, which is legitimate. The bug is not that it fires; it
is that **its hits are presented with the same confidence as a structured fingerprint match.**

Options to weigh, and state your reasoning:
* require a stronger match than a bare substring (word-boundary/token match against the entry's
  `meta.fingerprint.service`, not a blind `in` over the whole blob)
* keep the fallback but **mark it distinctly** — `fingerprint_match` should be reserved for a
  structured hit, with fallback hits ranked below and labelled so the proposer's grounding line
  does not claim an exact-stack match it does not have
* both

**Do not simply delete the fallback to drive the number to zero.** Measure what that would cost
on the COVERED group first — if removing it drops covered hit rate, it is doing real work and
the answer is to label it honestly rather than remove it.

### The bar
| metric | current | requirement |
|---|---|---|
| UNCOVERED false-fire | 20% (3/15) | **materially lower** |
| COVERED hit rate | 93% | **must not drop** |
| precision when firing | 96% | must not drop |
| NEAR-MISS false-fire | 0% | **must stay 0%** |
| corpus self-match | 105/105 | must stay 105/105 |
| fire above boundary | 0/45 | must stay 0/45 |

Re-run the eval's three groups from `docs/FINGERPRINT-EVAL.md` and report before/after on all
six. **A fix that lowers false-fire by making the matcher stricter and also drops covered hit
rate has traded one defect for another — say so rather than presenting it as a win.**

### Regression lock
Add a test in the style of the two the fix session added (`test_fingerprint_versions.py`,
`test_fingerprint_norm.py`): iterate the **real corpus** plus a list of real services it does not
cover, assert the fallback does not claim a structured fingerprint match for them, carry a
**positive control** that demonstrably fails. Wire it into `backend/run_safety_tests.sh` (54 files
currently, all green).

---

## TASK 2 — close out the enrichment series in the assessment

The series is finished. **`PROMPT-pdf-and-pages.md` (batch 3) is deliberately NOT being run** —
record that as a decision with its evidence, not as an omission.

### The scoreboard, measured
```
transcript corpus (687k chars)      13 entries
batch 1 — 24 repos + gist            2 entries   (22 sources yielded zero)
batch 2 — 7 GitBook spaces           0 entries
batch 4 — 0xdf pass 1 (55 posts)    19 entries
          0xdf pass 2 (51 posts)     8 entries
batch 3 — PDFs/pages/CPENT          NOT RUN, deliberately
                                    ── 42 entries; KB 2,699 -> 2,741
```

### The finding worth stating plainly
**Cert notes: 31 sources → 2 entries. Narrative writeups: 106 posts → 27 entries.** Roughly a
25× difference in yield per source. Exam notes are condensed and derivative and cover a syllabus
the KB had already absorbed; writeups that start at a scan result and end at root supply a shape
nothing else did. That is the reusable lesson for choosing future sources, and it is why batch 3
— five more cert-note sources — is being closed unrun rather than executed to confirm what 31
sources already established.

### The uncomfortable number, which must also be stated
**The thin categories the series set out to fill did not move.** Measured now against the start:
```
services 9 (unchanged) · credentials 5 (unchanged) · persistence 4 (unchanged)
iot 2 (unchanged) · phishing 1 (unchanged) · pivoting 6 -> 8
```
All 27 fingerprint entries land in `category="writeup"` (173 → 200) because
`ingest_exploitation_writeups.py` forces it as part of its `no_merge` discipline. They function —
2.7 keys on `meta.fingerprint`, not category — but **the series did not achieve its stated goal**,
and the assessment should say so rather than reporting 42 entries as though it did.

Record the open question without acting on it: is `category="writeup"` right for discoverability,
or should fingerprint entries carry the service category they describe? That is a contract change
to the ingester and belongs in its own session.

### Also record
* **D22** proxychains laundering the red-confirm — found by cataloguing a tool, not by looking
  for it. The most valuable single output of the whole series.
* **D24** the shared-predicate boundary convention, and that it was the **third** instance of
  that pattern (build #5 WinRM `argv[0]`, D22 proxychains, D24). Worth watching for a fourth.
* **The token diff nominates, it never confirms** — `seshutdownprivilege` looked like a certain
  gap and was already present spelled `SeShutdown`.
* Sources declined and why: **themastermindnotes** (commercial product), **mqt.gitbook.io**
  (refused itself via `robots.txt`), **0xdf declined then reversed**, **0xdf now closed** as a
  fingerprint source on a declining tail (19/55 → 8/51).
* **Windows Defender deleted files mid-run in three separate sessions**, including from fetched
  source trees, not just `data/kb/entries.jsonl`. It is now a standing operational hazard for
  this repo, not an anecdote.

Add a **D-entry** for the residual fix if it turns out to be a real design call. **No
strikethrough (`~~`).** Update Verification and Status, then
`backend/.venv/Scripts/python.exe docs/build-assessment.py` and verify the PDF with a
**positive control first** (`pypdf` on the system python — the venv has no pip — confirm
"HackPit" extracts before trusting any "missing" result).

---

## OUTPUT
Append the after-fix numbers to `docs/FINGERPRINT-EVAL.md`, keeping the earlier tables intact so
the full arc is visible. Commit with `-F` and the trailer
`Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`; push
`sandbox-kali-image`, fast-forward `main`.

`sh backend/run_safety_tests.sh` must be green on the exact state you commit. **Never report a
green suite you did not see.**

## ENVIRONMENT
* `backend/.venv/Scripts/python.exe` (no pip); system `python` has `pypdf`.
* `PYTHONIOENCODING=utf-8` before printing non-ASCII.
* Back up `data/kb/entries.jsonl` before anything that could rewrite it, and tolerate a file
  vanishing between listing and reading.
* If the classifier refuses git, write a self-verifying `.sh` and hand over the exact `! sh ...`
  line rather than stalling.
