# HackPit — does the fingerprint corpus actually make the proposer sharper?

Repo `C:\Users\zaid_\Downloads\HackPit`, branch `sandbox-kali-image`. `git pull --rebase` first.

**This is a MEASUREMENT session. Do not add, edit or remove a single KB entry.** An eval that
fixes things while measuring produces numbers that mean nothing. If you find a gap, write it
down as a finding; do not close it here.

---

## THE QUESTION

Five enrichment batches ran. `hackpit-distilled` went 78 → 97 fingerprints, and the KB is at
2,733 rows. The whole point of that corpus is `backend/reasoning/retrieval.py` — 2.7
fingerprint-keyed retrieval, which floats an exact service+version match above token matches so
the proposer sees *"this exact stack was solved by X"* instead of keyword soup.

**Nobody has checked whether it works.** That is the only question here:

1. When a realistic scan banner arrives, does a fingerprint actually fire?
2. When it fires, is the technique it returns the RIGHT one?
3. Did the 19 entries the 0xdf batch added measurably improve either number — or not?

A defensible "no measurable improvement" is a **success** for this session. It would mean the
next 12 fingerprints are not worth writing, which is worth far more than 12 fingerprints.

---

## WHAT TO READ FIRST
* `backend/reasoning/retrieval.py` — `fingerprint()`, `service_fingerprint()`, the structured
  `meta.fingerprint` reader, and the re-rank. Understand exactly what counts as a match
  (product normalisation, version-range coverage) before measuring anything.
* `backend/reasoning/__init__.py` — where 2.7 sits in the proposer chain.
* `sources/0xdf-manifest.md`, `repos-manifest.md`, `gitbooks-manifest.md` — what each batch
  claimed to add.

---

## LEVEL 1 — DETERMINISTIC, NO LLM. This is the core; do it properly.

### 1a. Build the test set — and do NOT build it from the corpus alone
A test set drawn only from the 97 fingerprints measures nothing but "can it find itself".
Build three groups:

* **COVERED (~30)** — service+version strings the corpus claims to cover, but written the way a
  real scanner emits them, not the way the entry stores them. Take real `nmap -sV` product
  strings: `vsftpd 2.3.4`, `Apache httpd 2.4.49 ((Unix))`, `Apache Tomcat/9.0.30`,
  `OpenSSH 8.2p1 Ubuntu 4ubuntu0.1`. The formatting mismatch is the point — if retrieval only
  matches its own storage format it will never fire on real scan output.
* **NEAR-MISS (~15)** — same product, a version OUTSIDE the entry's stated range. A fingerprint
  that fires here is **worse than one that never fires**: it will confidently point the operator
  at an exploit that does not apply. Measure this explicitly.
* **UNCOVERED (~15)** — real services the corpus does not claim (pick from state/engagement data
  or common banners absent from the 97). Every hit here is a false positive.

Draw the covered/near-miss versions from the entries' own `meta.fingerprint` version ranges so
the boundaries are exact.

### 1b. Measure
For each test string call the real retrieval path — not a reimplementation of it. Report:

| metric | what it means |
|---|---|
| **hit rate on COVERED** | how often a fingerprint fires when it should |
| **precision on COVERED** | when it fires, is the returned entry the right service+version |
| **rank** | is the fingerprint hit actually above the token matches, or merely present |
| **false-fire rate on NEAR-MISS** | pointing at an inapplicable exploit — the dangerous failure |
| **false-fire rate on UNCOVERED** | pure false positives |

**Report the format-mismatch failures separately.** If `Apache httpd 2.4.49 ((Unix))` misses
while `apache 2.4.49` hits, that is a normalisation bug in `fingerprint()` and it is the single
most valuable thing this session can find — it would mean the corpus is nearly inert against
real scanner output no matter how large it grows.

### 1c. The ablation — the actual question about batch 4
Re-run the same test set against the corpus **with the 19 0xdf-sourced entries excluded**
(identify them by a `0xdf` URL in `references`; filter in memory, **do not modify the KB file**).

Report the before/after delta on every metric. If the delta is ~0 on realistic banners, say so
plainly — that is the finding, and it decides whether a second 0xdf pass is worth running.

---

## LEVEL 2 — WITH THE LLM. Optional, and only if Level 1 shows retrieval fires.

If Level 1 shows retrieval is broken or inert, **stop and report** — running the proposer on top
of broken retrieval measures nothing.

Otherwise take 5–8 realistic service findings and run the proposer twice, with and without the
fingerprint context, and compare what it proposes: does it name the specific technique/CVE, or
stay generic? This is qualitative and noisy — present it as illustration, not as a number, and
keep the sample small. Ollama must be running.

---

## OUTPUT

A written report at `docs/FINGERPRINT-EVAL.md` (committable — it is your own analysis, no
third-party content):
* the three metrics tables with real numbers
* the ablation delta
* every failure mode found, with the exact input that triggered it
* **a recommendation**: is growing this corpus worth it, is there a normalisation bug to fix
  first, or is 2.7 wired in a way that means it rarely fires in practice?

Then commit with `-F` and the trailer
`Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`, push
`sandbox-kali-image`, fast-forward `main`.

**Do not update the assessment in this session.** The series close-out is already written; fold
this in only once the operator has decided what to do about the findings.

---

## RULES
* **Measure, never fix.** Findings go in the report; no KB or retrieval changes here.
* Use the real code path. A reimplementation of the matcher measures your reimplementation.
* Report negative results as prominently as positive ones. "The corpus does not fire on real
  scanner output" is the most valuable possible outcome of this session.
* `sh backend/run_safety_tests.sh` before committing — 52 files, all exit 0. Never report a
  green suite you did not see.

## ENVIRONMENT
* `backend/.venv/Scripts/python.exe` (no pip); system `python` has `pypdf`.
* `PYTHONIOENCODING=utf-8` before printing non-ASCII.
* Defender has deleted files mid-run three times in this series — back up anything you generate,
  and tolerate a file vanishing between listing and reading.
