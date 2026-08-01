# HackPit — fix the two defects suppressing fingerprint retrieval

Repo `C:\Users\zaid_\Downloads\HackPit`, branch `sandbox-kali-image`. `git pull --rebase` first.
Read `docs/FINGERPRINT-EVAL.md` before touching anything — it is the measured baseline and you
must beat it with the same test set.

**Do NOT add fingerprints in this session.** Growing the corpus while fixing the matcher makes
the improvement unattributable. `PROMPT-0xdf-pass2.md` runs after this, not alongside it.

---

## THE TWO DEFECTS — both independently verified

### D-A — 35 of 38 testable fingerprints cannot match their own stored version

`reasoning.retrieval._structured_match` delegates to the CVE index's
`ExploitIndex()._version_verdict`. Those two subsystems use **opposite boundary conventions**:

* the CVE→exploit index stores `versions[-1]` as the **fix** version, so exclusive `<` is right
* the fingerprint corpus stores the **last vulnerable** version, which needs inclusive `<=`

Measured against the live KB:

```
testable (exact/lte/range): 38
cannot match own last stored version: 35    (lte 25, range 10)

lte    log4j       versions=['2.15.0']       -> "2.15.0 is out of range"
lte    confluence  versions=['7.18.1']       -> "7.18.1 is out of range"
range  samba       ['3.0.20','3.0.26']       -> "3.0.26 is out of range"
```

A scan reporting exactly the vulnerable version — the most precise hit possible — silently
misses. Note also that **`lte` literally means "less than or equal"**, so the verdict function
currently contradicts its own kind name. That is a strong hint about where the defect really is.

**The real fault is a shared predicate with an unstated convention**, not either caller. This is
the third instance of that pattern in this project (build #5's WinRM `argv[0]` classification,
D22's proxychains red-confirm laundering, now this), and `backend/AGENTS.md` already states the
rule: **fix the PREDICATE, never narrow the caller.**

**Decide the fix deliberately and record the reasoning:**
* *(a)* make the boundary semantic **explicit** at the call — e.g. an `inclusive=` argument, or
  honour `lte` as genuinely inclusive — so neither caller relies on an implied convention. This
  is the option that stops the bug recurring, but it touches the CVE index's behaviour, so
  **prove the CVE→exploit index is unchanged** with its existing tests plus a before/after diff
  of its verdicts across the whole index.
* *(b)* rewrite the 35 corpus entries to store fix versions. Lower blast radius, but the
  convention stays implicit and the next entry author will get it wrong again.

Do not pick (b) just because it is smaller. Whichever you choose, say why in the commit.

### D-B — vendor-prefixed products collapse, and COLLIDE

`fingerprint()`'s first-token heuristic:

```
Apache Tomcat        -> apache/<ver>
Apache httpd         -> apache/<ver>      <-- same key as Tomcat
Microsoft SQL Server -> microsoft/<ver>
Atlassian Confluence -> atlassian/<ver>
```

The eval reported this as products being unreachable from their standard `nmap` banner. It is
worse than that: **Tomcat and httpd collide on one key**, so two unrelated products are
distinguished only by their version numbers. That can produce a *wrong* fingerprint hit, not
merely a missing one — and a confidently wrong exploit suggestion is the failure mode this whole
subsystem exists to avoid.

Fix the normalisation so vendor-prefixed names resolve to the **product**, not the vendor, while
keeping bare names (`vsftpd`, `openssh`) working. Drive it from the real corpus and real scanner
strings, not a hand-written list of special cases that rots.

---

## REGRESSION LOCKS — the point of the session

Both defects existed because nothing asserted the obvious. Add tests that would have caught them,
following `backend/AGENTS.md`'s safety-test rule (iterate the real source of truth, assert on
what you actually checked, carry a positive control):

1. **Every fingerprint entry must match its own stored version.** Iterate all
   `meta.fingerprint` rows from the live KB — not a hand-written sample — and assert
   `_structured_match` returns True for each entry's own boundary versions. Report the count
   checked. Positive control: a planted entry with a deliberately wrong range must fail.
2. **No two distinct products may normalise to the same fingerprint key.** Iterate the real
   corpus plus a list of real `nmap -sV` product strings; assert `Apache Tomcat` and
   `Apache httpd` produce different keys. Positive control: a planted colliding pair must be caught.

Wire both into `backend/run_safety_tests.sh`.

---

## VERIFY — beat the baseline with the same test set

Re-run the eval's three groups (COVERED in real scanner formatting, NEAR-MISS, UNCOVERED) from
`docs/FINGERPRINT-EVAL.md` and report before/after:

* hit rate on COVERED — baseline 70%
* precision when firing — baseline 90%
* **false-fire on NEAR-MISS — baseline 0%, and this must STAY 0%.** If a fix raises hit rate by
  making the matcher looser, it has made the tool more dangerous, not better. Inclusive `<=` at
  the exact boundary is correct; anything beyond it is not.
* false-fire on UNCOVERED

Then: `sh backend/run_safety_tests.sh` → all files exit 0 (52 before your two additions).
`test_corpora.py` may flake after any KB rewrite — documented Defender/sidecar cause, re-run
before investigating. **Never report a green suite you did not see.**

---

## OUTPUT

Append the results to `docs/FINGERPRINT-EVAL.md` as an "after the fix" section — keep the
original numbers intact so the delta is visible. Commit with `-F` and the trailer
`Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`; push
`sandbox-kali-image`, fast-forward `main`.

Fold into `docs/ASSESSMENT-2026-07-26.md`: a **D-entry** for the boundary-convention decision
(it is a real architectural call about a shared predicate), the two defects, the regression locks,
and the measured before/after. Note that this is the third shared-predicate defect in the
project's history and that the pattern is now worth watching for. **No strikethrough (`~~`).**
Update Verification and Status, regenerate with
`backend/.venv/Scripts/python.exe docs/build-assessment.py`, and verify the PDF with a
**positive control first** (`pypdf` on the system python — the venv has no pip — confirm
"HackPit" extracts before trusting any "missing" result).

---

## ENVIRONMENT
* `backend/.venv/Scripts/python.exe` (no pip); system `python` has `pypdf`.
* `PYTHONIOENCODING=utf-8` before printing non-ASCII.
* Defender has deleted files mid-run repeatedly in this series — back up `data/kb/entries.jsonl`
  before anything that rewrites it, and tolerate a file vanishing between listing and reading.
* If the classifier refuses git, write a self-verifying `.sh` to the repo root and hand over the
  exact `! sh ...` line rather than stalling.
