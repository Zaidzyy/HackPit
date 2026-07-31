# HackPit — KB enrichment from 24 cert/CTF/pentest repos

Repo `C:\Users\zaid_\Downloads\HackPit`, branch `sandbox-kali-image`. Read this whole prompt
first. Process: clone → profile → **triage and report back** → ingest → verify → clean up →
commit → push → update the assessment. Rebase on whatever has landed.

---

## GOAL

Fold 24 git repos (cert study notes + CTF writeups + cheatsheets) into HackPit's KB as
**distilled, non-duplicative authored entries** — and into `backend/arsenal/tools.json` where a
repo describes tools rather than techniques. Then delete every clone.

The KB is at **2,712 entries** across 33 categories. It is already saturated in exactly the
area these repos cover, so the job is **selection, not volume**.

---

## HARD RULES (do not negotiate these)

1. **Nothing raw is committed.** `sources/` and `data/` are gitignored — first line of
   `.gitignore` says "ship CODE ONLY". Clones, notes, PDFs and writeups NEVER enter git. The
   only committable artifact is `pipeline/authored/authored_entries.jsonl` (and `tools.json`).
2. **Check before you write.** Every candidate technique must be grepped against all 2,712
   existing rows first. If it is already covered, say so and skip it. Do not re-ingest
   Java deserialization (24 entries), cache poisoning (19), open redirect/OAuth (11),
   mass assignment (3), AD/Kerberos (123), web (636) or cloud (534) material that already exists.
3. **Distil, never parrot.** Write entries in HackPit's own voice against the canonical schema.
   Do not copy a repo's markdown into a KB entry. If a source teaches something confusedly,
   rewrite it correctly or drop it.
4. **Do not manufacture entries to make the batch look productive.** A repo that turns out to be
   a link list yields zero entries and you report zero. That is a correct outcome.
5. **No secrets, no personal data, no third-party prose** in anything committed.

---

## THE REPOS

Shallow-clone all of these into `sources/repos/` (gitignored) with
`git clone --depth 1 --single-branch`:

**CTF writeups (6)** — expect heavy overlap with the existing 173 `writeup` + 71 `ctf` entries
```
https://github.com/infosec-ucalgary/magpieCTF-2025.git
https://github.com/tracelabs/searchparty-ctf-writeups.git
https://github.com/Sarah-Marion/ethical-hacking-ctf-writeups.git
https://github.com/daffainfo/ctf-writeup.git
https://github.com/sousa16/ctf-writeups.git
https://github.com/tim-barc/ctf_writeups.git
```
**OSCP (4)** — `awesome-oscp` is a curated link list; expect ~zero extractable technique
```
https://github.com/BlessedRebuS/OSCP-Pentesting-Cheatsheet.git
https://github.com/verylazytech/OSCP-Resources.git
https://github.com/saisathvik1/OSCP-Cheatsheet.git
https://github.com/0x4D31/awesome-oscp.git
```
**CRTP / Active Directory (2)** — KB already holds 123 AD entries; bar for "new" is high
```
https://github.com/Certs-Study/CRTP-Certified-Red-Team-Professional.git
https://github.com/0xStarlight/CRTP-Notes.git
```
**CPENT (2)** — **highest expected yield** (IoT, ICS/SCADA, pivoting — all thin in the KB)
```
https://github.com/rgallart101/CPENTv1StudyGuide.git
https://github.com/Cyber-Security-Warriors/CPENT-Learning.git
```
**eCPPT (4)** — pivoting and post-exploitation are thin; that is where to look
```
https://github.com/r-dandrea/Certified-Professional-Penetration-Tester-eCPPTv3---INE-.git
https://github.com/Dragkob/eCPPT.git
https://github.com/dev-angelist/eCPPTv2-PTP-Notes.git
https://github.com/calacuda/eCPPT-resources.git
```
**PNPT / TCM (4)** — credential attacks, pivoting, reporting
```
https://github.com/ciwen3/PNPT.git
https://github.com/ethanolivertroy/PNPT.git
https://github.com/peterrakolcza/PNPT-study-guide.git
https://github.com/Apoorv-Ban/PNPT-Prep-Guide.git
```
**General (1)**
```
https://github.com/bL34cHig0/Pentest-Resources-Cheat-Sheets.git
```
**Gist (1)** — clone as a normal git repo
```
https://gist.github.com/vitalyford/175f6c120f772a647bdbdf938e7ea3e0
```

**EXPLICITLY EXCLUDED — do not clone:**
* `danielmiessler/SecLists` — wordlists. Multi-GB, zero KB value. The operator excluded it.
* `https://0xdf.gitlab.io/` — this is a **website, not a repo to ingest here**. It is a very
  high-quality HTB writeup blog. Do NOT scrape it in this session. Report it as a separate
  follow-up with a proposal (sitemap-driven fetch, like the existing PortSwigger ingester), and
  first check overlap against the 41 `htb-writeups` + 173 `writeup` entries already present.

---

## THE THIN AREAS — where value actually is

Real KB category counts. Aim new entries at the bottom of this list, not the top:

```
SATURATED  web 636 · cloud 534 · network-services 183 · reference 175 · writeup 173
           active-directory 123 · privesc 116 · pwn 100 · methodology 100 · windows 99
THIN       wireless 16 · post-exploitation 15 · services 9 · reversing 9 · exploit-dev 7
           stego 7 · pivoting 6 · credentials 5 · exploitation 5 · persistence 4
           fuzzing 4 · iot 2 · mobile 2 · phishing 1
```

**`pivoting` (6), `credentials` (5), `persistence` (4), `iot` (2), `phishing` (1) are the
targets.** CPENT covers IoT/ICS and pivoting; eCPPT and PNPT cover pivoting, credential attacks
and post-exploitation. That is where these repos can genuinely add something.

---

## PIPELINE

### 1. Clone + profile
```bash
mkdir -p sources/repos
# per repo: git clone --depth 1 --single-branch <url> sources/repos/<name>
```
Then profile each **without reading everything into context**: file count, total size, file-type
mix, top-level structure, README first ~40 lines. Produce a table.

### 2. TRIAGE — STOP HERE AND REPORT
Before ingesting anything, report per repo:
* size / file count / what it actually is (notes, writeups, link list, tool collection, binaries)
* which KB categories it touches, and whether those are saturated or thin
* candidate techniques **grepped against the existing 2,712 rows** — new vs already covered
* destination: KB entry / `tools.json` arsenal row / **nothing**
* estimated entry count

Expect to report that several repos yield zero. Say so plainly.

### 3. Ingest (only after the triage is agreed)
* **KB entries** → append to `pipeline/authored/authored_entries.jsonl`.
  Build with a re-runnable script that validates each row via `schema.Entry.model_validate`
  and replaces by `id` (see the existing 25 rows for the exact shape: numbered `steps`, each
  with optional `code` blocks, `references`, `meta.phase`, `meta.canonical_keys`).
* **Arsenal tools** → `backend/arsenal/tools.json`. **Trap: that file is CRLF** — preserve line
  endings or the diff explodes. Aliases must be listed `.exe`-stripped.
* Then:
```bash
backend/.venv/Scripts/python.exe pipeline/ingest_authored.py
backend/.venv/Scripts/python.exe pipeline/embed.py
```

### 4. Verify — all four, and report real numbers
* **Per-source counts diffed before/after.** Total alone is not enough; prove no other source
  lost rows.
* `data/kb/entries.jsonl` still exists afterwards (Windows Defender has deleted it before —
  back it up first).
* Retrieval: run real natural-language queries through
  `search.search(entries, query, top)` — signature is **positional, there is no `k=`** — and
  confirm the new entries surface.
* `sh backend/run_safety_tests.sh` → currently **52 files, all exit 0**.
  **Known flake:** `test_corpora.py` can exit 1 immediately after a KB ingest and pass on re-run.
  `pipeline/ingest_corpora.py:139` shells to `git show HEAD:<file>` expressly "to recover
  AV-locked / dehydrated files", and rewriting the 22MB `entries.jsonl` triggers a Defender sweep
  that briefly locks corpus sidecars. **Re-run before investigating.**

### 5. CLEAN UP — required
After ingest and verification:
* **Delete every clone**: `rm -rf sources/repos/`
* Keep only `sources/repos-manifest.md` — one line per repo: URL, clone date, commit SHA,
  verdict (entries produced / zero / deferred). That is the reproducibility record.
* Confirm the repo is clean and no clone artifact is tracked.

### 6. Commit + push
Multi-line message to a file, commit with `-F`, trailer:
`Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
Push `sandbox-kali-image`, then fast-forward `main` if clean.

### 7. Assessment
Fold a section into `docs/ASSESSMENT-2026-07-26.md` recording the batch: repos taken, repos
that yielded nothing and why, entries added, which thin categories moved, and the final KB
count. Add a D-entry if a real decision was made. **No strikethrough (`~~`).** Update the
Verification and Status sections. Then regenerate both artifacts with the existing generator:
```bash
backend/.venv/Scripts/python.exe docs/build-assessment.py
```
It rebuilds the HTML (splicing a fresh ToC — do not hand-edit) and the PDF via headless Edge.
Verify: `%PDF` header, page count, and that the new section's text is actually **inside the
PDF** (extract with `pypdf` on the SYSTEM python — the venv has no pip — and always run a
positive control such as searching for "HackPit" first, or a broken extractor will report false
negatives).

---

## ENVIRONMENT NOTES
* Interpreter: `backend/.venv/Scripts/python.exe`. It has **no pip**; system `python` has `pypdf`.
* Set `PYTHONIOENCODING=utf-8` before printing non-ASCII or Windows cp1252 will crash the script.
* The classifier sometimes refuses git/docker calls. If git is refused, write a self-verifying
  `.sh` to the repo root and hand over the exact `! sh /c/Users/zaid_/Downloads/HackPit/<name>.sh`
  line rather than stalling.
* Never report a green suite you did not see.
