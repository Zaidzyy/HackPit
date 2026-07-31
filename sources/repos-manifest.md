# External source repos — clone manifest

The reproducibility record for KB enrichment batches built from third-party git repos.
**The clones themselves are never committed**: `sources/` is gitignored and every clone is
deleted once the batch is ingested and verified. This file is what remains — URL, clone
date, exact commit, and what the repo actually yielded.

---

## Batch: cert / CTF / pentest study repos — cloned 2026-08-01

24 repos (6 CTF writeup collections, 4 OSCP, 2 CRTP, 2 CPENT, 4 eCPPT, 4 PNPT/TCM, 1
general, 1 gist). **22 yielded nothing and 1 repo produced the batch's only 2 entries.**
That is the honest outcome: the KB was already saturated in exactly the areas these repos
cover. Every candidate technique was grepped against all 2,712 existing rows before being
written, and a token-level sweep found 308 terms that appear in three or more repo files and
never in the KB — on inspection all 308 were URL slugs, lab hostnames, playlist IDs,
filenames or typos. No new tool name and no new technique name.

Three repos (`magpieCTF-2025`, `OSCP-Resources`, `PNPT-study-guide`) carry paths that are
illegal on Windows (a trailing space, a `|`, a `dist.` segment), so `git clone` fetched the
objects but could not check out a working tree; their text files were materialised with
`git show HEAD:<path>` under sanitised names.

`danielmiessler/SecLists` was excluded by the operator (wordlists, multi-GB, zero KB value).
`https://0xdf.gitlab.io/` was NOT scraped — it is a website, not a repo, and is recorded as a
separate follow-up proposal in `docs/ASSESSMENT-2026-07-26.md`.

| Repo | Group | Commit | Verdict |
| --- | --- | --- | --- |
| [magpieCTF-2025](https://github.com/infosec-ucalgary/magpieCTF-2025.git) | CTF | `42ca3df534a8` | ZERO — CTF challenge sources + solution stubs; 49 md, median 185 words. Windows-illegal path (`dist.`); text materialised via git cat-file. |
| [searchparty-ctf-writeups](https://github.com/tracelabs/searchparty-ctf-writeups.git) | CTF | `38f0cfb7c26e` | ZERO — 669-word link index to external OSINT-CTF blog posts. No technique text. |
| [ethical-hacking-ctf-writeups](https://github.com/Sarah-Marion/ethical-hacking-ctf-writeups.git) | CTF | `e12fc3d1a7fc` | ZERO — 406 words, one THM-style writeup, no code blocks. |
| [daffainfo-ctf-writeup](https://github.com/daffainfo/ctf-writeup.git) | CTF | `ddb01203ac94` | ZERO — 643 per-challenge jeopardy writeups, median 123 words. Solutions, not reusable methodology; `writeup` (173) + `ctf` (71) already saturated. |
| [sousa16-ctf-writeups](https://github.com/sousa16/ctf-writeups.git) | CTF | `8220aff3f303` | ZERO — mostly PortSwigger Web Academy lab writeups; the KB already carries 372 `portswigger` entries. Its `scada`/`scada-v2` dirs are challenge NAMES (Jinja2 SSTI), not ICS. |
| [tim-barc-ctf_writeups](https://github.com/tim-barc/ctf_writeups.git) | CTF | `0dde10d9fa51` | ZERO — 209 PDFs of blue-team/DFIR writeups plus a README of 497 links (92 links per 1k words). |
| [OSCP-Pentesting-Cheatsheet](https://github.com/BlessedRebuS/OSCP-Pentesting-Cheatsheet.git) | OSCP | `1c99a1b5fa0a` | ZERO — densest cheatsheet in the batch (14.2k words, 289 code blocks) but every probed command already present via oscp-cpts-notes / madstuff / hacktricks. |
| [OSCP-Resources](https://github.com/verylazytech/OSCP-Resources.git) | OSCP | `e30a6aadcfa8` | ZERO — 53 links per 1k words; a pointer collection. Windows-illegal path (trailing space); text materialised via git cat-file. |
| [OSCP-Cheatsheet](https://github.com/saisathvik1/OSCP-Cheatsheet.git) | OSCP | `1d0b9f39ecfc` | ZERO — 6.3k words / 111 code blocks, fully covered by existing sources. |
| [awesome-oscp](https://github.com/0x4D31/awesome-oscp.git) | OSCP | `d8ff6186214b` | ZERO — curated link list (153 links per 1k words, 0 code blocks), exactly as predicted. |
| [CRTP-Certified-Red-Team-Professional](https://github.com/Certs-Study/CRTP-Certified-Red-Team-Professional.git) | CRTP | `67c9b2a3e4fb` | ZERO — 7.6k words / 243 code blocks of AD. Probed DCSync (47 KB hits), silver ticket (13), unconstrained delegation (11), ACL abuse, GPO, SID history, BloodHound: all covered by the KB's 123 `active-directory` entries. |
| [CRTP-Notes](https://github.com/0xStarlight/CRTP-Notes.git) | CRTP | `51d2fcae54f7` | ZERO — 7.9k words / 193 code blocks; same coverage result as above. |
| [CPENTv1StudyGuide](https://github.com/rgallart101/CPENTv1StudyGuide.git) | CPENT | `04eb993eecfb` | ZERO — only modules 05 (external) and 06 (internal) are written; 09 wireless, 11 IoT and 12 SCADA are [TBD] stubs. Content is nmap/enumeration, already saturated. |
| [CPENT-Learning](https://github.com/Cyber-Security-Warriors/CPENT-Learning.git) | CPENT | `f2231d9c691a` | ZERO — 6 files, 810 words, a link list to blogs and TryHackMe rooms. |
| [eCPPTv3-INE](https://github.com/r-dandrea/Certified-Professional-Penetration-Tester-eCPPTv3---INE-.git) | eCPPT | `7a76ad545c5d` | ZERO — 1.2k-word exam review, no code blocks. |
| [Dragkob-eCPPT](https://github.com/Dragkob/eCPPT.git) | eCPPT | `99f9ee0bbe31` | ZERO — 190-word README plus course-note PDFs; third-party prose, heavy overlap. |
| [eCPPTv2-PTP-Notes](https://github.com/dev-angelist/eCPPTv2-PTP-Notes.git) | eCPPT | `a543e9167445` | **2 ENTRIES** — 126k words; its `network-security/2.4-1/2.2-pivoting*.md` pair is a worked three-network, three-hop lab and the primary source for both authored pivoting entries. |
| [eCPPT-resources](https://github.com/calacuda/eCPPT-resources.git) | eCPPT | `3942303e3c52` | ZERO — a table of links to other people's exam reviews. |
| [ciwen3-PNPT](https://github.com/ciwen3/PNPT.git) | PNPT | `fafb22931b48` | ZERO — 188k words / 307 MB, largest clone in the batch, but its cheatsheets duplicate the KB and its `Windows/Persistence/README.md` is a pure link list. **Contains a `conti/` directory: leaked Conti ransomware operator manuals (Russian), rclone.exe and a Cobalt Strike 4.3 archive.** Nothing from it was committed; the clone is deleted. |
| [ethanolivertroy-PNPT](https://github.com/ethanolivertroy/PNPT.git) | PNPT | `7da8716206e3` | ZERO — TCM course notes that overlap the KB's existing `peh-notes` source (43 entries). |
| [PNPT-study-guide](https://github.com/peterrakolcza/PNPT-study-guide.git) | PNPT | `a675433b4c24` | CONTRIBUTED — 26.4k words / 373 code blocks; its TryHackMe Wreath pivoting notes are the second source for both authored entries (forward vs reverse SOCKS, the quiet socat relay). No entry of its own. Windows-illegal path (`|`); text materialised via git cat-file. |
| [PNPT-Prep-Guide](https://github.com/Apoorv-Ban/PNPT-Prep-Guide.git) | PNPT | `f6943f3322bd` | ZERO — 2.8k words, zero code blocks; a day-by-day course syllabus. |
| [Pentest-Resources-Cheat-Sheets](https://github.com/bL34cHig0/Pentest-Resources-Cheat-Sheets.git) | General | `9e57afe392e1` | ZERO — curated link list (45 links per 1k words). |
| [vitalyford-gist](https://gist.github.com/vitalyford/175f6c120f772a647bdbdf938e7ea3e0) | Gist | `3711c22f5611` | ZERO — 2k-word CPENT command list (OSINT, nmap, hydra); recon is saturated at 69 + 175 reference entries. |

### What the batch produced

* **KB:** 2 authored entries in `pivoting` (6 → 8), the thinnest category the batch could
  legitimately reach — `authored-multi-hop-pivot-chain` and
  `authored-pivot-primitive-selection`. KB total 2,712 → 2,714.
* **Arsenal:** 5 rows in a new `pivoting` category (chisel, ligolo-ng, socat, sshuttle,
  proxychains), 110 → 115 tools. All five binaries were confirmed present in the running
  sandbox image while the catalog held no pivoting tool at all.
* **Safety:** cataloguing proxychains surfaced a pre-existing gate hole — the danger
  heuristic classified `argv[0]` only, so `proxychains -q weevely …` produced zero reasons
  while bare `weevely` produced one. `cockpit/tunnels.py` builds exactly that argv, so
  routing a command through a tunnel stripped its red-confirm. Fixed in the predicate
  (unwrap, then classify the inner command) and regression-locked.

### What it did NOT produce, and why that matters

The batch was scoped expecting CPENT to be the highest-yield group (IoT, ICS/SCADA,
pivoting — all thin in the KB). It was not. Across **all 24 repos**, exactly one file
mentions ICS terms (modbus, s7comm, dnp3, scada, plc, profinet, HMI, Purdue) four or more
times, and it is a CTF challenge *named* "Scada" that turns out to be Jinja2 SSTI. There is
no ICS, no IoT-hardware and no firmware/UART/JTAG material in this batch at all. `iot` (2)
and `phishing` (1) remain the KB's thinnest categories and need a different source.

