# Batch 3 — PDFs, pages, and the CPENT repo (series close-out)

Run 2026-08-01. The last batch of the KB-enrichment series. One manifest line per source:
URL, date fetched, verdict. Raw trees deleted after ingest; `sources/` is gitignored.

| # | Source | Kind | Fetched | Verdict |
|---|--------|------|---------|---------|
| 1 | https://elhacker.info/ebooks%20Joas/OSCP%20NOTES.pdf | PDF, 78pp / 58.7k chars | 2026-08-01 | **0 entries.** Nmap/revshell cheat sheet; every technique already in KB (revshells, transfers, priv-esc all covered). |
| 2 | https://elhacker.info/ebooks%20Joas/eLearnSecurity%20eCPPT%20Notes%20Exam.pdf | PDF, 157pp / 177k chars | 2026-08-01 | **0 entries.** Broad eCPPT course notes (recon→web→AD→BOF); saturated against KB, largely tutorial prose rather than technique. |
| 3 | https://parzival.sh/blog/my-oscp-notes-and-resources | web page, 19.3k chars | 2026-08-01 | **0 entries.** As predicted by title — notes-AND-resources: a link list + a checklist of commands already in KB. Zero novel technique, exactly like `awesome-oscp` in batch 1. |
| 4 | https://pnpt.adot8.com | **GitBook space, 185 pages** (mis-scoped in the prompt as a single page) | 2026-08-01 | **0 entries.** Same PEH/PNPT curriculum already held as `peh-notes` (43) + `oscp-cpts-notes` (36). Pages are thin: overview prose + embedded links to other blogs + screenshots (mean 937 content chars, 31 of 184 near-empty). Every candidate — passback, IKE aggressive mode, open mail relay, LLMNR, kerberoast, o365 spray, chisel/sshuttle/ligolo — already covered, several better than the source. |
| 5 | https://gitlab.com/parfaittolefo23/cpent-sheet-cheat | git repo, 12 module .md files | 2026-08-01 | **2 entries.** The only productive source. Its IoT/SCADA nmap notes and perimeter-device module nominated two real gaps (below). Its pivoting/AD/wireless/web modules were fully saturated. |

## Entries added (2)

Both **distilled** from the CPENT cheat sheet's nominations, written from scratch (D21); the
source is a bare flag list, the entries are the mechanism and judgement around it.

- `authored-perimeter-filter-mapping` [recon] — reading a packet filter: three-state model,
  ACK/window scans for ACL enumeration, firewalking to locate the device, and scan-time
  evasion (fragmentation / source-port trust / decoy caveats). KB gap confirmed: `--spoof-mac`,
  `--data-length`, `firewalk`, `--mtu`, `nmap -f`, window-scan were all **0 hits** pre-ingest;
  retrieval for "map firewall rules with nmap" returned cloud firewall enumeration.
- `authored-ot-safe-scanning` [ics] — scanning an ICS/OT segment without faulting a PLC: never
  `-sV`/`-A`/`-O`, prefer `-sT` over `-sS`, passive-first, `--max-parallelism 1`, abort path in
  the ROE. KB gap confirmed: `--max-parallelism` was **0 hits**; the `ics` category held exactly
  one entry (an operator persona, not a technique).

## Excluded (per prompt, never fetched)

- https://themastermindnotes.com/products/ecppt-study-notes-guide-unofficial — commercial
  product page. Not scraped, not fetched, not worked around.

## Operational notes

- **Defender deleted-file hazard recurred:** `pnpt-adot8/post-exploitation/av-evasion/bypassing-amsi.md`
  became unreadable (errno 22) mid-triage while still 3,453 bytes on disk — the standing
  file-lock hazard, one more instance. Measurement code was made tolerant of it.
- **`test_corpora.py` flake fired and cleared on re-run**, as documented: the 22 MB KB rewrite
  triggered a Defender sweep that briefly locked corpus sidecars; second run green (55 files).
- **pnpt.adot8.com was mis-scoped** in the prompt as one of the "two web pages". Its sitemap
  resolves to 185 pages on a custom domain — a GitBook space — so it was routed through
  `fetch_gitbook.py` (added as space `pnpt-adot8`), not the plain-page path.
