# Design — reconFTW recon capabilities into HackPit

**Date:** 2026-07-27
**Status:** Approved (design), pre-implementation
**Source assessment:** `docs/RECONFTW-ASSESSMENT.md`
**Upstream:** six2dez/reconFTW (MIT). We adopt public tool names + public flag patterns + methodology ordering — **not** reconFTW's code.

---

## 1. Goal

Close HackPit's thinnest area — external / bug-bounty recon — by adopting reconFTW's *knowledge* (tools + invocation flags + recon ordering) into HackPit's existing arsenal + KB + composer, **without** adopting its autonomous fire-and-forget runner. Every added command still flows through the one gated executor, one human-approved command at a time.

Scope was fixed by two user decisions: **catalog + install in one pass**, and **full scope** (arsenal + KB methodology + composer grounding).

## 2. Non-goals / explicitly excluded

The reconftw.sh runner, `reconftw.cfg` engine, `interlace` (parallel exec), `notify` (auto-alerts), monitor/incremental/diff auto-rescan, axiom/Ax fleet, `reconftw_ai`, faraday export, `inscope` (HackPit's `scope.py` is stronger and stays). `interactsh`/OOB stays **deferred** (needs a VPS — unchanged prior decision). No change to `scope.py`, the executor, or any safety gate.

## 3. Tool set — 26 tools, 4 categories

Install route per tool: **apt** = kali-rolling package (verified at build, not assumed); **pin** = upstream release binary → `/usr/local/bin` with a `-version`/`-h` smoke test (katana/gau idiom); **venv** = python venv + PATH wrapper (jwt_tool idiom).

### New `osint` category (6) — HackPit has no OSINT home today
| tool | route | purpose | runtime caveat |
|---|---|---|---|
| trufflehog | pin | secret scanning in repos/filesystems | — |
| msftrecon | venv | M365 / Azure tenant recon | needs egress |
| github-subdomains | pin | subdomains from GitHub code search | GitHub token (optional) |
| gitlab-subdomains | pin | subdomains from GitLab | GitLab token (optional) |
| dorks_hunter | venv | Google dorking | needs egress |
| gitdorks_go | pin | GitHub dork search | GitHub token (optional) |

### `recon` (10)
| tool | route | purpose | caveat |
|---|---|---|---|
| gotator | pin | rule-based subdomain permutations | — |
| regulator | venv | regex/pattern-based permutations | — |
| subwiz | **catalog-only, NOT baked** | ML subdomain prediction | fetches model at runtime → runs in engagement/`:kali` (egress), **not** in the airgapped lab; reconcile marks it not-installed there |
| puredns | apt else pin | mass resolve + wildcard filter | needs massdns; resolver validation needs egress |
| massdns | apt | high-speed DNS resolver | — |
| dnsvalidator | venv | build a trusted-resolver list | needs egress; static `/usr/share/resolvers.txt` is the lab fallback |
| asnmap | apt else pin | ASN → CIDR expansion | PDCP key optional |
| mapcidr | apt else pin | CIDR manipulation | — |
| tlsx | apt else pin | TLS SAN subdomain grabbing | — |
| csprecon | pin | CSP-header subdomain extraction | — |

### `web` (10)
| tool | route | purpose | caveat |
|---|---|---|---|
| gf | pin | pattern-grep URLs for vuln candidates | **inert without gf-patterns** (baked, see §5) |
| qsreplace | pin | query-string value replacement | — |
| unfurl | pin | URL component parsing | — |
| jsluice | pin | JS endpoint/secret extraction | — |
| subjs | pin | discover JS files from pages | — |
| getjs | pin | fetch JS files | — |
| commix | apt | command-injection testing | trips executor red-confirm (correct, unchanged) |
| SSTImap | venv | SSTI detection/exploitation | — |
| nomore403 | pin | 403/4xx bypass | complements the `bypass-403` skill |
| crlfuzz | pin | CRLF injection | — |

Result: arsenal grows **73 → 99 tools**, **8 → 9 categories**.

## 4. Component 1 — Arsenal catalog (`backend/arsenal/tools.json`)

Pure data. One object per tool in the confirmed schema:
`name, category, purpose, phases[], techniques[], docs, templates[{label,template,note}], flags[{flag,what}], aliases[]?, platform?`.
Add any missing top-level `placeholders` (`<domain>`, `<urls-file>`, `<resolvers>`, `<wordlist>`). Templates are `<target>`-based so the composer's `substitute_target` fills them; unfilled placeholders stay visible by design. `subwiz` gets no `platform` flag (it's Linux) — its lab-unavailability is handled by reconcile (not baked), and noted in its `note`.

**Invariant:** `executes_nothing: true` is unchanged. Adding entries introduces no execution path. Validated by `test_arsenal.py` (schema) and `test_arsenal_safety.py` (safety heuristics, impacket-style multi-binary rules, red-confirm expectations).

Feeds the composer automatically: `orchestrator._arsenal_reference(goal)` → `arsenal.planner.prompt_block(...)`, already phase/technique-filtered and gated on the reconcile "is_present" probe — so a catalogued-but-uninstalled tool (e.g. subwiz in the lab) is never proposed there.

## 5. Component 2 — Sandbox image (`docker/Dockerfile.sandbox`)

A new themed layer group placed **below** the stable Kali/AD layers (so their cache survives edits), following existing conventions:
- apt layer for kali-packaged tools (`massdns`, `commix`, and any of `puredns/asnmap/mapcidr/tlsx` kali actually ships — verified at build).
- pinned-binary layer: curl release → `/usr/local/bin`, each ending in a smoke test so a bad URL fails the build loudly.
- python-venv layer: `regulator`, `dnsvalidator`, `msftrecon`, `dorks_hunter`, `SSTImap`, each in its own venv with a PATH wrapper (jwt_tool idiom; avoids PEP-668 collisions).
- layer 9b aliases: any binary whose installed name ≠ catalog name gets a guarded symlink (so reconcile doesn't report it missing).

**Baked supporting data (no-egress correctness):**
- **gf-patterns** cloned into both `/root/.gf` and the sandbox user's `~/.gf` (nuclei-templates dual-home pattern) — otherwise `gf` matches nothing.
- **Static trusted resolvers** → `/usr/share/resolvers.txt`; puredns/dnsx templates default to it. (dnsvalidator can refresh it only where there's egress.)
- **Permutation wordlists**: point gotator/regulator templates at existing SecLists paths (already baked); no new wordlist blob.

**subwiz:** not installed in the image (option 1). Runs in engagement/`:kali` at runtime where egress exists.

## 6. Component 3 — KB methodology + composer grounding

- **Two `checklist`-shaped KB entries** (shape already defined in `pipeline/ingest_corpora.py`: "an ordered sequence of checks"):
  1. **External subdomain enumeration ordering** — passive → CT → ASN/CIDR → permutations → mass-resolve+wildcard-filter → NOERROR → scraping (TLS/CSP) → recursive → reverse-IP.
  2. **URL → gf-triage → fuzz pipeline** — harvest (gau/wayback/katana) → dedup → gf-pattern classify → qsreplace → targeted dalfox/nuclei-dast/sqlmap.
  Each attributes the ordering to reconFTW.
- **Additive ingester** (new, small; mirrors `ingest_corpora.py` discipline): owns only its own lines via a `meta` marker, copies every other line through as **raw bytes** (no JSON round-trip), idempotent (re-run → byte-identical, asserted by a test). Never rewrites an existing entry. Provides `--dry-run`.
- **Composer recon-ordering note**: a short advisory paragraph added to the orchestrator recon prompt encoding the sequence. **Advisory only — still one gated command at a time; no auto-chaining.**

## 7. Verification

1. `test_arsenal.py` + `test_arsenal_safety.py` green (catalog schema + safety).
2. New ingester: `--dry-run`, then real run; re-run byte-identity assertion; KB entry retrievable via search.
3. `sh backend/run_safety_tests.sh` — the 4 safety gates stay green.
4. Frontend `/arsenal` still builds/renders the new category (spot check).
5. **Image build (background):** the ~8–10 GB cold rebuild + per-tool smoke tests is the real proof for Component 2. Kicked off in the background; results reported when done. (Defender/AV note: watch for KB-file quarantine per prior incidents.)

## 8. Risks / open caveats

- Some Go tools may not be in kali-rolling → they fall back to pinned binaries; build verifies, doesn't assume.
- Token-gated OSINT tools (github/gitlab-subdomains, gitdorks_go) are catalogued with a note; absence of a token is a runtime limitation, not a build failure — same posture as reconFTW.
- Image size grows modestly (mostly small Go binaries + gf-patterns); no large model blobs (subwiz excluded).
- No safety-model surface changes; the only executable-capability change is additional tools in the sandbox, gated identically to the existing 63.
