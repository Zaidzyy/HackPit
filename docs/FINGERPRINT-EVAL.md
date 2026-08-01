# Does the fingerprint corpus make the proposer sharper? — a measurement

*2026-08-01. Measurement session: not one KB entry or line of `retrieval.py` was changed.
Every number below comes from the real production path
(`orchestrator._fingerprint_reference` → `reasoning.retrieval.retrieve`), driven against the
live KB (2,704 retrievable rows, 97 `hackpit-distilled` fingerprints). Ollama up; hybrid and
lexical both measured.*

## The one-paragraph answer

The fingerprint layer **works when it fires** — 90% precision on a covered hit, **0% false-fire on
near-miss versions** (the version verdict correctly refuses an out-of-range exploit, which is the
dangerous failure it exists to prevent), and when it fires it flips the local LLM from a confident
*hallucinated* CVE to the exact right one. **But it fires far less often than its size implies,
because of two structural defects that suppress it independently of how many entries the corpus
holds** — and both hit the 19 new 0xdf entries exactly as hard as the old ones. Until they are
fixed, **a second 0xdf pass is not worth running**: new fingerprints inherit the same suppression.
The corpus is not inert, but it is running at roughly half its reachable hit rate on realistic
scanner output.

---

## The two defects, corpus-wide and deterministic

### D-A. `lte` / `range` fingerprints cannot match their own stored boundary version — 35 of 97

`reasoning/retrieval.py` range-matches versions through `exploits/index.py::_version_verdict`.
For `lte` that verdict is `_cmp_versions(q_ver, bound) < 0` (index.py:264) and for `range` it is
`q >= lo and q < hi` (index.py:270) — **half-open, exclusive of the top version**, because the
CVE→exploit index stores `versions[-1]` as the *fix boundary* (the first **patched** release).

The fingerprint corpus populates `versions` with the opposite convention: the **last vulnerable**
version. `opensmtpd lte ['6.6.1']` means "6.6.1 is vulnerable" (CVE-2020-7247 is fixed in 6.6.2);
`cups lte ['1.6.1']`, `gitlab lte ['13.10.3']`, `solr range ['5.0.0','8.3.1']` all store the
vulnerable release as the endpoint. Two subsystems share one verdict function with **opposite
conventions for what `versions[-1]` means.**

Consequence, measured by feeding every fingerprint its own stored boundary version through the real
reranker:

| kind | matches its own boundary version |
|---|---|
| exact (3) | 3/3 |
| none (59) | 59/59 |
| **lte (25)** | **0/25** |
| **range (10)** | **0/10** |
| **total** | **62/97 — 35 cannot match their own stored version** |

Every `lte` and every `range` fingerprint — including all the version-bearing 0xdf entries
(cups, opensmtpd, gitlab, solr, tomcat, netdata, pgadmin, xwiki, vim, firejail, rails, saltstack,
cacti) — **misses on a scan reporting exactly the version the entry was written about**, which is
the single most common precise hit. It still fires for a version strictly *below* the boundary
(Netdata 1.44.0 fires against `lte 1.45.2`), so the defect is silent — it degrades the most
important case while leaving the feature apparently working.

This is conservative (it errs toward *not* firing, so it never causes a false exploit), which is
why near-miss false-fire is 0% — but it is why hit rate is capped.

### D-B. `fingerprint()` collapses a vendor-prefixed product to the vendor — ≥6 corpus families unreachable

`fingerprint()` (retrieval.py:29) takes the **first meaningful token** of the product string and
de-aliases it. Real `nmap -sV` product strings are frequently vendor-prefixed, and the vendor is
the first token:

| nmap product string | → fingerprint head | keyed service | fires? |
|---|---|---|---|
| `Apache Tomcat` / `Apache Tomcat/Coyote JSP engine` | `apache` | tomcat | **no** |
| `Apache Solr` | `apache` | solr | **no** |
| `Apache log4j` | `apache` | log4j | **no** |
| `Microsoft SQL Server 2022` | `microsoft` | mssql | **no** |
| `Microsoft Exchange` | `microsoft` | exchange | **no** |
| `Oracle WebLogic` | `oracle` | weblogic | **no** |
| `Atlassian Confluence` | `atlassian` | confluence | **no** |
| `Apache httpd` | `apache` | apache | yes |
| `nginx`, `OpenSSH`, `vsftpd`, `MariaDB`, `Redis…` | (self) | — | yes |

Demonstrated directly with plain-vs-prefixed contrast pairs (identical version, same KB):

```
Tomcat      9.0.30 -> tomcat/9.0.30      FIRES
Apache Tomcat 9.0.30 -> apache/9.0.30    MISS
Confluence  7.13.0 -> confluence/7.13.0  FIRES
Atlassian Confluence 7.13.0 -> atlassian/7.13.0  MISS
log4j       2.14.1 -> log4j/2.14.1       FIRES
Apache log4j 2.14.1 -> apache/2.14.1     MISS
```

The `iis → microsoft-iis` alias is itself defeated the same way (`Microsoft IIS httpd` → head
`microsoft`), surviving only because `microsoft` is a substring of `microsoft-iis`. `mssql`,
`exchange`, `weblogic` are not substrings of their vendor token, so they fail outright. Six corpus
service families (tomcat ×2 entries, exchange ×2, solr, mssql, weblogic, confluence) are
effectively unreachable from their standard scanner banner no matter how good the entry is.

---

## Level 1 — the test-set metrics

Three groups, versions drawn from the entries' own `meta.fingerprint` ranges, products written the
way `nmap -sV` emits them. `hybrid` and `lexical` gave **identical** results on every metric — the
exploit-writeup entries carry strong lexical signal, so vector search is not the variable here.

### COVERED (30 real service+version strings the corpus claims)

| metric | value | meaning |
|---|---|---|
| hit rate (fires at all) | **21/30 = 70%** | how often a fingerprint fires when it should |
| precision (fired → top hit is right) | **19/21 = 90%** | when it fires, it's usually the right entry |
| correct / total | 19/30 = 63% | end-to-end useful-fire rate |
| **format-mismatch misses** | **8** | in base top-5 but `fingerprint()` won't match (D-B + D-A boundary) |
| base-recall misses | 2 | fingerprint *would* match, but the base search didn't surface the entry in top-5 |

The 2 base-recall misses (`sudo 1.9.5`, `Jenkins 2.121`) are a distinct, smaller issue: the
reranker only ever sees the base retriever's top-5 (`_resilient_search(q,5)` with `limit=2`), so an
entry the token/vector search ranks 6th or lower can never be floated even when its fingerprint is a
perfect match. Enlarging the base window would recover these.

### NEAR-MISS (15 — same product, version OUTSIDE the range)

| metric | value |
|---|---|
| **false-fire rate** | **0/15 = 0%** |

The single most important safety number, and it is clean: not once did the corpus point the operator
at an exploit for a version outside the vulnerable range (patched Apache 2.4.52, OpenSSH 8.2p1,
log4j 2.17.1, Solr 9.4.0, sudo 1.9.15, …). The version verdict is doing its job.

### UNCOVERED (15 — services the corpus does not claim)

| metric | value |
|---|---|
| false-fire rate | **3/15 = 20%** |

Three false positives — `Pure-FTPd`→`pure`, `Node.js Express framework`→`node.js`,
`MinIO object storage`→`minio` — all share one cause: they were **version-less** banners, and the
non-structured substring fallback in `rerank()` (retrieval.py:137, `has_product and not version`)
fires whenever the product token appears anywhere in a KB entry's text. With a version present the
fallback requires both product *and* version, so this is confined to version-less products whose
name is a common substring. Minor, but real: the block can surface an unrelated entry as a
"fingerprint match" for a service the corpus never covered.

---

## Level 1c — the ablation: what did the 19 0xdf entries buy?

Same 30-item COVERED set, re-run with the 19 0xdf-sourced entries filtered out in memory (identified
by a `0xdf` URL in `references`; the KB file was never touched).

| metric | full corpus (97) | 0xdf excluded (78) | delta |
|---|---|---|---|
| COVERED correct | 19/30 (63%) | 13/30 (43%) | **+6 correct fires** |
| precision | 90% | 87% | ~0 |
| near-miss false-fire | 0% | 0% | 0 |
| uncovered false-fire | 20% | 20% | 0 |

The batch-4 contribution is **additive and clean**: the 6 services it newly covers and that fire
(pgAdmin, Netdata, XWiki, Vim, Firejail, Squid) go from miss to correct, and **no pre-existing
fingerprint was displaced or degraded** — the 13 old fires are identical with or without the new
entries. So the 19 entries measurably improved coverage **in exact proportion to the services they
added, for the cases the two defects don't suppress**. They did **not** change the *rate* at which
the corpus fires: cups and opensmtpd (both 0xdf) miss their boundary versions, solr misses via both
D-A and D-B — the new entries are hobbled by the same two defects as the old ones.

---

## Level 2 — illustration (small, noisy, not a number)

The real grounding block from `_fingerprint_reference`, then llama3.1:8b asked to name the single
most likely CVE for the exact service+version, with and without the block.

| service | fired? | LLM **without** grounding | LLM **with** grounding |
|---|---|---|---|
| pgAdmin 8.5 | yes | *CVE-2021-3920* (invented) | **CVE-2025-2945** (correct) |
| Netdata 1.44.0 | yes | *CVE-2022-30594* (invented) | **CVE-2024-32019** (correct) |
| Apache Tomcat 9.0.30 | **no (D-B)** | *CVE-2021-30154* (invented) | — (no block produced) |

When the fingerprint fires it converts a confident hallucination into the right answer — that is the
whole value of the feature, and it is real. The Tomcat row is the point of the whole eval: it is
exactly the case where grounding would have helped most, and the normalization defect denies it,
leaving the model with an invented CVE.

---

## Recommendation

**Fix the two defects before writing a single additional fingerprint.** They cap the effective hit
rate independent of corpus size, so every new entry — 0xdf pass #2 or otherwise — inherits the same
suppression. In descending value:

1. **Reconcile the `lte`/`range` boundary convention (D-A).** Highest impact by far: it unlocks
   **35 of 97** fingerprints on their own canonical version, including 13 of the 19 batch-4 entries.
   Either store the *fix* version in the corpus (so `versions[-1]` means what `_version_verdict`
   already assumes) or give the fingerprint path an inclusive verdict. A measurement session does not
   pick which — but note that changing the verdict touches the CVE index's convention too, so the
   lower-blast-radius fix is in the corpus data.
2. **Fix `fingerprint()` product normalization (D-B).** Don't collapse `Apache Tomcat` → `apache`.
   Walk the product tokens and prefer one that matches a known corpus service key, or de-prefix a
   known vendor set (`apache`, `microsoft`, `oracle`, `atlassian`, `eclipse`) when a later token is
   the real product. Unlocks ≥6 service families off their standard nmap banner.
3. **(Minor) Tighten the version-less substring fallback** to remove the 20% uncovered false-fire,
   and **widen the base-retriever window** past top-5 so a perfect fingerprint isn't lost to token
   rank (2 of the covered misses).

**Then** a second 0xdf pass is worth running — the source is proven to supply the right shape and
the grounding proven to sharpen the model. **Until then it is not**, because the marginal entries
fire at the same suppressed rate as the ones already there. The verdict on batch 4 specifically: it
paid for itself on the services it covers, but the corpus's ceiling is set by the plumbing, not by
its size — which is the single most useful thing this session found.

---

*Verification: `sh backend/run_safety_tests.sh` → 52 files, all exit 0. KB unchanged
(2,733 rows on disk, 2,704 after `filter_excluded`; no ingester or embed run this session).
Measurement harness used `reasoning.retrieval.retrieve` and `pipeline/search.py` directly — the
same functions the loop calls — never a reimplementation.*

---

# After the fix (2026-08-01)

*The two defects above are fixed. No KB entry was added or changed — the fixes are entirely in the
matcher (`reasoning/retrieval.py`, `exploits/index.py`). Same test set, same real code path, so the
delta is attributable to the plumbing alone.*

## What changed

* **D-A — the shared predicate now names its boundary convention explicitly.** `_version_verdict`
  took an `inclusive` argument: `False` (exclusive `<`, the CVE→exploit index's fix-version
  convention — its default and historical behaviour) or `True` (inclusive `<=`, the fingerprint
  corpus's last-vulnerable convention). Every caller now states which it means —
  `exploits.index.search_service` and `reasoning.critic` pass `inclusive=False`,
  `retrieval._structured_match` passes `inclusive=True` — so **neither relies on an implied
  default**. This is option (a) from the eval: it stops the bug recurring instead of papering over
  the 35 entries, and it honours the `lte` kind name as the `<=` it literally reads.
  **The CVE→exploit index is provably unchanged:** every one of its **110,695 verdicts across
  47,108 entries** is byte-identical before and after (full snapshot diff), and `test_exploits.py`
  stays green.
* **D-B — `fingerprint()` resolves the product, not the vendor.** It drops generic descriptors
  (`httpd`, `server`, `engine`…) and numeric edition tokens, then — if the first specific token is
  an umbrella vendor and a product token follows — takes the product (`Apache Tomcat` → `tomcat`,
  `Oracle WebLogic` → `weblogic`), while a vendor followed only by a descriptor stays the vendor
  (`Apache httpd` → `apache`). The vendor set is small and stable; the **collision regression test
  is the real guard**, and it already earned its keep — it flagged `ISC BIND` → `isc` mid-session,
  which added `isc` to the vendor set (BIND is the product, ISC the org).

## The measured delta — same test set as the baseline

| metric | baseline | after fix |
|---|---|---|
| COVERED hit rate | 70% (21/30) | **93% (28/30)** |
| COVERED precision when firing | 90% | **96% (27/28)** |
| COVERED correct / total | 63% | **90% (27/30)** |
| **exact-boundary versions fire** (the D-A core) | **0/4** | **4/4** |
| **NEAR-MISS false-fire** | 0% | **0% (0/15)** — held |
| NEAR-MISS *just above* the boundary | — | **0/3** — inclusive means `==`, not looser |
| UNCOVERED false-fire | 20% | 20% — unchanged (separate cause, below) |
| corpus-wide: fingerprints matching their own stored version | 62/97 | **97/97** |

The safety number held: **inclusive `<=` at the exact boundary is the whole of the change** — a
version one step above the boundary (`CUPS 1.6.2`, `OpenSMTPD 6.6.2`, `Solr 8.3.2`) still does not
fire (0/3), so the matcher did not get looser, only correct at the boundary. Near-miss stayed 0%.

## What the fix did NOT address (and why)

Two residuals remain, both **outside D-A/D-B** and left deliberately so the improvement stays
attributable:

* **UNCOVERED false-fire still 20%** (`Pure-FTPd`→`pure`, `Node.js Express`→`node.js`,
  `MinIO`→`minio`). All three are *version-less* banners caught by the non-structured **substring
  fallback** in `rerank()`, a different code path from the vendor-normalisation this session fixed.
  It did not get worse. A follow-up should require a stronger signal than a bare product substring
  for a version-less query.
* **2 of the 30 COVERED still miss** (`sudo 1.9.5`, `Jenkins 2.121`) — the fingerprint matches, but
  the base retriever (`_resilient_search(q,5)`, `limit=2`) never surfaced the entry in its top-5, so
  the reranker never saw it. Widening the base window past top-5 recovers these. A retriever-recall
  issue, not a fingerprint one.

## Regression locks added

Two tests, wired into `run_safety_tests.sh` (52 → 54 files, all green), each iterating the **real**
corpus and carrying a positive control that proves it can fail:

* `test_fingerprint_versions.py` — every `meta.fingerprint` row in the live KB must match its own
  stored version(s); 97 fingerprints / 49 exact-lte-range checks. Control: a planted out-of-range
  version must be rejected *and* the exact boundary accepted.
* `test_fingerprint_norm.py` — 16 real `nmap -sV` banners each resolve to the product not the
  vendor, and no two distinct products share a key (`Apache Tomcat` ≠ `Apache httpd`). Control: a
  reintroduced first-token normaliser is caught (verified by monkeypatch — it fails as it must).

## Recommendation, updated

The plumbing ceiling the baseline identified is lifted: the corpus now fires on **93%** of covered
banners at **96%** precision with **0%** dangerous false-fire, and every fingerprint matches its own
version. **A second 0xdf pass is now worth running** — new entries will fire at the fixed rate, not
the suppressed one. The two residuals (substring fallback, base-retriever window) are worth a small
follow-up but neither blocks growing the corpus.

*Verification: `sh backend/run_safety_tests.sh` → **54 files, all exit 0** (52 + the two new locks).
CVE→exploit index proven unchanged (110,695/110,695 verdicts identical). KB untouched. Same harness
as the baseline — `reasoning.retrieval.retrieve` + `pipeline/search.py`, never a reimplementation.*

---

# The last residual, closed (2026-08-01)

*The two fixes above left one known gap named but unfixed: **20% false-fire on UNCOVERED services**,
stable across the corpus's growth (0xdf pass 2 re-measured it at exactly 20% after adding 8 entries).
This session closed it. No KB entry changed — the fix is entirely in `reasoning/retrieval.py`.*

## What it was, measured before touching it

The residual was a **different code path** from the structured matcher (`_structured_match`, now
correct). It was the *version-less substring fallback* in `rerank()`: a plain (non-structured) entry
matched when the scanned product merely appeared as a substring anywhere in its blob — `product in
blob` — and that hit was marked `fingerprint_match=True`, the same field the grounding line filters
on to make its "this exact stack was solved by X" claim. So `Pure-FTPd` (`pure`), `Node.js`
(`node.js`) and `MinIO` (`minio`) each surfaced a precise-looking pointer to an unrelated entry.

Before changing anything, the eval was instrumented to classify each covered fire as **structured**
(a real `meta.fingerprint` match) vs **fallback** (the substring path):

```
COVERED fires: 28 STRUCTURED, 0 FALLBACK
UNCOVERED false-fires: 3, ALL FALLBACK
```

That settled the design question the fix had to answer honestly — *is the fallback doing real work?*
**It contributes 0 of the 28 covered fires** (every covered banner matches a structured fingerprint),
and it is the **whole** of the false-fire. So this is not a stricter-matcher-vs-hit-rate trade-off:
demoting the fallback costs nothing on covered and removes the entire residual.

## The fix — reserve `fingerprint_match` for structured hits

`fingerprint_match=True` is now set **only** by a structured `meta.fingerprint` match. An unstructured
product-name hit becomes a distinct, lower-ranked `fallback_match` (new field on `Ranked`): it still
ranks above pure token matches (so a version-less scan keeps *some* signal, which is legitimate), but
it never claims the exact stack, so the grounding line — whose only consumer, `orchestrator.py:395`,
filters on `fingerprint_match` — stops over-claiming. The fallback substring was also tightened to a
**word boundary**, so a product token no longer fires on any word that merely contains it (`pure`
inside `purely`). The fallback was **not deleted** — the prompt's caution, and the measurement,
agree: it is kept and labelled honestly rather than removed.

## The measured delta — same three groups, all six metrics

| metric | before | after | bar |
|---|---|---|---|
| **UNCOVERED false-fire** | 20% (3/15) | **0% (0/15)** | materially lower ✓ |
| COVERED hit rate | 93% (28/30) | **93% (28/30)** | must not drop ✓ |
| precision when firing | 96% | **96%** | must not drop ✓ |
| NEAR-MISS false-fire | 0% | **0%** | must stay 0% ✓ |
| corpus self-match | 105/105 | **105/105** | must stay 105/105 ✓ |
| fire above boundary | 0/45 | **0/45** | must stay 0/45 ✓ |

No metric regressed. This is a clean removal of the residual, not one defect traded for another.

## Regression lock

`test_fingerprint_fallback.py`, wired into `run_safety_tests.sh` (54 → **55 files**, all green):
iterates the live corpus plus 15 real uncovered services and asserts none get a structured
fingerprint claim from the fallback. Positive controls: a covered service (`vsftpd 2.3.4`) still
produces a structured match; a planted unstructured `MinIO` entry is a `fallback_match` not a
`fingerprint_match`; and `pure` inside `purely` matches neither. Verified can-fail by monkeypatching
the old fallback-as-fingerprint behavior back — the test fails, as it must.

*This is the last known correctness gap in the 2.7 path. `sh backend/run_safety_tests.sh` → 55 files,
all exit 0. KB untouched; same harness as every table above.*
