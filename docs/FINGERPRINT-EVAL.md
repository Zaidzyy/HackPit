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
