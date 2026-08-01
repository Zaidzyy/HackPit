# 0xdf fingerprint corpus — batch 4 manifest

Source: **0xdf hacks stuff** — https://0xdf.gitlab.io  (personal HTB/CTF writeup blog, GitLab Pages)
Fetched: 2026-08-01.  robots.txt: 404 (no restrictions published) — honoured.  Delay: 1.8s serialised.
Fetcher: `pipeline/fetch_0xdf.py` (sitemap + the site's own /tags/ index; never crawled).

Policy: **distil, never parrot** (D-entry this batch). Each entry below was learned from the
credited writeup and written from scratch from the technique + the public CVE; the writeup URL
is in the entry's `references`. Raw pages fetched to `sources/0xdf/` (gitignored) and deleted.

## Scope
- Index: **614 posts / 3,981 tags** pulled in 2 requests. 276 distinct CVE tags; **175 of them
  never appeared anywhere in the KB** before this batch — a different signal from the cert notes.
- Prioritised subset: **55 posts**, scored by (network-service tags ×3 + thin-category tags ×2
  + KB-absent CVEs ×4 − web-app tags). All 55 fetched, 0 failures.
- Windows Defender deleted 5 of 58 files mid-triage (OSError 22→2); triage tolerated it, re-fetched.

## Yield: **19 entries from 12 posts** (hackpit-distilled 78 → 97)
Thin categories moved: services, pivoting, credentials, persistence, reversing/privesc.

### Posts that produced an entry
- https://0xdf.gitlab.io/2021/06/19/htb-tentacle.html
    - opensmtpd MAIL FROM (CVE-2020-7247)
    - squid CONNECT pivot
- https://0xdf.gitlab.io/2021/02/20/htb-feline.html
    - saltstack master auth-bypass (CVE-2020-11651)
    - tomcat FileStore deser (CVE-2020-9484)
- https://0xdf.gitlab.io/2020/12/19/htb-laser.html
    - solr velocity RCE (CVE-2019-17558)
- https://0xdf.gitlab.io/2021/10/09/htb-monitors.html
    - ofbiz XML-RPC deser (CVE-2020-9496)
    - cacti graph_realtime SQLi (CVE-2020-14295)
- https://0xdf.gitlab.io/2022/05/03/htb-antique.html
    - cups ErrorLog read (CVE-2012-5519)
    - printer 9100/PJL+SNMP cred leak
- https://0xdf.gitlab.io/2022/04/02/htb-shibboleth.html
    - mariadb wsrep RCE (CVE-2021-27928)
    - ipmi RAKP hash leak
- https://0xdf.gitlab.io/2021/05/15/htb-ready.html
    - gitlab SSRF->redis RCE (CVE-2018-19571)
- https://0xdf.gitlab.io/2021/05/08/htb-attended.html
    - vim modeline RCE (CVE-2019-12735)
- https://0xdf.gitlab.io/2021/02/13/htb-jewel.html
    - rails cache Marshal deser (CVE-2020-8165)
- https://0xdf.gitlab.io/2025/12/06/htb-editor.html
    - xwiki SolrSearch groovy (CVE-2025-24893)
    - netdata ndsudo PATH (CVE-2024-32019)
- https://0xdf.gitlab.io/2023/07/29/htb-cerberus.html
    - firejail --join privesc (CVE-2022-31214)
    - manageengine SAML RCE (CVE-2022-47966)
- https://0xdf.gitlab.io/2026/07/25/htb-fries.html
    - pgadmin Query Tool RCE (CVE-2025-2945)

### The other 43 shortlisted posts produced nothing
Their standout CVE/technique was already in the KB (verified by CONCEPT grep — synonyms, tool
names, technique words — not the token, per batch 2's correction). Examples confirmed already
present: runc fd-leak escape (via cred-toctou), Azure AD Connect decrypt, fail2ban, vm2 escape,
Office/RTF CVE-2017-0199, polkit CVE-2021-3560, Craft/Openfire/Jenkins-CLI CVEs, rsync 873.
One candidate (CrushFTP / htb-soulmate) was DROPPED because Defender deleted the page twice and
the rule is: if you cannot read it, do not write it.

---

# Pass 2 — the remaining novel-CVE service footholds (2026-08-01)

Run after the two gating sessions landed: `dcbf5dd` (the eval that measured the corpus half-firing)
and `6c3ba42` (both defects fixed at the predicate). Retrieval now works, so pass-2 entries fire.

## Scope
- Re-pulled the index in 2 requests (614 posts / 3,422 tags). Of 276 CVE tags, **158 are still
  absent from the current KB** (down from 175 pre-pass-1: pass-1's 19 closed part of the gap).
- Shortlisted **58 posts** by current-KB-absent CVE, service-weighted, excluding pass-1's 12
  productive posts. (Pass-1's full 55-post shortlist could not be reproduced exactly — it was
  scored against the pre-pass-1 KB and the gitignored list was deleted — so a few pass-1-examined
  posts recur; concept-grep against the current KB, which now holds pass-1's 19, is the gate that
  catches any already-covered overlap.)
- Windows Defender deleted the **same 7 of 58 pages** on every fetch (scavenger, schooled, pandora,
  vessel, hospital, mist, soulmate — their content matches a Defender signature); tolerated,
  re-fetched 3×, they stay gone → **51 posts analysed**, recorded and moved on per the pass-1 rule.

## Yield: **8 entries from 8 posts** (hackpit-distilled 97 → 105; KB 2,733 → 2,741)
Every candidate concept-grepped (synonyms/tool/technique, not the CVE token) against the current KB
first; the grep killed the large web-CMS majority as already-covered (SSTI/SQLi/Craft/etc.) and
these 8 versioned-service footholds survived:

- https://0xdf.gitlab.io/2021/03/17/htb-optimum.html — Rejetto HFS 2.3 null-byte macro RCE (CVE-2014-6287)
- https://0xdf.gitlab.io/2020/05/28/htb-grandpa.html — IIS 6.0 WebDAV ScStoragePathFromUrl overflow (CVE-2017-7269)
- https://0xdf.gitlab.io/2023/07/29/htb-cerberus.html — Icinga Web 2 file-read → RCE (CVE-2022-24716/-24715)
- https://0xdf.gitlab.io/2022/05/28/htb-admirertoo.html — OpenTSDB Gnuplot param injection RCE (CVE-2020-35476)
- https://0xdf.gitlab.io/2025/01/11/htb-sightless.html — SQLPad nunjucks template-injection RCE (CVE-2022-0944)
- https://0xdf.gitlab.io/2021/10/30/htb-explore.html — ES File Explorer open port 59777 file read (CVE-2019-6447)
- https://0xdf.gitlab.io/2026/01/10/htb-previous.html — Next.js middleware auth bypass (CVE-2025-29927)
- https://0xdf.gitlab.io/2022/02/05/htb-horizontall.html — Strapi unauth reset → authed RCE (CVE-2019-18818/-19609)

Note Cerberus recurs from pass 1: pass 1 wrote firejail + ManageEngine from it and left Icinga
unwritten — concept-grep confirmed `icinga` was a genuine gap, so it was written now.

## Where the rows land, measured (not where they thematically belong)
All 8 landed in `category="writeup"` (192 → 200), which `ingest_exploitation_writeups.py` forces as
part of its `no_merge` discipline. The thin categories (`services` 9, `pivoting` 8) did NOT move —
same as pass 1. The entries still fire because 2.7 keys on `meta.fingerprint`, not category. Whether
`writeup` is the right category for discoverability is a standing open question, not changed here.

## Rate + recommendation
Pass 1: 19 entries / 12 productive posts of 55. Pass 2: **8 entries / 8 posts of 51** — a declining
but not collapsed tail. Combined 0xdf: **27 fingerprints**. The remaining unfetched novel-CVE posts
skew heavily to web-CMS boxes whose bug the KB's 636 web entries already cover, so the
fingerprint-shaped (versioned network-service) tail is nearly exhausted. **Recommend closing 0xdf as
a fingerprint source after this pass**; a pass 3 would likely yield <5 and only web-app entries.

Verified: per-source diff (only hackpit-distilled +8, no source lost a row); entries.jsonl +
embeddings.npy + ids.json all present; all 8 fire on scanner-format banners; **UNCOVERED false-fire
held at 20% (3/15), zero delta** — the 8 entries did not worsen the version-less substring-fallback
residual; safety suite 54 files all green (the self-match lock now validates all 105 fingerprints).
