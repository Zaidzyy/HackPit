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
