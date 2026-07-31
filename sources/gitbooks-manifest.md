# External source GitBooks — fetch manifest

The reproducibility record for KB enrichment batches built from third-party GitBook spaces.
**Nothing fetched is ever committed**: `sources/` is gitignored and the fetched tree is
deleted once the batch is triaged. This file is what remains — URL, fetch date, how many
pages the space publishes, how many were actually taken, and what each one yielded.

Fetched with `pipeline/fetch_gitbook.py`: sitemap-driven, `robots.txt` honoured before the
first request, serialised with a 0.6 s delay, honest User-Agent, and pages taken as the
markdown the publisher itself offers at `<url>.md`.

---

## Batch: certification note-spaces — fetched 2026-08-01

Seven spaces. **All seven yielded zero entries.** Two were fetched (one of those only in
part); five were never fetched at all, four because an index-level gate proved them
saturated before a page was requested and one because its operator has opted out of machine
collection.

That is the honest outcome, and it is the outcome the batch was scoped to expect: these are
certification notes, and certification notes are the most duplicated material in this KB.
The KB stood at **2,714 entries before and after** this batch.

| Space | Pages published | Pages fetched | Verdict |
| --- | --- | --- | --- |
| [dev-angelist/ecpptv3-ptp-notes](https://dev-angelist.gitbook.io/ecpptv3-ptp-notes) | 163 | 14 (delta only) | **ZERO** — 75 of its 90 distinct page slugs are shared with the author's own eCPPTv2 space, which is already mined. Only the 15-page delta was fetched: **1,058 words, 0 code blocks, median 23 words/page.** The delta is an Active Directory chapter that has been outlined but not written — `6.1.4-ad-enumeration` is 25 words, `6.1.7-ad-persistence` is 24. |
| [dev-angelist/ecpptv2-ptp-notes](https://dev-angelist.gitbook.io/ecpptv2-ptp-notes) | 77 | 0 | **DUPLICATE of `github.com/dev-angelist/eCPPTv2-PTP-Notes` @ `a543e9167445`**, mined in the repo batch. Confirmed at path level, not by inference: the space publishes `network-security/2.4-1/2.2-pivoting` and `…/2.2-pivoting-1`, byte-identical to the repo paths recorded in `repos-manifest.md` as the source of both authored pivoting entries. Not fetched. |
| [dev-angelist/crtp-notes](https://dev-angelist.gitbook.io/crtp-notes) | 86 | 0 | **ZERO** — index gate. Of 59 slug words, 3 are absent from the KB: `crtp`, and the typos `accross` and `uncostrained`. Not fetched. |
| [team-anonymous/…crtp-notes](https://team-anonymous.gitbook.io/certified-red-team-professional-crtp-notes) | 70 | 0 | **ZERO** — index gate. Of 37 slug words, exactly 1 is absent from the KB: `crtp`. Not fetched. |
| [dudisamarel/crtp-notes](https://dudisamarel.gitbook.io/crtp-notes) | 36 | 0 | **ZERO** — index gate. Of 56 slug words, 2 are absent: `crtp` and the typo `gnereral`. Covers `crtp-methodology`, supplied separately as a subpage and therefore already accounted for. Not fetched. |
| [mqt/oscp-notes](https://mqt.gitbook.io/oscp-notes) | — | 0 | **NOT FETCHED — operator opted out.** Its `robots.txt` carries `Content-Signal: ai-train=no` and a blanket `Disallow: /` for ClaudeBot, GPTBot, CCBot, Google-Extended, Applebot-Extended, Bytespider, Amazonbot and meta-externalagent. `fetch_gitbook.py` refuses the space automatically; the sitemap was never requested. Independently a likely zero — all four OSCP repos in the repo batch yielded nothing. |
| [gokulkarthik/pentesting-checklist](https://gokulkarthik.gitbook.io/pentesting-checklist) | 113 | 113 (full) | **ZERO** — the one space fetched in full, and the one whose hypothesis could not be tested from an index. 20,248 words, 214 code blocks, median 174 words/page. Three independent probes, all negative; see below. |

### The checklist space, in detail — why a 20k-word fetch produced nothing

It was fetched in full deliberately. Its hypothesis was *methodology structure*, not
technique novelty, and a slug-token gate cannot test shape. Three probes, each a different
angle:

1. **Word novelty.** 10 words appear 3+ times and never in the KB. Eight are the author's
   name and lab hostnames (`gokulkarthik`, `gokul`, `bth`, `toffee`, `facdc`, `vmtools`,
   `windowsprivesc`, `endhint`) — the repo batch's exact pattern. The remaining two were
   `setakeownership` and `seshutdownprivilege`.
2. **Both survivors were false positives.** `setakeownership` already has 7 KB hits including
   a dedicated `oscp-setakeownershipprivilege` entry. `seshutdownprivilege` looked like the
   real find — 11 occurrences, 0 in the KB — and it is not: `ex-windows-checking-services`
   step 4 already reads *"Stop the service, check its start mode, reboot if you hold
   SeShutdown"* and carries `shutdown /r /t 0`. Same technique, spelled without the
   `Privilege` suffix. **A token miss is not a coverage miss** — the same trap the repo batch
   recorded, caught here by grepping the concept rather than trusting the diff.
   `ht-service-triggers` additionally covers the harder form of that hinge: starting a
   service without `SERVICE_START` rights, via trigger activation rather than a reboot.
3. **Tool novelty.** 175 distinct leading commands across the 214 code blocks; 10 appear
   nowhere in the KB. All 10 resolve to covered material — PowerView cmdlets (`powerview`:
   47 entries), `rpcclient` subcommands (23), `vshadow.exe` as an alternate shadow-copy
   binary (`diskshadow` 5, `tool-sebackupprivilege`), and a Linux capability string
   (`ht-linux-capabilities`, `checklist-privesc-02-check-linux-capabilities`).

**The structure hypothesis failed too, and that is the finding worth keeping.** The KB
already carries **118 `checklist-*` entries** in exactly this shape — 51 Active Directory,
21 privesc, 21 recon, 19 enumeration, 4 credentials, 2 persistence. gokulkarthik's space is
74 Windows/AD pages, 17 Linux, 5 pivoting and a handful of others. Its pivoting section names
proxychains, ssh port forwarding, ligolo-ng and chisel — the same five primitives the repo
batch catalogued into the arsenal a day earlier, against KB hit counts of 24, 21 and 18.
There is no structural gap for it to fill.

### Two operational notes

* **Windows Defender deleted two fetched pages mid-triage.** `enumeration/ports.md` (8.4 KB
  of port-enumeration commands) went from `OSError 22` to `OSError 2` between two reads, and
  `exploitation/web-attacks/lfi-and-rfi.md` followed. This is the same signature-on-our-own-
  examples behaviour that has deleted `data/kb/entries.jsonl` before, now reaching the
  fetched source tree. Triage was made tolerant of unreadable files rather than retried; 111
  of 113 pages were analysed and the two lost pages are in saturated categories
  (`network-services` 183, `web` 642).
* **GitBook serves `<url>.md` and advertises an `llms.txt` index.** `fetch_gitbook.py` asks
  for that rather than scraping HTML: a third of the bytes, real ```lang fences, no nav
  chrome. A missing page is served as HTTP 200 with a `# Page Not Found` body, so that is
  detected explicitly — otherwise renamed pages land on disk as stubs and get triaged as
  though they were content.
