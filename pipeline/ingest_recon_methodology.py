"""Fold reconFTW's recon *ordering* into the KB as two checklist entries.

reconFTW (six2dez, MIT) is an autonomous external-recon runner. HackPit does not adopt
its auto-runner — every command still goes through the one gated executor, approved one at
a time. What is worth mining is its *methodology*: the order in which recon steps pay off.
This ingester captures that ordering as two ``checklist`` entries (§4.4 — "a checklist is a
sequence, meaningful in order"), citing only tools HackPit actually catalogues.

Discipline mirrors ``ingest_corpora.py``:

1. **Additive + byte-preserving.** Existing lines are copied through as raw bytes and never
   JSON round-tripped, so no other entry can drift by a key order or an escape.
2. **Idempotent.** Every line this ingester owns carries ``meta.recon_methodology``. A re-run
   drops exactly those lines and regenerates them from source, so running twice yields a
   byte-identical file.
3. **Own marker.** ``recon_methodology`` is distinct from ``corpus_ingest`` (the payload/dork
   corpora), so the two ingesters never touch each other's lines.

Embeddings are NOT rebuilt here: ``search.vector_ranking`` maps vectors to entries by id, so
new ids simply aren't in the vector space yet (no misalignment) — the entries are retrievable
lexically (BM25) immediately. Run ``python pipeline/embed.py`` to add them to the vector space.

Run::

    python pipeline/ingest_recon_methodology.py --dry-run
    python pipeline/ingest_recon_methodology.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # local: schema.py lives beside this file
from schema import Entry  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
KB_PATH = REPO_ROOT / "data" / "kb" / "entries.jsonl"

MARK = "recon_methodology"
SOURCE = "reconftw"
SOURCE_LABEL = "reconFTW (six2dez, MIT) — methodology only, not its auto-runner"


def _meta(kind: str) -> dict:
    return {
        MARK: True,          # ownership / idempotency marker (distinct from corpus_ingest)
        "kind": kind,
        "no_merge": True,    # an ordering is a sequence; never let consolidate fold it away
        "source_label": SOURCE_LABEL,
        "attribution": "Ordering distilled from reconFTW's module pipeline (MIT-licensed).",
        "origin": "reconftw-assessment",
    }


def _entries() -> list[Entry]:
    subdomain = Entry(
        id="recon-methodology-subdomain-enumeration",
        title="External subdomain enumeration — the ordering (reconFTW methodology)",
        category="recon",
        subcategory="subdomain-enumeration",
        source=SOURCE,
        tier=2,
        tags=["recon", "subdomain-enumeration", "osint", "methodology", "reconftw",
              "attack-surface", "dns"],
        tools=["subfinder", "amass", "github-subdomains", "gitlab-subdomains", "asnmap",
               "mapcidr", "gotator", "regulator", "subwiz", "puredns", "massdns", "dnsx",
               "tlsx", "csprecon"],
        summary=(
            "The order external subdomain enumeration pays off: passive sources first, then "
            "certificate transparency, ASN→CIDR expansion, permutations, mass-resolve with "
            "wildcard filtering, NOERROR discovery, web-metadata scraping, recursion and "
            "reverse-IP. One gated command at a time — this is advisory ordering, not an "
            "auto-chain."
        ),
        steps=[
            {"n": 1, "text": "Passive sources — collect names from public APIs and code search.",
             "code": [{"lang": "bash", "cmd": "subfinder -d <domain> -all -silent -o subs_passive.txt\ngithub-subdomains -d <domain> -t ~/.tokens/github -o subs_github.txt"}]},
            {"n": 2, "text": "Certificate transparency — CT logs name hosts DNS never resolves publicly.",
             "code": [{"lang": "bash", "cmd": "amass enum -passive -d <domain> -o subs_ct.txt"}]},
            {"n": 3, "text": "ASN → CIDR — on a wide target, map owned ranges (only act inside authorised scope).",
             "code": [{"lang": "bash", "cmd": "asnmap -d <domain> -silent | mapcidr -silent -o ranges.txt"}]},
            {"n": 4, "text": "Permutations — generate candidates from what you already found (gotator/regulator offline; subwiz where there is egress).",
             "code": [{"lang": "bash", "cmd": "gotator -sub subs_all.txt -perm <wordlist> -depth 1 -numbers 3 -mindup -adv -md > perms.txt"}]},
            {"n": 5, "text": "Resolve + wildcard-filter — turn candidates into real hosts with trusted resolvers.",
             "code": [{"lang": "bash", "cmd": "puredns resolve perms.txt -r /usr/share/resolvers.txt --write resolved.txt"}]},
            {"n": 6, "text": "DNS bruteforce — a large wordlist over the apex, wildcard-filtered the same way.",
             "code": [{"lang": "bash", "cmd": "puredns bruteforce <wordlist> <domain> -r /usr/share/resolvers.txt --write brute.txt"}]},
            {"n": 7, "text": "NOERROR discovery — probe for names that return NOERROR even without an A record.",
             "code": [{"lang": "bash", "cmd": "dnsx -l subs_all.txt -silent -o live.txt"}]},
            {"n": 8, "text": "Web-metadata scraping — pull extra hostnames from TLS SANs and CSP headers.",
             "code": [{"lang": "bash", "cmd": "tlsx -l resolved.txt -san -cn -silent | anew resolved.txt\ncsprecon -u https://<target> -d <domain>"}]},
            {"n": 9, "text": "Recursion — repeat passive+permute on the most productive parent domains, then a final resolve. Keep every discovered host inside the authorised scope."},
        ],
        body_md=(
            "# External subdomain enumeration — the ordering\n\n"
            "Distilled from reconFTW's subdomain module (MIT). HackPit does **not** run this as a "
            "chain — each step is a command you approve individually through the gated executor. "
            "The value is the *sequence*: doing these in order compounds (permutations feed the "
            "resolver; the resolver feeds scraping; scraping feeds recursion), and skipping the "
            "wildcard-filtering resolve step is the classic way an enum drowns in false positives.\n\n"
            "1. **Passive** — `subfinder`, `github-subdomains`, `gitlab-subdomains`.\n"
            "2. **Certificate transparency** — `amass -passive` (crt.sh and friends).\n"
            "3. **ASN → CIDR** — `asnmap` → `mapcidr` for wide targets (scope-check every range).\n"
            "4. **Permutations** — `gotator`/`regulator` offline, `subwiz` where there is egress.\n"
            "5. **Resolve + wildcard filter** — `puredns` (over `massdns`) with a trusted resolver list.\n"
            "6. **DNS bruteforce** — `puredns bruteforce` with a large wordlist.\n"
            "7. **NOERROR discovery** — `dnsx`.\n"
            "8. **Web-metadata scraping** — `tlsx` (SANs), `csprecon` (CSP).\n"
            "9. **Recursion + reverse-IP** — repeat on the best parents; resolve once more.\n\n"
            "*Constraint: recon can widen what you can **see**, never what you may **touch** — the "
            "scope model still gates every host.*\n"
        ),
        references=["https://github.com/six2dez/reconftw"],
        meta=_meta("checklist"),
    )

    urltriage = Entry(
        id="recon-methodology-url-triage-fuzz",
        title="URL harvesting → gf triage → targeted fuzzing (reconFTW methodology)",
        category="web",
        subcategory="content-discovery",
        source=SOURCE,
        tier=2,
        tags=["web", "content-discovery", "url-harvesting", "methodology", "reconftw",
              "fuzzing", "javascript"],
        tools=["gau", "waybackurls", "katana", "unfurl", "gf", "qsreplace", "dalfox",
               "nuclei", "sqlmap", "subjs", "jsluice"],
        summary=(
            "Turn a raw URL dump into findings: harvest (gau/waybackurls/katana), dedup, triage "
            "by bug class with gf patterns, inject with qsreplace, then point a targeted scanner "
            "at each class. A parallel JS-mining branch extracts endpoints and secrets. One gated "
            "command at a time."
        ),
        steps=[
            {"n": 1, "text": "Harvest URLs — archived + live crawl.",
             "code": [{"lang": "bash", "cmd": "echo <domain> | gau > urls.txt\nwaybackurls <domain> >> urls.txt\nkatana -u https://<target> -silent >> urls.txt"}]},
            {"n": 2, "text": "Dedup / normalise so the triage set is unique.",
             "code": [{"lang": "bash", "cmd": "sort -u urls.txt | unfurl format %s://%d%p\\?%q | sort -u > urls_uniq.txt"}]},
            {"n": 3, "text": "gf pattern triage — split the dump into per-bug-class candidate lists.",
             "code": [{"lang": "bash", "cmd": "cat urls_uniq.txt | gf xss   > cand_xss.txt\ncat urls_uniq.txt | gf ssrf  > cand_ssrf.txt\ncat urls_uniq.txt | gf sqli  > cand_sqli.txt"}]},
            {"n": 4, "text": "Inject payloads into the parameter values with qsreplace.",
             "code": [{"lang": "bash", "cmd": "cat cand_xss.txt | qsreplace '\"><svg onload=alert(1)>' > fuzz_xss.txt"}]},
            {"n": 5, "text": "Targeted scanning — one scanner per class, over its candidate list only.",
             "code": [{"lang": "bash", "cmd": "cat cand_xss.txt  | dalfox pipe\nnuclei -l cand_ssrf.txt -dast\nsqlmap -m cand_sqli.txt --batch"}]},
            {"n": 6, "text": "JS-mining branch — discover JS, then extract endpoints and secrets.",
             "code": [{"lang": "bash", "cmd": "cat urls_uniq.txt | subjs | tee js.txt | jsluice urls\njsluice secrets js.txt"}]},
        ],
        body_md=(
            "# URL harvesting → gf triage → targeted fuzzing\n\n"
            "Distilled from reconFTW's web module (MIT). HackPit already had the harvesters "
            "(`gau`, `waybackurls`, `katana`) and scanners (`dalfox`, `nuclei`, `sqlmap`); what was "
            "missing was the **triage step in the middle** that makes them efficient — and the JS "
            "mining branch. This is advisory ordering: every command still goes through the gated "
            "executor one at a time.\n\n"
            "1. **Harvest** — `gau` + `waybackurls` (archived) + `katana` (live crawl).\n"
            "2. **Dedup / normalise** — `unfurl` + `sort -u`.\n"
            "3. **Triage by bug class** — `gf` pattern packs (`xss`, `ssrf`, `sqli`, `redirect`, `lfi`, …) split the dump into worklists. `gf` needs its pattern packs (baked into the sandbox at `~/.gf`).\n"
            "4. **Inject** — `qsreplace` swaps parameter values for payloads.\n"
            "5. **Scan, per class** — `dalfox` (XSS), `nuclei -dast` (broad), `sqlmap` (SQLi), each over its own candidate list rather than the whole dump.\n"
            "6. **JS mining** — `subjs` finds JS files; `jsluice` extracts endpoints and secrets crawling alone misses.\n\n"
            "*Only run scanners against hosts inside the authorised scope.*\n"
        ),
        references=["https://github.com/six2dez/reconftw"],
        meta=_meta("checklist"),
    )

    return [subdomain, urltriage]


CORPUS_MARK = "corpus_ingest"  # ingest_corpora.py's marker — it always appends its lines LAST


def merge(kb_path: Path, new_entries: list[dict]) -> dict:
    """Drop this ingester's own lines, keep every other line as raw bytes, rebuild.

    Order is the fixed point BOTH ingesters converge on: ``[other lines, our methodology
    lines, the corpus block last]``. ``ingest_corpora.py`` always re-appends its
    ``corpus_ingest`` lines at the end, so if we appended ours after that block the corpora
    ingester's byte-identity test would fail on the next run. Segregating the corpus block to
    the tail here keeps both ingesters idempotent and order-stable against each other.

    Atomic (tmp + os.replace) so a crash mid-write can't truncate the gitignored KB.
    """
    original = kb_path.read_bytes()
    lines = [ln for ln in original.split(b"\n") if ln.strip()]
    mark = MARK.encode()
    corpus_mark = CORPUS_MARK.encode()

    head: list[bytes] = []       # everything that is neither ours nor corpus
    corpus_tail: list[bytes] = []  # the corpus block, kept in its existing (canonical) order
    dropped = 0
    for raw in lines:
        if mark in raw or corpus_mark in raw:  # cheap pre-filter — only parse candidates
            try:
                meta = (json.loads(raw).get("meta") or {})
            except json.JSONDecodeError:
                head.append(raw)
                continue
            if meta.get(MARK):
                dropped += 1
                continue
            if meta.get(CORPUS_MARK):
                corpus_tail.append(raw)
                continue
        head.append(raw)

    added = [json.dumps(e, ensure_ascii=False).encode("utf-8") for e in new_entries]
    payload = b"\n".join(head + added + corpus_tail) + b"\n"

    tmp = kb_path.with_suffix(".jsonl.tmp")
    tmp.write_bytes(payload)
    os.replace(tmp, kb_path)
    return {
        "kb_lines_before": len(lines),
        "kb_lines_after": len(head) + len(added) + len(corpus_tail),
        "existing_kept": len(head) + len(corpus_tail),
        "own_lines_replaced": dropped,
        "own_lines_written": len(added),
        "corpus_block_preserved": len(corpus_tail),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing.")
    args = ap.parse_args()

    entries = [e.model_dump() for e in _entries()]
    ids = [e["id"] for e in entries]

    if not KB_PATH.exists():
        raise SystemExit(f"KB not found: {KB_PATH}")

    if args.dry_run:
        original = KB_PATH.read_bytes()
        present = sum(1 for ln in original.split(b"\n") if MARK.encode() in ln)
        print("DRY RUN — no changes written.")
        print(f"  KB: {KB_PATH}")
        print(f"  would write {len(ids)} entries: {ids}")
        print(f"  existing {MARK} lines that would be replaced: {present}")
        for e in entries:
            print(f"    - {e['id']}  [{e['category']}]  {len(e['steps'])} steps")
        return

    report = merge(KB_PATH, entries)

    # Defender-quarantine trap: the file MUST still be present and countable afterwards.
    after = sum(1 for _ in open(KB_PATH, encoding="utf-8"))
    assert after == report["kb_lines_after"], (
        f"post-write count {after} != expected {report['kb_lines_after']} "
        "(entries.jsonl may have been quarantined — check Windows Defender)"
    )
    print("Merged reconFTW methodology entries into the KB.")
    for k, v in report.items():
        print(f"  {k}: {v}")
    print(f"  ids: {ids}")
    print("  NOTE: embeddings not rebuilt — entries are lexically retrievable now; "
          "run `python pipeline/embed.py` to add them to the vector space.")


if __name__ == "__main__":
    main()
