"""Curation analysis — READ-ONLY.

Scans the built KB and produces a prioritized report of entries that likely
need a human curation pass. It NEVER modifies an entry; it only reads
data/kb/entries.jsonl and writes a report (data/kb/curation_report.json +
curation_report.md). Three flag classes:

  1. outdated   — commands/tech that are deprecated or superseded (old tool
                  versions, retired tools, EOL platforms) per current knowledge.
  2. low-quality— OCR-junk fragments, near-empty stubs, garbled/symbol-soup text.
  3. gap        — common techniques that are MISSING or only THINLY covered.

Findings carry a severity (high|medium|low|info), the entry id/title/category,
and a one-line reason, grouped by category for the readable summary.

Run:  uv run python curate_scan.py
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import consolidate  # canonical_keys, content_len (read-only reuse)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KB = REPO_ROOT / "data" / "kb" / "entries.jsonl"
OUT_JSON = REPO_ROOT / "data" / "kb" / "curation_report.json"
OUT_MD = REPO_ROOT / "data" / "kb" / "curation_report.md"

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# --------------------------------------------------------------------------- #
# 1. OUTDATED / DEPRECATED markers — (regex, severity, reason). Kept
# conservative: only genuinely superseded/EOL things, not merely "old but fine".
# --------------------------------------------------------------------------- #
OUTDATED = [
    (r"\bcrackmapexec\b|\bcme\b", "low",
     "CrackMapExec is archived — superseded by NetExec (nxc)"),
    (r"\bdirbuster\b|\bdirb\b", "low",
     "dirb/DirBuster largely retired — prefer ffuf / feroxbuster / gobuster"),
    (r"\bwfuzz\b", "low", "wfuzz is largely unmaintained — prefer ffuf"),
    (r"\bunicornscan\b", "low", "unicornscan unmaintained — prefer nmap / masscan / rustscan"),
    (r"\bpython2(?:\.\d)?\b|\bpython2\.7\b", "medium",
     "Python 2 is EOL — port to Python 3"),
    (r"\bwmic\b", "medium",
     "wmic is deprecated / removed in current Windows — use PowerShell CIM cmdlets"),
    (r"powershell[^\n]*-version\s*2|\bpowershell\s*v2\b", "low",
     "PowerShell v2 is legacy — assume v5+/pwsh"),
    (r"\bbacktrack\b", "medium", "BackTrack is EOL — use Kali / Parrot"),
    (r"\bkali\s*(?:linux\s*)?20(?:1\d|20)\b", "info", "pinned to a dated Kali release"),
    (r"\bwindows\s*(?:xp|vista|7|8)\b|\bserver\s*200[38]\b|\bwin2k(?:3|8)?\b", "info",
     "targets a legacy Windows version — verify relevance on current targets"),
    (r"\b(?:adobe\s*)?flash\b|\bsilverlight\b|\bjava\s*applet\b", "info",
     "references retired browser tech (Flash / Silverlight / Java applets)"),
    (r"\bsslv2\b|\bsslv3\b|\btls\s*1\.0\b|\btls\s*1\.1\b", "info",
     "references deprecated SSL/TLS versions"),
    (r"\bmd5\b[^\n]{0,20}\bsecure\b|\bsha1\b[^\n]{0,20}\bsecure\b", "low",
     "describes MD5/SHA-1 as secure — both are broken for integrity/auth"),
    (r"\benum4linux\b(?!-ng)", "info",
     "enum4linux — consider enum4linux-ng (actively maintained rewrite)"),
]
OUTDATED = [(re.compile(p, re.I), sev, why) for p, sev, why in OUTDATED]

# --------------------------------------------------------------------------- #
# 3. EXPECTED common techniques — (name, keyword regex). A technique is a GAP
# when no substantial (non-stub) entry covers it, THIN when only a stub does.
# --------------------------------------------------------------------------- #
EXPECTED = [
    ("Kerberoasting", r"kerberoast"),
    ("AS-REP Roasting", r"as[\s-]?rep\s*roast"),
    ("LLMNR/NBT-NS poisoning", r"llmnr|nbt-?ns|responder"),
    ("Pass-the-Hash", r"pass[\s-]the[\s-]hash|\bpth\b"),
    ("Pass-the-Ticket", r"pass[\s-]the[\s-]ticket|\bptt\b"),
    ("DCSync", r"dcsync"),
    ("Golden Ticket", r"golden\s*ticket"),
    ("Silver Ticket", r"silver\s*ticket"),
    ("NTLM relay", r"ntlm\s*relay|ntlmrelayx"),
    ("ADCS (ESC1-8)", r"adcs|esc[1-9]\b|certipy"),
    ("BloodHound", r"bloodhound|sharphound"),
    ("Unconstrained/Constrained delegation", r"delegation"),
    ("SQL injection", r"sql\s*injection|sqli\b"),
    ("XSS", r"\bxss\b|cross[\s-]site\s*scripting"),
    ("SSRF", r"\bssrf\b|server[\s-]side\s*request"),
    ("IDOR", r"\bidor\b|insecure\s*direct\s*object"),
    ("XXE", r"\bxxe\b|xml\s*external\s*entity"),
    ("LFI/RFI", r"file\s*inclusion|\blfi\b|\brfi\b"),
    ("SSTI", r"\bssti\b|template\s*injection"),
    ("Command injection", r"command\s*injection"),
    ("File upload", r"file\s*upload"),
    ("Insecure deserialization", r"deserial"),
    ("Prototype pollution", r"prototype\s*pollution"),
    ("JWT attacks", r"\bjwt\b|json\s*web\s*token"),
    ("OAuth attacks", r"\boauth\b"),
    ("CSRF", r"\bcsrf\b|cross[\s-]site\s*request\s*forgery"),
    ("Open redirect", r"open\s*redirect"),
    ("Subdomain takeover", r"subdomain\s*takeover"),
    ("Request smuggling", r"request\s*smuggling|desync"),
    ("GraphQL attacks", r"graphql"),
    ("SUID privesc", r"suid|-perm\s*-\d*4000"),
    ("sudo privesc / GTFOBins", r"sudo\s*-l|gtfobins"),
    ("Cron privesc", r"\bcron"),
    ("Linux capabilities", r"getcap|capabilit"),
    ("Kernel exploit (DirtyPipe/Cow/PwnKit)", r"dirty(?:cow|pipe)|pwnkit|cve-2021-4034"),
    ("Windows UAC bypass", r"uac\s*bypass"),
    ("AlwaysInstallElevated", r"alwaysinstallelevated"),
    ("Unquoted service path", r"unquoted\s*service"),
    ("DLL hijacking", r"dll\s*hijack"),
    ("Token impersonation (Potato)", r"impersonat|juicy\s*potato|printspoofer|rotten\s*potato"),
    ("Port forwarding / pivoting", r"chisel|ligolo|proxychains|ssh\s*-[lrd]\b|socat"),
    ("Reverse shells", r"reverse\s*shell|/dev/tcp"),
]
EXPECTED = [(n, re.compile(p, re.I)) for n, p in EXPECTED]

STUB_LEN = 300
THIN_LEN = 450
_VOWEL = re.compile(r"[aeiou]", re.I)
_WORD = re.compile(r"[A-Za-z]{4,}")


def _entry_text(e: dict) -> str:
    parts = [e.get("title", ""), e.get("summary", ""), e.get("body_md", "")]
    for s in e.get("steps", []) or []:
        parts.append(s.get("text", "") or "")
        for c in s.get("code", []) or []:
            parts.append(c.get("cmd", "") or "")
    return "\n".join(parts)


def _garble_score(body: str) -> float:
    """Fraction of longish alpha words with no vowel — high => OCR gibberish."""
    words = _WORD.findall(body)
    if len(words) < 20:
        return 0.0
    novowel = sum(1 for w in words if not _VOWEL.search(w))
    return novowel / len(words)


def scan(entries: list[dict]) -> dict:
    findings: list[dict] = []
    seen_outdated: dict[str, set] = defaultdict(set)  # entry id -> reasons

    for e in entries:
        eid, title = e.get("id", ""), e.get("title", "")
        cat = e.get("category", "")
        src = e.get("source", "")
        text = _entry_text(e)
        low = text.lower()
        clen = consolidate.content_len(e)
        n_code = sum(len(s.get("code", []) or []) for s in e.get("steps", []) or [])

        # ---- 1. outdated ---------------------------------------------------
        for rx, sev, why in OUTDATED:
            if rx.search(low) and why not in seen_outdated[eid]:
                seen_outdated[eid].add(why)
                findings.append({"flag": "outdated", "severity": sev, "category": cat,
                                 "id": eid, "title": title, "source": src, "reason": why})

        # ---- 2. low quality ------------------------------------------------
        if e.get("category") == "writeup":
            pass  # whole-box writeups are intentionally long-form; skip stub checks
        elif n_code == 0 and clen < STUB_LEN:
            findings.append({"flag": "low-quality", "severity": "medium", "category": cat,
                             "id": eid, "title": title, "source": src,
                             "reason": f"near-empty stub (no commands, ~{clen} chars)"})
        elif clen < THIN_LEN and len(e.get("steps", []) or []) <= 1:
            findings.append({"flag": "low-quality", "severity": "low", "category": cat,
                             "id": eid, "title": title, "source": src,
                             "reason": f"thin entry (~{clen} chars, <=1 step)"})

        g = _garble_score(e.get("body_md", "") or "")
        if g >= 0.16:
            findings.append({"flag": "low-quality", "severity": "medium", "category": cat,
                             "id": eid, "title": title, "source": src,
                             "reason": f"possible OCR/garbled text ({g:.0%} vowel-less words)"})
        if "�" in text:
            findings.append({"flag": "low-quality", "severity": "low", "category": cat,
                             "id": eid, "title": title, "source": src,
                             "reason": "contains U+FFFD replacement chars (encoding damage)"})

    # ---- 3. coverage gaps -------------------------------------------------
    gaps: list[dict] = []
    for name, rx in EXPECTED:
        substantial = thin = 0
        for e in entries:
            if rx.search(_entry_text(e).lower()):
                if consolidate.content_len(e) >= THIN_LEN:
                    substantial += 1
                else:
                    thin += 1
        if substantial == 0 and thin == 0:
            gaps.append({"technique": name, "status": "MISSING", "severity": "high",
                         "note": "no entry matches — common technique appears absent"})
        elif substantial == 0:
            gaps.append({"technique": name, "status": "THIN", "severity": "medium",
                         "note": f"only {thin} thin/stub match(es) — no substantial entry"})
        elif substantial < 2:
            gaps.append({"technique": name, "status": "SPARSE", "severity": "low",
                         "note": f"{substantial} substantial entry — consider depth/variants"})

    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["category"], f["id"]))
    by_flag = Counter(f["flag"] for f in findings)
    by_sev = Counter(f["severity"] for f in findings)
    by_cat: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        by_cat[f["category"]][f["flag"]] += 1

    return {
        "kb_entries": len(entries),
        "summary": {
            "total_findings": len(findings),
            "by_flag": dict(by_flag),
            "by_severity": dict(by_sev),
            "gaps": Counter(g["status"] for g in gaps),
        },
        "findings": findings,
        "gaps": sorted(gaps, key=lambda g: SEV_ORDER.get(g["severity"], 9)),
        "by_category": {k: dict(v) for k, v in sorted(by_cat.items())},
    }


def write_md(rep: dict, path: Path) -> None:
    L = [f"# KB curation report", "",
         f"Read-only analysis of {rep['kb_entries']} entries. "
         f"**{rep['summary']['total_findings']} findings** + "
         f"{len(rep['gaps'])} coverage notes. Nothing was modified.", "",
         "## Summary", "",
         f"- by flag: {rep['summary']['by_flag']}",
         f"- by severity: {rep['summary']['by_severity']}",
         f"- gaps: {dict(rep['summary']['gaps'])}", "",
         "## Coverage gaps (missing / thin common techniques)", ""]
    for g in rep["gaps"]:
        L.append(f"- **{g['status']}** · {g['technique']} — {g['note']}")
    L += ["", "## Top findings (most severe first)", ""]
    for f in rep["findings"][:60]:
        L.append(f"- `{f['severity']}` [{f['flag']}] **{f['title']}** "
                 f"({f['category']}/{f['id']}, src={f['source']}) — {f['reason']}")
    if len(rep["findings"]) > 60:
        L.append(f"- … and {len(rep['findings']) - 60} more (see curation_report.json)")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Read-only KB curation analysis.")
    ap.add_argument("--kb", default=str(DEFAULT_KB))
    args = ap.parse_args()
    entries = [json.loads(l) for l in Path(args.kb).open(encoding="utf-8") if l.strip()]
    rep = scan(entries)
    OUT_JSON.write_text(json.dumps(rep, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_md(rep, OUT_MD)
    print(f"Curation report -> {OUT_JSON.name} + {OUT_MD.name}")
    print(f"  {rep['kb_entries']} entries scanned")
    print(f"  findings: {rep['summary']['total_findings']}  "
          f"by_flag={rep['summary']['by_flag']}  by_sev={rep['summary']['by_severity']}")
    print(f"  coverage: {dict(rep['summary']['gaps'])}")
    print("  gaps:")
    for g in rep["gaps"]:
        print(f"    [{g['status']}] {g['technique']} — {g['note']}")


if __name__ == "__main__":
    main()
