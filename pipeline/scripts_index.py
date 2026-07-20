"""Scripts Arsenal — extract every genuinely-runnable script/payload from the
built KB into one copy-ready, deduped index grouped by type.

Unlike the entry KB (technique write-ups), this is an *operator* view: the
actual reverse shells, payload one-liners, privesc scripts, delivery snippets,
persistence and web payloads scattered across hundreds of entries, collapsed so
the same shell seen in 30 boxes shows once with all its sources attributed.

Pipeline
--------
* SCAN   every entry's copyable code — ``steps[].code[].cmd`` plus fenced
  ```code``` blocks in ``body_md``.
* CLASSIFY each candidate into ONE type by signature (first match wins, in a
  deliberate priority order). Plain single commands (``whoami``, ``nmap -sV``)
  are rejected — only multi-line scripts or strong payload/shell signatures pass.
* DEDUPE on a normalized key (whitespace collapsed; IPs/ports/LHOST/LPORT and
  the ``$target`` vars folded to ``<IP>``/``<PORT>``) so the same script from
  many entries becomes one row recording every source entry.
* WRITE  ``data/kb/scripts.json`` (gitignored) — the grouped arsenal the API
  serves + a classification-review block (counts + samples) for sanity-checking.

Deterministic: no timestamps in the output, sources sorted, so re-running yields
a byte-identical file. Run:  ``uv run python scripts_index.py``
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict, OrderedDict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KB = REPO_ROOT / "data" / "kb" / "entries.jsonl"
DEFAULT_OUT = REPO_ROOT / "data" / "kb" / "scripts.json"

# --------------------------------------------------------------------------- #
# type registry — display label + on-theme icon/colour for the /scripts view
# and the home card. Order here is the CLASSIFICATION PRIORITY (first match
# wins), chosen so the more-specific payload types beat the generic ones.
# --------------------------------------------------------------------------- #
TYPES: "OrderedDict[str, dict]" = OrderedDict([
    ("reverse-shells", {"label": "Reverse Shells", "icon": "⇌", "color": "#f0776a"}),
    ("web-payloads", {"label": "Web Payloads", "icon": "⚑", "color": "#5aa9f0"}),
    ("payloads-delivery", {"label": "Payloads & Delivery", "icon": "☣", "color": "#e0913a"}),
    ("persistence", {"label": "Persistence", "icon": "⚓", "color": "#c98af0"}),
    ("privesc", {"label": "Privilege Escalation", "icon": "▲", "color": "#e88a5a"}),
    ("enumeration", {"label": "Enumeration", "icon": "◈", "color": "#a996f5"}),
])

# Signatures per type. A "strong" hit qualifies a single-line candidate on its
# own; otherwise a candidate must be multi-line to be considered a script.
_SIG: dict[str, list[re.Pattern]] = {
    "reverse-shells": [re.compile(p, re.I) for p in [
        r"/dev/tcp/", r"\bnc(?:at)?\b[^\n]*(-e|-c|--exec|/bin/(?:ba)?sh|mkfifo)",
        r"\bmkfifo\b[^\n]*\bnc\b", r"\bbash\s+-i\b", r"\bsh\s+-i\b",
        r"pty\.spawn\(", r"socket\.socket\([^\n]*(SOCK_STREAM|AF_INET)",
        r"\bfsockopen\(", r"perl\s+-e[^\n]*(Socket|connect)", r"\bruby\s+-rsocket\b",
        r"System\.Net\.Sockets\.TCPClient|New-Object\s+Net\.Sockets",
        r"\bsocat\b[^\n]*(exec|EXEC|tcp|TCP)", r"\bstty\s+raw\s+-echo\b",
        r"php\s+-r\s+['\"][^\n]*(exec|system|shell_exec)",
    ]],
    "web-payloads": [re.compile(p, re.I) for p in [
        r"\{\{\s*7\s*\*\s*7\s*\}\}", r"\{\{[^\n}]*(config|self|request|cycler|lipsum)",
        r"\$\{[^\n}]*(T\(|Runtime|exec|@)", r"<%=[^\n]*%>", r"#\{[^\n}]*(exec|Runtime)",
        r"ysoserial", r"ObjectInputStream", r"pickle\.(loads|dumps)",
        r"yaml\.(?:unsafe_)?load\b", r"marshal\.loads", r"__reduce__",
        r"O:\d+:\\?\"", r"<\?php[^\n]*(system|exec|shell_exec|passthru|eval)\(",
        r"eval\(\$_(GET|POST|REQUEST|COOKIE)", r"<!ENTITY\b", r"<!DOCTYPE[^\n]*ENTITY",
        r"UNION\s+SELECT[^\n]*(FROM|--|#)",  # sqlmap (a scanner tool) intentionally
    ]],                                       # excluded — it is not a payload script
    "payloads-delivery": [re.compile(p, re.I) for p in [
        r"\bmsfvenom\b", r"base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh)",
        r"echo\s+[A-Za-z0-9+/=]{16,}\s*\|\s*base64\s+(?:-d|--decode)",
        r"\bIEX\b|Invoke-Expression", r"DownloadString\(|DownloadFile\(",
        r"New-Object\s+Net\.WebClient", r"certutil[^\n]*(-urlcache|-decode|-f)",
        r"curl\s+[^\n|]*\|\s*(?:bash|sh)", r"wget\s+[^\n]*(?:&&|;)\s*(?:chmod|\./|bash|sh)",
        r"\bxp_cmdshell\b", r"powershell[^\n]*(-enc\b|-EncodedCommand)",
        r"bitsadmin[^\n]*/transfer", r"\bInvoke-WebRequest\b[^\n]*-OutFile",
    ]],
    "persistence": [re.compile(p, re.I) for p in [
        # ESTABLISHING persistence only (writing a job/key/service) — not merely
        # reading cron (that is privesc enumeration) or backgrounding a process.
        r"crontab\s+-e\b", r"(echo|printf|cat)[^\n]*(>>?)[^\n]*(cron|crontab)",
        r"@reboot\b", r"(echo|cat|printf)[^\n]*>>?[^\n]*authorized_keys",
        r"ssh-keygen\b[^\n]*-f", r"schtasks[^\n]*/create", r"\bNew-Service\b",
        r"\bsc(?:\.exe)?\s+create\b", r"reg\s+add[^\n]*\\Run", r"systemctl[^\n]*enable",
        r"ExecStart=",
    ]],
    "privesc": [re.compile(p, re.I) for p in [
        r"\blinpeas\b", r"\bwinpeas\b", r"\blinenum\b", r"\bPowerUp\b",
        r"Invoke-PrivescCheck|PrivescCheck", r"\bpspy\b", r"GTFOBins",
        r"find\s+/\s+-perm\s+-[0-9]*[64]000", r"find\s+/[^\n]*-perm[^\n]*-u=s",
        r"getcap\s+-r\s+/", r"\bpkexec\b", r"dirty(?:cow|pipe|_pipe)",
        r"chmod\s+[ug]?\+s\b", r"cp\s+/bin/bash", r"\bdoas\b",
        r">>?\s*/etc/sudoers", r"ALL=\(ALL(?::ALL)?\)\s*NOPASSWD",
        r"sudo\s+-l\b[^\n]*\n", r"capsh\s+--", r"unshare\b[^\n]*sh",
    ]],
    "enumeration": [re.compile(p, re.I) for p in [
        r"\benum4linux(?:-ng)?\b", r"\bsnmpwalk\b", r"\bkerbrute\b",
        r"ldapsearch\s+-", r"\b(?:crackmapexec|netexec|nxc)\b", r"smbclient\s+-L",
        r"smbmap\s+-", r"rpcclient\s+-U", r"for\s+\w+\s+in\b[^\n]*\n[^\n]*(curl|wget|nmap|dig|host|ping|nslookup|smb|ldap|snmp)",
        r"while\s+read\b[^\n]*\n[^\n]*(curl|wget|nmap|dig|host|ping)",
        r"\bgobuster\b[^\n]*(vhost|dns)", r"\bffuf\b[^\n]*-w[^\n]*FUZZ[^\n]*(-H|-mc|-fc|-fs)",
    ]],
}
# a subset whose FIRST-line match qualifies even a one-liner (canonical payloads)
_STRONG = {"reverse-shells", "web-payloads", "payloads-delivery"}

# trivial single commands to reject outright (recon/info verbs, bare tools)
_TRIVIAL_HEAD = re.compile(
    r"^\s*(?:sudo\s+)?(?:whoami|id|ls|ll|dir|pwd|cat|head|tail|echo|hostname|uname|"
    r"ifconfig|ip\s+a|ipconfig|ping|dig|nslookup|host|nmap|ps|netstat|ss|env|export|"
    r"cd|clear|which|type|man|history|w|who|date|cd\b)\b", re.I)
_SHELLISH = re.compile(r"[|;&>]|/dev/|\bfor\b|\bwhile\b|python|perl|ruby|php|powershell|"
                       r"bash|/bin/|base64|curl|wget|nc\b|socat|msfvenom", re.I)

_FENCE_RE = re.compile(r"```([\w+-]*)\n(.*?)```", re.S)
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_WS_RE = re.compile(r"\s+")
MAX_PER_TYPE = 250       # display cap per group (records the dropped count)
MAX_CODE_LEN = 1400      # per-script display cap


def _iter_code(entry: dict):
    """Yield (lang, code) for every copyable block in an entry."""
    for s in entry.get("steps", []) or []:
        for c in s.get("code", []) or []:
            cmd = (c.get("cmd") or "").strip()
            if cmd:
                yield (c.get("lang") or "bash"), cmd
    for lang, body in _FENCE_RE.findall(entry.get("body_md", "") or ""):
        body = body.strip()
        if body:
            yield (lang or "bash"), body


def classify(code: str) -> str | None:
    """The single best type for a code block, or None if it isn't a runnable
    script/payload worth arsenal-ing."""
    lines = [ln for ln in code.splitlines() if ln.strip()]
    if not lines or len(code.strip()) < 15:
        return None
    multiline = len(lines) >= 2
    for t, sigs in _SIG.items():
        if any(rx.search(code) for rx in sigs):
            if multiline or t in _STRONG:
                return t
            # single-line weak-type hit (e.g. a lone `sudo -l`): keep only if it
            # still looks like a script, not a bare command.
            if _SHELLISH.search(code) and not _TRIVIAL_HEAD.match(code):
                return t
            return None
    return None


def _norm_key(code: str) -> str:
    """Dedup key: lowercase, whitespace-collapsed, IP/port/target-var folded."""
    s = code.strip()
    s = _IPV4_RE.sub("<IP>", s)
    s = re.sub(r"\$\{?target_?ip\}?|\$\{?ip\}?|\$\{?rhost\}?", "<IP>", s, flags=re.I)
    s = re.sub(r"(<IP>|localhost|LHOST=\S+)[:/ ]\s*\d{2,5}\b", r"\1:<PORT>", s)
    s = re.sub(r"\b(LPORT|RPORT|-p)\s*=?\s*\d{2,5}\b", r"\1=<PORT>", s, flags=re.I)
    s = _WS_RE.sub(" ", s).lower()
    return s


def build(entries: list[dict]) -> dict:
    # type -> norm_key -> {code, lang, sources{id:title}, count}
    buckets: dict[str, "OrderedDict[str, dict]"] = {t: OrderedDict() for t in TYPES}
    scanned = 0
    for e in entries:
        # skip entries whose source export mangled code whitespace — their
        # commands are corrupted (spaceless flags / collapsed lines) and must not
        # enter the copy-ready arsenal.
        if (e.get("meta") or {}).get("source_damaged"):
            continue
        eid, title, cat = e.get("id", ""), e.get("title", ""), e.get("category", "")
        seen_here: set[tuple[str, str]] = set()
        for lang, code in _iter_code(e):
            t = classify(code)
            if t is None:
                continue
            scanned += 1
            key = _norm_key(code)
            if (t, key) in seen_here:      # same script twice in one entry
                continue
            seen_here.add((t, key))
            slot = buckets[t].get(key)
            if slot is None:
                slot = {"code": code[:MAX_CODE_LEN], "lang": _clean_lang(lang),
                        "sources": OrderedDict(), "count": 0}
                buckets[t][key] = slot
            elif len(code) < len(slot["code"]) and len(code) >= 15:
                # prefer the tightest representative variant for display
                slot["code"] = code[:MAX_CODE_LEN]
            slot["sources"].setdefault(eid, {"id": eid, "title": title, "category": cat})
            slot["count"] += 1

    groups = []
    review_samples: dict[str, list[str]] = {}
    for t, meta in TYPES.items():
        rows = list(buckets[t].values())
        # rank: most-reused first (broadest arsenal value), then shortest
        rows.sort(key=lambda r: (-len(r["sources"]), len(r["code"])))
        total = len(rows)
        shown = rows[:MAX_PER_TYPE]
        scripts = [{
            "id": f"{t}-{i+1}",
            "label": _label_for(t, r["code"]),
            "lang": r["lang"],
            "code": r["code"],
            "type": t,
            "reuse": len(r["sources"]),
            "sources": list(r["sources"].values())[:12],
            "source_total": len(r["sources"]),
        } for i, r in enumerate(shown)]
        groups.append({
            "type": t, "label": meta["label"], "icon": meta["icon"],
            "color": meta["color"], "count": total, "shown": len(scripts),
            "scripts": scripts,
        })
        review_samples[t] = [s["code"][:200] for s in scripts[:4]]

    total_scripts = sum(g["count"] for g in groups)
    return {
        "total": total_scripts,
        "kb_entries": len(entries),
        "code_blocks_matched": scanned,
        "groups": groups,
        "review": {
            "by_type": {g["type"]: g["count"] for g in groups},
            "samples": review_samples,
            "dropped_over_cap": {g["type"]: g["count"] - g["shown"]
                                 for g in groups if g["count"] > g["shown"]},
        },
    }


def _clean_lang(lang: str) -> str:
    lang = (lang or "").strip().lower()
    alias = {"ps": "powershell", "ps1": "powershell", "sh": "bash", "shell": "bash",
             "console": "bash", "text": "bash", "": "bash", "py": "python"}
    return alias.get(lang, lang)


def _label_for(t: str, code: str) -> str:
    """A short human label for a script row (first meaningful token/tool)."""
    first = next((ln.strip() for ln in code.splitlines() if ln.strip()
                  and not ln.strip().startswith("#")), code.strip())
    m = re.search(r"\b(msfvenom|nc|ncat|socat|bash|python\d?|php|perl|ruby|powershell|"
                  r"linpeas|winpeas|pspy|certutil|curl|wget|crontab|schtasks|"
                  r"enum4linux|netexec|crackmapexec|ldapsearch|ysoserial|sqlmap)\b",
                  first, re.I)
    head = (m.group(1).lower() if m else first.split()[0] if first.split() else t)
    label = {"reverse-shells": "reverse shell", "web-payloads": "web payload",
             "payloads-delivery": "delivery", "persistence": "persistence",
             "privesc": "privesc", "enumeration": "enum"}[t]
    return f"{head} · {label}"


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the Scripts Arsenal index.")
    ap.add_argument("--kb", default=str(DEFAULT_KB))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    kb = Path(args.kb)
    entries = [json.loads(l) for l in kb.open(encoding="utf-8") if l.strip()]
    result = build(entries)

    Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")
    print(f"Scripts arsenal -> {args.out}")
    print(f"  scanned {result['kb_entries']} entries, "
          f"{result['code_blocks_matched']} script blocks matched")
    print(f"  total deduped scripts: {result['total']}")
    for g in result["groups"]:
        print(f"    {g['label']:22s} {g['count']:4d}  (shown {g['shown']})")
    if result["review"]["dropped_over_cap"]:
        print(f"  over display cap: {result['review']['dropped_over_cap']}")


if __name__ == "__main__":
    main()
