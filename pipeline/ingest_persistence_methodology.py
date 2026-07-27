"""Fold the TA0003 (Persistence) *mechanism map* into the KB as two checklist entries.

Persistence is technique-heavy and tool-light. HackPit already *executes* persistence on scoped
targets through the one gated executor (engagement mode + WinRM + ``:kali``) — every command is
approved one at a time. What the KB was missing was not the commands (they exist, scattered
through the OSCP/HackTricks corpus) but the *organised methodology*: a per-mechanism map of the
Windows and Linux TA0003 techniques, each pointing at the detection footprint it leaves. This
ingester captures that map as two ``checklist`` entries (§4.4 — "a checklist is a sequence,
meaningful in order").

Discipline mirrors ``ingest_recon_methodology.py`` / ``ingest_corpora.py`` exactly:

1. **Additive + byte-preserving.** Existing lines are copied through as raw bytes and never JSON
   round-tripped, so no other entry can drift by a key order or an escape.
2. **Idempotent.** Every line this ingester owns carries ``meta.persistence_methodology``. A
   re-run drops exactly those lines and regenerates them from source, so running twice yields a
   byte-identical file.
3. **Own marker.** ``persistence_methodology`` is distinct from ``corpus_ingest`` (payload/dork
   corpora) and ``recon_methodology`` (the reconFTW ordering), so the three ingesters never touch
   each other's lines.

This adds NO execution capability — it is knowledge only, describe-and-cross-reference. Rootkits
and bootkits are named as KB knowledge, never as tooling.

Embeddings are NOT rebuilt here: ``search.vector_ranking`` maps vectors to entries by id, so new
ids simply aren't in the vector space yet (no misalignment) — the entries are retrievable
lexically (BM25) immediately. Run ``python pipeline/embed.py`` to add them to the vector space.

Run::

    python pipeline/ingest_persistence_methodology.py --dry-run
    python pipeline/ingest_persistence_methodology.py
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

MARK = "persistence_methodology"
SOURCE = "hackpit-methodology"
SOURCE_LABEL = "HackPit persistence methodology (TA0003 mechanism map)"
ATTACK_TA0003 = "https://attack.mitre.org/tactics/TA0003/"


def _meta(kind: str) -> dict:
    return {
        MARK: True,          # ownership / idempotency marker (distinct from the other ingesters)
        "kind": kind,
        "no_merge": True,    # a mechanism map is a sequence; never let consolidate fold it away
        "source_label": SOURCE_LABEL,
        "attribution": "TA0003 mechanism map; MITRE ATT&CK technique ids cited for cross-reference.",
        "origin": "persistence-ta0003-enrich",
    }


def _entries() -> list[Entry]:
    windows = Entry(
        id="persistence-methodology-windows",
        title="Windows host persistence — the mechanism map (TA0003)",
        category="persistence",
        subcategory="windows",
        source=SOURCE,
        tier=2,
        tags=["persistence", "ta0003", "windows", "methodology", "backdoor", "autostart",
              "scheduled-task", "registry-run", "service", "wmi", "web-shell", "post-exploitation"],
        tools=["schtasks", "reg", "sc", "wmic", "net", "sharpersist", "msfconsole"],
        summary=(
            "The Windows TA0003 mechanisms, mapped: Registry Run keys, Startup folder, scheduled "
            "tasks, services, WMI event subscriptions, accessibility/IFEO, backdoor accounts and "
            "web shells. For each, one command that already lives in the corpus plus the footprint "
            "it leaves for a defender. Advisory — every command still goes through the gated "
            "executor one at a time; this is not an auto-chain."
        ),
        steps=[
            {"n": 1, "text": "Registry Run / RunOnce key (T1547.001) — runs at logon; the classic user-level autostart.",
             "code": [{"lang": "cmd", "cmd": "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v <name> /t REG_SZ /d \"<payload>\" /f"}]},
            {"n": 2, "text": "Startup folder / shortcut (T1547.001) — a file dropped here runs at logon; no registry write.",
             "code": [{"lang": "cmd", "cmd": "copy <payload>.lnk \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\""}]},
            {"n": 3, "text": "Scheduled task (T1053.005) — trigger at logon/onstart/interval; the most flexible mechanism.",
             "code": [{"lang": "cmd", "cmd": "schtasks /create /sc onlogon /tn <name> /tr \"<payload>\" /rl highest /f"}]},
            {"n": 4, "text": "Service (T1543.003) — SYSTEM-level, auto-start; loud but powerful (needs admin).",
             "code": [{"lang": "cmd", "cmd": "sc create <name> binPath= \"<payload>\" start= auto"}]},
            {"n": 5, "text": "WMI permanent event subscription (T1546.003) — filter→consumer→binding; fileless, survives reboot.",
             "code": [{"lang": "powershell", "cmd": "$f=Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{Name='<name>';EventNamespace='root\\cimv2';QueryLanguage='WQL';Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"}\n$c=Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{Name='<name>';CommandLineTemplate='<payload>'}\nSet-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c}"}]},
            {"n": 6, "text": "Accessibility feature / IFEO debugger (T1546.008) — pre-auth trigger (sethc/utilman) or a Debugger key.",
             "code": [{"lang": "cmd", "cmd": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ /d \"cmd.exe\" /f"}]},
            {"n": 7, "text": "Backdoor account + privileged group (T1136.001 / T1098) — a durable local admin.",
             "code": [{"lang": "cmd", "cmd": "net user <u> <p> /add\nnet localgroup administrators <u> /add"}]},
            {"n": 8, "text": "Web shell (T1505.003) — drop a script into the web root for a web-triggered foothold.",
             "code": [{"lang": "cmd", "cmd": "copy shell.aspx C:\\inetpub\\wwwroot\\"}]},
        ],
        body_md=(
            "# Windows host persistence — the mechanism map (TA0003)\n\n"
            "HackPit already *runs* these — each command below is one you approve individually "
            "through the gated executor. This entry is the **map**: which mechanism, which ATT&CK "
            "technique, and (one line each) what a defender sees, so you pick the mechanism that "
            "fits the access you have and stay honest about the trail it leaves.\n\n"
            "| Mechanism | ATT&CK | Trigger / privilege | What the defender sees |\n"
            "|---|---|---|---|\n"
            "| Registry Run/RunOnce key | T1547.001 | logon, user-level | Sysmon 13 / Security 4657; Autoruns baselines it — see footprint `persist_registry_run` |\n"
            "| Startup folder / shortcut | T1547.001 | logon, user-level | Sysmon 11 file-create in Startup; Autoruns — `persist_startup_folder` |\n"
            "| Scheduled task | T1053.005 | flexible; highest with admin | Security 4698/4702, TaskScheduler/Operational 106 — `persist_scheduled_task` |\n"
            "| Service | T1543.003 | SYSTEM; needs admin | System 7045, Security 4697 — `persist_service` |\n"
            "| WMI event subscription | T1546.003 | fileless, reboot-persistent | WMI-Activity/Operational 5859/5861, Sysmon 19/20/21 — `persist_wmi_event` |\n"
            "| Accessibility / IFEO | T1546.008 | pre-auth (sethc/utilman) | Sysmon 11 / registry 13, sethc→cmd 4688 — `persist_accessibility` |\n"
            "| Backdoor account + group | T1136.001 / T1098 | durable local admin | Security 4720/4722/4732/4728 — `persist_account_windows` |\n"
            "| Web shell | T1505.003 | web-triggered | web-server child process, Sysmon 11 in webroot — `persist_webshell` |\n\n"
            "**Rootkits / bootkits** are out of scope as *tooling* — kernel-level persistence is "
            "knowledge here, never something HackPit installs.\n\n"
            "*Every mechanism is a single gated command, not a chain. The detection footprint keys "
            "above open the purple-team panel for that mechanism.*\n"
        ),
        references=[ATTACK_TA0003, "https://attack.mitre.org/techniques/T1547/001/"],
        meta=_meta("checklist"),
    )

    linux = Entry(
        id="persistence-methodology-linux",
        title="Linux host persistence — the mechanism map (TA0003)",
        category="persistence",
        subcategory="linux",
        source=SOURCE,
        tier=2,
        tags=["persistence", "ta0003", "linux", "methodology", "backdoor", "cron", "systemd",
              "ssh", "authorized-keys", "shell-profile", "post-exploitation"],
        tools=["crontab", "systemctl", "ssh-keygen", "useradd", "msfconsole"],
        summary=(
            "The Linux TA0003 mechanisms, mapped: cron, systemd units and timers, SSH "
            "authorized_keys, shell-init profiles and backdoor accounts. For each, one command "
            "that already lives in the corpus plus the footprint it leaves. Advisory — one gated "
            "command at a time, not an auto-chain."
        ),
        steps=[
            {"n": 1, "text": "Cron / /etc/cron.d (T1053.003) — @reboot or scheduled; user or root.",
             "code": [{"lang": "bash", "cmd": "(crontab -l 2>/dev/null; echo \"@reboot <payload>\") | crontab -"}]},
            {"n": 2, "text": "systemd unit + optional timer (T1543.002 / T1053.006) — a service that starts at boot.",
             "code": [{"lang": "bash", "cmd": "printf '[Unit]\\nDescription=<name>\\n[Service]\\nExecStart=<payload>\\n[Install]\\nWantedBy=multi-user.target\\n' | sudo tee /etc/systemd/system/<name>.service\nsudo systemctl enable --now <name>.service"}]},
            {"n": 3, "text": "SSH authorized_keys (T1098.004) — append your public key for keyed re-entry.",
             "code": [{"lang": "bash", "cmd": "mkdir -p ~/.ssh && echo \"<your-public-key>\" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"}]},
            {"n": 4, "text": "Shell-init profile (T1546.004) — code in ~/.bashrc or /etc/profile.d runs on each interactive shell.",
             "code": [{"lang": "bash", "cmd": "echo '<payload>' >> ~/.bashrc"}]},
            {"n": 5, "text": "Backdoor account / /etc/passwd (T1136.001) — a new local user, or an appended passwd line with a known hash.",
             "code": [{"lang": "bash", "cmd": "useradd -m -s /bin/bash -G sudo <u> && echo '<u>:<p>' | chpasswd"}]},
        ],
        body_md=(
            "# Linux host persistence — the mechanism map (TA0003)\n\n"
            "As on Windows, HackPit already *runs* each of these one gated command at a time. This "
            "entry is the **map** — mechanism, ATT&CK technique, and what a defender sees — so you "
            "match the mechanism to your access and stay honest about the trail.\n\n"
            "| Mechanism | ATT&CK | Trigger / privilege | What the defender sees |\n"
            "|---|---|---|---|\n"
            "| Cron / /etc/cron.d | T1053.003 | schedule/@reboot; user or root | auditd on `/etc/cron*`, cron syslog, file-create — footprint `persist_cron` |\n"
            "| systemd unit + timer | T1543.002 / T1053.006 | boot; needs root | auditd on `/etc/systemd`, journald, `systemctl` execve — `persist_systemd` |\n"
            "| SSH authorized_keys | T1098.004 | keyed re-entry; user-level | auditd file-watch, sshd accepted-key login from a new key — `persist_ssh_authkeys` |\n"
            "| Shell-init profile | T1546.004 | each interactive shell | auditd file-watch on `.bashrc`/`profile.d`, file mtime — `persist_shell_profile` |\n"
            "| Backdoor account / /etc/passwd | T1136.001 | durable login | auditd on `/etc/passwd`+`/etc/shadow`, `auth.log` useradd, wtmp — `persist_account_linux` |\n\n"
            "**Rootkits / LKM & bootkits** are KB knowledge only — kernel-level persistence is "
            "never something HackPit installs or runs.\n\n"
            "*Each row is a single gated command. The footprint keys open the purple-team panel for "
            "that mechanism.*\n"
        ),
        references=[ATTACK_TA0003, "https://attack.mitre.org/techniques/T1053/003/"],
        meta=_meta("checklist"),
    )

    return [windows, linux]


CORPUS_MARK = "corpus_ingest"  # ingest_corpora.py's marker — it always appends its lines LAST


def merge(kb_path: Path, new_entries: list[dict]) -> dict:
    """Drop this ingester's own lines, keep every other line as raw bytes, rebuild.

    Order is the fixed point ALL the ingesters converge on: ``[other lines, our methodology
    lines, the corpus block last]``. ``ingest_corpora.py`` always re-appends its ``corpus_ingest``
    lines at the end, so if we appended ours after that block the corpora ingester's byte-identity
    test would fail on the next run. Segregating the corpus block to the tail here keeps every
    ingester idempotent and order-stable against the others.

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
    print("Merged persistence methodology entries into the KB.")
    for k, v in report.items():
        print(f"  {k}: {v}")
    print(f"  ids: {ids}")
    print("  NOTE: embeddings not rebuilt — entries are lexically retrievable now; "
          "run `python pipeline/embed.py` to add them to the vector space.")


if __name__ == "__main__":
    main()
