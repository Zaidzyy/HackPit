"""Build the batch-3 authored entries and merge them into `authored_entries.jsonl`.

WHY A BUILDER AND NOT A HAND-EDITED JSONL
`authored_entries.jsonl` is one JSON object per line with embedded markdown and command
blocks. Hand-editing that is how you get an unparseable line or a silently duplicated `id`.
This script holds the entries as ordinary Python, validates each one through the canonical
`schema.Entry`, and replaces by `id` — so it is re-runnable, and running it twice is a no-op
rather than a duplication. Every authored batch should get one of these.

WHERE THESE TWO ENTRIES CAME FROM (D21 — DISTIL, NEVER PARROT)
Batch 3's sources were five cert-notes collections. Triage grepped every candidate technique
in them against the KB and found almost all of it already present — printer pass-back, IKE
aggressive mode, open mail relays, ligolo/chisel pivoting, employee OSINT and password
spraying are all covered, several of them better than the sources cover them. Two things
were NOT:

  * the perimeter device itself as an object of enumeration — `--spoof-mac`, `--data-length`,
    `firewalk`, `--mtu`, `nmap -f` and window scan were all ZERO in the KB, and retrieval for
    "map firewall rules with nmap" returned cloud firewall enumeration;
  * scan safety on an OT segment — `--max-parallelism` was ZERO, and the `ics` category held
    exactly one entry, an operator persona rather than a technique.

Both were NOMINATED by the CPENT cheat sheet (gitlab.com/parfaittolefo23/cpent-sheet-cheat)
and are written here from scratch: the source is a flag list, these are the mechanisms and
the judgement around them. No sentence, ordering or example is taken from it — its own text
carries typos (`airoplay-ng`, `namp`, `nmap -Ss`) that a copy would have inherited.

Run:  backend/.venv/Scripts/python.exe pipeline/authored/build_scan_discipline_entries.py
      ... then ingest_authored.py and embed.py, as the module docstrings there describe.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schema import Entry  # noqa: E402 - path shim above must run first

AUTHORED = Path(__file__).with_name("authored_entries.jsonl")

ENTRIES: list[dict] = [
    {
        "id": "authored-perimeter-filter-mapping",
        "title": "Reading a Packet Filter — ACL Enumeration and Scan-Time Evasion",
        "category": "recon",
        "subcategory": "perimeter",
        "source": "hackpit-authored",
        "tier": 1,
        "tags": [
            "recon",
            "scanning",
            "firewall",
            "acl",
            "evasion",
            "nmap",
            "perimeter",
            "network",
        ],
        "tools": ["nmap", "hping3", "traceroute"],
        "summary": (
            "A port that does not answer has told you something about the FILTER, not about the "
            "port. Most scanning notes treat that silence as 'closed' and move on, which throws "
            "away the perimeter device as an object of enumeration and leaves you unable to say "
            "whether a service is absent or merely unreachable from where you are standing. This "
            "is how to map the filter itself: separate refused from dropped, use the scan types "
            "that report reachability rather than port state, locate the device on the path, and "
            "only then adapt the scan to what that device does not inspect."
        ),
        "steps": [
            {
                "n": 1,
                "text": (
                    "Start from the three-state model, because two of the states look identical if "
                    "you only run a default scan. OPEN answers with SYN/ACK. CLOSED answers with "
                    "RST — the packet reached a live host and was refused. FILTERED does not answer "
                    "at all, or comes back as ICMP unreachable type 3 code 13 (administratively "
                    "prohibited), which is a router telling you it dropped the packet on policy. "
                    "That ICMP is the single most useful reply on an external test: it names the "
                    "filtering device's address in the packet header."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": (
                            "# --reason prints WHY nmap assigned each state; without it you cannot\n"
                            "# tell a dropped probe from a refused one\n"
                            "nmap -sS --reason -p 22,80,443,3389 <target>\n\n"
                            "# the ICMP admin-prohibited reply names the device that dropped it\n"
                            "nmap -sS --reason -p- <target> | grep -i 'admin-prohibited'"
                        ),
                        "copyable": True,
                    }
                ],
                "images": [],
            },
            {
                "n": 2,
                "text": (
                    "Run an ACK scan to map the ACL rather than the host. -sA deliberately tells you "
                    "NOTHING about whether a port is open: a bare ACK gets a RST from any live host, "
                    "open or closed. What it distinguishes is 'unfiltered' (the RST came back, so the "
                    "filter PASSED your packet) from 'filtered' (nothing came back). Diff that "
                    "against the SYN scan and you have the rule set: ports that are unfiltered but "
                    "closed are holes in the ACL with no service behind them, and ports filtered "
                    "under ACK but open under SYN indicate stateful inspection rather than a static "
                    "list."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": (
                            "nmap -sA --reason -p1-65535 <target> -oA acl-ack\n"
                            "nmap -sS --reason -p1-65535 <target> -oA acl-syn\n\n"
                            "# the interesting set is the difference between the two\n"
                            "comm -3 <(grep -E '^[0-9]+/tcp' acl-ack.gnmap | sort) \\\n"
                            "        <(grep -E '^[0-9]+/tcp' acl-syn.gnmap | sort)"
                        ),
                        "copyable": True,
                    }
                ],
                "images": [],
            },
            {
                "n": 3,
                "text": (
                    "Where the ACK scan comes back uniformly filtered, try a window scan. -sW sends "
                    "the same bare ACK but reads the TCP window field of the RST instead of merely "
                    "noting that a RST arrived. A number of stacks set a non-zero window for open "
                    "ports and zero for closed ones, which recovers real port state through a device "
                    "that an ACK scan could only call 'unfiltered'. It is stack-dependent and it "
                    "lies on modern targets — treat a -sW result as a hypothesis to confirm, never "
                    "as a finding on its own."
                ),
                "code": [
                    {"lang": "bash", "cmd": "nmap -sW --reason -p1-65535 <target>", "copyable": True},
                ],
                "images": [],
            },
            {
                "n": 4,
                "text": (
                    "Locate the device on the path before you try to get around it. Firewalking sends "
                    "probes with the TTL set to expire ONE hop past the last router you can see: if "
                    "the probe is forwarded you get an ICMP time-exceeded from beyond the filter, and "
                    "if it is dropped you get nothing — so the port is being filtered by THAT hop "
                    "rather than by the host. This turns 'something is filtering' into 'this address "
                    "is filtering, on these ports'."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": (
                            "# establish the path first - the last responding hop is the candidate\n"
                            "traceroute -n -T -p 80 <target>\n\n"
                            "# then let nmap do the TTL arithmetic per port\n"
                            "nmap --script firewalk --traceroute <target>"
                        ),
                        "copyable": True,
                    }
                ],
                "images": [],
            },
            {
                "n": 5,
                "text": (
                    "Now adapt the scan, choosing the technique that matches what the device fails to "
                    "inspect. Fragmentation (-f, or --mtu at a multiple of 8) splits the TCP header "
                    "across IP fragments so a filter that matches on port numbers without "
                    "reassembling sees no port to match; it is defeated by anything that reassembles, "
                    "which is most modern kit. Source-port trust is the more productive one in "
                    "practice: many rule sets still permit inbound traffic FROM 53, 123 or 20 on the "
                    "assumption that it is a reply, so --source-port walks straight through. "
                    "--data-length breaks the fixed payload length that some IDS signatures key on, "
                    "and --spoof-mac only matters where the control is a MAC allowlist on the local "
                    "segment."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": (
                            "nmap -f <target>                       # fragment\n"
                            "nmap --mtu 16 <target>                 # explicit size, MUST be /8\n"
                            "nmap --source-port 53 <target>         # -g 53 is the same flag\n"
                            "nmap --data-length 25 <target>         # break fixed-length signatures\n"
                            "nmap --spoof-mac 0 <target>            # random MAC, local segment only"
                        ),
                        "copyable": True,
                    }
                ],
                "images": [],
            },
            {
                "n": 6,
                "text": (
                    "Understand what decoys actually buy before you reach for them, because the "
                    "common belief about them is wrong in two ways. -D does NOT hide you: your real "
                    "address is still in the set, so the defender's job goes from reading one "
                    "address to reading N, and correlation across a long scan usually recovers you "
                    "anyway. Worse, a decoy address that is OFFLINE cannot complete the handshakes "
                    "you are attributing to it, so the target is left holding half-open connections "
                    "from a dead host — you have run a small SYN flood against your client and it "
                    "will appear in their logs as exactly that. Only use live, in-scope decoys, and "
                    "note that full source spoofing (-S) forfeits the replies entirely unless you "
                    "are positioned to sniff them."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": (
                            "# prefer named, verified-live decoys over RND\n"
                            "nmap -D <live-ip-1>,<live-ip-2>,ME <target>\n\n"
                            "# -S needs -e and only makes sense where you can read the answers\n"
                            "nmap -S <spoofed-ip> -e eth0 <target>"
                        ),
                        "copyable": True,
                    }
                ],
                "images": [],
            },
            {
                "n": 7,
                "text": (
                    "Finally, slow down rather than dressing up. Most perimeter alerting is "
                    "rate-based — N connections to M ports inside a window — so timing beats packet "
                    "trickery on any device that reassembles fragments. --scan-delay puts a floor "
                    "between probes and -T2 or lower pulls the whole profile down. Confirm anything "
                    "you found from a second vantage point before you report it: a port that is open "
                    "from one source address and filtered from another is a finding about the ACL, "
                    "and it is the finding the client most wants."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": (
                            "nmap -T2 --scan-delay 1s -p <ports> <target>\n"
                            "nmap --max-rate 10 -p <ports> <target>   # explicit ceiling"
                        ),
                        "copyable": True,
                    }
                ],
                "images": [],
            },
        ],
        "body_md": "",
        "references": [
            "https://nmap.org/book/man-bypass-firewalls-ids.html",
            "https://nmap.org/book/scan-methods-ack-scan.html",
            "https://gitlab.com/parfaittolefo23/cpent-sheet-cheat",
        ],
        "meta": {
            "authored_batch": "kb-batch-3-pdfs-pages",
            "nominated_by": "cpent-sheet-cheat module 07 (perimeter devices) + module 05 (external)",
            "kb_gap": "--spoof-mac/--data-length/firewalk/--mtu/nmap -f/window-scan all 0 hits pre-ingest",
        },
    },
    {
        "id": "authored-ot-safe-scanning",
        "title": "Scanning an ICS/OT Segment Without Knocking It Over",
        "category": "ics",
        "subcategory": "scanning",
        "source": "hackpit-authored",
        "tier": 1,
        "tags": [
            "ics",
            "ot",
            "scada",
            "scanning",
            "recon",
            "safety",
            "nmap",
            "network",
        ],
        "tools": ["nmap", "wireshark", "tcpdump"],
        "summary": (
            "On an IT network the scan is reconnaissance and the exploit is the risk. On an OT "
            "segment the SCAN is the risk. Controllers run tiny embedded TCP stacks with a handful "
            "of connection slots and no expectation of being probed, and a default nmap invocation "
            "faults them often enough that it is a normal outcome rather than bad luck — the "
            "version-detection probes in particular exist to send deliberately malformed protocol "
            "traffic. A faulted PLC is not a ticket; it is a stopped process and potentially a "
            "safety event. This is the discipline that lets you enumerate one anyway."
        ),
        "steps": [
            {
                "n": 1,
                "text": (
                    "Establish that you are on OT before you scan, and do not rely on being told. "
                    "The protocol ports are the reliable tell: 502 (Modbus/TCP), 102 (S7comm over "
                    "ISO-TSAP), 20000 (DNP3), 44818 and 2222 (EtherNet/IP/CIP), 47808/udp (BACnet), "
                    "4840 (OPC UA). If any of those answer, treat the whole segment as fragile until "
                    "proven otherwise — flat OT networks are the norm, so one controller means the "
                    "engineering workstations and the historian are probably sharing the broadcast "
                    "domain with it."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": (
                            "# a single, slow, connect-scan probe of the OT tells - nothing else yet\n"
                            "nmap -n -Pn -sT --max-parallelism 1 --scan-delay 500ms \\\n"
                            "     -p 102,502,4840,20000,44818,2222 <range>"
                        ),
                        "copyable": True,
                    }
                ],
                "images": [],
            },
            {
                "n": 2,
                "text": (
                    "Exhaust the passive route first, because on OT it usually works. Process traffic "
                    "is cyclic and chatty by design — controllers poll their I/O on a fixed interval "
                    "— so a span port or tap left running for one full process cycle hands you the "
                    "asset inventory, the master/slave relationships and often the firmware versions "
                    "without a single packet leaving your interface. That is a better inventory than "
                    "an active scan would produce, at zero risk."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": (
                            "tcpdump -i <iface> -nn -s0 -w ot-baseline.pcap\n\n"
                            "# then read the asset list back out of the capture\n"
                            "tshark -r ot-baseline.pcap -q -z conv,tcp\n"
                            "tshark -r ot-baseline.pcap -Y 'mbtcp || s7comm || cip || bacapp' \\\n"
                            "       -T fields -e ip.src -e ip.dst -e _ws.col.Protocol | sort -u"
                        ),
                        "copyable": True,
                    }
                ],
                "images": [],
            },
            {
                "n": 3,
                "text": (
                    "If you must go active, the single most important rule is: never -A, and never "
                    "-sV, against a controller. -A bundles OS fingerprinting, version detection, "
                    "traceroute and the default script set. Version detection is the specific "
                    "danger: it works by sending crafted, often protocol-violating payloads and "
                    "reading the reply, which is precisely the input an embedded stack was never "
                    "tested against. OS fingerprinting is nearly as bad — it deliberately sends "
                    "malformed TCP flag combinations. Take the version from the passive capture or "
                    "from the vendor's own management protocol instead."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": (
                            "# WRONG on an OT segment - each of these has faulted controllers\n"
                            "# nmap -A <target>\n"
                            "# nmap -sV <target>\n"
                            "# nmap -O <target>"
                        ),
                        "copyable": False,
                    }
                ],
                "images": [],
            },
            {
                "n": 4,
                "text": (
                    "Prefer the full connect scan (-sT) over the half-open SYN scan (-sS), which "
                    "inverts the usual IT advice for a reason. -sS never completes the handshake, so "
                    "the device is left holding connection state it must time out on its own; a "
                    "controller with a very small connection table can have every slot consumed by "
                    "abandoned half-opens and then refuse the legitimate poll from its master. -sT "
                    "completes and closes the connection properly, which costs you stealth you were "
                    "not going to get on a quiet OT network anyway."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": "nmap -n -Pn -sT --max-parallelism 1 -p <narrow-list> <target>",
                        "copyable": True,
                    }
                ],
                "images": [],
            },
            {
                "n": 5,
                "text": (
                    "Serialise everything. --max-parallelism 1 holds nmap to a single outstanding "
                    "probe rather than the hundreds it will otherwise open, --scan-delay puts a "
                    "floor between them, and -T2 or -T1 pulls the overall profile down. Add "
                    "--host-timeout so a device that stops answering ends that host's scan instead "
                    "of provoking retries against something you may already have hurt. This is slow "
                    "on purpose — an OT scan is measured in hours."
                ),
                "code": [
                    {
                        "lang": "bash",
                        "cmd": (
                            "nmap -n -Pn -sT -T2 \\\n"
                            "     --max-parallelism 1 --scan-delay 1s --host-timeout 15m \\\n"
                            "     -p 102,502,4840,20000,44818 <target>"
                        ),
                        "copyable": True,
                    }
                ],
                "images": [],
            },
            {
                "n": 6,
                "text": (
                    "Widen the port range last, never first. Start from the known OT ports and the "
                    "handful of IT services you expect (22, 80, 443, 445), confirm the segment "
                    "tolerates that, and only then consider going broader. -p- against a PLC is the "
                    "classic way to end a test early. Keep -n so you are not also generating DNS "
                    "lookups, and -Pn so nmap does not run its own host-discovery probes before the "
                    "scan you carefully configured."
                ),
                "code": [],
                "images": [],
            },
            {
                "n": 7,
                "text": (
                    "Agree the abort path before the first packet, and get it into the rules of "
                    "engagement in writing. That means a named control-room engineer watching the "
                    "HMI while you scan, a phone line open to them rather than to a ticket queue, an "
                    "agreed stop word, and a shared understanding that the test stops the moment a "
                    "process alarm fires — not after you have finished the sweep. Record the exact "
                    "command and timestamp for every scan you run, so that if something does fault "
                    "an hour later the question of whether it was you can be answered from evidence."
                ),
                "code": [],
                "images": [],
            },
        ],
        "body_md": "",
        "references": [
            "https://www.cisa.gov/topics/industrial-control-systems",
            "https://nmap.org/book/man-port-scanning-techniques.html",
            "https://gitlab.com/parfaittolefo23/cpent-sheet-cheat",
        ],
        "meta": {
            "authored_batch": "kb-batch-3-pdfs-pages",
            "nominated_by": "cpent-sheet-cheat module 10 (IoT/ICS nmap notes)",
            "kb_gap": "--max-parallelism 0 hits pre-ingest; ics category held 1 entry, an operator persona",
        },
    },
]


def main() -> None:
    for row in ENTRIES:
        Entry.model_validate(row)  # abort loudly rather than write a bad row

    existing: list[dict] = []
    if AUTHORED.exists():
        with AUTHORED.open(encoding="utf-8") as fh:
            existing = [json.loads(line) for line in fh if line.strip()]

    new_ids = {r["id"] for r in ENTRIES}
    kept = [r for r in existing if r.get("id") not in new_ids]
    replaced = len(existing) - len(kept)
    merged = kept + [Entry.model_validate(r).model_dump() for r in ENTRIES]

    with AUTHORED.open("w", encoding="utf-8") as fh:
        for row in merged:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"authored entries: {len(existing)} before -> {len(merged)} after")
    print(f"  {len(ENTRIES) - replaced} added, {replaced} replaced by id")
    for row in ENTRIES:
        print(f"  - {row['id']}  [{row['category']}]  {len(row['steps'])} steps")
    print("NEXT: pipeline/ingest_authored.py, then pipeline/embed.py")


if __name__ == "__main__":
    main()
