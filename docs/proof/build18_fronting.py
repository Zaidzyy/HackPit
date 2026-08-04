#!/usr/bin/env python3
"""Build #18 item 2 — is each in-scope host CDN-fronted, and what is behind it?

*** THIS IS THE ANSWER THE REST OF BUILD #18 IS BUILT AROUND. ***
Build #17 measured two walls on an Akamai-fronted host: Bot Manager refuses the CLIENT, and the
WAF refuses the REQUEST CONTENT. Items 1, 3, 4 and 5 all answer one wall or the other. This
answers the question that comes first: WHICH of these hosts is actually fronted? The plan names
two by hand — `api-prod.thatconceptstore.com` and `lapi.yellowblocks.me` — because if they are
reachable directly then two of eleven need none of the rest of this plan.

PASSIVE ONLY. DNS (CNAME/A/TXT/MX), Team Cymru's ASN zones, optional certificate transparency,
and ONE `HEAD` request per host — the same request a browser makes opening a page. No scanning,
no brute force, no subdomain guessing. It runs from inside the open sandbox, so no new egress
path from this Windows host is created.

    backend/.venv/Scripts/python.exe docs/proof/build18_fronting.py --engagement <id>
    backend/.venv/Scripts/python.exe docs/proof/build18_fronting.py --hosts a.com b.com --ct

Prints VERDICT= and exits non-zero on failure. A host that reports `unknown` is NOT a failure —
it is a real answer, and the exit code only fails when the SWEEP could not run at all (the
sandbox down, no hosts).

*** A DISCOVERED ORIGIN IS OUT OF SCOPE UNTIL THE SCOPE SAYS OTHERWISE. *** This prints leads.
`engagement.add_pivot_subnet` is the one audited widening path and a human uses it.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

from cockpit import config, engagement, fronting  # noqa: E402

#: The two the plan asks about by name. Printed separately at the end whether or not they were
#: in the sweep, so the question the build exists for gets an explicit answer.
NAMED_QUESTIONS = ("api-prod.thatconceptstore.com", "lapi.yellowblocks.me")


def _sandbox_up(name: str) -> bool:
    try:
        out = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                             capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return (out.stdout or b"").decode("utf-8", "replace").strip() == "true"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement", default="", help="Sweep this engagement's allowed set.")
    ap.add_argument("--hosts", nargs="*", default=[], help="Explicit hosts.")
    ap.add_argument("--ct", action="store_true", help="Also query crt.sh (third-party service).")
    ap.add_argument("--json", default="", help="Also write the full result to this path.")
    args = ap.parse_args()

    print("=" * 74)
    print("BUILD #18 ITEM 2 -- CDN fronting and candidate origins. PASSIVE LOOKUPS ONLY.")
    print("=" * 74)

    if not _sandbox_up(config.KALI_OPEN_CONTAINER):
        print(f"VERDICT=NOT-RUN -- open sandbox {config.KALI_OPEN_CONTAINER} is not running.")
        print("  docker compose -f docker/docker-compose.yml up -d")
        return 2

    hosts = list(args.hosts)
    if args.engagement:
        record = engagement.get_active(args.engagement)
        if record is None:
            print(f"VERDICT=FAIL -- engagement {args.engagement!r} is not active")
            return 1
        hosts += [h for h in record.allowed_hosts if h not in hosts]
        print(f"engagement {args.engagement}: {len(record.allowed_hosts)} hosts in the allowed set")
    for named in NAMED_QUESTIONS:
        if named not in hosts:
            hosts.append(named)

    if not hosts:
        print("VERDICT=FAIL -- no hosts to analyse (pass --hosts or --engagement)")
        return 1

    print(f"analysing {len(hosts)} host(s){' with certificate transparency' if args.ct else ''}")
    print()

    result = fronting.sweep(hosts, with_ct=args.ct)

    for host in result["hosts"]:
        print(f"--- {host.host}")
        print(f"    VERDICT: {host.verdict.upper()}"
              + (f"  ({host.provider})" if host.provider else ""))
        if host.cname_chain:
            print(f"    CNAME  : {' -> '.join(host.cname_chain)}")
        if host.addresses:
            print(f"    A      : {', '.join(host.addresses[:6])}")
        if host.asn:
            print(f"    ASN    : AS{host.asn} {host.asn_org}")
        if host.server_header:
            print(f"    Server : {host.server_header}")
        for ev in host.evidence:
            print(f"    why    : [{ev.source}] {ev.detail}")
        for origin in host.candidate_origins[:12]:
            print(f"    lead   : {origin}")
        for note in host.notes:
            print(f"    note   : {note}")
        print()

    print("=" * 74)
    print(f"fronted     : {len(result['fronted'])}  {result['fronted']}")
    print(f"not-fronted : {len(result['not_fronted'])}  {result['not_fronted']}")
    print(f"unknown     : {len(result['unknown'])}  {result['unknown']}")
    print()
    print("THE QUESTION THIS BUILD EXISTS FOR:")
    by_host = {h.host: h for h in result["hosts"]}
    for named in NAMED_QUESTIONS:
        entry = by_host.get(named)
        if entry is None:
            print(f"  {named}: NOT ANALYSED")
            continue
        print(f"  {named}: {entry.verdict.upper()}"
              + (f" ({entry.provider})" if entry.provider else "")
              + ("   <-- needs NONE of items 1/3/4/5" if entry.verdict == "not-fronted" else ""))
    print()
    print("CANDIDATE ORIGINS ARE LEADS, NOT SCOPE. add_pivot_subnet is the one audited")
    print("widening path in this codebase, and a human uses it.")

    if args.json:
        Path(args.json).write_text(
            json.dumps({
                "hosts": [h.model_dump() for h in result["hosts"]],
                "fronted": result["fronted"],
                "not_fronted": result["not_fronted"],
                "unknown": result["unknown"],
            }, indent=2),
            encoding="utf-8",
        )
        print(f"\nfull result -> {args.json}")

    # UNKNOWN IS NOT A FAILURE. It is a real answer about a host that would not resolve or would
    # not answer, and treating it as an error would push the next person to make the sweep say
    # something it does not know. The sweep FAILS only when it could not run.
    if len(result["unknown"]) == len(result["hosts"]):
        print("\nVERDICT=FAIL -- EVERY host reported unknown, which means the lookups themselves")
        print("  are not working (dig/curl inside the sandbox?), not that eleven hosts vanished.")
        return 1
    print("\nVERDICT=PASS -- the sweep ran and every host has a verdict")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nVERDICT=INTERRUPTED")
        sys.exit(130)
