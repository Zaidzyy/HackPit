#!/usr/bin/env python3
"""Build #18 item 3 — MEASURE the scan policy: default vs targeted-web, same endpoint.

The plan asks for a measured claim: "requests sent, 403 share, and alerts raised, default policy
vs targeted, against a lab target. If the narrower policy does not measurably help, say so — a
negative result recorded is worth more than a feature that quietly does nothing."

So this runs the SAME scan twice against the SAME lab URL, once per policy, reads the counts back
out of ZAP, and prints both. It is a lab measurement on purpose: burning ~40 requests a time
against a real target that paces us to about three a minute would cost half an hour to learn
something a lab answers in two minutes.

*** IT ALSO PROVES THE POLICY TOOK, WHICH IS THE HALF THAT CAN LIE. ***
`enableAllScanners` / `disableScanners` both answer `{"Result":"OK"}`. This module's own history
has `setOptionBrowserId` answering OK for a browser it could not use. So the policy is READ BACK
from `ascan/view/scanners` before either scan starts, and a plugin id ZAP does not hold is
reported as `not_held` rather than counted as a success.

    backend/.venv/Scripts/python.exe docs/proof/build18_scan_policy.py --url <lab url>

Prints VERDICT= and exits non-zero on failure. It needs a LAB proxy with the URL already in its
Sites tree (ZAP answers `url_not_found` otherwise — a containment property, not an error).
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

from cockpit import config, proxy  # noqa: E402

MAX_WALL_SECONDS = 600


def _run_one(container: str, port: int, url: str, policy: str) -> dict:
    """One scan under one policy. Returns the observed counts, or an `error` key."""
    print(f"\n--- policy: {policy}")
    held = proxy.apply_scan_policy(container, port, policy)
    print(f"    ZAP holds: strength={held.attack_strength} threshold={held.alert_threshold}")
    print(f"    disabled : {held.disabled_ids}")
    if held.not_held:
        print(f"    NOT HELD : {held.not_held}  <-- requested off, ZAP does not report them off")
    if held.scanners_seen == 0:
        return {"error": "the scanner list could not be READ -- this is a failed read, not an "
                         "empty policy. Nothing below would mean anything."}
    print(f"    (read back from {held.scanners_seen} scan rules)")

    alerts_before, ok = proxy.alerts_snapshot(container, port, base_url=url, count=500)
    if not ok:
        return {"error": "the alert list could not be read before the scan"}

    try:
        scan = proxy.start_scan(proxy.ScanStartRequest(
            target_url=url, recurse=False, scan_policy=policy,
            approved=True, dangerous_ack=True,
        ))
    except proxy.ProxyRefused as exc:
        return {"error": f"refused at gate={exc.gate}: {exc.reason}"}

    deadline = time.monotonic() + MAX_WALL_SECONDS
    last = scan
    while time.monotonic() < deadline:
        current = proxy.scan_status(container, port, scan.id)
        if current is None:
            break
        last = current
        print(f"      {current.state} {current.progress}%  "
              f"{current.requests} requests  {current.alerts} alerts", end="\r")
        if not proxy.is_running(current):
            break
        time.sleep(5)
    print()

    # THE 403 SHARE COMES FROM THE RESPONSES, NOT FROM A SUMMARY LINE. Build #17's first verdict
    # read "answered" as "allowed" and counted every WAF block page as a served request.
    window = proxy.history(container, port, start=0, count=400)
    ours = [e for e in window if e.request.url.startswith(url.split("?", 1)[0])]
    statuses: dict[int, int] = {}
    for exchange in ours:
        statuses[exchange.response.status or 0] = statuses.get(exchange.response.status or 0, 0) + 1
    refused = sum(n for s, n in statuses.items() if s in (403, 406, 429, 503))

    alerts_after, _ = proxy.alerts_snapshot(container, port, base_url=url, count=500)
    return {
        "policy": policy,
        "requests": last.requests,
        "progress": last.progress,
        "state": last.state,
        "alerts_delta": len(alerts_after) - len(alerts_before),
        "sampled_responses": len(ours),
        "edge_refusals": refused,
        "status_mix": dict(sorted(statuses.items())),
        "disabled_held": held.disabled_ids,
        "disabled_not_held": held.not_held,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default=config.SANDBOX_CONTAINER)
    ap.add_argument("--port", type=int, default=proxy.DEFAULT_PROXY_PORT)
    ap.add_argument("--url", required=True,
                    help="A LAB url already in ZAP's Sites tree (proxy a request to it first).")
    args = ap.parse_args()

    print("=" * 74)
    print("BUILD #18 ITEM 3 -- default vs targeted-web, same endpoint, counts read from ZAP")
    print("=" * 74)
    print(f"container={args.container} port={args.port}")
    print(f"url      ={args.url}")

    if '"version"' not in proxy._api_get(args.container, args.port, proxy._VIEW_VERSION, timeout=8):
        print("\nVERDICT=NOT-RUN -- no live ZAP daemon on that container:port")
        return 2

    results = []
    for policy in (proxy.DEFAULT_SCAN_POLICY, "targeted-web"):
        outcome = _run_one(args.container, args.port, args.url, policy)
        if "error" in outcome:
            print(f"\nVERDICT=FAIL -- {policy}: {outcome['error']}")
            return 1
        results.append(outcome)

    # Leave the daemon on the DEFAULT policy. ZAP persists, so walking away with targeted-web
    # still installed would silently narrow whatever the operator runs next -- the exact trap
    # this item is written around.
    proxy.apply_scan_policy(args.container, args.port, proxy.DEFAULT_SCAN_POLICY)
    print("\n(daemon reset to the default policy -- ZAP persists, so leaving it narrowed would")
    print(" silently condition the next scan)")

    print()
    print("=" * 74)
    print(f"{'policy':<16}{'requests':>10}{'alerts':>9}{'sampled':>9}{'refused':>9}  status mix")
    print("-" * 74)
    for r in results:
        print(f"{r['policy']:<16}{r['requests']:>10}{r['alerts_delta']:>9}"
              f"{r['sampled_responses']:>9}{r['edge_refusals']:>9}  {r['status_mix']}")
    print()

    base, narrow = results
    if base["requests"] <= 0:
        print("VERDICT=FAIL -- the default-policy scan sent ZERO requests, so there is no")
        print("  baseline to compare against and the narrow result means nothing.")
        return 1

    saved = base["requests"] - narrow["requests"]
    share = (saved / base["requests"]) * 100 if base["requests"] else 0.0
    lost = base["alerts_delta"] - narrow["alerts_delta"]

    print(f"requests saved by targeted-web : {saved} of {base['requests']}  ({share:.1f}%)")
    print(f"alerts given up                : {lost}")
    print()
    if saved <= 0:
        print("VERDICT=PASS-NO-BENEFIT -- the narrower policy sent no fewer requests. THAT IS")
        print("  THE RESULT, and it is worth more than a feature that quietly does nothing:")
        print("  the disabled rules were not the ones doing the work against this target.")
    elif lost > 0:
        print(f"VERDICT=PASS -- targeted-web saved {saved} requests and cost {lost} alert(s).")
        print("  The trade is REAL and is stated rather than smoothed over.")
    else:
        print(f"VERDICT=PASS -- targeted-web saved {saved} requests and lost no alerts.")
    print()
    print("SCOPE OF THE CLAIM: measured against a LAB target with no WAF. The 403 share here is")
    print("whatever the lab app returns; it is NOT a measurement of an edge refusing payloads.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nVERDICT=INTERRUPTED")
        sys.exit(130)
