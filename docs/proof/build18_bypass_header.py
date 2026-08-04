#!/usr/bin/env python3
"""Build #18 item 1 — prove the bypass header reaches the OUTGOING request. End to end.

VERIFIED WITH A DUMMY HEADER. Zaid has no real bypass header from the program yet, and the
decision (2026-08-05) was to build the mechanism now and prove it with a placeholder — which is
provable without one and without touching a real target: set the header, drive one request
through the proxy, and READ IT BACK OUT OF ZAP'S OWN HISTORY on the request side.

WHY THIS IS A SCRIPT AND NOT A TEST. It needs a LIVE ZAP DAEMON. A hermetic test can prove the
value never reaches a model and never reaches an argv (backend/test_bypass_header.py does), but
only a running daemon can prove a replacer rule actually rewrites a request.

*** IT ALSO SETTLES AN UNMEASURED FACT. *** The Replacer add-on renamed its actions across
versions — `addRule` vs `addReplacerRule`. The daemon was not running while build #18 was
written, so the product tries both and lets the read-back decide. This script PRINTS WHICH ONE
ANSWERED, which is how the guess becomes a measurement.

Prints VERDICT= and exits non-zero on failure.

    backend/.venv/Scripts/python.exe docs/proof/build18_bypass_header.py [--target URL]

The default target is a LOCAL page, not the real program: proving a header is on an outgoing
request needs no production traffic at all, and spending a real-target request on it would be
spending one of about three a minute for nothing.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

from cockpit import config, proxy  # noqa: E402

DUMMY_NAME = "X-HackPit-Proof"
DUMMY_VALUE = "build18-dummy-not-a-real-bypass-header"

FAILURES: list[str] = []
PASSES: list[str] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    (PASSES if ok else FAILURES).append(label)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default=config.ENGAGE_SANDBOX_CONTAINER)
    ap.add_argument("--port", type=int, default=proxy.DEFAULT_PROXY_PORT)
    ap.add_argument("--target", default="http://example.com/",
                    help="A page to drive through the proxy. Deliberately NOT the real program.")
    args = ap.parse_args()

    print("=" * 70)
    print("BUILD #18 ITEM 1 -- the bypass header, proved on the OUTGOING request")
    print("=" * 70)
    print(f"container={args.container} port={args.port} target={args.target}")
    print(f"header    {DUMMY_NAME}: {DUMMY_VALUE}")
    print()

    # ---- precondition: a live daemon we can read ----------------------------
    version = proxy._api_get(args.container, args.port, proxy._VIEW_VERSION, timeout=8)
    if not check('"version"' in version, "the ZAP API answers", version[:120]):
        print()
        print("VERDICT=NOT-RUN -- no live daemon. Start one from the :proxy panel first.")
        return 2

    before_count = proxy.captured_count(args.container, args.port)
    print(f"  (ZAP holds {before_count} captured messages before this run)")

    # ---- 1. clean slate, so what we measure is ours -------------------------
    cleared = proxy.clear_bypass_headers(args.container, args.port)
    held = [r for r in proxy.observed_replacer_rules(args.container, args.port)
            if r.hackpit_managed]
    check(not held, "no HackPit replacer rules remain after a clear",
          f"cleared={cleared} still_held={[r.description for r in held]}")

    # ---- 2. install, and WHICH SPELLING ANSWERED ----------------------------
    # Tried one at a time so the answer is attributable rather than "one of them worked".
    which = ""
    for path in proxy._ACTION_REPLACER_ADD:
        answer = proxy._api_post(args.container, args.port, path, {
            "description": proxy.bypass_rule_description(DUMMY_NAME),
            "enabled": "true", "matchType": proxy.BYPASS_MATCH_TYPE,
            "matchString": DUMMY_NAME, "matchRegex": "false",
            "replacement": DUMMY_VALUE, "initiators": "",
        })
        code = str(proxy._json(answer).get("code", ""))
        print(f"    {path} -> {answer.strip()[:90]!r}")
        if answer.strip() and code not in ("no_implementor", "bad_action", "illegal_parameter"):
            which = path
            break
    check(bool(which), "one of the two Replacer action spellings answered", which or "neither")

    # ---- 3. THE READ-BACK IS THE ARBITER, not the OK ------------------------
    rules = [r for r in proxy.observed_replacer_rules(args.container, args.port)
             if r.hackpit_managed]
    ours = next((r for r in rules if r.match_string.lower() == DUMMY_NAME.lower()), None)
    check(ours is not None, "ZAP REPORTS HOLDING the rule (read back, not the OK)",
          f"rules={[r.description for r in rules]}")
    if ours is not None:
        check(ours.enabled, "the rule is enabled")
        check(ours.replacement_set, "the rule holds a non-empty replacement")
        check(DUMMY_VALUE not in ours.model_dump_json(),
              "the reported rule does NOT carry the value (it is a credential)")

    # ---- 4. drive ONE request through the proxy -----------------------------
    proc = subprocess.run(
        ["docker", "exec", args.container, "curl", "-s", "-o", "/dev/null",
         "-w", "%{http_code}", "--max-time", "20",
         "-x", f"http://127.0.0.1:{args.port}", args.target],
        capture_output=True, timeout=40,
    )
    status = (proc.stdout or b"").decode("utf-8", "replace").strip()
    check(status.isdigit() and status != "000",
          "a request went through the proxy and got a response", f"HTTP {status}")
    time.sleep(2)

    # ---- 5. THE PROOF: the header is on the REQUEST in ZAP's history --------
    found = None
    for exchange in reversed(proxy.history(args.container, args.port, start=0, count=25)):
        for header in exchange.request.headers:
            if header.name.lower() == DUMMY_NAME.lower():
                found = (exchange.request.url, header.value)
                break
        if found:
            break
    ok = check(found is not None,
               "*** THE HEADER IS ON THE OUTGOING REQUEST, read back out of ZAP's history ***",
               f"{found[0]} -> {found[1]!r}" if found else "not on any of the last 25 requests")
    if found:
        check(found[1] == DUMMY_VALUE, "the value on the wire is the value that was set")

    # ---- 6. and it comes off again ------------------------------------------
    removed = proxy.clear_bypass_headers(args.container, args.port)
    still = [r for r in proxy.observed_replacer_rules(args.container, args.port)
             if r.hackpit_managed]
    check(not still, "the rule is removed again -- nothing survives into the next engagement",
          f"removed={removed}")

    print()
    print("-" * 70)
    print(f"replacer action spelling THIS daemon accepts: {which or 'NEITHER'}")
    print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
    if FAILURES:
        for f in FAILURES:
            print(f"  FAILED: {f}")
        print("VERDICT=FAIL")
        return 1
    print("VERDICT=PASS -- the bypass header reaches the outgoing request and is removable")
    print("NOTE: proved with a DUMMY header. No real bypass header has been issued by the")
    print("      program yet; the mechanism is what is proved, and it is target-independent.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nVERDICT=INTERRUPTED")
        sys.exit(130)
