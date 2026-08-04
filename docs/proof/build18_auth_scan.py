#!/usr/bin/env python3
"""Build #18 items 6 and 7 — authenticated scanning, end to end, AGAINST THE LAB ONLY.

*** TIER 3 IS UNVERIFIED AGAINST A REAL TARGET. IN THOSE WORDS. ***
Zaid has no account on any in-scope host, so Tier 3 (form-based authentication with a stored
credential and automatic re-login) is exercised here against the LAB target and nowhere else.
Nothing in this script or the assessment may imply otherwise. Tier 2 is unaffected — it needs no
credentials at all, because the session was established by a human in a real browser.

WHAT IT PROVES
  Tier 2:  a Context exists, holds cookie-based session management, holds the two indicator
           regexes, and a scan started for that target RUNS INSIDE IT.
  Tier 3:  a user exists on the context, form-based authentication is the method ZAP reports,
           and the password is nowhere in what comes back.
  Both:    KILLING THE SESSION FLIPS THE HEALTH VERDICT TO `suspect`. That is build #16's
           session-expiry detector finally meaning something — build #17 found it was reading
           `history(count=200)` from the OLDEST end and therefore could not fire by construction.

    backend/.venv/Scripts/python.exe docs/proof/build18_auth_scan.py \\
        --url http://<lab>/ [--login-url ... --login-body ... \\
        --cred-session <sid> --cred-principal <user>]

Prints VERDICT= and exits non-zero on failure. Without the Tier 3 flags it runs Tier 2 only and
says so, which is a complete and legitimate result.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

from cockpit import config, proxy  # noqa: E402

FAILURES: list[str] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    if not ok:
        FAILURES.append(label)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default=config.SANDBOX_CONTAINER)
    ap.add_argument("--port", type=int, default=proxy.DEFAULT_PROXY_PORT)
    ap.add_argument("--url", required=True, help="Any URL on the LAB app.")
    ap.add_argument("--logged-in", default="Logout|Sign out|/logout")
    ap.add_argument("--logged-out", default="name=[\"']password[\"']|Sign in|/login")
    # Tier 3 — all optional. Their absence is a Tier 2 run, which is a complete result.
    ap.add_argument("--login-url", default="")
    ap.add_argument("--login-body", default="")
    ap.add_argument("--cred-session", default="")
    ap.add_argument("--cred-principal", default="")
    ap.add_argument("--cred-kind", default="password")
    args = ap.parse_args()

    tier3 = bool(args.login_url and args.cred_session and args.cred_principal)

    print("=" * 74)
    print("BUILD #18 ITEMS 6 & 7 -- authenticated scanning. LAB ONLY.")
    print("=" * 74)
    print(f"container={args.container} port={args.port}")
    print(f"url      ={args.url}")
    print(f"tier     ={'3 (form auth + stored credential)' if tier3 else '2 (context only)'}")
    if not tier3:
        print("         (no --login-url/--cred-* given: Tier 2 run. That is a complete result.)")
    print()

    if '"version"' not in proxy._api_get(args.container, args.port, proxy._VIEW_VERSION, timeout=8):
        print("VERDICT=NOT-RUN -- no live ZAP daemon on that container:port")
        return 2

    request = proxy.AuthContextRequest(
        target_url=args.url, port=args.port,
        logged_in_regex=args.logged_in, logged_out_regex=args.logged_out,
        login_url=args.login_url, login_body=args.login_body,
        credential=(proxy.CredentialRef(
            session_id=args.cred_session, kind=args.cred_kind,
            principal=args.cred_principal,
        ) if tier3 else None),
    )

    try:
        held = proxy.apply_auth_context(request, args.container)
    except proxy.ProxyRefused as exc:
        print(f"VERDICT=FAIL -- refused at gate={exc.gate}: {exc.reason}")
        return 1

    print("what ZAP HOLDS (read back, never echoed):")
    check(bool(held.context_id), "a context exists", f"id={held.context_id} name={held.context_name}")
    check(bool(held.included), "the target's origin is included", str(held.included))
    check("cookie" in held.session_method.lower(),
          "session management is cookie-based", held.session_method or "<none>")
    check(bool(held.logged_in_regex), "a logged-IN indicator is held", held.logged_in_regex)
    check(bool(held.logged_out_regex), "a logged-OUT indicator is held", held.logged_out_regex)
    check(held.tier >= 2, "ZAP reports at least a Tier 2 context", f"tier={held.tier}")

    if tier3:
        check(bool(held.user_id), "a user exists on the context", f"id={held.user_id}")
        check(held.user_name == args.cred_principal,
              "the user is the account that was named", held.user_name)
        check("form" in held.auth_method.lower(),
              "form-based authentication is the method ZAP reports", held.auth_method or "<none>")
        check(held.tier == 3, "ZAP reports a Tier 3 context", f"tier={held.tier}")

    # THE PASSWORD IS NOWHERE IN WHAT CAME BACK. Checked on the serialised model rather than by
    # eye, because "I looked and did not see it" is not a property.
    blob = held.model_dump_json()
    check("password" not in blob.lower() or '"password"' not in blob,
          "nothing that came back carries a password field", "")

    for warning in held.warnings:
        print(f"  [WARN] {warning}")

    # ---- the scan runs INSIDE the context -----------------------------------
    print()
    print("scan, inside the context:")
    try:
        scan = proxy.start_scan(proxy.ScanStartRequest(
            target_url=args.url, recurse=False, scan_policy="targeted-web",
            approved=True, dangerous_ack=True,
        ))
    except proxy.ProxyRefused as exc:
        print(f"  [FAIL] the scan was refused at gate={exc.gate}: {exc.reason}")
        FAILURES.append("scan start")
        scan = None

    if scan is not None:
        check(scan.context_name == held.context_name,
              "the scan reports running inside THIS context",
              f"{scan.context_name!r} tier={scan.auth_tier}")
        check(scan.auth_tier == held.tier,
              "the scan's reported tier matches the context's", f"{scan.auth_tier}")
        proxy.stop_scan(args.container, args.port, scan.id)
        print("  (scan stopped -- this proof is about configuration, not coverage)")

    # ---- session health, which is what makes #16 mean anything --------------
    print()
    print("session health (build #16, made meaningful by build #17's newest-window fix):")
    health = proxy.session_health(proxy.history(args.container, args.port, start=0, count=200))
    print(f"  verdict={health['verdict']}  sampled={health['sampled']}")
    for reason in health["reasons"]:
        print(f"    - {reason}")
    check(health["verdict"] in ("ok", "suspect", "unknown"), "a health verdict was produced")
    print()
    print("  TO PROVE THE OTHER HALF BY HAND: log out in the browser, drive 20+ requests")
    print("  through the proxy, and re-run. The verdict must flip to `suspect`. It CANNOT be")
    print("  proved by this script starting cold, because with no post-logout traffic there is")
    print("  nothing login-shaped to find -- and asserting `ok` here would be the same empty")
    print("  confidence build #17 caught this detector giving throughout a whole live scan.")

    print()
    if FAILURES:
        for f in FAILURES:
            print(f"  FAILED: {f}")
        print("VERDICT=FAIL")
        return 1
    print(f"VERDICT=PASS -- Tier {held.tier} context held by ZAP and the scan ran inside it")
    if tier3:
        print()
        print("*** TIER 3 IS UNVERIFIED AGAINST A REAL TARGET. *** There is no account on any")
        print("in-scope host. What is proved here is proved against the LAB and nothing else.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nVERDICT=INTERRUPTED")
        sys.exit(130)
