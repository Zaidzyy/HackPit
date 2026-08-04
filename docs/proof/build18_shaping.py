#!/usr/bin/env python3
"""Build #18 item 4 — MEASURE payload shaping: same request, shaped vs unshaped.

*** IT MEASURES THE TRANSFORMS, NOT A TARGET. ***
The plan asks for "the same request, shaped vs unshaped, and whether the 403 becomes a 200 —
against the LAB target with a rule that mimics a signature match. Do not burn real-target
requests discovering that an encoder works."

So this stands up a deliberately NAIVE signature matcher inside the open sandbox — one that
refuses a request whose query contains `' OR 1=1` or `UNION SELECT` as literal, case-sensitive,
space-separated text — and drives the repeater at it. That is a fair model of the class of rule
these transforms exist for, and every result is attributable to the transform rather than to
somebody else's undocumented WAF.

WHAT IT CANNOT TELL YOU: whether Akamai's rules are that naive. They are not, and this does not
claim otherwise. What it proves is that each named transform DOES WHAT IT SAYS to the bytes, end
to end through the real send path — which is the part that would otherwise be a fake knob.

    backend/.venv/Scripts/python.exe docs/proof/build18_shaping.py

Prints VERDICT= and exits non-zero on failure. It touches no external host: the matcher listens
on loopback INSIDE the sandbox and is killed on the way out.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

from cockpit import config, repeater, shaping  # noqa: E402

PORT = 8099
MARKER = "hackpit-build18-sigmatch"

#: A deliberately naive rule set: literal, case-sensitive, space-separated. Exactly the class of
#: signature that encoding, case variation and comment insertion exist to test.
SERVER_SRC = f'''
import re, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

SIGNATURES = ["' OR 1=1", "UNION SELECT", "<script>", "; cat /etc/passwd"]

class H(BaseHTTPRequestHandler):
    def _judge(self, raw):
        # ONE decode, on purpose: a real edge normalises once and hands the rest downstream,
        # which is the whole premise of double encoding.
        text = unquote(raw)
        for sig in SIGNATURES:
            if sig in text:
                return sig
        return ""
    def do_GET(self):
        hit = self._judge(self.path)
        body = ("BLOCKED " + hit if hit else "OK {MARKER}").encode()
        self.send_response(403 if hit else 200)
        self.send_header("Server", "hackpit-naive-sigmatch/1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked" and not n:
            raw = "<chunked body not reassembled by this naive matcher>"
        hit = self._judge(raw)
        body = ("BLOCKED " + hit if hit else "OK {MARKER}").encode()
        self.send_response(403 if hit else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", {PORT}), H).serve_forever()
'''

PAYLOAD = "' OR 1=1"

#: Each row is (shape list, what it is testing). The FIRST row is the CONTROL: unshaped, and it
#: must be BLOCKED, or the matcher is not matching and every "bypass" below is meaningless.
CASES: list[tuple[list[str], str]] = [
    ([], "CONTROL: unshaped -- must be BLOCKED or this whole run proves nothing"),
    (["url-encode"], "percent-encode everything (one decode layer at the edge)"),
    (["double-url-encode"], "encode twice -- the edge decodes once, the app decodes again"),
    (["case-vary"], "alternate case -- a probe for a case-sensitive rule"),
    (["sql-comment"], "whitespace becomes /**/, which SQL reads as a space"),
    (["whitespace-tab"], "spaces become tabs"),
    (["sql-comment", "url-encode"], "comment first, then encode the comment"),
    (["param-pollution"], "duplicate the parameter -- which copy is inspected?"),
]


def _sandbox_up() -> bool:
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", config.KALI_OPEN_CONTAINER],
            capture_output=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return (out.stdout or b"").decode("utf-8", "replace").strip() == "true"


def _start_matcher() -> bool:
    subprocess.run(
        ["docker", "exec", "-d", config.KALI_OPEN_CONTAINER,
         "python3", "-c", SERVER_SRC],
        capture_output=True, timeout=30, check=False,
    )
    for _ in range(20):
        probe = subprocess.run(
            ["docker", "exec", config.KALI_OPEN_CONTAINER, "curl", "-s", "--max-time", "3",
             f"http://127.0.0.1:{PORT}/?q=hello"],
            capture_output=True, timeout=15,
        )
        if MARKER.encode() in (probe.stdout or b""):
            return True
        time.sleep(0.5)
    return False


def _stop_matcher() -> None:
    # `pkill -f` with a pattern unique to THIS server, and bracketed so the killer's own argv
    # cannot match it. Both halves of that lesson are written up in cockpit/proxy.py.
    subprocess.run(
        ["docker", "exec", config.KALI_OPEN_CONTAINER, "pkill", "-f",
         f"[h]ackpit-build18-sigmatch"],
        capture_output=True, timeout=20, check=False,
    )


def main() -> int:
    print("=" * 74)
    print("BUILD #18 ITEM 4 -- payload shaping, measured against a naive signature matcher")
    print("=" * 74)

    if not _sandbox_up():
        print(f"VERDICT=NOT-RUN -- {config.KALI_OPEN_CONTAINER} is not running.")
        return 2
    if not _start_matcher():
        print(f"VERDICT=NOT-RUN -- the signature matcher did not come up on 127.0.0.1:{PORT}")
        _stop_matcher()
        return 2
    print(f"naive matcher up on 127.0.0.1:{PORT} inside {config.KALI_OPEN_CONTAINER}")
    print(f"payload: {PAYLOAD!r}   (marked as {shaping.SHAPE_OPEN}{PAYLOAD}{shaping.SHAPE_CLOSE})")
    print()

    rows: list[tuple[str, int, str, str]] = []
    try:
        for shapes, why in CASES:
            req = repeater.RepeaterRequest(
                method="GET",
                url=(f"http://127.0.0.1:{PORT}/search?q="
                     f"{shaping.SHAPE_OPEN}{PAYLOAD}{shaping.SHAPE_CLOSE}"),
                shapes=shapes,
            )
            sent_url, _, applied, warnings = repeater.shape_request(req)
            exchange = repeater.send(req)
            status = exchange.response.status or 0
            rows.append((",".join(shapes) or "(none)", status,
                         sent_url.split("?", 1)[-1], why))
            print(f"  {status}  {','.join(shapes) or '(none)':<28} q={sent_url.split('q=', 1)[-1]}")
            for warning in warnings:
                print(f"       warn: {warning}")
    finally:
        _stop_matcher()

    print()
    print("-" * 74)
    print(f"{'shape':<28} {'status':<8} verdict")
    print("-" * 74)
    control = rows[0]
    for name, status, _, why in rows:
        if name == "(none)":
            verdict = "BLOCKED (as required)" if status == 403 else "*** CONTROL DID NOT BLOCK ***"
        elif status == 200:
            verdict = "BYPASSES this rule"
        elif status == 403:
            verdict = "still blocked"
        else:
            verdict = f"no verdict (HTTP {status})"
        print(f"{name:<28} {status:<8} {verdict}")
        print(f"{'':<28} {'':<8} {why}")

    print()
    if control[1] != 403:
        print("VERDICT=FAIL -- the UNSHAPED control was not blocked, so the matcher never")
        print("  matched and every 200 below it means nothing. This is the same defect as")
        print("  build #17's single DOM threshold declaring both controls broken.")
        return 1

    bypassed = [n for n, s, _, _ in rows if n != "(none)" and s == 200]
    print(f"VERDICT=PASS -- control blocked; {len(bypassed)} of {len(rows) - 1} shapes turned")
    print(f"  the 403 into a 200: {bypassed}")
    print()
    print("SCOPE OF THE CLAIM: this measures the TRANSFORMS against a naive, single-decode,")
    print("case-sensitive rule. It says nothing about whether a commercial WAF is that naive,")
    print("and the assessment must not read it as though it did.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        _stop_matcher()
        print("\nVERDICT=INTERRUPTED")
        sys.exit(130)
