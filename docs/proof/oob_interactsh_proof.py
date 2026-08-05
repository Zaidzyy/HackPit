#!/usr/bin/env python3
"""LIVE proof: the interact.sh OOB backend, end to end against a public server (spec 2026-08-06).

This is the check the self-hosted canary cannot run without infrastructure, and it is the whole
reason interact.sh is worth wiring in: with NO VPS and NO domain, a real callback can be caught.

What it does, for real, over the network:
  1. register a session with a public interact.sh server (default oast.fun);
  2. generate a payload host under it and record what it is for;
  3. resolve that host through the system resolver — the query reaching interact.sh's
     authoritative DNS is the hit;
  4. poll the server, unwrap the AES key with our private key, decrypt the interaction, and
     assert it correlates back to the engagement/step that generated it;
  5. deregister and forget the session.

It uses the operator's OWN sessions.db is NOT touched: a temp database is used, so running this
never disturbs a live interact.sh session or files a finding.

This reaches the public internet (DNS + HTTPS), so it is a PROOF, not a hermetic test — the same
reason the loopback proof lives here rather than in the suite.

Run:  python docs/proof/oob_interactsh_proof.py
      python docs/proof/oob_interactsh_proof.py --server oast.pro
"""
from __future__ import annotations

import argparse
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from oob import interactsh as ish  # noqa: E402

ENGAGEMENT = "_interactsh-proof"
SETTLE_SECONDS = 3
POLL_ATTEMPTS = 6


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Live interact.sh round-trip proof")
    parser.add_argument("--server", default=ish.DEFAULT_SERVER, help="interact.sh server host")
    parser.add_argument("--auth-token", default="", help="auth token for a self-hosted server")
    args = parser.parse_args()

    print(f"== interact.sh live round-trip against {args.server} ==")
    workdir = tempfile.mkdtemp()
    ish.DB_PATH = Path(workdir) / "proof.db"
    ish.init_db()
    try:
        # 1. register
        try:
            pub = ish.register(server_host=args.server, auth_token=args.auth_token)
        except ish.InteractshError as exc:
            _fail(f"could not register with {args.server}: {exc}")
        print(f"  registered: correlation-id {pub['correlation_prefix']} on {pub['server']}")

        # 2. generate
        generated = ish.generate(ENGAGEMENT, step_id="proof-step", note="interact.sh proof")
        host, suffix = generated["host"], generated["suffix"]
        print(f"  generated host: {host}")

        # 3. trigger a callback — a DNS resolution AND an HTTP GET, so the proof lands on a
        #    network that allows either. (On a filtered network that intercepts interact.sh
        #    traffic — e.g. an EDR/DNS filter that blocklists oast.* — neither reaches the real
        #    server, and this proof correctly reports FAIL; run it from an unfiltered network.)
        print("  triggering a callback (DNS + HTTP) ...")
        try:
            socket.getaddrinfo(host, None, family=socket.AF_INET)
        except OSError:
            pass  # a DNS query that 'fails' locally may still have reached interact.sh
        try:
            import urllib.request

            urllib.request.urlopen(f"http://{host}/hp-proof", timeout=10).read()
        except Exception:
            pass  # the request reaching interact.sh's HTTP listener is the hit, not the response

        # 4. poll until it comes back
        found = None
        for attempt in range(POLL_ATTEMPTS):
            time.sleep(SETTLE_SECONDS)
            try:
                hits = ish.poll_correlated()
            except ish.InteractshError as exc:
                _fail(f"poll failed: {exc}")
            match = [h for h in hits if h.get("token") == suffix]
            if match:
                found = match[0]
                break
            print(f"    attempt {attempt + 1}/{POLL_ATTEMPTS}: no correlated hit yet")

        if not found:
            _fail(
                "resolved the host but no correlated interaction came back — outbound DNS may be "
                "blocked from this machine, or the server dropped the session"
            )

        # 5. assert correlation
        assert found["correlated"] is True, "the hit did not correlate to the mint record"
        assert found["engagement_id"] == ENGAGEMENT, "the hit correlated to the wrong engagement"
        assert found["step_id"] == "proof-step", "the hit correlated to the wrong step"
        print(f"  PASS: {found['kind'].upper()} callback from {found['source_ip']} "
              f"correlated back to {found['engagement_id']}/{found['step_id']}")
        print("PASS: interact.sh caught a real callback with no infrastructure of our own")
    finally:
        try:
            ish.deregister()
        except Exception:
            pass
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
