#!/usr/bin/env python3
"""In-container probe for the :jsrecon Cloudflare-403 fix.

Runs INSIDE hackpit/kali-sandbox:m1 (the only place curl_chrome116 lives). Drives the SAME
collect -> mine pipeline the :jsrecon surface runs, against the in-scope Fishbowl bundle:

  * BEFORE the fix, js-mine fetched with stdlib urllib; Cloudflare fingerprints the TLS
    handshake (JA3) and 403'd it, so collect returned no JS and mine returned results:[].
  * AFTER the fix, js-mine fetches through curl-impersonate (browser JA3), clears Cloudflare,
    collect finds the bundles and mine extracts endpoints.

Endpoints > 0 == PASS. Read-only recon (two GETs of public JS), in the authorized program scope.
"""
import json
import shutil
import subprocess
import sys

SEED = "https://www.fishbowlapp.com/feed"


def jsmine(job: dict) -> dict:
    p = subprocess.run(["js-mine", "--job-stdin"], input=json.dumps(job),
                       capture_output=True, text=True, timeout=90)
    try:
        return json.loads(p.stdout or "{}")
    except ValueError:
        print("  js-mine did not return JSON:", (p.stdout or p.stderr)[:200])
        return {}


def main() -> int:
    print("curl_chrome116:", shutil.which("curl_chrome116") or "MISSING (fix cannot work)")
    st = subprocess.run(["js-mine", "--selftest"], capture_output=True, text=True)
    print("selftest:", (st.stdout or st.stderr).strip())

    c = jsmine({"action": "collect", "seed_urls": [SEED]})
    urls = c.get("js_urls", [])
    print("collect errors:", c.get("errors"))
    print("js_urls discovered:", len(urls))
    for u in urls[:8]:
        print("   ", u)
    if not urls:
        print("RESULT: FAIL — collect still returned no JS (Cloudflare still blocking the fetch?)")
        return 1

    m = jsmine({"action": "mine", "js_urls": urls[:3], "verify": False, "maps": False})
    eps = [e for r in m.get("results", []) for e in r.get("endpoints", [])]
    errs = [r.get("error") for r in m.get("results", []) if r.get("error")]
    print("mine per-url errors:", errs)
    print("endpoints mined:", len(eps))
    for e in eps[:12]:
        print("   ", e)
    ok = bool(eps)
    print("RESULT:", "PASS — js-mine cleared Cloudflare and mined endpoints"
          if ok else "FAIL — mine still empty")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
