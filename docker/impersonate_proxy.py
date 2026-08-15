"""HackPit impersonating upstream — a mitmproxy addon.

The active discovery tools (ffuf, feroxbuster, arjun) each speak their own TLS, so a WAF that
fingerprints the handshake (Cloudflare/Akamai JA3) 403s them before request one — the same wall
js-mine/repeater/graphql now clear with curl-impersonate. Those tools can't impersonate
themselves, so the impersonation goes in a PROXY they route through:

  tool  --(plain/its-own-TLS, verify skipped)-->  mitmproxy (this addon)  --(Chrome JA3 via
  curl_cffi)-->  target

mitmproxy terminates the tool's connection (its own on-the-fly cert; the fuzzers skip verification
or run -k). This addon does the REAL upstream leg with curl_cffi's Chrome fingerprint and hands
the response back, so the target sees a browser handshake. It OBSERVES and forwards — it decides
no scope (the backend scope-locks the discover target; the proxy only re-fingerprints).

Baked into the sandbox image and launched by ``impersonate-proxy``; started lazily by the
:discover worker only when the operator ticks 'impersonate'. Beats JA3 (wall 1), NOT a JS
challenge / Turnstile (wall 2) — that needs a real browser and is impractical for bulk fuzzing.
"""
from __future__ import annotations

from mitmproxy import http

try:
    from curl_cffi import requests as _cffi
except Exception:  # pragma: no cover - the image installs it; a missing dep fails loud per-request
    _cffi = None

#: Which browser to impersonate. Chrome 116 matches the curl_chrome116 wrapper the rest of the
#: stack uses, so every surface presents the same fingerprint.
IMPERSONATE = "chrome116"

#: Request headers curl_cffi's impersonation OWNS — drop the tool's versions so the browser set is
#: sent on the wire (a fuzzer's User-Agent would otherwise undo half the disguise).
_DROP_REQ = {
    "user-agent", "accept", "accept-encoding", "accept-language", "connection",
    "proxy-connection", "host", "content-length", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-ch-ua-platform", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    "sec-fetch-user", "upgrade-insecure-requests",
}
#: Response headers that describe an encoding/length curl_cffi ALREADY resolved (it returns the
#: decoded body). Forwarding them would make the tool try to gunzip an already-decoded body;
#: mitmproxy recomputes content-length from the body we hand it.
_DROP_RESP = {"content-encoding", "transfer-encoding", "content-length", "connection"}


def request(flow: http.HTTPFlow) -> None:
    """Short-circuit the upstream: fetch via curl_cffi (browser JA3) and set the response, so
    mitmproxy never makes its own (plain-fingerprint) upstream connection.

    The hook is fully guarded: if it ever RAISED, mitmproxy would silently fall back to its own
    non-impersonated upstream (defeating the whole purpose — and a 403 that looks like the target's
    answer). So any failure returns a LOUD 502 instead. This is not defensive noise: the first
    version threw 'Header fields must be bytes' from Response.make and every request quietly went
    out un-impersonated and got 403'd."""
    if _cffi is None:
        flow.response = http.Response.make(502, b"curl_cffi unavailable in the proxy", {})
        return
    try:
        req = flow.request
        headers = {k: v for k, v in req.headers.items() if k.lower() not in _DROP_REQ}
        r = _cffi.request(
            req.method, req.url, headers=headers,
            data=req.raw_content or None,
            impersonate=IMPERSONATE, allow_redirects=False, verify=False, timeout=30,
        )
        pairs = list(r.headers.multi_items()) if hasattr(r.headers, "multi_items") \
            else list(r.headers.items())
        # mitmproxy's Response.make wants header fields as BYTES; curl_cffi hands back str. HTTP
        # headers are latin-1. Encoding here is the fix — without it the hook threw and mitmproxy
        # fell back to a plain-fingerprint upstream that Cloudflare 403'd.
        resp_headers = [
            (k.encode("latin-1", "replace"), v.encode("latin-1", "replace"))
            for k, v in pairs if k.lower() not in _DROP_RESP
        ]
        flow.response = http.Response.make(r.status_code, r.content, resp_headers)
    except Exception as exc:  # NEVER raise: a silent fall-through to a non-impersonated upstream
        flow.response = http.Response.make(502, f"impersonate proxy error: {exc}".encode(), {})
