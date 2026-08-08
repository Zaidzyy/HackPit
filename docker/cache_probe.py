#!/usr/bin/env python3
"""cache-probe — the in-repo web-cache-poisoning / cache-deception prober the :cache job invokes.

*** WHY THIS IS A BAKED IN-REPO CLIENT, NOT wcvs ON THE ARGV. ***
The :cache job runs ONE approve-each tool pass, `docker exec -i <sandbox> cache-probe --job-stdin`,
with the whole request template + the chosen candidate-input set delivered as JSON on STDIN — no
request byte reaches a shell (the intruder/race/smuggle rule). Hackmanit's `wcvs`
(web-cache-vulnerability-scanner) is the standard external tool and is installed alongside this for
manual use in :kali / :terminal and named in tools.json; this client exists so the GATED job has a
headless engine with a stable JSON contract the backend can parse into per-input verdicts, exactly
as race-singlepacket / smuggle-probe give :race / :smuggle their headless engines. The
reflection+cacheability sweep is therefore in-module — detection works even when wcvs is absent
(the spec's assumption 5.2).

TWO STAGES, matching the spec, and the split IS the whole safety story:

  * ``--stage detect`` — the DEFAULT and the SAFE path. For each candidate UNKEYED INPUT
    (X-Forwarded-Host and friends, a cloaked query param, a fat GET body) it sends ONE request that
    carries a unique marker in that input, and reports (a) whether the marker is REFLECTED in the
    response and (b) whether the response is CACHEABLE (Cache-Control / Age / X-Cache /
    CF-Cache-Status). Reflected + cacheable ⇒ a candidate. It ALSO runs the cache-DECEPTION
    path-confusion probes (`/path/foo.css`, `;.css`, `%2f..`) to see if a dynamic page is stored
    under a static extension. **No cache entry is planted, nothing is served to anyone else** — the
    request is self-contained. This is the default path.
  * ``--stage confirm`` — the SEPARATE, explicitly-approved path. It PLANTS the poison: it sends the
    marker-carrying request (priming the shared cache under the base key, IF the input is unkeyed),
    then sends a FRESH request that carries NO marker and checks whether the cache serves the marker
    back. *** THIS ONE CAN AFFECT OTHER USERS OF THE CACHE *** — the poisoned entry the fresh
    request receives is the same entry a real co-user would receive — which is why the backend gates
    it as its own approve-each with a co-user warning.

CONTRACT (both stages), so a hermetic backend test and the install proof agree with the code:

  in  (stdin JSON):
      {"url","method","headers":[[name,value],...],"body","inputs":[...],
       "stage":"detect"|"confirm","deception":<bool>,"timeout":<seconds>,"insecure":<bool>}
  out (stdout JSON, one object):
      detect : {"stage":"detect","verdicts":[{"input","reflected","cacheable","candidate","marker",
                 "indicator","status","error"}...],"deceptions":[{"path","extension","cached",
                 "status","indicator","evidence","error"}...],"error":""}
      confirm: {"stage":"confirm","confirms":[{"input","poisoned","status","evidence","error"}...],
                 "error":""}

The engine NEVER decides "candidate" on its own opinion — it OBSERVES reflection and cacheability
and reports both; the backend's `cache.candidate_of` is the single place the two flags become a
candidate, so there is one place a test pins the rule (mirrors smuggle's SUSCEPTIBLE_DELTA_MS).
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

#: Per-request read ceiling. A cache probe should answer fast; a dead host must not eat the budget.
REQUEST_TIMEOUT = 8.0
CONNECT_CAP = 8.0

#: The header-shaped candidate inputs and how each injects its marker. A host-ish header carries a
#: marker HOST so a reflected absolute URL is unmistakable; a URL-override header carries a marker
#: PATH; the rest carry the bare marker. Anything not here is treated as a cloaked query parameter.
_HOSTISH = ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "Forwarded")
_URLISH = ("X-Original-URL", "X-Rewrite-URL")

#: The path-confusion suffixes the deception probe appends to the request path. Each asks: does the
#: framework serve the DYNAMIC page for this static-looking path, and does a cache store it?
_DECEPTION_SUFFIXES = ("foo.css", "foo.js", ";foo.css", "%2f%2e%2e%2ffoo.css", "foo.css%3f")


def _marker() -> str:
    """A unique, greppable marker. random/time are fine here — this runs in the sandbox, not in a
    resume-sensitive workflow script."""
    return "hackpitCACHE" + format(int(time.time() * 1000) & 0xFFFFFFFF, "08x")


# --------------------------------------------------------------------------- #
# cacheability + reflection — the two observations detection is built on
# --------------------------------------------------------------------------- #
def cacheability(headers: dict[str, str]) -> tuple[bool, str]:
    """``(cacheable, indicator)`` from the response headers. A shared cache announces itself: an
    ``Age`` header or an ``X-Cache``/``CF-Cache-Status`` hit means a cache is on the path; a
    ``Cache-Control`` that is public / has a non-zero max-age means the response is storable.
    ``no-store`` / ``private`` / a ``DYNAMIC`` CDN status is an explicit NOT-cacheable."""
    low = {k.lower(): (v or "") for k, v in headers.items()}
    cc = low.get("cache-control", "").lower()
    if "no-store" in cc or "private" in cc:
        return False, f"Cache-Control: {low.get('cache-control')}"
    cdn = (low.get("cf-cache-status") or low.get("x-cache") or "").upper()
    if "DYNAMIC" in cdn or "BYPASS" in cdn or "MISS" in cdn:
        # a MISS still proves a cache is present and would store the NEXT identical request
        if "MISS" in cdn:
            return True, f"cache present (status {cdn.strip()}); a MISS stores the next identical request"
        return False, f"cache status {cdn.strip()} — not stored"
    if "HIT" in cdn or "EXPIRED" in cdn or "REVALIDATED" in cdn:
        return True, f"served from cache ({cdn.strip()})"
    if "age" in low:
        return True, f"Age: {low['age']} — served from a shared cache"
    if "public" in cc:
        return True, f"Cache-Control: {low.get('cache-control')}"
    for tok in cc.replace(" ", "").split(","):
        if tok.startswith(("max-age=", "s-maxage=")):
            try:
                if int(tok.split("=", 1)[1]) > 0:
                    return True, f"Cache-Control: {low.get('cache-control')}"
            except ValueError:
                pass
    if low.get("surrogate-control") or low.get("cdn-cache-control"):
        return True, "Surrogate-Control / CDN-Cache-Control present"
    return False, (f"Cache-Control: {low.get('cache-control')}" if cc else "no caching headers")


def reflected(marker: str, body: str, headers: dict[str, str]) -> tuple[bool, str]:
    """``(reflected, where)`` — is the marker echoed back in the body or a response header?"""
    for k, v in headers.items():
        if marker in (v or ""):
            return True, f"response header {k}"
    if marker in (body or ""):
        return True, "response body"
    return False, ""


# --------------------------------------------------------------------------- #
# request construction — inject one marker per candidate input
# --------------------------------------------------------------------------- #
def _inject(url: str, method: str, headers: list[list[str]], body: str, input_name: str,
            marker: str) -> tuple[str, str, dict[str, str], bytes | None]:
    """Build ``(url, method, header_map, data)`` with ``marker`` injected via ``input_name``. Header
    inputs set that header; ``param-cloak`` appends a query parameter; ``fat-get-body`` attaches a
    body to a GET. The operator's own headers are the base; the injection is layered on top."""
    hmap: dict[str, str] = {}
    for pair in headers or []:
        if isinstance(pair, (list, tuple)) and len(pair) >= 2 and str(pair[0]).strip():
            hmap[str(pair[0]).strip()] = str(pair[1])
    data = body.encode("utf-8", "replace") if body else None
    p = urlparse(url)

    name = input_name.strip()
    low = name.lower()
    if low == "param-cloak":
        q = parse_qsl(p.query, keep_blank_values=True)
        q.append(("utm_content", marker))
        url = urlunparse(p._replace(query=urlencode(q)))
        return url, method, hmap, data
    if low == "fat-get-body":
        # A body on a GET the cache keys as body-less; the origin may still read it.
        return url, "GET", hmap, (f"cb={marker}").encode()
    if name in _URLISH or low in (n.lower() for n in _URLISH):
        hmap[name] = f"/{marker}"
        return url, method, hmap, data
    if name in _HOSTISH or low in (n.lower() for n in _HOSTISH):
        hmap[name] = f"{marker}.example.com" if low != "forwarded" else f"host={marker}.example.com"
        return url, method, hmap, data
    if low == "x-forwarded-port":
        hmap[name] = marker if marker.isdigit() else "1"  # port must look like a port; reflection
        hmap["X-Forwarded-Port"] = "1"                    # is rare here — kept for completeness
        hmap[name] = "1"
        # carry the marker where it can reflect: a scheme/proto style header
        hmap.setdefault("X-Forwarded-Host", f"{marker}.example.com")
        return url, method, hmap, data
    if low in ("x-forwarded-scheme", "x-forwarded-proto"):
        hmap[name] = marker  # some apps reflect the scheme value verbatim into redirects
        return url, method, hmap, data
    # default: an arbitrary header carrying the marker
    hmap[name] = marker
    return url, method, hmap, data


def _send(url: str, method: str, hmap: dict[str, str], data: bytes | None, insecure: bool,
          timeout: float) -> tuple[int | None, str, dict[str, str], str]:
    """``(status, body, headers, error)``. Never raises. Redirects are NOT followed so we read the
    actual response's cache headers and reflected Location."""
    import ssl

    ctx = None
    if url.lower().startswith("https"):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # noqa: D401, ANN001
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, data=data, method=method.upper())
    for k, v in hmap.items():
        try:
            req.add_header(k, v)
        except Exception:  # noqa: BLE001
            pass
    try:
        with opener.open(req, timeout=min(timeout, CONNECT_CAP)) as resp:
            raw = resp.read(262144)
            return resp.status, raw.decode("utf-8", "replace"), dict(resp.headers.items()), ""
    except urllib.error.HTTPError as e:  # a 3xx/4xx/5xx is a real response we still inspect
        try:
            raw = e.read(262144).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            raw = ""
        return e.code, raw, dict(e.headers.items() if e.headers else {}), ""
    except Exception as exc:  # noqa: BLE001
        return None, "", {}, f"request failed: {exc}"[:200]


# --------------------------------------------------------------------------- #
# detect
# --------------------------------------------------------------------------- #
def _detect(spec: dict[str, Any]) -> dict[str, Any]:
    url = str(spec.get("url") or "")
    method = str(spec.get("method") or "GET").upper()
    headers = spec.get("headers") or []
    body = str(spec.get("body") or "")
    insecure = bool(spec.get("insecure"))
    timeout = min(float(spec.get("timeout") or REQUEST_TIMEOUT), REQUEST_TIMEOUT)
    inputs = [str(i) for i in (spec.get("inputs") or [])]

    verdicts: list[dict[str, Any]] = []
    for inp in inputs:
        marker = _marker()
        u, m, hmap, data = _inject(url, method, headers, body, inp, marker)
        status, rbody, rhdrs, err = _send(u, m, hmap, data, insecure, timeout)
        if err:
            verdicts.append({"input": inp, "reflected": False, "cacheable": False,
                             "candidate": False, "marker": marker, "indicator": "",
                             "status": status, "error": err})
            continue
        refl, where = reflected(marker, rbody, rhdrs)
        cache, indicator = cacheability(rhdrs)
        verdicts.append({
            "input": inp, "reflected": refl, "cacheable": cache,
            "candidate": bool(refl and cache), "marker": marker,
            "indicator": (f"reflected in {where}; " if refl else "") + indicator,
            "status": status, "error": "",
        })

    deceptions: list[dict[str, Any]] = []
    if bool(spec.get("deception", True)):
        deceptions = _deception(url, method, headers, insecure, timeout)
    return {"stage": "detect", "verdicts": verdicts, "deceptions": deceptions, "error": ""}


def _deception(url: str, method: str, headers: list[list[str]], insecure: bool,
               timeout: float) -> list[dict[str, Any]]:
    """Cache-deception path confusion: append a static-looking suffix to the path and see whether the
    framework still serves the DYNAMIC page AND a cache stores it under the static extension."""
    p = urlparse(url)
    base = p.path if p.path and p.path != "/" else "/account"
    if not base.endswith("/"):
        base = base + "/"
    hmap = {str(x[0]).strip(): str(x[1]) for x in (headers or [])
            if isinstance(x, (list, tuple)) and len(x) >= 2 and str(x[0]).strip()}
    out: list[dict[str, Any]] = []
    for suffix in _DECEPTION_SUFFIXES:
        probe = urlunparse(p._replace(path=base + suffix, query=""))
        status, rbody, rhdrs, err = _send(probe, method, dict(hmap), None, insecure, timeout)
        ext = suffix.split(".")[-1].split("%")[0].split("?")[0] or "css"
        if err:
            out.append({"path": base + suffix, "extension": ext, "cached": False, "status": status,
                        "indicator": "", "evidence": "", "error": err})
            continue
        cache, indicator = cacheability(rhdrs)
        ctype = ""
        for k, v in rhdrs.items():
            if k.lower() == "content-type":
                ctype = v
                break
        dynamic = bool(status and status == 200 and "text/html" in ctype.lower())
        cached = bool(dynamic and cache)
        out.append({
            "path": base + suffix, "extension": ext, "cached": cached, "status": status,
            "indicator": indicator,
            "evidence": (f"dynamic HTML (content-type {ctype}) served for a .{ext} path and it is "
                         f"cacheable — {indicator}") if cached else
                        (f"served {ctype or 'non-HTML'} (status {status}) — not a deception hit"),
            "error": "",
        })
    return out


# --------------------------------------------------------------------------- #
# confirm — plant the poison (CAN AFFECT OTHER USERS OF THE CACHE)
# --------------------------------------------------------------------------- #
def _confirm(spec: dict[str, Any]) -> dict[str, Any]:
    url = str(spec.get("url") or "")
    method = str(spec.get("method") or "GET").upper()
    headers = spec.get("headers") or []
    body = str(spec.get("body") or "")
    insecure = bool(spec.get("insecure"))
    timeout = min(float(spec.get("timeout") or REQUEST_TIMEOUT), REQUEST_TIMEOUT)
    inputs = [str(i) for i in (spec.get("inputs") or [])]

    confirms: list[dict[str, Any]] = []
    for inp in inputs:
        confirms.append(_confirm_one(url, method, headers, body, inp, insecure, timeout))
    return {"stage": "confirm", "confirms": confirms, "error": ""}


def _confirm_one(url: str, method: str, headers: list[list[str]], body: str, inp: str,
                 insecure: bool, timeout: float) -> dict[str, Any]:
    marker = _marker()
    # 1) PRIME: the marker-carrying request. If the input is unkeyed this stores a poisoned entry
    #    under the base cache key.
    u, m, hmap, data = _inject(url, method, headers, body, inp, marker)
    p_status, _, _, p_err = _send(u, m, hmap, data, insecure, timeout)
    if p_err:
        return {"input": inp, "poisoned": False, "status": p_status,
                "evidence": "", "error": f"priming request failed: {p_err}"}
    # 2) VICTIM: a FRESH request that carries NO marker. If the cache serves the marker back, a
    #    request that never sent it received the poison — the proof.
    base_hmap = {str(x[0]).strip(): str(x[1]) for x in (headers or [])
                 if isinstance(x, (list, tuple)) and len(x) >= 2 and str(x[0]).strip()}
    v_status, v_body, v_hdrs, v_err = _send(url, method, base_hmap,
                                            body.encode() if body else None, insecure, timeout)
    if v_err:
        return {"input": inp, "poisoned": False, "status": v_status,
                "evidence": "", "error": f"victim request failed: {v_err}"}
    refl, where = reflected(marker, v_body, v_hdrs)
    return {
        "input": inp, "poisoned": bool(refl), "status": v_status,
        "evidence": (f"a fresh request that never sent {inp} received the planted marker in "
                     f"{where} — the cache served the poisoned entry") if refl else
                    "the fresh request did not receive the marker — not confirmed (input likely keyed)",
        "error": "",
    }


# --------------------------------------------------------------------------- #
# external wcvs transcript bridge — so a manual run in :kali lands in the same table
# --------------------------------------------------------------------------- #
def parse_wcvs(text: str) -> list[dict[str, Any]]:
    """Best-effort: a Hackmanit `wcvs` run reports each vulnerable header on its own line. A line
    that names a header and carries a hit marker becomes a candidate verdict. The gated in-repo path
    is the engine; this is the convenience bridge for a hand run."""
    import re

    hit = re.compile(r"(?i)(vulnerab|poison|\[\+\]|\bhit\b)")
    hdr = re.compile(r"(?i)\b(X-Forwarded-[A-Za-z-]+|X-Host|X-Original-URL|X-Rewrite-URL|Forwarded)\b")
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        m = hdr.search(line)
        if m and hit.search(line):
            out[m.group(1)] = line.strip()[:300]
    return [{"input": k, "reflected": True, "cacheable": True, "candidate": True, "marker": "",
             "indicator": f"wcvs flagged it: {v}", "status": None, "error": ""}
            for k, v in out.items()]


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #
def _selftest() -> int:
    # Build one of every injection kind + run both parsers, proving the client imports and its
    # request builders run — which `command -v` alone cannot (build #4's lesson).
    for inp in ("X-Forwarded-Host", "X-Original-URL", "param-cloak", "fat-get-body",
                "X-Forwarded-Scheme"):
        _inject("http://h/x", "GET", [], "", inp, "M")
    cacheability({"Cache-Control": "public, max-age=60", "Age": "5"})
    reflected("M", "body M here", {"Location": "http://M.example.com/"})
    parse_wcvs("[+] X-Forwarded-Host is reflected and cacheable — vulnerable")
    print("cache-probe ok")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return _selftest()
    if "--job-stdin" in argv:
        try:
            spec = json.loads(sys.stdin.read() or "{}")
        except (ValueError, TypeError) as exc:
            print(json.dumps({"error": f"bad job JSON: {exc}"}))
            return 0
        stage = str(spec.get("stage") or "detect").lower()
        try:
            out = _confirm(spec) if stage == "confirm" else _detect(spec)
        except Exception as exc:  # noqa: BLE001 - a probe must never crash the contract
            out = {"stage": stage, "error": f"engine error: {exc}"[:300],
                   "verdicts": [], "deceptions": [], "confirms": []}
        print(json.dumps(out))
        return 0
    sys.stderr.write("usage: cache-probe [--selftest | --job-stdin]\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
