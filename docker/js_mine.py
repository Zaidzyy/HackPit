#!/usr/bin/env python3
"""js-mine — the in-repo JavaScript-recon engine the :jsrecon job invokes.

*** WHY THIS IS A BAKED IN-REPO ENGINE, NOT getjs/LinkFinder/SecretFinder ON THE ARGV. ***
The :jsrecon job runs ONE approve-each pass, ``docker exec -i <engage sandbox> js-mine --job-stdin``,
with the (already scope-filtered) JS URL set delivered as JSON on STDIN — no URL byte reaches a
shell (the intruder/race/smuggle/cache rule). getjs/subjs (collect), LinkFinder (endpoints),
SecretFinder (regex secrets), trufflehog / gitleaks (high-signal + verified) and sourcemapper (map
unpack) are the standard external tools; they are installed alongside this for MANUAL use in
:kali / :terminal and named in tools.json. This engine exists so the GATED job has a headless engine
with a stable JSON contract the backend can parse into typed records, exactly as
cache-probe / race-singlepacket / smuggle-probe give :cache / :race / :smuggle their engines. The
mining is therefore in-module — it works even when the external tools are absent — and trufflehog is
folded in BEST-EFFORT to mark VERIFIED keys when it is present (the spec's high-signal path).

TWO ACTIONS, matching the spec's collect→fetch→mine flow, and the split keeps scope-safety where it
belongs — in the BACKEND, which filters between the two calls:

  * ``--action collect`` — given seed page URLs, fetch each and list the JavaScript URLs it loads
    (``<script src>`` resolved to absolute, plus any seed that is itself a ``.js``). It DECIDES
    NOTHING about scope; it just lists. The backend scope-filters the returned list before handing
    the in-scope subset back for mining, so only in-scope JS is ever fetched — by construction.
  * ``--action mine`` — given a JS URL set (the in-scope subset), fetch each and mine it:
    ENDPOINTS/paths (LinkFinder-style regex, relatives resolved against the JS origin so the backend
    can scope-filter them), PARAMETER names, SECRETS / API keys (a SecretFinder-style regex set),
    and — when the JS advertises a ``sourceMappingURL`` — the SOURCE MAP is fetched and its original
    source paths + comments recovered, and its ``sourcesContent`` mined too. trufflehog, if present,
    runs over the downloaded JS and its VERIFIED hits are merged and flagged.

CONTRACT (so a hermetic backend test and the install proof agree with the code):

  in  (stdin JSON):
      {"action":"collect","seed_urls":[...],"timeout":<s>,"insecure":<bool>}
      {"action":"mine","js_urls":[...],"maps":<bool>,"verify":<bool>,"timeout":<s>,"insecure":<bool>}
  out (stdout JSON, one object):
      collect: {"action":"collect","js_urls":[...],"errors":[...]}
      mine   : {"action":"mine","results":[{"url","endpoints":[abs...],"params":[name...],
                 "secrets":[{"type","value","verified","context"}...],
                 "source_map":{"map_url","recovered_sources":[...],"comments":[...]},"error"}...],
                 "error":""}

THE ENGINE NEVER DECIDES SCOPE and never writes loot: it OBSERVES what a JS file contains and reports
it; the backend owns the scope filter (twice — which JS to fetch, which mined host to keep) and the
secret→loot handling. This mirrors cache-probe reporting reflection+cacheability while
``cache.candidate_of`` owns the verdict.

Stdlib only (json, re, ssl, urllib, subprocess for the OPTIONAL trufflehog) — no venv, no third-party
deps — so the wrapper execs the system python3 directly.
"""
from __future__ import annotations

import json
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urljoin, urlparse

#: Per-fetch read ceiling. A JS bundle can be large but a recon fetch should not run forever.
REQUEST_TIMEOUT = 12.0
#: Never mine more than this many bytes of one file — a hostile server could stream forever.
MAX_BYTES = 8 * 1024 * 1024
#: Cap the mined lists per file so one giant bundle cannot produce an unbounded result blob.
MAX_ENDPOINTS = 2000
MAX_PARAMS = 500
MAX_SECRETS = 300


# --------------------------------------------------------------------------- #
# SECRETS — a SecretFinder-style high-signal regex set. Each entry is (type, compiled).
# High-signal, provider-specific patterns first (few false positives); the generic
# assignment pattern last (broader, marked as such by its type name).
# --------------------------------------------------------------------------- #
_SECRET_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("google-oauth-token", re.compile(r"\bya29\.[0-9A-Za-z_\-]+")),
    ("gcp-service-account", re.compile(r'"type"\s*:\s*"service_account"')),
    ("github-token", re.compile(r"\bgh[opsur]_[0-9A-Za-z]{36,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+")),
    ("stripe-secret-key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b")),
    ("stripe-pub-key", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b")),
    ("twilio-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[\w_\-]{22}\.[\w_\-]{43}\b")),
    ("mailgun-key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("square-token", re.compile(r"\b(?:sq0atp|sq0csp)-[0-9A-Za-z_\-]{22,}\b")),
    ("npm-token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("firebase-db", re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    # GENERIC assignment — an api_key/secret/token/password set to a long-ish literal. Broader, so it
    # is deliberately last and named 'generic-*' so the backend/operator treats it as lower-signal.
    ("generic-api-key", re.compile(
        r"""(?i)(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|"""
        r"""secret[_-]?key|client[_-]?secret|x-api-key)['"]?\s*[:=]\s*['"]([0-9A-Za-z\-_./+=]{16,})['"]""")),
]

#: A private key body is captured whole (multi-line) so the value in loot is usable.
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    re.S,
)

# --------------------------------------------------------------------------- #
# ENDPOINTS — a LinkFinder-style regex. Captures quoted paths, filenames-with-extension,
# REST-looking segments and bare absolute URLs. Relatives are resolved by the caller.
# --------------------------------------------------------------------------- #
_ENDPOINT_RE = re.compile(
    r"""(?:"|'|`)(
        (?:https?:)?//[^"'`\s><;()]{2,}                              # //host/... or https://host/...
        |
        /[a-zA-Z0-9_?&=#.\-/~%]{1,}                                  # a rooted /path (with query/frag)
        |
        \.\.?/[a-zA-Z0-9_?&=#.\-/~%]{1,}                             # ./ or ../ relative path
        |
        [a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:php|asp|aspx|jsp|do|action|json|xml|rss|txt|do)(?:[?#][^"'`]{0,}|)
        |
        [a-zA-Z0-9_\-]{1,}/[a-zA-Z0-9_\-/]{2,}(?:[?#][^"'`]{0,}|)    # segment/segment REST endpoint
    )(?:"|'|`)""",
    re.X,
)
#: A JS bundle's source-map pointer (LAST occurrence wins, per the spec).
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
#: A quick sieve for obvious non-endpoints the broad patterns can catch (mime types, dates, versions).
_ENDPOINT_REJECT = re.compile(r"^(?:image|text|application|audio|video|font|multipart)/|^\d+/\d+$")


def _now_ctx(text: str, start: int, end: int, width: int = 40) -> str:
    """A short, single-line snippet around a match — for the loot record, never a finding."""
    a = max(0, start - width)
    b = min(len(text), end + width)
    snippet = text[a:b].replace("\n", " ").replace("\r", " ")
    return re.sub(r"\s+", " ", snippet).strip()[:160]


def _query_param_names(path: str) -> list[str]:
    """Distinct query-parameter NAMES in a path/URL (never the values), order-preserved."""
    if "?" not in path:
        return []
    query = path.split("?", 1)[1].split("#", 1)[0]
    out: list[str] = []
    for pair in query.split("&"):
        if not pair:
            continue
        key = pair.split("=", 1)[0].strip()
        if key and key not in out:
            out.append(key)
    return out


def extract_script_srcs(html: str, base_url: str) -> list[str]:
    """Absolute JS URLs a page loads: ``<script src=...>`` resolved against the page URL.

    Only http(s) results are kept; a data: or javascript: src is dropped. Order-preserved, deduped.
    """
    out: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"""<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""",
                         html, re.I):
        raw = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        if not raw:
            continue
        absu = urljoin(base_url, raw)
        p = urlparse(absu)
        if p.scheme in ("http", "https") and absu not in seen:
            seen.add(absu)
            out.append(absu)
    return out


def _resolve_endpoint(raw: str, base_url: str) -> str:
    """Resolve one mined endpoint string to an absolute http(s) URL against the JS origin.

    A bare ``//host/..`` gets the base scheme; a rooted or relative path is joined to the JS URL so it
    lands on the JS's own (in-scope) origin. Returns '' for anything that does not resolve to http(s).
    """
    raw = raw.strip()
    if not raw or _ENDPOINT_REJECT.match(raw):
        return ""
    if raw.startswith("//"):
        scheme = urlparse(base_url).scheme or "https"
        raw = f"{scheme}:{raw}"
    absu = urljoin(base_url, raw)
    p = urlparse(absu)
    if p.scheme in ("http", "https") and p.netloc:
        return absu
    return ""


def mine_js(text: str, base_url: str) -> dict[str, Any]:
    """Mine one JS blob: endpoints (absolute), param names, secrets. PURE — no I/O.

    Endpoints are resolved against ``base_url`` (the JS URL) so a relative ``/api/x`` becomes the
    JS origin's absolute URL and the backend can scope-filter it. Secrets carry the raw VALUE and a
    short context snippet; the backend masks the value out of any finding and writes it to loot.
    """
    endpoints: list[str] = []
    ep_seen: set[str] = set()
    params: list[str] = []
    param_seen: set[str] = set()

    for m in _ENDPOINT_RE.finditer(text):
        absu = _resolve_endpoint(m.group(1), base_url)
        if not absu or absu in ep_seen:
            continue
        ep_seen.add(absu)
        endpoints.append(absu)
        for name in _query_param_names(absu):
            if name not in param_seen:
                param_seen.add(name)
                params.append(name)
        if len(endpoints) >= MAX_ENDPOINTS:
            break

    secrets: list[dict[str, Any]] = []
    sec_seen: set[tuple[str, str]] = set()

    def _add_secret(stype: str, value: str, ctx: str) -> None:
        value = value.strip()
        if not value:
            return
        key = (stype, value)
        if key in sec_seen or len(secrets) >= MAX_SECRETS:
            return
        sec_seen.add(key)
        secrets.append({"type": stype, "value": value, "verified": False, "context": ctx})

    for stype, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            # For patterns with a capture group (generic assignment), the value is group 1; otherwise
            # the whole match IS the secret.
            value = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
            _add_secret(stype, value, _now_ctx(text, m.start(), m.end()))
    for m in _PRIVATE_KEY_BLOCK.finditer(text):
        _add_secret("private-key", m.group(0), "PEM private key block")

    return {"endpoints": endpoints[:MAX_ENDPOINTS],
            "params": params[:MAX_PARAMS], "secrets": secrets[:MAX_SECRETS]}


def parse_source_map(text: str, map_url: str) -> dict[str, Any]:
    """A .map JSON -> recovered original source paths + comments mined from ``sourcesContent``.

    ``sources`` are the original file paths webpack/rollup emitted (``src/api/client.ts`` etc.); those
    are the real recovery. ``sourcesContent`` (when present) is the original source, which is mined for
    MORE endpoints/secrets by the caller. Fails soft — a malformed map returns empty lists.
    """
    out = {"map_url": map_url, "recovered_sources": [], "comments": [], "sources_content": []}
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return out
    if not isinstance(doc, dict):
        return out
    srcs = doc.get("sources")
    if isinstance(srcs, list):
        out["recovered_sources"] = [str(s) for s in srcs if isinstance(s, (str, int))][:500]
    content = doc.get("sourcesContent")
    if isinstance(content, list):
        joined = "\n".join(c for c in content if isinstance(c, str))
        out["sources_content"] = [joined] if joined else []
        # Recover top-of-file comments (a banner, an author note, a leftover TODO) — the first few
        # comment lines across the recovered sources.
        comments: list[str] = []
        for c in content:
            if not isinstance(c, str):
                continue
            for cm in re.finditer(r"/\*.*?\*/|//[^\n]{4,}", c[:4000], re.S):
                line = re.sub(r"\s+", " ", cm.group(0)).strip()[:200]
                if line and line not in comments:
                    comments.append(line)
                if len(comments) >= 40:
                    break
            if len(comments) >= 40:
                break
        out["comments"] = comments
    return out


# --------------------------------------------------------------------------- #
# fetch — the only I/O. Not used by the selftest, which mines fixture text.
# --------------------------------------------------------------------------- #
def _ctx(insecure: bool) -> "ssl.SSLContext | None":
    if not insecure:
        return None
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _fetch(url: str, timeout: float, insecure: bool) -> tuple[str, str]:
    """Fetch a URL -> (text, error). NEVER follows to a new host is not enforced here — the backend
    only ever hands in-scope URLs — but the read is byte-capped and time-bounded. Never raises."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hackpit-js-mine/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx(insecure)) as resp:
            raw = resp.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raw = raw[:MAX_BYTES]
        return raw.decode("utf-8", "replace"), ""
    except urllib.error.HTTPError as exc:
        return "", f"HTTP {exc.code}"
    except (urllib.error.URLError, ValueError, OSError) as exc:
        return "", str(getattr(exc, "reason", exc))[:200]
    except Exception as exc:  # noqa: BLE001 - a fetch must never take the engine down
        return "", str(exc)[:200]


def _trufflehog_verify(js_url: str, text: str, timeout: float) -> list[dict[str, Any]]:
    """BEST-EFFORT: write the JS to a temp file and let trufflehog flag VERIFIED secrets in it.

    trufflehog is the spec's high-signal / verified path. If it is absent or errors, this returns []
    and the regex secrets stand alone — the engine still works without it. Verified hits carry the
    detector name as the type and ``verified=True`` so the backend can rank them High.
    """
    exe = shutil.which("trufflehog")
    if not exe:
        return []
    out: list[dict[str, Any]] = []
    try:
        with tempfile.TemporaryDirectory() as d:
            path = f"{d}/bundle.js"
            with open(path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(text)
            proc = subprocess.run(
                [exe, "filesystem", d, "--json", "--no-update"],
                capture_output=True, text=True, timeout=max(20.0, timeout * 2),
            )
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(obj, dict):
                continue
            raw = obj.get("Raw") or obj.get("RawV2") or obj.get("Redacted") or ""
            detector = obj.get("DetectorName") or obj.get("DetectorType") or "trufflehog"
            verified = bool(obj.get("Verified"))
            if raw:
                out.append({"type": f"trufflehog:{str(detector).lower()}", "value": str(raw),
                            "verified": verified, "context": "trufflehog"})
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return out
    except Exception:  # noqa: BLE001
        return out
    return out


def _merge_secrets(regex_hits: list[dict[str, Any]],
                   verified_hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge regex + trufflehog hits. A value trufflehog VERIFIED is upgraded (verified=True) rather
    than duplicated; a verified value the regex missed is added."""
    by_value: dict[str, dict[str, Any]] = {}
    for s in regex_hits:
        by_value[s["value"]] = dict(s)
    for v in verified_hits:
        val = v["value"]
        if val in by_value:
            if v.get("verified"):
                by_value[val]["verified"] = True
                by_value[val]["type"] = v["type"]
        else:
            by_value[val] = dict(v)
    return list(by_value.values())[:MAX_SECRETS]


# --------------------------------------------------------------------------- #
# actions
# --------------------------------------------------------------------------- #
def do_collect(job: dict[str, Any]) -> dict[str, Any]:
    seeds = [str(u).strip() for u in (job.get("seed_urls") or []) if str(u).strip()]
    timeout = float(job.get("timeout") or REQUEST_TIMEOUT)
    insecure = bool(job.get("insecure"))
    js_urls: list[str] = []
    seen: set[str] = set()
    errors: list[str] = []

    def _add(u: str) -> None:
        if u and u not in seen:
            seen.add(u)
            js_urls.append(u)

    for seed in seeds:
        p = urlparse(seed)
        if p.scheme not in ("http", "https"):
            errors.append(f"{seed}: not an http(s) URL")
            continue
        # A seed that is itself a .js is already a JS URL.
        if p.path.lower().endswith(".js"):
            _add(seed)
        html, err = _fetch(seed, timeout, insecure)
        if err:
            errors.append(f"{seed}: {err}")
            continue
        for src in extract_script_srcs(html, seed):
            _add(src)
    return {"action": "collect", "js_urls": js_urls, "errors": errors}


def do_mine(job: dict[str, Any]) -> dict[str, Any]:
    urls = [str(u).strip() for u in (job.get("js_urls") or []) if str(u).strip()]
    timeout = float(job.get("timeout") or REQUEST_TIMEOUT)
    insecure = bool(job.get("insecure"))
    maps = bool(job.get("maps", True))
    verify = bool(job.get("verify", True))
    results: list[dict[str, Any]] = []

    for url in urls:
        text, err = _fetch(url, timeout, insecure)
        if err:
            results.append({"url": url, "endpoints": [], "params": [], "secrets": [],
                            "source_map": {}, "error": err})
            continue
        mined = mine_js(text, url)
        secrets = mined["secrets"]
        if verify:
            secrets = _merge_secrets(secrets, _trufflehog_verify(url, text, timeout))

        source_map: dict[str, Any] = {}
        if maps:
            sm = _SOURCEMAP_RE.findall(text)
            if sm:
                ref = sm[-1].strip()
                if not ref.startswith("data:"):  # inline base64 maps are skipped — no fetch, no host
                    map_url = urljoin(url, ref)
                    mp = urlparse(map_url)
                    if mp.scheme in ("http", "https"):
                        map_text, map_err = _fetch(map_url, timeout, insecure)
                        if not map_err and map_text:
                            source_map = parse_source_map(map_text, map_url)
                            # Mine the recovered original source for MORE endpoints/secrets.
                            for content in source_map.get("sources_content", []):
                                extra = mine_js(content, url)
                                for e in extra["endpoints"]:
                                    if e not in mined["endpoints"]:
                                        mined["endpoints"].append(e)
                                for pnm in extra["params"]:
                                    if pnm not in mined["params"]:
                                        mined["params"].append(pnm)
                                more = extra["secrets"]
                                if verify:
                                    more = _merge_secrets(more, _trufflehog_verify(map_url, content, timeout))
                                have = {s["value"] for s in secrets}
                                secrets += [s for s in more if s["value"] not in have]
                            source_map.pop("sources_content", None)  # not shipped — mined already
        results.append({
            "url": url,
            "endpoints": mined["endpoints"][:MAX_ENDPOINTS],
            "params": mined["params"][:MAX_PARAMS],
            "secrets": secrets[:MAX_SECRETS],
            "source_map": source_map,
            "error": "",
        })
    return {"action": "mine", "results": results, "error": ""}


# --------------------------------------------------------------------------- #
# selftest — the smoke test the Docker layer + install proof run (command -v is not one)
# --------------------------------------------------------------------------- #
_SELFTEST_JS = (
    "var base='/api/v2/users?id=1&debug=true';"
    "fetch('https://api.example.com/v2/orders?oid=7');"
    "const k='AKIAIOSFODNN7EXAMPLE';"
    "const g='api_key=\"abcdef0123456789abcdef0123456789\"';"  # generic assignment
    "//# sourceMappingURL=bundle.js.map"
)


def selftest() -> int:
    mined = mine_js(_SELFTEST_JS, "https://app.example.com/static/bundle.js")
    eps = mined["endpoints"]
    ok = (
        any("/api/v2/users" in e for e in eps)
        and any("api.example.com/v2/orders" in e for e in eps)
        and "id" in mined["params"] and "debug" in mined["params"]
        and any(s["type"] == "aws-access-key-id" for s in mined["secrets"])
        and _SOURCEMAP_RE.search(_SELFTEST_JS) is not None
    )
    sm = parse_source_map('{"sources":["src/api/client.ts"],"sourcesContent":["// secret note\\nconst x=1;"]}',
                          "https://app.example.com/static/bundle.js.map")
    ok = ok and "src/api/client.ts" in sm["recovered_sources"] and len(sm["comments"]) >= 1
    if ok:
        print("js-mine ok")
        return 0
    print("js-mine SELFTEST FAILED", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    if "--job-stdin" not in argv:
        print("usage: js-mine --job-stdin  (JSON job on stdin)  |  js-mine --selftest", file=sys.stderr)
        return 2
    try:
        job = json.loads(sys.stdin.read() or "{}")
    except (ValueError, TypeError) as exc:
        print(json.dumps({"error": f"bad job JSON: {exc}"}))
        return 0
    if not isinstance(job, dict):
        print(json.dumps({"error": "job must be a JSON object"}))
        return 0
    action = str(job.get("action") or "mine").strip().lower()
    try:
        out = do_collect(job) if action == "collect" else do_mine(job)
    except Exception as exc:  # noqa: BLE001 - always answer with JSON so the backend never hangs
        out = {"action": action, "error": f"engine error: {exc}"}
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
