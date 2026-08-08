#!/usr/bin/env python3
"""race-singlepacket — a minimal single-packet / last-byte-sync race client.

Fires ONE request N times so the copies arrive in the same instant, to hit a target's
check-then-act window (limit overrun, TOCTOU, coupon reuse, one-time-token replay). Two transports:

  * ``h2-single-packet`` — one HTTP/2 connection, N requests queued with their final frame
    withheld, then every final frame released together so all N complete in one TCP packet
    (PortSwigger's single-packet attack). Uses the ``h2`` library.
  * ``h1-last-byte``     — N TLS connections, every byte but the last written, then the last byte
    released on all connections together via a barrier. Pure stdlib.

*** THIS IS INVOKED BY HackPit's RACE JOB, argv-only, with the whole request on STDIN. ***
The backend runs ``docker exec -i <open sandbox> race-singlepacket --job-stdin`` and pipes a JSON
job in — so no request byte (URL, header, body) ever reaches a shell. It prints a single JSON line
to stdout: ``{"mode", "baseline", "results":[{status,size_bytes,time_ms,body,error}], "error"}``.
The backend clusters those results into the win-count verdict; this client only fires and reports.

It is an ordinary tool in the sandbox: every run of it goes through the SAME four gates as curl,
and it introduces no new capability — it opens sockets to the URL it is handed, nothing else.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlparse

_UA = "HackPit-Race/1.0"


# --------------------------------------------------------------------------- #
# request assembly + response parsing (HTTP/1.1)
# --------------------------------------------------------------------------- #
def _target(url):
    p = urlparse(url)
    tls = p.scheme == "https"
    host = p.hostname or ""
    port = p.port or (443 if tls else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return tls, host, port, path


def _h1_request_bytes(method, host, port, path, headers, body, tls):
    have = {(k or "").strip().lower() for k, _ in headers}
    body_bytes = (body or "").encode("utf-8", "surrogateescape")
    lines = [f"{method} {path} HTTP/1.1"]
    if "host" not in have:
        default_port = (443 if tls else 80)
        lines.append(f"Host: {host}" if port == default_port else f"Host: {host}:{port}")
    for k, v in headers:
        if (k or "").strip():
            lines.append(f"{k}: {v}")
    if "user-agent" not in have:
        lines.append(f"User-Agent: {_UA}")
    if body_bytes and "content-length" not in have:
        lines.append(f"Content-Length: {len(body_bytes)}")
    if "connection" not in have:
        lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "surrogateescape")
    return head + body_bytes


def _connect(tls, host, port, insecure, timeout):
    raw = socket.create_connection((host, port), timeout=timeout)
    if not tls:
        return raw
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname=host)


def _read_all(sock, timeout, cap):
    sock.settimeout(timeout)
    chunks = []
    total = 0
    try:
        while True:
            b = sock.recv(65536)
            if not b:
                break
            total += len(b)
            if len(b"".join(chunks)) < cap + 4096:
                chunks.append(b)
    except (socket.timeout, OSError):
        pass
    return b"".join(chunks), total


def _parse_h1(raw, total, cap):
    if not raw:
        return {"status": None, "size_bytes": total, "body": "", "error": "no response"}
    status = None
    body = ""
    try:
        head, _, rest = raw.partition(b"\r\n\r\n")
        first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        bits = first.split(" ", 2)
        if len(bits) >= 2 and bits[1].isdigit():
            status = int(bits[1])
        body = rest[:cap].decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return {"status": status, "size_bytes": total, "body": body, "error": str(exc)[:200]}
    return {"status": status, "size_bytes": total, "body": body, "error": ""}


def _send_serial(spec):
    """One ordinary request, sent fully — the serial baseline the verdict is rare against."""
    tls, host, port, path = _target(spec["url"])
    req = _h1_request_bytes(spec["method"], host, port, path, spec["headers"], spec["body"], tls)
    t0 = time.monotonic()
    try:
        s = _connect(tls, host, port, spec["insecure"], spec["timeout"])
        s.sendall(req)
        raw, total = _read_all(s, spec["timeout"], spec["body_cap"])
        s.close()
    except OSError as exc:
        return {"status": None, "size_bytes": 0, "time_ms": int((time.monotonic() - t0) * 1000),
                "body": "", "error": str(exc)[:200]}
    out = _parse_h1(raw, total, spec["body_cap"])
    out["time_ms"] = int((time.monotonic() - t0) * 1000)
    return out


# --------------------------------------------------------------------------- #
# h1-last-byte: N connections, last byte released together
# --------------------------------------------------------------------------- #
def _fire_h1_last_byte(spec):
    tls, host, port, path = _target(spec["url"])
    req = _h1_request_bytes(spec["method"], host, port, path, spec["headers"], spec["body"], tls)
    n = spec["count"]
    head, last = req[:-1], req[-1:]
    socks = [None] * n
    results = [None] * n

    # Open every connection and send everything but the final byte.
    for i in range(n):
        try:
            s = _connect(tls, host, port, spec["insecure"], spec["timeout"])
            s.sendall(head)
            socks[i] = s
        except OSError as exc:
            results[i] = {"status": None, "size_bytes": 0, "time_ms": 0, "body": "",
                          "error": f"connect/prime failed: {str(exc)[:160]}"}

    live = [i for i in range(n) if socks[i] is not None]
    barrier = threading.Barrier(len(live)) if live else None

    def _finish(i):
        s = socks[i]
        t0 = time.monotonic()
        try:
            barrier.wait(timeout=spec["timeout"])
            s.sendall(last)
            raw, total = _read_all(s, spec["timeout"], spec["body_cap"])
            out = _parse_h1(raw, total, spec["body_cap"])
        except (OSError, threading.BrokenBarrierError) as exc:
            out = {"status": None, "size_bytes": 0, "body": "", "error": str(exc)[:200]}
        finally:
            try:
                s.close()
            except OSError:
                pass
        out["time_ms"] = int((time.monotonic() - t0) * 1000)
        results[i] = out

    threads = [threading.Thread(target=_finish, args=(i,)) for i in live]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=spec["timeout"] + 5)
    return results


# --------------------------------------------------------------------------- #
# h2-single-packet: one connection, all final frames released together
# --------------------------------------------------------------------------- #
def _fire_h2_single_packet(spec):
    try:
        import h2.config
        import h2.connection
        import h2.events
    except Exception as exc:  # noqa: BLE001
        return [{"status": None, "size_bytes": 0, "time_ms": 0, "body": "",
                 "error": f"h2 library unavailable ({exc}); use mode h1-last-byte"}] * spec["count"]

    tls, host, port, path = _target(spec["url"])
    if not tls:
        return [{"status": None, "size_bytes": 0, "time_ms": 0, "body": "",
                 "error": "single-packet needs TLS/ALPN h2; a plaintext target must use h1-last-byte"}] \
            * spec["count"]

    n = spec["count"]
    body_bytes = (spec["body"] or "").encode("utf-8", "surrogateescape")
    authority = host if port == 443 else f"{host}:{port}"
    base_headers = [
        (":method", spec["method"]),
        (":authority", authority),
        (":scheme", "https"),
        (":path", path),
    ]
    have = {(k or "").strip().lower() for k, _ in spec["headers"]}
    for k, v in spec["headers"]:
        kk = (k or "").strip().lower()
        if kk and kk not in (":method", ":authority", ":scheme", ":path", "host", "connection",
                             "transfer-encoding", "keep-alive", "upgrade"):
            base_headers.append((kk, v))
    if "user-agent" not in have:
        base_headers.append(("user-agent", _UA))
    if body_bytes and "content-length" not in have:
        base_headers.append(("content-length", str(len(body_bytes))))

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    if spec["insecure"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    results = [{"status": None, "size_bytes": 0, "time_ms": 0, "body": "", "error": "no response"}
               for _ in range(n)]
    try:
        raw = socket.create_connection((host, port), timeout=spec["timeout"])
        sock = ctx.wrap_socket(raw, server_hostname=host)
    except OSError as exc:
        return [{"status": None, "size_bytes": 0, "time_ms": 0, "body": "",
                 "error": f"connect failed: {str(exc)[:160]}"}] * n
    if sock.selected_alpn_protocol() != "h2":
        sock.close()
        return [{"status": None, "size_bytes": 0, "time_ms": 0, "body": "",
                 "error": "server did not negotiate HTTP/2 (ALPN h2); use h1-last-byte"}] * n

    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # Queue every stream with its final frame WITHHELD (headers/body sent, END_STREAM not).
    stream_ids = []
    for _ in range(n):
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, base_headers, end_stream=False)
        if len(body_bytes) > 1:
            conn.send_data(sid, body_bytes[:-1], end_stream=False)
        stream_ids.append(sid)
    sock.sendall(conn.data_to_send())
    time.sleep(0.10)  # let the withheld frames settle at the server before the release

    # THE RELEASE — the final byte + END_STREAM on every stream, flushed in ONE write (one packet).
    t0 = time.monotonic()
    tail = body_bytes[-1:] if len(body_bytes) >= 1 else b""
    for sid in stream_ids:
        conn.send_data(sid, tail, end_stream=True)
    sock.sendall(conn.data_to_send())

    idx = {sid: i for i, sid in enumerate(stream_ids)}
    ended = set()
    sizes = {sid: 0 for sid in stream_ids}
    bodies = {sid: b"" for sid in stream_ids}
    sock.settimeout(spec["timeout"])
    try:
        while len(ended) < n:
            data = sock.recv(65536)
            if not data:
                break
            for event in conn.receive_data(data):
                sid = getattr(event, "stream_id", None)
                if isinstance(event, h2.events.ResponseReceived) and sid in idx:
                    for name, value in event.headers:
                        if name in (b":status", ":status"):
                            v = value.decode() if isinstance(value, bytes) else value
                            try:
                                results[idx[sid]]["status"] = int(v)
                            except ValueError:
                                pass
                elif isinstance(event, h2.events.DataReceived) and sid in idx:
                    sizes[sid] += len(event.data)
                    if len(bodies[sid]) < spec["body_cap"]:
                        bodies[sid] += event.data
                    conn.acknowledge_received_data(len(event.data), sid)
                elif isinstance(event, h2.events.StreamEnded) and sid in idx:
                    ended.add(sid)
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
    except (socket.timeout, OSError):
        pass

    dt = int((time.monotonic() - t0) * 1000)
    for sid, i in idx.items():
        results[i]["size_bytes"] = sizes[sid]
        results[i]["time_ms"] = dt
        results[i]["body"] = bodies[sid][:spec["body_cap"]].decode("utf-8", "replace")
        if results[i]["status"] is not None:
            results[i]["error"] = ""
    try:
        conn.close_connection()
        sock.sendall(conn.data_to_send())
    except Exception:  # noqa: BLE001
        pass
    sock.close()
    return results


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def _normalise(spec):
    spec.setdefault("method", "GET")
    spec["method"] = (spec.get("method") or "GET").upper()
    spec.setdefault("headers", [])
    spec["headers"] = [(str(k), str(v)) for k, v in spec.get("headers", [])]
    spec.setdefault("body", "")
    spec.setdefault("mode", "h2-single-packet")
    spec["count"] = max(2, int(spec.get("count", 2)))
    spec.setdefault("insecure", False)
    spec.setdefault("timeout", 30)
    spec["timeout"] = float(spec.get("timeout") or 30)
    spec.setdefault("body_cap", 2000)
    spec["body_cap"] = int(spec.get("body_cap") or 2000)
    return spec


def _run(spec):
    spec = _normalise(spec)
    baseline = _send_serial(spec)
    mode = spec["mode"]
    if mode == "h1-last-byte":
        results = _fire_h1_last_byte(spec)
    else:
        results = _fire_h2_single_packet(spec)
    return {"mode": mode, "baseline": baseline, "results": results, "error": ""}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="race-singlepacket",
                                 description="single-packet / last-byte-sync race client")
    ap.add_argument("--job-stdin", action="store_true",
                    help="read the whole request as a JSON job on stdin (how HackPit invokes it)")
    ap.add_argument("--selftest", action="store_true", help="prove the client loads and exit")
    ap.add_argument("-u", "--url", default="")
    ap.add_argument("-X", "--method", default="GET")
    ap.add_argument("--mode", default="h2-single-packet", choices=list(("h2-single-packet",
                                                                         "h1-last-byte")))
    ap.add_argument("-n", "--count", type=int, default=20)
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("-d", "--data", default="")
    ap.add_argument("-k", "--insecure", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        try:
            import h2  # noqa: F401
            print("race-singlepacket ok (h2 present)")
        except Exception as exc:  # noqa: BLE001
            print(f"race-singlepacket ok (h1-last-byte only; h2 missing: {exc})")
        return 0

    if args.job_stdin:
        try:
            spec = json.loads(sys.stdin.read() or "{}")
        except ValueError as exc:
            print(json.dumps({"error": f"bad job JSON: {exc}", "results": []}))
            return 2
    else:
        if not args.url:
            ap.error("either --job-stdin or -u/--url is required")
        headers = []
        for h in args.header:
            k, _, v = h.partition(":")
            headers.append([k.strip(), v.strip()])
        spec = {"url": args.url, "method": args.method, "headers": headers, "body": args.data,
                "mode": args.mode, "count": args.count, "insecure": args.insecure}

    print(json.dumps(_run(spec)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
