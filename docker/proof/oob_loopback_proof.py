#!/usr/bin/env python3
"""LIVE proof: the out-of-band canary, end to end on loopback (build #13 part 3, spec §5).

The first assumption about this component was that nothing in it could be demonstrated
without a VPS and a domain. That is wrong, and it is worth being precise about how wrong:
everything except PUBLIC REACHABILITY can be proven on 127.0.0.1 right now. A real UDP
datagram carrying a real minted token is sent to a real authoritative listener on a real
socket; the answer is parsed off the wire; the hit is read back through the authenticated
API; and the token resolves to the engagement and step that minted it.

That is the whole product path. What loopback cannot show is that a stranger's resolver can
find the box — so exactly two things are reported NOT-RUN below, never folded into a pass:

  1. NS delegation resolves publicly to this server.
  2. One live hit from a real target.

Both become real checks the moment a VPS and zone are configured (the verify button, spec
§3.5). Until then they are gaps in the DEMONSTRATION, not passed checks.

This binds sockets, so it is a proof rather than a hermetic test — the same reason
isolation_proof.sh lives here. No Docker and no network beyond loopback are required.

Run:  python docker/proof/oob_loopback_proof.py
      sh backend/run_safety_tests.sh --with-proof   # runs it alongside the others
"""
from __future__ import annotations

import http.client
import json
import socket
import struct
import sys
import tempfile
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from oob import tokens  # noqa: E402

_spec = importlib.util.spec_from_file_location("hackpit_oob_server", ROOT / "oob" / "server.py")
assert _spec and _spec.loader
S = importlib.util.module_from_spec(_spec)
sys.modules["hackpit_oob_server"] = S
_spec.loader.exec_module(S)

ZONE = "oob.proof.local"
ANSWER_IP = "203.0.113.10"
SECRET = "loopback-proof-shared-secret-0123456789"
ENGAGEMENT = "proof-oob-loopback"
STEP = "proof-step-1"
PREFERRED_DNS_PORT = 5353

_tally = {"pass": 0, "fail": 0, "notrun": 0}
_notes: list[str] = []


def result(name: str, status: str, detail: str) -> None:
    """Emit one line in the harness's RESULT protocol and fold it into the tally.

    Same three words c2_lib.sh's `drive` reads (PASS / FAIL / NOTRUN), so this proof can be
    folded into a shell wrapper later without changing what it prints.
    """
    print(f"RESULT {name} {status} {detail}", flush=True)
    _tally[status.lower()] += 1
    if status == "NOTRUN":
        _notes.append(f"{name} — {detail}")


def check(name: str, condition: bool, detail: str) -> bool:
    result(name, "PASS" if condition else "FAIL", detail)
    return condition


# --------------------------------------------------------------------------- #
# the wire, spoken by this file
# --------------------------------------------------------------------------- #
def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_query(qname: str, txid: int = 0x4242) -> bytes:
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + encode_name(qname) + struct.pack(">HH", 1, 1)


def decode_a_record(packet: bytes) -> tuple[int, int, str | None]:
    """Return (rcode, ancount, first A address) straight off the datagram."""
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", packet[:12])
    off = 12
    while packet[off] != 0:
        off += packet[off] + 1
    off += 5  # terminator + qtype + qclass
    address = None
    if an:
        off += 2 if packet[off] & 0xC0 == 0xC0 else 0
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", packet[off : off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            address = ".".join(str(b) for b in packet[off : off + 4])
    return flags & 0x000F, an, address


def http_request(port: int, method: str, path: str, headers: dict, body: bytes = b"") -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
def run() -> int:
    print("== HackPit out-of-band canary — LOOPBACK END-TO-END PROOF ==")
    print(f"   zone={ZONE}  answer-ip={ANSWER_IP}  (nothing leaves 127.0.0.1)")

    scratch = tempfile.TemporaryDirectory()
    hits_path = Path(scratch.name) / "hits.jsonl"

    def _build(dns_port: int) -> "S.Canary":
        return S.Canary(
            S.Config(
                zone=ZONE,
                answer_ip=ANSWER_IP,
                read_secret=S.load_read_secret({S.ENV_READ_SECRET: SECRET}),
                hits_path=hits_path,
                bind="127.0.0.1",
                dns_port=dns_port,
                http_port=0,
                ttl=60,
            )
        )

    # Bind udp/5353 by ATTEMPTING IT, not by probing first. A probe opens a second socket
    # with different options than the listener uses (the listener sets SO_REUSEADDR), so it
    # can report the port busy when the real bind would have succeeded — and this ran on a
    # host with mDNS on 0.0.0.0:5353, where exactly that happened. A falsely-taken fallback
    # is the quiet kind of wrong: the proof still passes, on a port the spec never named.
    fallback_note = ""
    try:
        canary = _build(PREFERRED_DNS_PORT)
    except OSError as exc:
        canary = _build(0)
        fallback_note = (
            f"udp/{PREFERRED_DNS_PORT} could not be bound on this host ({exc}); an ephemeral "
            f"port was used instead. The wire path is identical — only the number differs."
        )
    canary.start()
    print(f"   listening: dns=127.0.0.1:{canary.dns_port}  http=127.0.0.1:{canary.http_port}")
    if fallback_note:
        print(f"   NOTE: {fallback_note}")

    minted = tokens.mint(ENGAGEMENT, step_id=STEP, note="loopback proof — blind SSRF stand-in")
    token = minted["token"]

    try:
        # -- 1. a real DNS query, over a real socket -------------------------- #
        qname = f"exfil-data.{token}.{ZONE}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(dns_query(qname), ("127.0.0.1", canary.dns_port))
        packet, _ = sock.recvfrom(512)
        sock.close()
        rcode, ancount, address = decode_a_record(packet)
        check(
            "dns.answered",
            rcode == 0 and ancount == 1 and address == ANSWER_IP,
            f"query for {qname} answered rcode={rcode} an={ancount} A={address} "
            f"(an answer, not NXDOMAIN — this is what keeps a chained proof alive)",
        )

        # -- 2. the hit was recorded, with the token ------------------------- #
        page = canary.hits.read(after=0, limit=10)
        dns_hits = [h for h in page["hits"] if h["kind"] == "dns"]
        check(
            "dns.recorded",
            bool(dns_hits) and dns_hits[0]["token"] == token,
            f"the canary recorded token={dns_hits[0]['token'] if dns_hits else None} "
            f"qname={dns_hits[0]['qname'] if dns_hits else None} "
            f"src={dns_hits[0]['source_ip'] if dns_hits else None}",
        )
        check(
            "dns.token_survives_a_data_prefix",
            bool(dns_hits) and dns_hits[0]["qname"].startswith("exfil-data."),
            "the token correlated even with command output prepended to the name — the shape "
            "every blind-RCE and DNS-exfil one-liner actually sends",
        )

        # -- 3. correlation: the hit resolves back to the step --------------- #
        correlated = tokens.correlate(token.upper())  # as a 0x20-randomising resolver would echo it
        check(
            "correlate.to_engagement_and_step",
            correlated is not None
            and correlated["engagement_id"] == ENGAGEMENT
            and correlated["step_id"] == STEP,
            f"token -> engagement={correlated and correlated['engagement_id']} "
            f"step={correlated and correlated['step_id']} — the correlation is the product, "
            f"not the hit",
        )

        # -- 4. an HTTP hit, carrying a credential and a body ---------------- #
        marker = "REFLECT-ME-9f3c2a"
        status, body = http_request(
            canary.http_port,
            "POST",
            f"/{token}/callback?probe={marker}",
            {
                "Host": f"{token}.{ZONE}",
                "Authorization": "Bearer INTERNAL-SERVICE-TOKEN-DO-NOT-STORE",
                "Cookie": "session=should-never-be-recorded",
                "Content-Type": "application/json",
            },
            body=json.dumps({"marker": marker, "padding": "x" * 5000}).encode("utf-8"),
        )
        check("http.answered", status == 200, f"the canary answered {status}")
        check(
            "http.never_reflects",
            marker.encode() not in body and len(body) <= 16,
            f"the response is {body!r} — a constant, so the canary is not an open reflection "
            f"oracle for anyone who can reach it",
        )

        page = canary.hits.read(after=0, limit=10)
        http_hits = [h for h in page["hits"] if h["kind"] == "http"]
        hit = http_hits[0] if http_hits else {}
        check(
            "http.recorded",
            bool(http_hits) and hit.get("token") == token and hit.get("method") == "POST",
            f"recorded method={hit.get('method')} path={str(hit.get('path'))[:48]!r} "
            f"token={hit.get('token')}",
        )
        stored = json.dumps(hit)
        check(
            "http.credentials_redacted",
            "INTERNAL-SERVICE-TOKEN" not in stored
            and "should-never-be-recorded" not in stored
            and hit.get("headers", {}).get("authorization") == S.REDACTED,
            "the target's own Authorization and Cookie arrived and were recorded as PRESENT "
            "with their values dropped — a canary is evidence, not a credential store",
        )
        check(
            "http.body_capped",
            len(hit.get("body", "")) <= S.MAX_BODY and hit.get("body_truncated") is True,
            f"a 5KB body was stored as a {len(hit.get('body', ''))}-byte excerpt, flagged "
            f"truncated (spec §7: not a copy of the target's traffic)",
        )

        # -- 5. the read API is the client's data, so it is authenticated ---- #
        status, body = http_request(canary.http_port, "GET", "/_hp/hits?after=0&limit=10", {})
        check(
            "api.refuses_anonymous",
            status == 401 and token.encode() not in body,
            f"an unauthenticated read got {status} and no hit data",
        )
        status, body = http_request(
            canary.http_port, "GET", "/_hp/hits", {"Authorization": f"Bearer {SECRET}wrong"}
        )
        check(
            "api.refuses_wrong_bearer",
            status == 401 and token.encode() not in body,
            f"a wrong bearer got {status} and no hit data",
        )

        status, body = http_request(
            canary.http_port, "GET", "/_hp/hits?after=0&limit=10", {"Authorization": f"Bearer {SECRET}"}
        )
        served = json.loads(body)
        seqs = [h["seq"] for h in served["hits"]]
        check(
            "api.serves_the_operator",
            status == 200 and seqs == sorted(seqs, reverse=True) and served["cursor"] == max(seqs),
            f"the right bearer got {len(served['hits'])} hits newest-first, cursor="
            f"{served['cursor']}",
        )
        fresh = json.loads(
            http_request(
                canary.http_port,
                "GET",
                f"/_hp/hits?after={served['cursor']}",
                {"Authorization": f"Bearer {SECRET}"},
            )[1]
        )
        check(
            "api.cursor_is_honest",
            fresh["hits"] == [],
            "a caught-up poll returns nothing — the cursor does not re-deliver old hits",
        )
        check(
            "api.reads_are_not_recorded",
            not any(str(h.get("path", "")).startswith("/_hp/") for h in served["hits"]),
            "the operator's own read traffic never lands in the hit log as a canary hit",
        )

        # -- 6. the log on disk ---------------------------------------------- #
        lines = [l for l in hits_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        check(
            "log.append_only_jsonl",
            len(lines) == served["cursor"] and all(json.loads(l)["seq"] == i + 1 for i, l in enumerate(lines)),
            f"{len(lines)} JSONL lines on disk, sequential, one per hit — nothing rewrites "
            f"what was recorded",
        )

        # -- 7. what loopback CANNOT show ------------------------------------ #
        result(
            "public.ns_delegation",
            "NOTRUN",
            "needs the VPS and domain: that NS records at the registrar delegate the zone to "
            "this server and resolve from the public internet. HackPit does not provision "
            "either (spec §2) — the verify button turns this into a real check once they exist.",
        )
        result(
            "public.live_target_hit",
            "NOTRUN",
            "needs one real engagement: a hit arriving from a target's own resolver or HTTP "
            "client, which is the only thing that proves the path a client's network actually "
            "takes.",
        )
    finally:
        canary.stop()
        tokens.clear(ENGAGEMENT)
        scratch.cleanup()

    print()
    print("==========================================================================")
    print(f"== oob loopback proof: {_tally['pass']} passed, {_tally['fail']} failed, "
          f"{_tally['notrun']} not-run ==")
    print("==========================================================================")
    if _notes:
        print()
        print("NOT RUN (reported as not-run, never as passed):")
        for note in _notes:
            print(f"  * {note}")
    print()
    if _tally["fail"] == 0:
        print("No assertion FAILED. Every code path except public reachability was exercised")
        print("over real sockets: a real query, a real answer, a real hit, a real correlation.")
        return 0
    print("FAILURES PRESENT — the canary is not trustworthy until these are understood.")
    return 1


if __name__ == "__main__":
    raise SystemExit(run())
