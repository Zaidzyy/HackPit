"""Build #13 part 3 — the out-of-band canary server (spec §3.1).

`oob/server.py` is the first HackPit component that faces the internet, and it faces it
from a machine holding a client's evidence. Everything below follows from those two facts.

The wire format is tested against BYTES THIS FILE BUILDS ITSELF rather than against the
server's own encoder. A canary answers queries from resolvers that HackPit will never see;
if the test asked the implementation to describe its own output, the pair could agree
perfectly and still be unintelligible to BIND. So the question is encoded here, by hand,
from RFC 1035, and the answer is decoded here the same way.

What is locked:

  * **An answer, not NXDOMAIN.** A chained proof (DNS hit -> HTTP follow-up) dies if the
    canary refuses the name. The A record is the feature.
  * **The token is the label left of the zone**, so exfil-style prefixes
    (`whoami-output.<token>.<zone>`) still correlate. Agreed byte-for-byte with
    backend/oob/tokens.py over a real minted population — the two grammars live in
    different files by design and would otherwise drift into silent non-correlation.
  * **Hostile packets do not hang it.** Compression pointers, loops and truncation arrive
    from the internet unsolicited.
  * **Reads are authenticated, rate-limited and constant-time.** The hit log holds a
    target's internal hostnames; an open read endpoint would publish the client's
    information to anyone who guessed the host.
  * **Credentials in a hit are redacted.** A blind SSRF often arrives carrying the target's
    own Authorization header. A canary records that something arrived and from where — not
    a copy of the target's secrets (spec §7).
  * **Append-only, executes nothing, forwards nothing.** The strongest guarantee available
    for an exposed component is that there is nothing in it worth attacking.

Hermetic: not one socket is bound here. Every function under test is pure; the live
end-to-end lives in docker/proof/oob_loopback_proof.py, which binds real sockets and is why
it is a proof rather than a test.

Run: python test_oob_server.py
"""
from __future__ import annotations

import ast
import importlib.util
import json
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from oob import tokens  # noqa: E402

BACKEND = Path(__file__).resolve().parent
SERVER_PATH = BACKEND.parent / "oob" / "server.py"

# Loaded by path, under a name of our choosing. The deployable is a standalone file that is
# copied to a VPS — it is deliberately not a package member, and importing it as `server`
# would squat a very common module name inside the test process.
_spec = importlib.util.spec_from_file_location("hackpit_oob_server", SERVER_PATH)
assert _spec and _spec.loader, f"cannot load {SERVER_PATH}"
S = importlib.util.module_from_spec(_spec)
sys.modules["hackpit_oob_server"] = S
_spec.loader.exec_module(S)

ZONE = "oob.example.net"
SECRET = "s" * 32


# --------------------------------------------------------------------------- #
# the wire, spoken by hand
# --------------------------------------------------------------------------- #
def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _query(qname: str, qtype: int = 1, txid: int = 0x1234, rd: bool = True) -> bytes:
    """A standard recursive-desired query, encoded from RFC 1035 rather than from the code."""
    flags = 0x0100 if rd else 0x0000
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    return header + _encode_name(qname) + struct.pack(">HH", qtype, 1)


def _decode_answer(packet: bytes) -> dict:
    """Pull the header counts, rcode and the first A record's address back out."""
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", packet[:12])
    off = 12
    while packet[off] != 0:  # the question name; no compression in a question
        off += packet[off] + 1
    off += 1
    qtype, qclass = struct.unpack(">HH", packet[off : off + 4])
    off += 4
    answers = []
    for _ in range(an):
        if packet[off] & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", packet[off : off + 2])[0] & 0x3FFF
            off += 2
        else:
            ptr = off
            while packet[off] != 0:
                off += packet[off] + 1
            off += 1
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", packet[off : off + 10])
        off += 10
        rdata = packet[off : off + rdlen]
        off += rdlen
        answers.append(
            {
                "name_ptr": ptr,
                "type": rtype,
                "class": rclass,
                "ttl": ttl,
                "rdata": ".".join(str(b) for b in rdata) if rtype == 1 else rdata,
            }
        )
    return {
        "txid": txid,
        "qr": bool(flags & 0x8000),
        "aa": bool(flags & 0x0400),
        "tc": bool(flags & 0x0200),
        "rd": bool(flags & 0x0100),
        "rcode": flags & 0x000F,
        "counts": (qd, an, ns, ar),
        "question": (qtype, qclass),
        "answers": answers,
    }


# --------------------------------------------------------------------------- #
# DNS: parsing what arrives
# --------------------------------------------------------------------------- #
def test_a_real_query_parses() -> None:
    """The header, the name, the type and the raw question bytes all come back."""
    packet = _query(f"abc.{ZONE}", qtype=1, txid=0xBEEF)
    q = S.parse_query(packet)
    assert q is not None, "a well-formed A query did not parse"
    assert q.txid == 0xBEEF, q.txid
    assert q.qname == f"abc.{ZONE}", q.qname
    assert q.qtype == 1 and q.qclass == 1, (q.qtype, q.qclass)
    assert q.rd is True, "the RD bit was not carried through; the response would drop it"
    assert q.qbytes == _encode_name(f"abc.{ZONE}") + struct.pack(">HH", 1, 1), (
        "the raw question bytes must be kept verbatim so the answer can echo them"
    )
    print("  a well-formed query parses to txid/qname/qtype/RD and its raw question: PASS")


def test_a_hostile_packet_is_refused_without_hanging() -> None:
    """Unsolicited malformed packets are the normal traffic of an open UDP/53.

    The compression-pointer cases are the ones that matter: a question is never compressed
    in practice, so a pointer here is either a broken client or someone trying to walk the
    parser into a loop. Refusing the packet outright costs nothing real and removes the
    class of bug.
    """
    pointer_loop = (
        struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    )
    hostile = {
        "empty": b"",
        "header only": struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0),
        "truncated header": b"\x00\x01\x00",
        "no question at all": struct.pack(">HHHHHH", 1, 0x0100, 0, 0, 0, 0),
        "unterminated name": struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x03abc",
        "compression pointer in the question": pointer_loop,
        "pointer to itself": (
            struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0e\x00\x00" + b"\x00" * 4
        ),
        "label length past the packet": (
            struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x40abc"
        ),
        "missing type/class": struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + _encode_name("a.b"),
        "a response, not a query": (
            struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + _encode_name("a.b") + b"\x00\x01\x00\x01"
        ),
        "random bytes": bytes(range(64)),
    }
    for label, packet in hostile.items():
        got = S.parse_query(packet)
        assert got is None, f"{label!r} parsed to {got!r} — it must be refused"
    print(f"  all {len(hostile)} hostile/malformed packets are refused, none hung: PASS")


# --------------------------------------------------------------------------- #
# DNS: what goes back
# --------------------------------------------------------------------------- #
def test_the_answer_is_an_a_record_never_nxdomain() -> None:
    """An answer is what makes a chained proof work: DNS hit, then an HTTP follow-up.

    NXDOMAIN would record the DNS half and kill the second half, so this is not a
    politeness — it is the difference between half a proof and a whole one.
    """
    q = S.parse_query(_query(f"tok.{ZONE}", txid=0x0F0F))
    got = _decode_answer(S.build_response(q, "203.0.113.10", ttl=60))
    assert got["txid"] == 0x0F0F, "the transaction id must be echoed or the resolver drops it"
    assert got["qr"] and got["aa"], "the canary is authoritative for its zone; QR+AA must be set"
    assert got["rcode"] == 0, f"rcode {got['rcode']} — an answer, never NXDOMAIN(3)"
    assert got["counts"][0] == 1 and got["counts"][1] == 1, got["counts"]
    (answer,) = got["answers"]
    assert answer["type"] == 1 and answer["class"] == 1, answer
    assert answer["rdata"] == "203.0.113.10", answer
    assert answer["ttl"] == 60, answer
    assert answer["name_ptr"] == 12, "the answer name must point at the question name"
    print("  a query is answered NOERROR with the configured A record, AA set: PASS")


def test_the_question_is_echoed_byte_for_byte() -> None:
    """0x20 case randomisation is an anti-spoofing measure; the response must preserve it.

    A resolver that sent `tOkEn.Oob.ExAmPlE.nEt` compares the echoed question against what
    it sent. Re-encoding from the lowercased name would fail that comparison and the answer
    would be thrown away as a spoof — while every log here said the hit was answered.
    """
    mixed = f"AbCdEf.{ZONE.upper()}"
    q = S.parse_query(_query(mixed))
    response = S.build_response(q, "203.0.113.10", ttl=60)
    assert _encode_name(mixed) in response, (
        "the response did not echo the question as it arrived; a 0x20-randomising resolver "
        "would reject this answer as a spoof"
    )
    assert q.qname == mixed.lower(), "the RECORDED qname is folded for correlation"
    print("  the question is echoed verbatim while the recorded qname is folded: PASS")


def test_a_non_a_query_is_answered_with_no_data_not_a_refusal() -> None:
    """AAAA/TXT/MX arrive constantly. NOERROR-no-data keeps the name alive for the A retry."""
    for qtype, label in ((28, "AAAA"), (16, "TXT"), (15, "MX"), (2, "NS")):
        q = S.parse_query(_query(f"tok.{ZONE}", qtype=qtype))
        got = _decode_answer(S.build_response(q, "203.0.113.10", ttl=60))
        assert got["rcode"] == 0, f"{label} got rcode {got['rcode']}, must be NOERROR"
        assert got["counts"][1] == 0, f"{label} must not be answered with an A record"
    # ANY still gets the address.
    q = S.parse_query(_query(f"tok.{ZONE}", qtype=255))
    assert _decode_answer(S.build_response(q, "203.0.113.10", ttl=60))["counts"][1] == 1
    print("  AAAA/TXT/MX/NS answer NOERROR-no-data; A and ANY get the address: PASS")


def test_a_response_fits_in_a_udp_datagram() -> None:
    """Over 512 bytes a resolver retries over TCP, which this server does not speak."""
    q = S.parse_query(_query("x" * 63 + "." + "y" * 63 + "." + ZONE))
    response = S.build_response(q, "203.0.113.10", ttl=60)
    assert len(response) <= 512, f"{len(response)}-byte response would force a TCP retry"
    print(f"  a maximal-name response is {len(response)} bytes, inside the 512 UDP limit: PASS")


# --------------------------------------------------------------------------- #
# the token: the label left of the zone
# --------------------------------------------------------------------------- #
def test_the_token_is_the_label_left_of_the_zone() -> None:
    """`data.<token>.<zone>` must correlate, because exfil payloads prepend to the token.

    Taking the LEFTMOST label instead would work for the bare case and silently fail for
    every blind-RCE one-liner that prefixes command output.
    """
    cases = {
        f"tok.{ZONE}": "tok",
        f"tok.{ZONE}.": "tok",
        f"whoami-output.tok.{ZONE}": "tok",
        f"a.b.c.tok.{ZONE}": "tok",
        f"TOK.{ZONE.upper()}": "tok",
        ZONE: None,
        f".{ZONE}": None,
        "tok.someone-elses-zone.net": None,
        "": None,
        f"tok.{ZONE}x": None,
        f"nottheZONE{ZONE}": None,
    }
    for qname, want in cases.items():
        got = S.token_from_qname(qname, ZONE)
        assert got == want, f"{qname!r} -> {got!r}, expected {want!r}"
    print(f"  the token is read from the label left of the zone across {len(cases)} names: PASS")


def test_the_server_and_hackpit_agree_on_what_a_token_is() -> None:
    """The deployable owes nothing to the repo, so it carries its own copy of the grammar.

    That is the right call for a file shipped by `scp` — and it is exactly the seam where a
    later change to one side turns real hits into uncorrelated ones, in production, silently.
    So the two are held together against a real minted population rather than a reading.
    """
    minted = [tokens.mint("test-oob-grammar")["token"] for _ in range(200)]
    for tok in minted:
        assert S.is_token(tok), (
            f"the server rejects {tok!r}, which backend/oob/tokens.py just minted — every hit "
            f"on this token would be recorded with no token at all"
        )
        assert S.token_from_qname(f"{tok}.{ZONE}", ZONE) == tok
    tokens.clear("test-oob-grammar")

    junk = ["", "a", "_hp", "tok-with-hyphen", "1leadingdigit", "UPPER" * 3, "a" * 64, "tok.dot"]
    for value in junk:
        assert S.is_token(value) == tokens.is_token(value) is False, (
            f"the two grammars disagree on {value!r}"
        )
    print(f"  server and HackPit agree on all {len(minted)} minted tokens and {len(junk)} rejects: PASS")


def test_an_http_token_comes_from_the_subdomain_or_the_first_path_segment() -> None:
    """Some payload sinks take a hostname, some take a URL path. Both have to correlate."""
    tok = "abcdefghijkm"
    cases = [
        ((f"{tok}.{ZONE}", "/"), tok),
        ((f"{tok}.{ZONE}:8080", "/anything"), tok),
        ((f"data.{tok}.{ZONE}", "/x/y"), tok),
        ((ZONE, f"/{tok}"), tok),
        ((ZONE, f"/{tok}/deeper?q=1"), tok),
        ((f"{tok}.{ZONE}", "/someotherpath"), tok),   # the host wins
        ((ZONE, "/"), None),
        (("", "/"), None),
        ((ZONE, "/_hp/hits"), None),                  # the read API is never a token
        (("evil.example.com", "/nope"), None),
    ]
    for (host, path), want in cases:
        got = S.token_from_http(host, path, ZONE)
        assert got == want, f"host={host!r} path={path!r} -> {got!r}, expected {want!r}"
    print(f"  the HTTP token reads from the host, then the path, across {len(cases)} cases: PASS")


# --------------------------------------------------------------------------- #
# what a hit records — and what it deliberately does not
# --------------------------------------------------------------------------- #
def test_a_dns_hit_records_the_correlation_fields() -> None:
    hit = S.hit_from_dns(f"tok.{ZONE}", 1, "198.51.100.9", ZONE, at="2026-08-03T10:00:00+00:00")
    assert hit["kind"] == "dns" and hit["token"] == "tok", hit
    assert hit["qname"] == f"tok.{ZONE}" and hit["qtype"] == "A", hit
    assert hit["source_ip"] == "198.51.100.9" and hit["at"], hit
    # An out-of-zone query is still recorded — with no token, never dropped.
    stray = S.hit_from_dns("www.google.com", 1, "198.51.100.9", ZONE, at="x")
    assert stray["token"] is None and stray["qname"] == "www.google.com", stray
    print("  a DNS hit records (token, qname, source, at); an out-of-zone query still lands: PASS")


def test_credentials_arriving_in_a_hit_are_redacted() -> None:
    """A blind SSRF frequently arrives carrying the target's own Authorization header.

    Recording it would turn the canary from evidence into a credential store sitting on a
    VPS. The header is noted as present and its value is dropped: the finding needs "an
    authenticated internal client reached out", not the bearer token it used.
    """
    headers = [
        ("Host", f"tok.{ZONE}"),
        ("Authorization", "Bearer eyJhbGciOi.REAL.SECRET"),
        ("Cookie", "session=deadbeefcafe"),
        ("Proxy-Authorization", "Basic YWRtaW46aHVudGVyMg=="),
        ("X-Api-Key", "k-live-1234567890"),
        ("User-Agent", "python-requests/2.31.0"),
    ]
    clean = S.clean_headers(headers)
    for sensitive in ("authorization", "cookie", "proxy-authorization", "x-api-key"):
        assert sensitive in clean, f"{sensitive} must still be RECORDED as present"
        assert clean[sensitive] == S.REDACTED, f"{sensitive} leaked its value: {clean[sensitive]!r}"
    assert clean["user-agent"] == "python-requests/2.31.0", clean
    assert "REAL.SECRET" not in json.dumps(clean), clean
    assert "deadbeefcafe" not in json.dumps(clean), clean
    print("  credential-bearing headers are recorded as present with their values dropped: PASS")


def test_headers_are_capped_in_count_and_length() -> None:
    """Header storage is attacker-controlled; unbounded, it is a disk-fill on the VPS."""
    flood = [(f"X-H{i}", "v" * 5000) for i in range(500)]
    clean = S.clean_headers(flood)
    assert len(clean) <= S.MAX_HEADERS, f"{len(clean)} headers stored, cap is {S.MAX_HEADERS}"
    assert all(len(v) <= S.MAX_HEADER_VALUE for v in clean.values()), "a header value was not capped"
    print(f"  headers cap at {S.MAX_HEADERS} entries of {S.MAX_HEADER_VALUE} bytes: PASS")


def test_a_body_is_stored_only_as_a_capped_excerpt() -> None:
    """"A canary records that something arrived and from where, not a copy of the target's
    traffic" (spec §7). The cap is that sentence made mechanical."""
    text, truncated = S.excerpt(b"A" * 100_000)
    assert len(text) <= S.MAX_BODY, f"{len(text)} bytes stored, cap is {S.MAX_BODY}"
    assert truncated is True, "a truncated body must say so, or the excerpt reads as the whole"
    short, truncated = S.excerpt(b"hello")
    assert short == "hello" and truncated is False, (short, truncated)
    binary, _ = S.excerpt(bytes(range(256)))
    assert isinstance(binary, str), "a binary body must not raise on the way into JSON"
    json.dumps({"body": binary})  # would raise if the excerpt were not serialisable
    assert S.excerpt(b"") == ("", False)
    print(f"  a body is stored as a {S.MAX_BODY}-byte excerpt, flagged when truncated: PASS")


def test_the_canary_response_never_reflects_the_request() -> None:
    """Reflection would make the canary a free XSS/SSRF-response oracle for anyone.

    The body is a constant, so the assertion is that it is byte-identical no matter what
    arrived — including the classic reflected-content payloads.
    """
    baseline = S.canary_response()
    for wild in ("<script>alert(1)</script>", "../../etc/passwd", "\x00\xff", "A" * 10_000):
        hit = S.hit_from_http(
            "POST", f"/{wild}", f"{wild}.{ZONE}", [("X-Wild", wild)], wild.encode("latin-1"),
            "198.51.100.9", ZONE, at="x",
        )
        assert S.canary_response() == baseline, "the response changed with the request"
        assert wild.encode("latin-1")[:20] not in baseline, "the response reflects request content"
        assert hit["kind"] == "http", hit
    print("  the canary response is a constant; nothing from the request reaches it: PASS")


# --------------------------------------------------------------------------- #
# the read API: this is engagement data
# --------------------------------------------------------------------------- #
def test_the_server_refuses_to_start_without_a_read_secret() -> None:
    """Fail closed. A canary that starts with no secret is a public evidence log.

    The failure mode this prevents is an operator deploying, seeing the listeners come up,
    and never learning that the read endpoint was open the whole time.
    """
    for env in ({}, {"HACKPIT_OOB_TOKEN": ""}, {"HACKPIT_OOB_TOKEN": "   "}):
        try:
            S.load_read_secret(env)
        except S.ConfigError:
            pass
        else:
            raise AssertionError(f"the server accepted {env!r} and would expose the hit log")
    try:
        S.load_read_secret({"HACKPIT_OOB_TOKEN": "short"})
    except S.ConfigError:
        pass
    else:
        raise AssertionError("a 5-character shared secret was accepted on an internet-facing API")
    assert S.load_read_secret({"HACKPIT_OOB_TOKEN": SECRET}) == SECRET
    print("  the server refuses to start with a missing, blank or trivial read secret: PASS")


def test_the_read_api_refuses_a_wrong_bearer() -> None:
    wrong = [
        None, "", "Bearer", "Bearer ", f"Bearer {SECRET}x", f"Bearer {SECRET[:-1]}",
        SECRET, f"Basic {SECRET}", f"bearer{SECRET}", f"Bearer  {SECRET}",
    ]
    for value in wrong:
        assert S.authorized(value, SECRET) is False, f"{value!r} was accepted as authorisation"
    assert S.authorized(f"Bearer {SECRET}", SECRET) is True, "the correct bearer was refused"
    print(f"  {len(wrong)} wrong/missing bearer forms refused, the right one accepted: PASS")


def test_the_bearer_comparison_is_constant_time() -> None:
    """Structural: `hmac.compare_digest`, not `==`.

    A byte-at-a-time comparison over the internet leaks the secret to a patient attacker,
    and no behavioural test in a hermetic suite can observe the difference.
    """
    tree = ast.parse(SERVER_PATH.read_text(encoding="utf-8"))
    fn = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "authorized"),
        None,
    )
    assert fn is not None, "authorized() not found in the server"
    calls = {
        f"{c.func.value.id}.{c.func.attr}"
        for c in ast.walk(fn)
        if isinstance(c, ast.Call)
        and isinstance(c.func, ast.Attribute)
        and isinstance(c.func.value, ast.Name)
    }
    assert "hmac.compare_digest" in calls, (
        f"authorized() does not use hmac.compare_digest (calls: {sorted(calls)}) — a plain "
        f"`==` on an internet-facing secret is a timing oracle"
    )
    print("  the bearer check goes through hmac.compare_digest: PASS")


def test_hits_are_served_newest_first_on_a_cursor() -> None:
    """The poll client asks "what is new since N". Newest-first bounds a burst to the recent."""
    with tempfile.TemporaryDirectory() as td:
        log = S.HitLog(Path(td) / "hits.jsonl")
        seqs = [log.append({"kind": "dns", "token": f"t{i}", "at": "x"}) for i in range(5)]
        assert seqs == [1, 2, 3, 4, 5], seqs

        page = log.read(after=0, limit=100)
        assert [h["seq"] for h in page["hits"]] == [5, 4, 3, 2, 1], page["hits"]
        assert page["cursor"] == 5, page

        page = log.read(after=3, limit=100)
        assert [h["seq"] for h in page["hits"]] == [5, 4], page["hits"]

        assert log.read(after=5, limit=100)["hits"] == [], "a caught-up poll must return nothing"
        assert len(log.read(after=0, limit=2)["hits"]) == 2, "limit was not applied"
        assert len(log.read(after=0, limit=10_000)["hits"]) <= S.READ_LIMIT_MAX, (
            "an unbounded limit lets one request pull the entire log"
        )
    print("  hits serve newest-first on a cursor, bounded by a maximum page: PASS")


def test_the_log_is_append_only_and_survives_a_restart() -> None:
    """Append-only is the safety story for an exposed component: nothing can be rewritten.

    The restart half matters just as much — a canary that lost its cursor on restart would
    re-deliver every historical hit to the poll client as if it were new.
    """
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "hits.jsonl"
        log = S.HitLog(path)
        log.append({"kind": "dns", "token": "first", "at": "x"})
        first_bytes = path.read_bytes()
        log.append({"kind": "dns", "token": "second", "at": "x"})
        after = path.read_bytes()
        assert after.startswith(first_bytes), "an earlier line changed — the log is not append-only"
        assert after.count(b"\n") == 2, after

        reopened = S.HitLog(path)
        assert reopened.cursor == 2, f"cursor {reopened.cursor} after restart, expected 2"
        assert reopened.append({"kind": "dns", "token": "third", "at": "x"}) == 3
        assert [h["token"] for h in reopened.read(after=0, limit=10)["hits"]] == [
            "third", "second", "first",
        ]
    print("  the log only ever grows, and a restart resumes the cursor: PASS")


def test_the_log_opens_its_file_only_for_appending() -> None:
    """Structural: no truncating open, no remove, no truncate anywhere in the server."""
    tree = ast.parse(SERVER_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name in ("remove", "unlink", "truncate", "rmtree", "replace"):
            raise AssertionError(f"server.py line {node.lineno}: calls {name}() — the log is append-only")
        if name == "open":
            modes = [a.value for a in node.args[1:2] if isinstance(a, ast.Constant)]
            modes += [k.value.value for k in node.keywords
                      if k.arg == "mode" and isinstance(k.value, ast.Constant)]
            for mode in modes:
                assert "w" not in mode and "+" not in mode, (
                    f"server.py line {node.lineno}: open(mode={mode!r}) can truncate the hit log"
                )
    print("  no truncating open, no remove/truncate call anywhere in the server: PASS")


def test_the_read_api_is_rate_limited_per_source() -> None:
    """An open TCP port with an auth check is a brute-force target; a slow one is not.

    Rate limiting the SOURCE rather than the whole endpoint means one attacker cannot lock
    the operator's own poll client out of its data.
    """
    rl = S.RateLimiter(limit=3, window=60.0)
    assert [rl.allow("198.51.100.9", now=1000.0) for _ in range(4)] == [True, True, True, False]
    assert rl.allow("203.0.113.7", now=1000.0) is True, (
        "one source exhausting its budget must not deny another — that is a free DoS on the "
        "operator's own polling"
    )
    assert rl.allow("198.51.100.9", now=1061.0) is True, "the window never reopened"
    print("  reads are rate-limited per source IP, and the window reopens: PASS")


# --------------------------------------------------------------------------- #
# nothing in it worth attacking
# --------------------------------------------------------------------------- #
_BANNED_ROOTS = {
    "subprocess", "pickle", "marshal", "shelve", "requests", "httpx", "urllib", "ftplib",
    "smtplib", "ctypes", "importlib", "shutil", "tempfile",
}
_BANNED_MODULES = {"http.client", "xmlrpc.client", "os.path"}
_BANNED_CALLS = {
    "eval", "exec", "compile", "__import__", "os.system", "os.popen", "os.execv",
    "socket.create_connection",
}
# The redirector lock (spec §7). An outbound connect is the one call that would turn a
# recorder into a forwarder — `sendto` is excluded deliberately, because replying to the
# datagram that just arrived is not forwarding.
_BANNED_ATTRS = {"connect", "connect_ex", "create_connection", "urlopen", "request", "forward"}


def test_the_server_executes_nothing_and_forwards_nothing() -> None:
    """This is the whole safety argument for exposing it (spec §4).

    "This server records hits; it never forwards traffic and never becomes a redirector"
    is a claim about code, so it is checked against the code rather than restated in a
    docstring.
    """
    source = SERVER_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    offences: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _BANNED_ROOTS or alias.name in _BANNED_MODULES:
                    offences.append(f"line {node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.split(".")[0] in _BANNED_ROOTS or module in _BANNED_MODULES:
                offences.append(f"line {node.lineno}: from {module} import ...")
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in _BANNED_CALLS:
                offences.append(f"line {node.lineno}: {fn.id}()")
            elif isinstance(fn, ast.Attribute):
                if isinstance(fn.value, ast.Name) and f"{fn.value.id}.{fn.attr}" in _BANNED_CALLS:
                    offences.append(f"line {node.lineno}: {fn.value.id}.{fn.attr}()")
                elif fn.attr in _BANNED_ATTRS:
                    offences.append(f"line {node.lineno}: .{fn.attr}() — outbound/forwarding")
    assert not offences, "the canary server is not inert:\n  " + "\n  ".join(offences)
    print("  the server executes nothing, imports no client, and makes no outbound call: PASS")


def test_the_inertness_scan_can_fail() -> None:
    """Control: the scan above prints the same line when it works and when it is broken."""
    planted = {
        "a shell": "import subprocess\nsubprocess.run(['id'])\n",
        "eval": "def f(x):\n    return eval(x)\n",
        "pickle": "import pickle\n",
        "an outbound connection": "import socket\ns = socket.socket()\ns.connect(('a', 1))\n",
        "a fetch": "from urllib.request import urlopen\n",
        "an http client": "import http.client\n",
    }
    for label, source in planted.items():
        tree = ast.parse(source)
        hit = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                hit |= any(
                    a.name.split(".")[0] in _BANNED_ROOTS or a.name in _BANNED_MODULES
                    for a in node.names
                )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                hit |= module.split(".")[0] in _BANNED_ROOTS or module in _BANNED_MODULES
            elif isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name):
                    hit |= fn.id in _BANNED_CALLS
                elif isinstance(fn, ast.Attribute):
                    hit |= fn.attr in _BANNED_ATTRS
                    hit |= (
                        isinstance(fn.value, ast.Name)
                        and f"{fn.value.id}.{fn.attr}" in _BANNED_CALLS
                    )
        assert hit, f"the inertness scan missed a planted {label} — it cannot fail"
    print(f"  control: {len(planted)} planted violations are all detected: PASS")


def test_the_deployable_depends_on_nothing_but_the_standard_library() -> None:
    """It is shipped by copying one file to a bare VPS. A third-party import is an install
    step, and an install step on a machine you reach by SSH once is a machine that stops
    working the day the wheel moves."""
    stdlib = set(sys.stdlib_module_names)
    tree = ast.parse(SERVER_PATH.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    outside = sorted(r for r in roots if r not in stdlib)
    assert not outside, f"server.py imports non-stdlib modules: {outside}"
    assert not any(
        isinstance(n, ast.ImportFrom) and n.level for n in ast.walk(tree)
    ), "a relative import means the file is not standalone"
    print(f"  the deployable imports {len(roots)} modules, all standard library: PASS")


if __name__ == "__main__":
    test_a_real_query_parses()
    test_a_hostile_packet_is_refused_without_hanging()
    test_the_answer_is_an_a_record_never_nxdomain()
    test_the_question_is_echoed_byte_for_byte()
    test_a_non_a_query_is_answered_with_no_data_not_a_refusal()
    test_a_response_fits_in_a_udp_datagram()
    test_the_token_is_the_label_left_of_the_zone()
    test_the_server_and_hackpit_agree_on_what_a_token_is()
    test_an_http_token_comes_from_the_subdomain_or_the_first_path_segment()
    test_a_dns_hit_records_the_correlation_fields()
    test_credentials_arriving_in_a_hit_are_redacted()
    test_headers_are_capped_in_count_and_length()
    test_a_body_is_stored_only_as_a_capped_excerpt()
    test_the_canary_response_never_reflects_the_request()
    test_the_server_refuses_to_start_without_a_read_secret()
    test_the_read_api_refuses_a_wrong_bearer()
    test_the_bearer_comparison_is_constant_time()
    test_hits_are_served_newest_first_on_a_cursor()
    test_the_log_is_append_only_and_survives_a_restart()
    test_the_log_opens_its_file_only_for_appending()
    test_the_read_api_is_rate_limited_per_source()
    test_the_server_executes_nothing_and_forwards_nothing()
    test_the_inertness_scan_can_fail()
    test_the_deployable_depends_on_nothing_but_the_standard_library()
    print("ALL OOB canary server tests pass")
