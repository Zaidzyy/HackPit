#!/usr/bin/env python3
"""Build #17 item 4 — runbook Sec 3.4: the ACTIVE SCANNER against the real target.

The last untested link in build #15, and the highest-value one. Part 1 (publish + manual
browsing) passed Akamai; part 2 (the AJAX spider) did not. Part 3 replays CAPTURED requests,
which carry Firefox's headers rather than a fresh browser's -- so the chain may hold end to
end even though the spider does not. Nobody has checked. Both outcomes matter:

  * it works   -> the captured-request -> scanner chain survives a WAF. That is the pipeline
                  you actually hunt with, confirmed.
  * it refuses -> the ATTACK half is blocked even though capture works, which is a
                  significantly larger finding than the spider's refusal.

*** THIS SENDS REAL ATTACK TRAFFIC AT A PRODUCTION STOREFRONT. *** 376 requests against a
single endpoint in the build #14 measurement, carrying SQLi / XSS / command-injection payloads
at every parameter.

THE SCAN IS NOT PACED. Build #16 added per-tool throttling, but `pace` is a field on
ExecRequest applied on the EXECUTOR path; cockpit/proxy.py contains no reference to it, and
this path drives ZAP's API directly. The request ceiling below is the only rate control there
is -- ZAP's own scanner.setOptionDelayInMs would be the real fix and is deliberately not in
this build's scope.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "http://127.0.0.1:8000"
ZAP_CONTAINER = "hackpit-engage-sandbox"
PORT = 8090
BASE = "https://www.crateandbarrel.me"

# --------------------------------------------------------------------------------------
# THE ENDPOINT, CHOSEN DELIBERATELY -- this is the safety decision of the whole item.
#
# A category listing with a REAL application filter parameter (`allCategories`) plus Next.js'
# `_rsc` flight parameter. A GET that reads a catalogue. Picked out of the 55 requests the
# proxy actually captured, not guessed.
#
# WHAT WAS REJECTED AND WHY:
#   * /en-ae/cart, /en-ae/login/register, /en-ae/gift-registry, /en-ae/guest/order -- all
#     present in the capture. Injection payloads at a cart or checkout parameter on a live
#     storefront can create orders or wipe a basket. This is the AJAX spider's hazard arriving
#     through a different door, and it is the reason the endpoint is a constant here rather
#     than an argument.
#   * /api?endpoint=https%3A%2F%2Fapi.crateandbarrel.me%2F... -- a server-side proxy that
#     takes a full URL in a query parameter. By far the most interesting thing in the capture
#     and EXACTLY WHY IT IS NOT SCANNED HERE: active-scanning it means asking the server to
#     fetch whatever the scanner puts in that parameter. That is not a read-only endpoint, it
#     is outbound request generation from the target's own infrastructure, and it deserves a
#     deliberate decision of its own rather than riding along inside a pipeline test.
TARGET_URL = (
    "https://www.crateandbarrel.me/en-ae/c/crate-and-kids/furniture-19172"
    "?allCategories=kids-bedroom-furniture%3Astudy-play-furnitur&_rsc=EPkJxyJVtrNNrxAH"
)

# *** NOTHING HERE REFUSES ANYTHING. *** An earlier version of this script hard-blocked a list
# of path tokens (cart, checkout, account, …) and refused to run under an engagement record whose
# prose forbade active scanning. Zaid stripped both, 2026-08-04, and he is right that they did
# not belong: HackPit's whole design is that the operator is the bound and every control informs
# rather than forbids — the danger gate demands a second confirm and then proceeds, the scope
# lock is documented as a handrail, and this build *declined* to make the authorization field
# enforceable. A proof script inventing a prohibition the product does not have was the one
# place in build #17 that said "you may not".
#
# What survives is the REASONING, because a recorded decision is worth more than a blocked path:
# injection payloads at a checkout parameter on a live storefront can create real orders or empty
# a basket. That is a fact about the target, and the operator weighs it.
WORTH_KNOWING = ("cart", "checkout", "account", "newsletter", "order", "payment", "registry")

# The only rate control on this path. 376 requests was the single-endpoint measurement; this
# leaves room for a normal scan to finish and stops a runaway well short of real load.
MAX_REQUESTS = 1000
MAX_SECONDS = 12 * 60
POLL = 10


def call(method: str, path: str, body: dict | None = None, **params):
    url = f"{API}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "null")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


fail = []


def need(cond: bool, msg: str) -> bool:
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        fail.append(msg)
    return cond


print("=" * 78)
print("BUILD #17 ITEM 4 -- runbook Sec 3.4, active scanner vs the real target")
print("=" * 78)

# --- PRECONDITION: item 1. Enforced, not assumed. --------------------------------------
# Running an active scan under a record that says "PASSIVE RECON ONLY ... no active scanning
# per rules of engagement" leaves an audit trail contradicting the action. Zaid decided NOT to
# make that field enforceable -- approve-each is the bound -- so this check lives here, in the
# thing that would create the contradiction, rather than as a gate in the product.
print("\n[pre] the engagement record must not forbid what this is about to do")
code, eng = call("GET", "/cockpit/engagement")
active = (eng or {}).get("active") or []
need(code == 200, f"GET /cockpit/engagement -> {code}")

# *** THE PROPERTY IS PER-TARGET, AND ASSERTING IT GLOBALLY WAS WRONG. *** An earlier version
# required "exactly one active engagement" and would have refused to run: there are ~21, twenty
# of them old lab records against RFC1918 addresses, still active because engagement expiry
# (D4) was reviewed and DECLINED. They have nothing to do with a scan of this host, and exiting
# them to satisfy a check would be a destructive tidy-up nobody asked for. What matters is
# narrower: the record this scan is ATTRIBUTED TO must permit it, and no other active record
# for the same host may contradict it.
HOST = "www.crateandbarrel.me"
mine = [e for e in active if e.get("target") == HOST]
print(f"       {len(active)} active engagement(s), {len(mine)} naming {HOST}")
if not need(len(mine) >= 1, f"an active engagement names {HOST}"):
    print("\n  Run build #17 item 1 first.")
    print("\nVERDICT=FAIL (no engagement for the target)"); sys.exit(1)

forbidding = [e.get("engagement_id") for e in mine
              if "PASSIVE RECON ONLY" in (e.get("authorization") or "").upper()]
if forbidding:
    # INFORMS, DOES NOT REFUSE. The authorization field is free prose that no gate reads — this
    # build reviewed that and accepted it. A script that turned it into a blocker would be
    # enforcing, by the back door, exactly the `passive_only` gate that was declined.
    print(f"  NOTE  {len(forbidding)} active record(s) for {HOST} still say PASSIVE RECON ONLY:")
    print(f"        {forbidding}")
    print("        The scan will run. Consider build17_item1_fix_engagement.py first, so the")
    print("        audit trail does not contradict the action.")
else:
    print(f"  ok   no active record for {HOST} contradicts active scanning")

# Newest wins: item 1 exits the stale record and enters a corrected one, so the most recently
# entered record for this host is the one whose text describes what is about to happen.
rec = sorted(mine, key=lambda e: e.get("entered_at") or "")[-1]
eid = rec.get("engagement_id")
print(f"       attributing to {eid} (entered {rec.get('entered_at')})")

# --- PRECONDITION: the endpoint is read-only and already captured -----------------------
print("\n[pre] the endpoint")
path_l = urllib.parse.urlsplit(TARGET_URL).path.lower()
hit = [w for w in WORTH_KNOWING if w in path_l]
if hit:
    print(f"  NOTE  this path contains {hit} — on a live storefront, injection payloads at a")
    print("        parameter like that can create real orders or empty a basket. Not blocked;")
    print("        said once so the choice is made with it in view.")
# NO SCOPE CHECK HERE, DELIBERATELY. An earlier version required the URL to contain the
# engagement's NAMED target — which would have refused the other ten in-scope hosts, since the
# scope is eleven and the named target is one. That is the harness inventing a bound narrower
# than the product's. `cockpit/scope.py` is the authority (wildcards, CIDR, exclusions, measured
# against this very program) and `executor.validate_request` runs it before ZAP is contacted, so
# an out-of-scope URL earns a 403 naming the target gate a few lines below. One scope model, and
# it is not this file's.
url_host = urllib.parse.urlsplit(TARGET_URL).hostname or ""
in_declared = url_host in (rec.get("scope_include") or [])
print(f"       {TARGET_URL}")
print(f"       host={url_host} — {'in' if in_declared else 'NOT in'} the engagement's declared "
      f"scope list; the target gate decides, not this script")

code, hist = call("GET", "/cockpit/proxy/history", container=ZAP_CONTAINER, port=PORT, count=1)
need(code == 200, f"the recording proxy answers ({code})")

# *** THE BACKEND MUST BE ABLE TO DRIVE THE DAEMON, AND IT SILENTLY CANNOT IF IT DID NOT START
# IT. *** proxy.py holds API keys in an IN-PROCESS dict (`_keys`), so a backend restart loses
# the key for a daemon that is still running. `_api_get` then sends no header, ZAP answers with
# an EMPTY BODY, and `history()` turns that into `[]`. Measured 2026-08-04: ZAP holds 1076
# messages while GET /cockpit/proxy returns [] and the history route returns zero exchanges.
#
# This check exists because of what the runbook says about exactly this: "a broken proxy is a
# bug in this build, and a refused browser is a finding about the target. Do not report one as
# the other." Without it, a scan that sent nothing would print REFUSED and be written down as
# "Akamai blocks the scanner" — the single most consequential wrong conclusion available here.
code_p, proxies = call("GET", "/cockpit/proxy")
live = [p for p in (proxies or [])
        if p.get("container") == ZAP_CONTAINER and p.get("status") != "down"]
if not need(bool(live) or bool(hist),
            "the backend can SEE the running daemon (key held, history readable)"):
    print("""
  The daemon is alive but this backend process did not start it, so it holds no API key for
  it and every read comes back empty. Do NOT run the scan in this state — a zero result would
  be indistinguishable from the target refusing us.

  Two ways forward, and it is a decision, not a detail:
    (a) fix the key recovery in cockpit/proxy.py so a daemon can be adopted, keeping the
        ~1000 already-captured messages; or
    (b) stop the daemon and start it through POST /cockpit/proxy, then re-browse the target
        in Firefox to repopulate ZAP's Sites tree (the scan can only aim at captured URLs).
""")
    print("VERDICT=FAIL (backend cannot drive the daemon)"); sys.exit(1)

# --- BASELINE: session health BEFORE, so the after-reading has something to mean ---------
code, health0 = call("GET", "/cockpit/proxy/session-health",
                     container=ZAP_CONTAINER, port=PORT, count=200)
print(f"\n[pre] session health BEFORE: {json.dumps(health0)[:200]}")

if fail:
    print("\nVERDICT=FAIL (preconditions)"); sys.exit(1)

# --- THE SCAN ----------------------------------------------------------------------------
print("\n[run] starting the active scan (recurse=false, ONE url)")
code, scan = call("POST", "/cockpit/proxy/scan", {
    "target_url": TARGET_URL,
    "port": PORT,
    "recurse": False,
    "engagement_id": eid,
    "approved": True,
    "dangerous_ack": True,
})
print(f"       HTTP {code}: {json.dumps(scan)[:400]}")
if code != 200:
    # A 403 names a safety gate; a 409 is availability -- including `url_not_found`, which is
    # ZAP refusing to attack a URL it has never seen. That is a containment property, not a bug.
    print(f"\nVERDICT=REFUSED-BY-HACKPIT ({code}) -- nothing was sent at the target.")
    sys.exit(1)

sid = scan.get("id")
t0 = time.time()
stopped_early = False
last = {}
print(f"       scan id={sid}. ceiling: {MAX_REQUESTS} requests / {MAX_SECONDS}s")
print("       watch `requests` climb -- this is the only rate control on this path")

while True:
    time.sleep(POLL)
    code, scans = call("GET", "/cockpit/proxy/scan", container=ZAP_CONTAINER, port=PORT)
    cur = next((s for s in (scans or []) if s.get("id") == sid), None)
    if cur is None:
        print("       scan vanished from ZAP's list")
        break
    last = cur
    el = int(time.time() - t0)
    print(f"       t+{el:>4}s  state={cur.get('state'):<9} progress={cur.get('progress'):>3}%"
          f"  requests={cur.get('requests'):>5}  alerts={cur.get('alerts')}")
    if cur.get("state") in {"FINISHED", "STOPPED"} or int(cur.get("progress") or 0) >= 100:
        break
    if int(cur.get("requests") or 0) > MAX_REQUESTS or el > MAX_SECONDS:
        print(f"       CEILING HIT -- stopping (stop is ungated for exactly this reason)")
        call("DELETE", f"/cockpit/proxy/scan/{sid}", container=ZAP_CONTAINER, port=PORT)
        stopped_early = True
        break

# --- WHAT CAME BACK ------------------------------------------------------------------------
print("\n[post] alerts")
code, alerts = call("GET", "/cockpit/proxy/alerts", container=ZAP_CONTAINER, port=PORT,
                    base_url=BASE, count=500)
alerts = alerts or []

# *** THE ALERT LIST IS NOT SCAN-SCOPED, AND THE FIRST RUN OF THIS SCRIPT REPORTED IT AS IF IT
# WERE. *** The route says so in its own docstring — it includes PASSIVE alerts raised merely by
# traffic passing through the proxy, with no active scan involved, and they survive a scan being
# removed. So it returned 153 alerts from an hour of manual browsing and this script announced
# "the chain survives the WAF" on the strength of them. Measured afterwards: exactly 2 of those
# 153 are on the endpoint that was scanned, and both are passive header findings. Walking into a
# trap the function documents is worse than walking into an undocumented one.
scanned_path = urllib.parse.urlsplit(TARGET_URL).path
on_target = [a for a in alerts if scanned_path in (a.get("url") or "")]
print(f"       {len(alerts)} alert(s) held for {BASE} — SITE-WIDE, mostly passive and mostly")
print(f"       predating this scan. On the endpoint actually scanned: {len(on_target)}")
for a in on_target[:20]:
    print(f"         [{a.get('risk','?'):<8}] {a.get('name','')[:60]} "
          f"param={a.get('param','')[:24]}")

# ZERO FINDINGS AND A DEAD SESSION LOOK IDENTICAL FROM THE OUTSIDE. Build #16 item 10 added
# this flag to tell them apart; it is read here rather than re-derived.
code, health1 = call("GET", "/cockpit/proxy/session-health",
                     container=ZAP_CONTAINER, port=PORT, count=200)
print(f"\n[post] session health AFTER: {json.dumps(health1)[:300]}")

# *** WHAT DID THE EDGE ACTUALLY DO WITH THE ATTACK REQUESTS? ***
# `requests` counts what ZAP SENT. It says nothing about whether anything was allowed through,
# and neither does an alert count. The first pass of this script had both and still got the
# answer backwards. So read the responses to the scanned path out of ZAP's own history and
# classify them: a 403 carrying a WAF block page is a REFUSAL, however cleanly it is served.
print("\n[post] what came back for the scanned endpoint")
# PAGE THE WHOLE HISTORY, do not take the first window. `start=0` is the OLDEST window, not the
# newest — the route's description says "newest window first" and the implementation passes
# start/count straight to ZAP, which counts from the beginning. Reading one window from 0
# returned ZERO exchanges on the scanned path while ZAP was holding 35 of them, i.e. a
# confident "no refusals" for a scan that was refused 35 times.
recent: list = []
for page in range(20):  # 500 * 20 = 10k exchanges; a bounded loop, not a while-true
    code, chunk = call("GET", "/cockpit/proxy/history", container=ZAP_CONTAINER, port=PORT,
                       start=page * 500, count=500)
    if code != 200 or not chunk:
        break
    recent.extend(chunk)
    if len(chunk) < 500:
        break
print(f"       paged {len(recent)} recorded exchange(s) in total")
# A CapturedExchange is NESTED — request.url and response.status, not flat keys. Reading it
# flat returns None for every field and yields a confident "0 refusals", which would have put
# the wrong verdict back in through a different door.
mine_msgs = [e for e in (recent or [])
             if scanned_path in ((e.get("request") or {}).get("url") or "")]
codes: dict[str, int] = {}
waf = 0
for e in mine_msgs:
    st = str((e.get("response") or {}).get("status") or "?")
    codes[st] = codes.get(st, 0) + 1
    if st in {"403", "406", "429"}:
        waf += 1
print(f"       {len(mine_msgs)} recorded exchange(s) on that path: {codes}")

reqs = int(last.get("requests") or 0)
blocked_share = (waf / len(mine_msgs)) if mine_msgs else 0.0

if reqs == 0:
    verdict = ("REFUSED -- the scanner sent nothing that landed. The ATTACK half is blocked "
               "even though capture works.")
elif blocked_share >= 0.5:
    verdict = (f"REFUSED BY THE WAF -- {reqs} attack requests were SENT and "
               f"{waf}/{len(mine_msgs)} of the recorded responses are edge refusals ({codes}). "
               "Capture works and the attack half does not: the payloads never reach the "
               "application. This is the larger of the two outcomes the plan named.")
elif (health1 or {}).get("verdict") == "suspect":
    verdict = (f"INCONCLUSIVE -- {reqs} requests, but session health says 'suspect': the "
               "traffic started coming back login-shaped. Findings (or their absence) cannot "
               "be trusted.")
elif on_target:
    verdict = (f"WORKS -- {reqs} attack requests reached the application and ZAP raised "
               f"{len(on_target)} alert(s) ON THE SCANNED ENDPOINT. The captured-request -> "
               "scanner chain survives the WAF.")
else:
    verdict = (f"WORKS, NO FINDINGS -- {reqs} attack requests reached the application; session "
               f"health is '{(health1 or {}).get('verdict')}', so zero findings on this "
               "endpoint is a real zero rather than a dead session.")

print("\n" + "=" * 78)
print(f"requests_sent={reqs}  alerts_on_endpoint={len(on_target)}  "
      f"alerts_site_wide={len(alerts)}  edge_refusals={waf}/{len(mine_msgs)}  "
      f"stopped_early={stopped_early}")
print(f"VERDICT={verdict}")
print("=" * 78)
print("JSON=" + json.dumps({"scan": last, "alerts_site_wide": len(alerts),
                            "alerts_on_endpoint": len(on_target), "status_codes": codes,
                            "edge_refusals": waf,
                            "health_before": health0, "health_after": health1,
                            "stopped_early": stopped_early, "target": TARGET_URL}))
