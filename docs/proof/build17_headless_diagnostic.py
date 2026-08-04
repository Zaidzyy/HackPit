#!/usr/bin/env python3
"""Build #17 item 2 — THE DIAGNOSTIC: why does Akamai refuse headless Chromium?

Runs INSIDE the engage sandbox, against the ZAP daemon build #15 left running. No build,
no product change: five probes and a verdict. Prints a decision-table row at the end.

WHAT IS ALREADY KNOWN AND IS NOT RE-MEASURED (build #15, assessment "acceptance test, run
live"): ZAP's own HTTP client passes Akamai -- all 55 captured requests were fetched BY ZAP.
Firefox -> ZAP -> target passes. So the upstream TLS stack is fine and the TLS-fingerprint
theory is dead. The discriminator is in what ZAP FORWARDED, i.e. the headers the client set.

EVERY probe is measured the same way: the delta in ZAP's own message history for the target,
and how many of those messages came back with a response at all. A page that never answers
leaves a request with an empty responseHeader. That signal works identically for headless,
headed and curl, which is the only reason the probes are comparable.

EVERY harness carries its own control against example.com. A headed browser that cannot
start would otherwise read as "Akamai refuses headed browsers", which is decision-table row
2, which is the one row that must never be reached by accident.

Nothing here is spoofed except P1, which is a MEASUREMENT and is labelled as one.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

ZAP = "http://127.0.0.1:8090"
PROXY = "http://127.0.0.1:8090"
TARGET = "https://www.crateandbarrel.me/"
CONTROL = "https://example.com/"
KEY = os.environ.get("ZAP_KEY", "").strip()

# *** A PER-URL SIZE FLOOR, BECAUSE ONE THRESHOLD FOR BOTH IS WRONG — AND IT WAS. ***
# The first run of this script used a single `dom > 5000` rule and declared BOTH controls
# broken, printing "ROW none: HARNESS BROKEN" over a set of probes that had worked perfectly.
# example.com is a ~1 KB page: a perfect fetch of it is 561 bytes of DOM. A retail homepage is
# megabytes. The floor has to belong to the URL, not to the harness. That mistake also cost
# P2c 76 seconds — the headed probe only stops early once it is over the floor, so it sat
# waiting on a page that had finished loading in three.
MIN_DOM = {TARGET: 50_000, CONTROL: 300}

# Statuses that mean "the edge answered INSTEAD of the site". A 403 with an Akamai block page
# is a response, and scoring it as one is the exact error that made this build's first pass
# report a WAF refusal as success.
REFUSAL_STATUS = ("403", "429", "503", "504")

# Probe timeout. ZAP's own read timeout is 20s; a real page load through a proxy can take
# longer, so this is deliberately well past both -- a probe that hits THIS limit hung.
PROBE_TIMEOUT = 75

# Akamai's refusal in build #15 was a silent hang, not a block page. Both are failures but
# they are DIFFERENT failures, so the block page is detected rather than lumped in.
BLOCK_MARKERS = (
    "access denied",
    "reference #",
    "pardon our interruption",
    "you don't have permission to access",
    "akamai",
)

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def zap(view: str, **params: str):
    """Call ZAP's API DIRECTLY -- never through the proxy, and never with proxies inherited
    from the environment (ProxyHandler({}) disables them; build #13's lesson about
    build_opener quietly re-adding a handler applies to redirects, not to this)."""
    params["apikey"] = KEY
    url = f"{ZAP}/JSON/{view}/?" + urllib.parse.urlencode(params)
    with _opener.open(url, timeout=30) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def site_of(url: str) -> str:
    """ZAP's `baseurl` is a PREFIX filter over the history. Measured: the bare host and the
    host-with-slash give different counts (170 vs 169), and a full URL with a query narrows to
    that one page's subtree. Every probe here loads the same page, so the comparison must be
    against one stable prefix -- scheme://host -- or two probes would silently be counting
    different things and the whole decision table would rest on it."""
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def msg_count(baseurl: str) -> int:
    return int(zap("core/view/numberOfMessages",
                   baseurl=site_of(baseurl))["numberOfMessages"])


def answered(baseurl: str, start: int, count: int) -> tuple[int, int, list[str]]:
    """(messages, answered, status lines) for a slice of ZAP's history.

    An empty responseHeader is ZAP saying "I sent this and got nothing back" -- which is the
    exact signature of the original curl failure and the thing being diagnosed."""
    if count <= 0:
        return 0, 0, []
    got = zap("core/view/messages", baseurl=site_of(baseurl),
              start=str(start), count=str(count))
    msgs = got.get("messages", [])
    lines, ok = [], 0
    for m in msgs:
        head = (m.get("responseHeader") or "").strip()
        if head:
            ok += 1
            lines.append(head.splitlines()[0][:80])
        else:
            lines.append("<NO RESPONSE>")
    return len(msgs), ok, lines


def client_hints(baseurl: str, start: int, count: int) -> tuple[bool, str]:
    """Did the client send `Sec-CH-UA`, and what User-Agent did it claim?

    *** THIS IS THE ANSWER, AND IT IS NOT THE HEADER EVERYONE EXPECTED. *** The prime suspect
    was the `HeadlessChrome` token in the User-Agent. It is not the discriminator. Measured
    across all four clients that hit this target: the headed browser sends
    `sec-ch-ua: "Not;A=Brand";v="8", "Chromium";v="150"` and is served; BOTH headless runs —
    stock UA and spoofed UA alike — send NO `sec-ch-ua` at all, and both time out.

    Which is why P1 could never have worked: overriding `--user-agent` changes the string the
    client CLAIMS and leaves untouched the set of headers a real browser EMITS. You cannot get
    there by lying about one header; you get there by using a browser that sends them all.
    """
    if count <= 0:
        return False, ""
    got = zap("core/view/messages", baseurl=site_of(baseurl),
              start=str(start), count=str(count))
    hints, ua = False, ""
    for m in got.get("messages", []):
        for line in (m.get("requestHeader") or "").splitlines():
            low = line.lower()
            if low.startswith("sec-ch-ua:"):
                hints = True
            elif low.startswith("user-agent:") and not ua:
                ua = line.split(":", 1)[1].strip()
    return hints, ua


def reap_browsers() -> None:
    """Kill stray browsers by process NAME. Never `pkill -f` here: the ZAP daemon's argv
    carries `-config selenium.chromeDriver=/usr/bin/chromedriver`, so a -f pattern for
    "chrome" kills the daemon this whole diagnostic depends on. That exact defect cost
    build #15 three failed proof checks."""
    for name in ("chromium", "chrome", "chromedriver"):
        subprocess.run(["pkill", "-x", name], capture_output=True)
    time.sleep(1)


def run(argv, timeout=PROBE_TIMEOUT, env=None):
    t0 = time.time()
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, time.time() - t0, False
    except subprocess.TimeoutExpired as e:
        return -9, (e.stdout or b""), time.time() - t0, True


RESULTS: list[dict] = []


def record(label: str, url: str, rc: int, dom: bytes, secs: float, hung: bool,
           before: int, after: int, note: str = "") -> dict:
    n, ok, lines = answered(url, before, after - before)
    text = dom.decode("utf-8", "replace")
    blocked = any(m in text.lower() for m in BLOCK_MARKERS) and len(text) < 200_000
    # *** "ANSWERED" IS NOT "ALLOWED", AND CONFLATING THEM IS THIS BUILD'S OWN MISTAKE. ***
    # `ok` counts messages that came back with any response at all. Akamai's refusal IS a
    # response — 403 with a block page, or the 504 ZAP emits when the upstream read starves.
    # Counting those as success is what made the first pass of item 4 report a WAF block as
    # "the chain survives the WAF".
    refused = [s for s in lines if any(f" {c}" in s for c in REFUSAL_STATUS)]
    served = [s for s in lines if " 200" in s or " 301" in s or " 302" in s]
    floor = MIN_DOM.get(url, 5_000)
    passed = (rc == 0 and len(dom) >= floor and not blocked
              and bool(served) and not refused)
    hints, sent_ua = client_hints(url, before, after - before)
    r = {
        "label": label, "url": url, "rc": rc, "secs": round(secs, 1), "hung": hung,
        "dom_bytes": len(dom), "dom_floor": floor, "zap_msgs": n, "zap_answered": ok,
        "refused_statuses": refused[:3], "block_page": blocked, "sec_ch_ua": hints,
        "claimed_ua": sent_ua[:90], "pass": passed, "note": note, "status": lines[:4],
    }
    RESULTS.append(r)
    print(f"  {label:<28} pass={str(passed):<5} rc={rc} {secs:5.1f}s "
          f"dom={len(dom)}B/{floor} zap={ok}/{n} answered{' HUNG' if hung else ''}"
          f"{' BLOCKPAGE' if blocked else ''}{' REFUSED' + str(refused[:1]) if refused else ''}"
          f" sec-ch-ua={'YES' if hints else 'no'}")
    for line in lines[:3]:
        print(f"      | {line}")
    return r


def probe_headless(label: str, url: str, ua: str | None = None) -> dict:
    reap_browsers()
    argv = ["chromium", "--headless", "--disable-gpu", "--ignore-certificate-errors",
            f"--proxy-server={PROXY}", "--dump-dom", url]
    if ua:
        argv.insert(-1, f"--user-agent={ua}")
    before = msg_count(url)
    rc, dom, secs, hung = run(argv)
    after = msg_count(url)
    return record(label, url, rc, dom, secs, hung, before, after,
                  note=("spoofed UA" if ua else "stock UA"))


# --------------------------------------------------------------------------------------
print("=" * 78)
print("BUILD #17 ITEM 2 -- headless refusal diagnostic")
print("=" * 78)
if not KEY:
    print("FATAL: ZAP_KEY not set"); sys.exit(2)
try:
    print("ZAP version:", zap("core/view/version")["version"])
except Exception as e:  # noqa: BLE001
    print(f"FATAL: cannot reach ZAP API: {e}"); sys.exit(2)

# ---- the exact UA under test -----------------------------------------------------------
# Read it from the browser rather than assuming it. P1's whole claim is "one token differs",
# and that claim is only checkable against the real string.
print("\n[UA] reading headless Chromium's own User-Agent")
_, ua_dom, _, _ = run(
    ["chromium", "--headless", "--disable-gpu", "--dump-dom",
     "data:text/html,<body id=x><script>document.getElementById('x')"
     ".textContent=navigator.userAgent</script>"], timeout=40)
m = re.search(r"Mozilla/5\.0[^<]*", ua_dom.decode("utf-8", "replace"))
HEADLESS_UA = m.group(0).strip() if m else ""
print("  headless UA:", HEADLESS_UA or "<COULD NOT READ>")
SPOOF_UA = HEADLESS_UA.replace("HeadlessChrome", "Chrome")
print("  P1 will send:", SPOOF_UA or "<COULD NOT DERIVE>")
if HEADLESS_UA and SPOOF_UA == HEADLESS_UA:
    print("  NOTE: no 'HeadlessChrome' token present -- P1 is not the experiment it "
          "was designed to be; read its result with that in mind.")

# ---- P0: reproduce, 3x. One measurement is not a result. --------------------------------
print("\n[P0] reproduce the failure 3x (headless, stock UA, real target)")
p0 = [probe_headless(f"P0.{i} headless->target", TARGET) for i in (1, 2, 3)]
print("\n[P0c] control: same binary, same proxy, example.com")
p0c = probe_headless("P0c headless->example", CONTROL)

p0_pass = sum(1 for r in p0 if r["pass"])
if p0_pass not in (0, 3):
    print(f"\n!! INTERMITTENT: {p0_pass}/3 headless runs passed. Everything below assumes a "
          "deterministic discriminator. STOP -- this is a different investigation.")
if not p0c["pass"]:
    print("\n!! The CONTROL failed: headless Chromium cannot fetch example.com through this "
          "proxy either. The harness is broken; no probe below means anything.")

# ---- P1: isolate the HeadlessChrome token -----------------------------------------------
print("\n[P1] headless + a normal Chrome UA  (ONE SPOOFED REQUEST, AS A MEASUREMENT)")
p1 = probe_headless("P1 headless+chromeUA", TARGET, ua=SPOOF_UA) if SPOOF_UA else None

# ---- P2: a genuinely headed browser, nothing spoofed -------------------------------------
print("\n[P2] headed Chromium under Xvfb, stock UA, nothing spoofed")
print("  installing xvfb into the RUNNING container (not rebuilding the image for a probe)")
inst = subprocess.run(["sh", "-c", "apt-get update -qq && apt-get install -y -qq xvfb"],
                      capture_output=True, timeout=600)
print(f"  apt rc={inst.returncode}")
if inst.returncode != 0:
    print("  apt stderr:", inst.stderr.decode("utf-8", "replace")[-500:])


def start_xvfb() -> bool:
    subprocess.run(["pkill", "-x", "Xvfb"], capture_output=True)
    time.sleep(1)
    subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1280x1024x24"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(20):
        time.sleep(0.5)
        if subprocess.run(["pgrep", "-x", "Xvfb"], capture_output=True).returncode == 0:
            return True
    return False


if not start_xvfb():
    # RECORDED TRAP: Kali ships some binaries with file capabilities, and the sandbox runs
    # with no-new-privileges, so the kernel refuses to exec them. Strip the caps and retry.
    print("  Xvfb did not start -- stripping file capabilities and retrying (recorded trap)")
    subprocess.run(["sh", "-c", "setcap -r /usr/bin/Xvfb 2>/dev/null; "
                                "setcap -r /usr/bin/Xorg 2>/dev/null"], capture_output=True)
    ok = start_xvfb()
    print(f"  retry: {'started' if ok else 'STILL DOWN'}")

XENV = dict(os.environ, DISPLAY=":99")


def probe_headed(label: str, url: str) -> dict:
    """A headed browser has no --dump-dom. Drive it over CDP instead and read the DOM the
    same way, so the pass criterion is identical to the headless probes."""
    reap_browsers()
    before = msg_count(url)
    t0 = time.time()
    proc = subprocess.Popen(
        ["chromium", "--ignore-certificate-errors", f"--proxy-server={PROXY}",
         "--remote-debugging-port=9222", "--remote-allow-origins=*",
         "--user-data-dir=/tmp/hp-headed", "--no-first-run", "--no-default-browser-check",
         url], env=XENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dom = b""
    deadline = t0 + PROBE_TIMEOUT
    while time.time() < deadline:
        time.sleep(3)
        try:
            with _opener.open("http://127.0.0.1:9222/json", timeout=10) as r:
                tabs = json.loads(r.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            continue
        page = next((t for t in tabs if t.get("type") == "page"), None)
        if not page:
            continue
        # The tab's own title+url is the cheap signal; the DOM is fetched via the debugger's
        # HTTP surface so the size comparison stays honest against the headless probes.
        got = fetch_dom_via_cdp(page)
        if got and len(got) > 5000:
            dom = got
            break
        dom = got or dom
    secs = time.time() - t0
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    reap_browsers()
    after = msg_count(url)
    return record(label, url, 0 if dom else -9, dom, secs, not dom, before, after,
                  note="headed/Xvfb, stock UA")


def fetch_dom_via_cdp(page: dict) -> bytes:
    """Evaluate document.documentElement.outerHTML over the DevTools websocket."""
    ws = page.get("webSocketDebuggerUrl", "")
    if not ws:
        return b""
    script = (
        "import json,sys\n"
        "try:\n"
        "    from websocket import create_connection\n"
        "except Exception:\n"
        "    sys.exit(3)\n"
        f"c=create_connection({ws!r},timeout=20)\n"
        "c.send(json.dumps({'id':1,'method':'Runtime.evaluate','params':"
        "{'expression':'document.documentElement.outerHTML','returnByValue':True}}))\n"
        "while True:\n"
        "    m=json.loads(c.recv())\n"
        "    if m.get('id')==1:\n"
        "        v=m.get('result',{}).get('result',{}).get('value','')\n"
        "        sys.stdout.write(v or '')\n"
        "        break\n")
    p = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=40)
    if p.returncode == 3:
        return b"<no-websocket-client>"
    return p.stdout


if subprocess.run(["pgrep", "-x", "Xvfb"], capture_output=True).returncode != 0:
    print("  SKIPPED: no virtual display. P2 is UNMEASURED -- not 'failed'.")
    p2 = p2c = None
else:
    subprocess.run(["sh", "-c", "python3 -m pip install --quiet --break-system-packages "
                                "websocket-client 2>/dev/null || true"],
                   capture_output=True, timeout=300)
    print("  [P2c] control first: headed -> example.com")
    p2c = probe_headed("P2c headed->example", CONTROL)
    if not p2c["pass"]:
        print("  !! The HEADED CONTROL failed. A headed result at the target would be "
              "measuring this harness, not Akamai. P2 is UNMEASURED.")
    print("  [P2] headed -> target")
    p2 = probe_headed("P2 headed->target", TARGET)

# ---- P3: the failure SHAPE, not just 'it failed' -----------------------------------------
print("\n[P3] failure shape through the proxy (connect? TLS? starved or reset?)")
for label, ua in (("P3a curl+headlessUA", HEADLESS_UA), ("P3b curl+chromeUA", SPOOF_UA)):
    if not ua:
        continue
    t0 = time.time()
    p = subprocess.run(
        ["curl", "-sv", "-o", "/dev/null", "--max-time", "40", "-x", PROXY, "-k",
         "-A", ua, TARGET], capture_output=True, timeout=60)
    err = p.stderr.decode("utf-8", "replace")
    shape = []
    for pat, desc in ((r"Connected to", "proxy TCP connected"),
                      (r"CONNECT tunnel established|HTTP/1\.[01] 200", "CONNECT tunnel up"),
                      (r"SSL connection using|TLS.*handshake", "TLS established"),
                      (r"Empty reply from server", "EMPTY REPLY (reset after request)"),
                      (r"Operation timed out|timed out after", "TIMED OUT (starved)"),
                      (r"Recv failure|Connection reset", "CONNECTION RESET")):
        if re.search(pat, err, re.I):
            shape.append(desc)
    print(f"  {label:<22} rc={p.returncode} {time.time()-t0:5.1f}s  {' | '.join(shape)}")
    RESULTS.append({"label": label, "rc": p.returncode,
                    "secs": round(time.time() - t0, 1), "shape": shape, "pass": p.returncode == 0})

# ---- the decision table ------------------------------------------------------------------
print("\n" + "=" * 78)
print("DECISION TABLE")
print("=" * 78)
P1 = bool(p1 and p1["pass"])
P2 = bool(p2 and p2["pass"])
p2_measured = p2 is not None and p2c is not None and p2c["pass"]

# The discriminator, stated from what was OBSERVED rather than from the prime suspect.
print("  what each client actually sent:")
for r in RESULTS:
    if r.get("url") == TARGET and "claimed_ua" in r:
        print(f"    {r['label']:<26} sec-ch-ua={'YES' if r['sec_ch_ua'] else 'NO ':<3}"
              f" served={'yes' if r['pass'] else 'no '}  ua={r['claimed_ua'][:60]}")
print()

print(f"  P0 (headless, stock UA): {p0_pass}/3 passed"
      f"   [control {'OK' if p0c['pass'] else 'BROKEN'}]")
print(f"  P1 (spoofed UA):         {'PASSES' if P1 else 'fails'}")
print(f"  P2 (headed/Xvfb):        "
      f"{('PASSES' if P2 else 'fails') if p2_measured else 'UNMEASURED'}")

if not p0c["pass"]:
    row, action = "none", "HARNESS BROKEN -- the control failed. Re-run; measure nothing."
elif p0_pass not in (0, 3):
    row, action = "none", "INTERMITTENT P0 -- not a deterministic discriminator. STOP."
elif p0_pass == 3:
    row, action = "none", ("headless now PASSES. The build #15 refusal did not reproduce. "
                           "Re-check before building anything on it.")
elif not p2_measured:
    row, action = "?", ("P2 UNMEASURED (headed harness never proved itself). No row can be "
                        "claimed. Fix the display, re-run.")
elif P1 and P2:
    row, action = "1", "BUILD OPTION A (Xvfb + browser id chrome). No spoofing needed."
elif P1 and not P2:
    row, action = "2", ("STOP. ASK ZAID. Only imitation works -- that reverses this build's "
                        "own line, 'nothing here imitates or evades, it uses one.'")
elif not P1 and not P2:
    row, action = "3", ("ACCEPT THE LIMIT. Deeper than headers. Record it, note it on the "
                        ":proxy crawl panel, move on. Do not chase it.")
else:
    row, action = "4", "Headed passes, spoof does not. Investigate once, then treat as row 1."

print(f"\n  ROW {row}: {action}")
print("\nJSON=" + json.dumps(RESULTS))
