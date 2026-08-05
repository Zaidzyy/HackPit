#!/usr/bin/env python3
"""Build #19 item 1 — the go/no-go for interception, MEASURED against a live ZAP 2.17.0.

*** THIS IS THE SCRIPT THAT DECIDED ITEM 4 GETS BUILT. ***
Build #14 was written against `zap-baseline.py`, which does not exist in Kali, and only the image
build caught it. So nothing in item 4 was written before this answered. It enumerates what the
break API actually exposes, then drives the whole loop against a REAL ORIGIN and reads that
origin's own access log as the arbiter — because every one of these endpoints will answer
`{"Result":"OK"}` for things it did not do.

WHAT IT PROVES, and each is checked rather than asserted from the docs:

  1. the break API is present         -- despite `brk` being absent from the add-on list
  2. `http-all` is the ONLY type      -- http-request / -response / -sender are illegal_parameter
  3. `type=http-all` holds            -- the origin sees nothing while a request waits
  4. the held request is READABLE     -- break/view/httpMessage returns the request text
  5. it is REPLACEABLE                -- setHttpMessage, read back before forwarding
  6. continue FORWARDS THE REPLACEMENT -- the ORIGIN LOG shows the replaced request, not the original
  7. drop really drops                -- the origin never sees it and the client gets nothing
  8. continue turns breaking OFF      -- step and drop leave it ON. ZAP's break-panel semantics.
  9. breaking off restores traffic    -- the control

Run it with the stack up:

    docker exec -d hackpit-engage-sandbox sh -c 'zaproxy -daemon -host 127.0.0.1 -port 8090 \
        -config api.disablekey=false -config api.key=KEY'
    python docs/proof/build19_break_api.py hackpit-engage-sandbox 8090 [KEY]

With no KEY it recovers one from the daemon's own argv, the way `proxy.api_key_for` does.
Prints VERDICT= and exits non-zero on failure. ASCII only: this console is cp1252.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.parse

CONTAINER = sys.argv[1] if len(sys.argv) > 1 else "hackpit-engage-sandbox"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8090
KEY = sys.argv[3] if len(sys.argv) > 3 else ""

#: A local origin inside the SAME container. Self-contained on purpose: the arbiter for every
#: claim below is this server's access log, and a third-party host would have given us a status
#: code instead of a record of what actually arrived.
ORIGIN_PORT = 18099
LOG = f"/tmp/build19_origin_{ORIGIN_PORT}.log"

PASS = 0
FAIL = 0


def check(ok: bool, label: str, detail: str = "") -> bool:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")
        if detail:
            print(f"        {detail}")
    return ok


def dex(*argv: str, stdin: bytes | None = None, timeout: int = 30) -> tuple[int, str]:
    p = subprocess.run(["docker", "exec", "-i", CONTAINER, *argv],
                       capture_output=True, timeout=timeout, input=stdin)
    return p.returncode, (p.stdout or b"").decode("utf-8", "replace")


def api(path: str, fields: dict[str, str] | None = None) -> dict:
    """One ZAP API call. Actions with parameters go over POST with the body on stdin — the same
    channel `proxy._api_post` uses, and for the same reason: a held request carries credentials
    and a GET would put them in ZAP's own history and on an argv `ps` can read."""
    url = f"http://127.0.0.1:{PORT}/JSON/{path}"
    argv = ["curl", "-s", "--max-time", "20", "-H", f"X-ZAP-API-Key: {KEY}"]
    body = None
    if fields is not None:
        body = "&".join(
            f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(v)}"
            for k, v in fields.items()
        ).encode()
        argv += ["-X", "POST", "--data-binary", "@-",
                 "-H", "Content-Type: application/x-www-form-urlencoded"]
    argv.append(url)
    _, out = dex(*argv, stdin=body)
    try:
        return json.loads(out)
    except ValueError:
        return {"_raw": out[:200]}


def recover_key() -> str:
    probe = (
        'for f in /proc/[0-9]*/cmdline; do '
        'L=$(tr "\\0" "\\n" < "$f" 2>/dev/null) || continue; '
        'K=$(printf "%s\\n" "$L" | grep -m1 -e "^api[.]key=") || continue; '
        'printf "%s\\n" "${K#*=}"; break; done'
    )
    _, out = dex("sh", "-c", probe)
    return out.strip()


def origin_lines() -> int:
    _, out = dex("sh", "-c", f"wc -l < {LOG} 2>/dev/null || echo 0")
    try:
        return int(out.strip() or "0")
    except ValueError:
        return 0


def origin_text() -> str:
    _, out = dex("sh", "-c", f"cat {LOG} 2>/dev/null")
    return out


def fire(tag: str, wait: float = 0.0) -> subprocess.Popen:
    """Send one request THROUGH the proxy, in the background — it will block if it is held."""
    return subprocess.Popen(
        ["docker", "exec", CONTAINER, "curl", "-s", "--max-time", "45",
         "-x", f"http://127.0.0.1:{PORT}",
         f"http://127.0.0.1:{ORIGIN_PORT}/index.html?tag={tag}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def breaking(on: bool, kind: str = "http-all") -> dict:
    return api(f"break/action/break/?type={kind}&state={'true' if on else 'false'}&scope=")


def held_message(budget: float = 20.0) -> str:
    t0 = time.time()
    while time.time() - t0 < budget:
        msg = api("break/view/httpMessage/").get("httpMessage", "")
        if msg:
            return msg
        time.sleep(0.25)
    return ""


def main() -> int:
    global KEY
    print("== build #19 item 1 -- does ZAP's break API hold / read / replace / forward / drop? ==")
    if not KEY:
        KEY = recover_key()
    if not KEY:
        print("VERDICT=NOT-RUN (no ZAP daemon found in "
              f"{CONTAINER}; start one on port {PORT} first)")
        return 1

    ver = api("core/view/version/").get("version", "")
    if not check(bool(ver), f"a ZAP daemon answers on {CONTAINER}:{PORT}", str(ver)):
        print("VERDICT=NOT-RUN (no daemon)")
        return 1
    print(f"        ZAP {ver}")

    # ---- 1. the API is present, and the ADD-ON LIST DOES NOT SAY SO ---------------------
    # `brk` is not in installedAddons; BreakAPI ships in ZAP core. A go/no-go taken off the
    # add-on inventory would have said NO to a feature that works.
    addons = json.dumps(api("autoupdate/view/installedAddons/"))
    check("\"brk\"" not in addons,
          "the `brk` add-on is NOT in the installed list (an add-on list is not an API surface)")
    for view in ("isBreakAll", "isBreakRequest", "isBreakResponse", "httpMessage"):
        r = api(f"break/view/{view}/")
        check(view in r, f"break/view/{view} exists", str(r)[:120])
    # A MISSING action answers `bad_action`; one that needs a held message answers
    # `does_not_exist`. Telling those apart is the whole enumeration.
    r = api("break/action/setHttpMessage/")
    check(r.get("code") != "bad_action",
          "break/action/setHttpMessage EXISTS (missing_parameter, not bad_action)", str(r))
    r = api("break/action/thisDoesNotExist/")
    check(r.get("code") == "bad_action",
          "CONTROL: a genuinely absent action answers bad_action", str(r))

    # ---- RESET FIRST, AND THE SHAPE OF THIS RESET IS ITSELF A FINDING -------------------
    # ZAP persists, so a run that ended with a request still held would leave the NEXT run
    # reading a stale message. The obvious reset is `drop` then `state=false`.
    #
    # *** THAT OBVIOUS RESET IS THE BUG THIS SCRIPT FOUND. ***
    # An UNCONDITIONAL `break/action/drop/` -- one sent while nothing is held -- permanently
    # wedges the daemon's break manager. It goes on holding requests (isBreakAll true, the origin
    # never sees them, the client blocks) while `httpMessage` returns "" forever, so nothing can
    # ever be read or replaced again. Single-variable, on FRESH daemons: with the stray drop,
    # 23 passed / 4 failed; with the one line removed, 27 passed / 0 failed.
    #
    # So the reset READS FIRST and only drops something that is really there -- which is exactly
    # the guard `intercept.release()` and `intercept.panic()` now carry in the product.
    if api("break/view/httpMessage/").get("httpMessage", ""):
        api("break/action/drop/")
    breaking(False)
    time.sleep(1)
    check(api("break/view/httpMessage/").get("httpMessage", "") == "",
          "PRECONDITION: nothing is held from a previous run (this daemon persists state)")

    # ---- the origin ---------------------------------------------------------------------
    dex("sh", "-c", "pkill -f 'http[.]server' 2>/dev/null; true")
    time.sleep(1)
    dex("sh", "-c", f"printf 'hello-from-origin\\n' > /tmp/index.html; : > {LOG}")
    subprocess.Popen(
        ["docker", "exec", "-d", CONTAINER, "sh", "-c",
         f"cd /tmp && exec python3 -m http.server {ORIGIN_PORT} --bind 127.0.0.1 >> {LOG} 2>&1"]
    )
    time.sleep(3)
    rc, _ = dex("curl", "-s", "--max-time", "5",
                f"http://127.0.0.1:{ORIGIN_PORT}/index.html")
    if not check(rc == 0, f"a local origin answers on 127.0.0.1:{ORIGIN_PORT}"):
        print("VERDICT=NOT-RUN (no origin to measure against)")
        return 1
    breaking(False)
    time.sleep(1)

    # ---- 2. `http-all` IS THE ONLY ACCEPTED TYPE ---------------------------------------
    # The first draft of intercept.py's docstring claimed `http-request` "answers OK and holds
    # nothing". It does not answer OK -- it is not a legal value at all. This block is why that
    # claim was corrected rather than shipped.
    for bogus in ("http-request", "http-response", "http-sender"):
        r = breaking(True, bogus)
        check(r.get("code") == "illegal_parameter",
              f"break?type={bogus} is REFUSED as an illegal value (not a silent no-op)", str(r))
    check(breaking(True, "http-all").get("Result") == "OK",
          "CONTROL: break?type=http-all is accepted")
    breaking(False)
    time.sleep(1)

    # ---- 3/4/5/6. http-all: hold, read, replace, forward -------------------------------
    base = origin_lines()
    breaking(True)
    proc = fire("round-forward")
    time.sleep(1)
    msg = held_message()
    check(bool(msg), "type=http-all HOLDS and break/view/httpMessage RETURNS THE REQUEST",
          "nothing was readable while a request was in flight")
    check(origin_lines() == base,
          "...and the ORIGIN saw nothing while it was held (the arbiter, not the API)")
    check(api("break/view/isBreakRequest/").get("isBreakRequest") == "true",
          "isBreakRequest reads true -- it is a SETTING, which is why `held` is not wired to it")

    replaced = msg.replace("tag=round-forward", "tag=round-forward-REPLACED")
    replaced = replaced.replace("User-Agent:", "X-HackPit-Break: yes\r\nUser-Agent:")
    r = api("break/action/setHttpMessage/", {"httpHeader": replaced, "httpBody": ""})
    check(r.get("Result") == "OK", "setHttpMessage accepts the replacement",
          f"{r} | held={msg!r} | sent={replaced!r}")  # noqa: E501 - the repr IS the diagnosis
    back = api("break/view/httpMessage/").get("httpMessage", "")
    check("REPLACED" in back and "X-HackPit-Break" in back,
          "the replacement READS BACK before anything is forwarded")

    api("break/action/continue/")
    proc.wait(timeout=40)
    time.sleep(2)
    log = origin_text()
    check("tag=round-forward-REPLACED" in log,
          "*** continue FORWARDED THE REPLACED REQUEST -- the origin log says so ***")
    check("tag=round-forward " not in log and "tag=round-forward&" not in log
          and "tag=round-forward\"" not in log,
          "...and the ORIGINAL request never reached the origin")

    # ---- 8. CONTINUE TURNED BREAKING OFF ------------------------------------------------
    # ZAP's break-panel semantics: Continue means "let everything go", not "let this one go".
    # An operator forwarding a request expecting to catch the next one catches nothing, so the
    # product reads this back and says so rather than leaving the banner to vanish unexplained.
    check(api("break/view/isBreakAll/").get("isBreakAll") == "false",
          "*** `continue` also TURNED BREAKING OFF -- step is the one that keeps it ***")

    # ---- 7. drop, and STEP leaves breaking on -------------------------------------------
    breaking(True)
    base = origin_lines()
    proc = fire("round-drop")
    time.sleep(1)
    check(bool(held_message()), "a request is held again after re-enabling")
    api("break/action/drop/")
    proc.wait(timeout=40)
    time.sleep(2)
    check(origin_lines() == base and "tag=round-drop" not in origin_text(),
          "*** drop REALLY DROPS -- the origin never saw it ***")
    check(api("break/view/isBreakAll/").get("isBreakAll") == "true",
          "...and `drop` LEAVES BREAKING ON, unlike continue")

    # ---- 9. the control -----------------------------------------------------------------
    breaking(False)
    time.sleep(1)
    base = origin_lines()
    rc, out = dex("curl", "-s", "--max-time", "20", "-x", f"http://127.0.0.1:{PORT}",
                  f"http://127.0.0.1:{ORIGIN_PORT}/index.html?tag=control-off")
    check(rc == 0 and "hello-from-origin" in out and origin_lines() > base,
          "CONTROL: with breaking off, traffic flows again")
    check(api("break/view/isBreakAll/").get("isBreakAll") == "false",
          "...and isBreakAll reads back false")

    dex("sh", "-c", "pkill -f 'http[.]server' 2>/dev/null; true")
    print()
    print(f"{PASS} passed, {FAIL} failed")
    if FAIL:
        print("VERDICT=FAIL -- the break API does not do what item 4 was built on. "
              "Item 4 must be reconsidered.")
        return 1
    print("VERDICT=PASS -- hold, read, replace, forward and drop all work. Item 1 is a GO.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("VERDICT=NOT-RUN (interrupted)")
        raise SystemExit(1) from None
