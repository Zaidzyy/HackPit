# Build #15 acceptance runbook — a real browser through the proxy

**Date written:** 2026-08-04
**Why it is a runbook and not a proof script:** every check below needs a human at a real
browser, pointed at a real in-scope host. `docker/proof/browser_intercept_proof.sh` covers
everything that can be asserted without one — the port, the key enforcement, the refusal without
it, the crawl actually launching Chromium. What remains is the one question the whole build
exists to answer, and it cannot be answered by a script:

> **Does a real browser get through where a bare HTTP client is refused outright?**

---

## What is already proven before you start

Run these two first. If either fails, stop — the runbook below would be measuring the wrong
thing.

```sh
sh backend/run_safety_tests.sh                  # hermetic; must be green
sh docker/proof/browser_intercept_proof.sh      # needs the stack up + the profile applied
```

The proof's load-bearing check is #4: **an API call from the host with no key must be REFUSED.**
That is what makes publishing a port acceptable at all — what becomes reachable is an HTTP
proxy, not scan control. If it ever reports ANSWERED, stop everything.

---

## 1. Publish the port

Two steps, deliberately separate. The first changes what the daemon binds *inside* its
container; the second opens a port *on this machine*. Neither implies the other.

1. **:proxy** → start the proxy with an engagement id, **publish** ticked, plus the approval and
   the red-confirm. Lab mode refuses `publish` (409, gate `publish`): `hackpit-isolated` is
   `internal: true`, so a published port there has no route in the first place.
2. **:exposure** → pick the **`zap-proxy`** preset (`127.0.0.1:8090`, engage-sandbox) → write the
   profile → **apply** it, which recreates the container.

> Applying a profile **recreates `engage-sandbox`**, killing every listener, session and
> background job inside it. That is why apply carries its own approval. Start the proxy *after*
> the apply if you would rather not restart it.

For a phone or a second machine use **`zap-proxy-lan`** instead. It fills in `0.0.0.0` and
**nothing else** — you still tick the wildcard acknowledgement yourself, and the generated file
records it as `# hackpit-ack: wildcard bind=0.0.0.0 engagement=<id>`. Read what that means in
§4 before you do it.

**If you know your LAN address, type it instead of using the LAN preset.** `0.0.0.0` is the
blunt instrument: it binds VPN adapters and mobile hotspots too. `address_is_live()` will confirm
a specific address can bind, and it is strictly narrower.

---

## 2. Point a browser at it

Firefox is easier than Chrome here because its proxy setting is per-profile rather than
system-wide.

- **Firefox** — Settings → Network Settings → Manual proxy configuration → HTTP Proxy
  `127.0.0.1`, Port `8090`, tick **Also use this proxy for HTTPS**.
- **Chrome** — needs a flag, because it otherwise takes the Windows system proxy:
  `chrome.exe --proxy-server="http://127.0.0.1:8090" --user-data-dir="%TEMP%\hackpit-proxy"`.
  The separate `--user-data-dir` keeps it out of your normal profile.

**HTTPS needs ZAP's CA certificate**, or every page fails with a certificate warning:

```sh
docker exec hackpit-engage-sandbox \
  curl -s -H "X-ZAP-API-Key: <key>" \
  "http://127.0.0.1:8090/OTHER/network/other/rootCaCert/" > zap-ca.cer
```

Import it as a trusted authority (Firefox: Settings → Privacy & Security → Certificates → View
Certificates → Authorities → Import → trust for websites).

The key is **random per start and never leaves the backend** — it is deliberately not in any
model, log or report. Read it from the running container if you need it for the command above:

```sh
docker exec hackpit-engage-sandbox sh -c 'tr "\0" "\n" < /proc/$(pgrep -f "[z]aproxy.*-daemon")/cmdline | grep api.key'
```

That this is the only way to retrieve it is the point: it never reaches a durable artefact.

---

## 3. The acceptance test

Browse a **real, in-scope, Akamai-fronted host** — one of the nine that returned nothing at all
to a bare `HEAD`.

1. Load the site normally in the proxied browser. Click around; log in if you have credentials.
2. **:proxy → captured traffic → refresh.** The requests should be there, with real responses.
3. **Crawl it** — :proxy → *crawl it with a real browser*, aimed at a page you reached in step 1,
   depth 3, 5 minutes, with both confirms. It inherits the session you just established, which
   is the entire reason it is ZAP's spider and not a separate headless browser.
4. **Attack one captured URL** with the scanner and confirm it runs against something real.

### Record the result either way — this is the part that matters

**If a real browser gets through:** note which hosts, whether login worked, and roughly how many
requests landed in the history. That is the build doing its job and it closes the question the
audit left open ("partly — breaks at volume").

**If a real browser is ALSO refused:** capture exactly this, because it is the evidence any
follow-up decision rests on, and a vague "it didn't work" is worth nothing:

| capture | how |
|---|---|
| the HTTP status (or the failure mode, if there is no response) | browser devtools → Network |
| the full response headers | devtools → Network → Headers, or the ZAP history entry |
| the timing — instant refusal vs. a hang | devtools timing column |
| **which protocol** — h2 or h1.1 | devtools → Network → Protocol column |
| whether the *proxy* worked and the *target* refused | does an ordinary site load through the same proxy? |

That last row is the one that separates two very different outcomes: a broken proxy is a bug in
this build, and a refused browser is a finding about the target. Do not report one as the other.

**A refused real browser is not a licence to go further.** This build's whole mechanism is that
the traffic comes from a genuine browser with a genuine profile. Whether to do anything beyond
that is a separate decision and a separate build — it is not foreclosed, it is simply not what
this one does. The captured evidence above is the input to that decision.

---

## 4. What a wide bind actually means

Stated here so the confirm is informed rather than reflexive.

The API stays key-protected, so a wildcard bind does **not** expose scan control. What it exposes
is an **open HTTP proxy**, and the engage sandbox has full egress (Wall A is down) — so anyone
who can reach that port can route traffic to the internet attributed to this machine's IP.

- On a home LAN: negligible.
- On café, hotel, coworking or conference wifi: the classic open-proxy problem, and scanners
  find it quickly.

This is precisely the case `backend/test_exposure_safety.py` exists for — *"the check that keeps
'my DC can reach the listener' from silently meaning 'so can the coffee-shop network'."*

---

## 5. Teardown

```sh
# stop the daemon (or use the stop button on :proxy — never gated)
docker exec hackpit-engage-sandbox sh -c 'pkill -f "[z]aproxy.*-daemon.*-port 8090"'
```

Then **remove the profile and recreate the container**. Deleting the profile alone does *not*
close the port — a published port is fixed when the container is created, which is why
`exposure.observe()` reports that state as `drifted` and never as `none`:

```sh
rm docker/listener-profile.yml
docker compose -f docker/docker-compose.yml up -d --force-recreate engage-sandbox
```

And put the browser's proxy setting back.
