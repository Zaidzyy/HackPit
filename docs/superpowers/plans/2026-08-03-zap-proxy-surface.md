# ZAP Proxy Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture the HTTP traffic of every tool run inside a HackPit sandbox into one searchable surface, feeding the repeater and engagement state — without publishing a port or adding an ungated control channel.

**Architecture:** A ZAP daemon bound to `127.0.0.1` **inside** the container. Unreachable from the host (measured); driven only by `docker exec`, which is the one channel into a sandbox and the thing `validate_request` already gates. Start is gated like the existing listeners; the history read is ungated and read-only by construction.

**Tech Stack:** Python 3 stdlib, existing `cockpit` modules (`lifecycle`, `executor`, `repeater`), Next.js for the one new screen. No new dependency.

**Spec:** `docs/superpowers/specs/2026-08-03-zap-proxy-surface-design.md`

## Global Constraints

Every task's requirements implicitly include this section.

- **No published port, ever.** The daemon binds `127.0.0.1` inside the container. If a task seems to need a host→container socket, stop — that is the browser-interception build, explicitly out of scope.
- **`docker exec` is the only channel.** No `requests`/`httpx` call from the backend to a container.
- **The history reader takes NO endpoint parameter.** Two module-level URL constants only. Zaid declined both the runtime allowlist and the static test (2026-08-03), so this is a convention with nothing enforcing it — if you find yourself adding a URL argument, that reopens the decision (spec §7.3); do not quietly satisfy it.
- **Bodies are stored RAW.** Redaction happens only in `report.py`. Do not redact on ingest.
- **`cockpit` and `arsenal` may not reference each other** in either direction — substring-enforced, comments count.
- **Measured facts, do not re-derive:** ZAP 2.17.0 takes **~7 s** to answer its API after `-daemon`; message fields are `id, requestHeader, requestBody, responseHeader, responseBody, rtt, timestamp, type, tags, note, cookieParams`; `requestHeader`'s first line is `METHOD URL HTTP/x`; `responseHeader`'s first line is `HTTP/x STATUS REASON`.
- **Test naming:** `test_zap_proxy.py` and `test_zap_proxy_safety.py`. Never `test_scans.py` (the shared source scanner).
- **Windows dev host.** Run tests with `backend/.venv/Scripts/python.exe`. In shell scripts touching container paths use `MSYS_NO_PATHCONV=1`, and pipe to Python rather than staging through a host `/tmp` file — bash's `/tmp` and Windows Python's `/tmp` are different directories (both cost a debugging round in part 1).
- **The assessment lands in the SAME commit** as the change it describes, regenerated with `python docs/build-assessment.py` and verified against the **HTML** (the PDF cannot be grepped).

---

### Task 1: `cockpit/proxy.py` — models, argv, gate

Pure logic. No spawning, no Docker. Everything here is testable without a container.

**Files:**
- Create: `backend/cockpit/proxy.py`
- Create: `backend/test_zap_proxy_safety.py`

**Interfaces:**
- Consumes: `executor.validate_request`, `models.ExecRequest`/`ExecRejected`, `config.SANDBOX_CONTAINER`/`ENGAGE_SANDBOX_CONTAINER`.
- Produces: `ProxyStartRequest`, `Proxy`, `ProxyRefused`, `server_argv_for(req) -> list[str]`, `validate_start(req) -> ExecRejected | None`.

- [ ] **Step 1: Write the failing test**

Create `backend/test_zap_proxy_safety.py`:

```python
"""ZAP proxy gating locks.  Run:  python test_zap_proxy_safety.py

THE INVARIANT: a proxy start passes the real executor gates, and the argv the gate classified is
the argv that gets spawned.
"""

from __future__ import annotations

from cockpit import proxy


def _req(**kw):
    base = dict(approved=True, dangerous_ack=True, engagement_id=None)
    base.update(kw)
    return proxy.ProxyStartRequest(**base)


def test_an_unapproved_start_is_refused_with_a_control() -> None:
    """approved=False must refuse. The control is in THIS test: the same request WITH approval
    must reach a different gate, or the check is passing for the wrong reason."""
    rejected = proxy.validate_start(_req(approved=False))
    assert rejected is not None, "an unapproved proxy start was NOT refused"
    assert rejected.gate == "approval", f"refused at {rejected.gate!r}, expected 'approval'"

    # control: approval satisfied -> the approval gate no longer fires
    other = proxy.validate_start(_req(approved=True))
    if other is not None:
        assert other.gate != "approval", (
            "the approval gate still fires with approved=True — it is not reading the field"
        )
    print("  an unapproved start is refused at the approval gate, control holds: PASS")


def test_the_red_confirm_is_required() -> None:
    """A proxy holds full request bodies — credentials and session tokens in cleartext."""
    rejected = proxy.validate_start(_req(dangerous_ack=False))
    assert rejected is not None, "a proxy start with no red-confirm was NOT refused"
    assert rejected.gate == "danger", f"refused at {rejected.gate!r}, expected 'danger'"
    print("  a start without the red-confirm is refused at the danger gate: PASS")


def test_the_gated_argv_is_the_spawned_argv() -> None:
    """*** CRITICAL 2. *** Classifying a different string than the one that runs reproduces the
    bug in a new place. One derivation, asserted — the same lock tunnels.py carries."""
    import inspect

    req = _req()
    argv = proxy.server_argv_for(req)
    gated = proxy._gate_request(req)
    assert gated.command == argv[0], (
        f"the gate classifies {gated.command!r} but the spawn runs {argv[0]!r}"
    )

    # and the spawn path must DERIVE from server_argv_for rather than rebuilding the argv
    src = inspect.getsource(proxy.start_proxy)
    assert "server_argv_for" in src, (
        "start_proxy does not call server_argv_for — it is building its own argv, which is "
        "exactly how the gated string and the executed string drift apart"
    )
    print("  the gated argv and the spawned argv come from one derivation: PASS")


def test_the_daemon_binds_loopback_only() -> None:
    """THE ISOLATION PROPERTY. `-host 127.0.0.1` is what keeps the API unreachable from the host.
    A change to 0.0.0.0 would publish nothing by itself, but it removes the last thing standing
    between a published port and an ungated control channel."""
    argv = proxy.server_argv_for(_req())
    joined = " ".join(argv)
    assert "-host 127.0.0.1" in joined, f"the daemon does not bind loopback: {joined}"
    for bad in ("0.0.0.0", "-config api.addrs.addr.name=.*"):
        assert bad not in joined, f"the argv opens the API beyond loopback: {bad!r} in {joined}"
    print("  the daemon binds 127.0.0.1 only: PASS")


def test_both_modes_are_reachable() -> None:
    """Deliberate divergence from tunnels.py, which refuses lab mode. The proxy runs in WHICHEVER
    sandbox the operator is in, so lab mode's isolation gate is the relevant condition, not an
    unrelated one — see spec §5. Neither mode may be refused for LACKING the other's precondition."""
    lab = proxy.validate_start(_req(engagement_id=None))
    if lab is not None:
        assert lab.gate != "engagement", (
            "lab mode is refused for having no engagement id — that is tunnels.py's rule, and "
            "it inverts here: the proxy runs in the container the lab isolation gate is about"
        )
    print("  lab mode is not refused for lacking an engagement id: PASS")


if __name__ == "__main__":
    test_an_unapproved_start_is_refused_with_a_control()
    test_the_red_confirm_is_required()
    test_the_gated_argv_is_the_spawned_argv()
    test_the_daemon_binds_loopback_only()
    test_both_modes_are_reachable()
    print("ALL ZAP proxy gating locks pass")
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd backend && .venv/Scripts/python.exe test_zap_proxy_safety.py
```

Expected: `ModuleNotFoundError: No module named 'cockpit.proxy'`

- [ ] **Step 3: Write the module's models, argv and gate**

Create `backend/cockpit/proxy.py`:

```python
"""ZAP as a recording proxy inside a sandbox — GATED START, read-only history.

WHY THIS IS NOT THE THING BUILD #14 PART 1 REFUSED. Part 1 excluded a ZAP daemon because an HTTP
control channel bypasses `executor.validate_request`, and because reaching one inside the lab
sandbox would mean opening the `internal: true` network that `assert_isolation_proven()` exists
to deny.

Neither happens here, and it was MEASURED before it was designed (2026-08-03, ZAP 2.17.0):

    zaproxy -daemon -host 127.0.0.1 -port 8090     API answers after ~7s
    curl 127.0.0.1:8090/... FROM THE HOST          refused — unreachable
    the same call via `docker exec`                {"version":"2.17.0"}

The daemon binds loopback INSIDE the container. No port is published, so the backend has no
socket to it; the only way in is `docker exec`, which is the one channel into a sandbox and the
thing the gates already classify. The API exists and is still unreachable from anywhere that
could bypass a gate.

WHAT IT CAPTURES: tools run inside the sandbox, pointed at the proxy (executor's `proxy` flag).
It records. It never scans — active scanning stays on part 1's gated command path.
"""

from __future__ import annotations

import threading
from typing import Any

from pydantic import BaseModel, Field

from . import config

#: ZAP's API and proxy share one listener. Loopback-only, inside the container.
PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 8090

#: The JVM needs this long before the API answers. MEASURED at ~7s; the headroom is for a loaded
#: host. lifecycle's default settle is far shorter, so this is passed explicitly.
READY_TIMEOUT_SECONDS = 60
SETTLE_SECONDS = 8.0

#: THE ONLY TWO URLS THIS MODULE ISSUES. No function here takes a path or endpoint argument, so
#: an `action/` call is not expressible without writing a visibly new function. Nothing enforces
#: that — both the runtime allowlist and a static test were declined (2026-08-03, Zaid) — so it
#: is a convention. Adding a URL parameter reopens the decision; see spec §7.3.
_VIEW_VERSION = "/JSON/core/view/version/"
_VIEW_COUNT = "/JSON/core/view/numberOfMessages/"
_VIEW_MSGS = "/JSON/core/view/messages/"

_lock = threading.Lock()
_live: dict[str, Any] = {}


class ProxyStartRequest(BaseModel):
    """Start the recording proxy in a sandbox."""

    port: int = Field(DEFAULT_PROXY_PORT, ge=1024, le=65535)
    engagement_id: str | None = Field(
        None, description="Engagement to attribute against. Omit for LAB mode — unlike a pivot "
        "listener, this runs in whichever sandbox you are using, so lab mode is coherent."
    )
    # THE GATE FIELDS. Both default False so an omitted field is REFUSED, never granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False,
        description="The red-confirm. A proxy records full request bodies — credentials, session "
        "tokens and payloads in cleartext — so this is always required.",
    )


class Proxy(BaseModel):
    """One live (or starting) recording proxy."""

    id: str
    container: str
    port: int
    status: str = Field(
        description="starting | listening | down — OBSERVED after the settle window, never "
        "assigned at spawn time."
    )
    liveness: str = ""
    captured: int = 0
    started_at: str
    engagement_id: str | None = None


class ProxyRefused(RuntimeError):
    """The proxy could not start / the request was invalid. NOTHING ran."""

    def __init__(self, reason: str, gate: str = "unavailable",
                 dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.gate = gate
        self.dangerous_flags = dangerous_flags or []


def container_for(req: ProxyStartRequest) -> str:
    """Engagement runs use the engage sandbox; everything else the isolated lab one."""
    return (config.ENGAGE_SANDBOX_CONTAINER if req.engagement_id
            else config.SANDBOX_CONTAINER)


def server_argv_for(req: ProxyStartRequest) -> list[str]:
    """The daemon argv this request will run. THE SINGLE DERIVATION.

    Both the gate and :func:`start_proxy` come through here, for the same reason the WinRM path
    funnels through one join: classifying a DIFFERENT argv than the one that executes reproduces
    Critical 2 in a new place. A test asserts they are equal.

    `-host 127.0.0.1` is the isolation property. Do not widen it — the API is only safe to leave
    ungated because nothing outside the container can reach it.
    """
    return [
        "zaproxy", "-daemon",
        "-host", PROXY_HOST,
        "-port", str(req.port),
        "-config", "api.disablekey=true",
    ]


def _gate_request(req: ProxyStartRequest):
    """The ExecRequest the real gates run against.

    Surface: the daemon binary plus the engagement. The port is not gated — it is a bind address
    on our own container, not a target, and feeding it to the scope extractor would produce a
    refusal about our own socket (the same reasoning tunnels.py gives for leaving `-laddr` out).
    """
    from .models import ExecRequest

    argv = server_argv_for(req)
    return ExecRequest(
        command=argv[0],
        args=[],
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate_start(req: ProxyStartRequest):
    """The gate verdict for starting this proxy, spawning nothing. PURE.

    NO ENGAGEMENT PRECONDITION, and that is a deliberate divergence from tunnels.py. A pivot
    listener lives in the engage sandbox, so tunnels refuses lab mode rather than make the
    operator satisfy an isolation gate about a container the listener is not in. Here the proxy
    runs in WHICHEVER sandbox the operator is using, so lab mode's isolation gate is asking about
    the very container the proxy occupies — the relevant condition, not an unrelated one.
    """
    from . import executor

    return executor.validate_request(_gate_request(req))
```

Add a placeholder `start_proxy` so the source-derivation assertion has something to read; Task 2 fills it in:

```python
def start_proxy(req: ProxyStartRequest) -> Proxy:
    """Start the daemon in the sandbox. Implemented in Task 2."""
    argv = server_argv_for(req)
    raise NotImplementedError(f"Task 2 wires the lifecycle spawn for: {argv}")
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd backend && .venv/Scripts/python.exe test_zap_proxy_safety.py
```

Expected: `ALL ZAP proxy gating locks pass`. If `test_the_red_confirm_is_required` fails with gate `approval`, the danger heuristic does not flag `zaproxy` bare — check `_TOOL_ATTACK_FLAGS` from part 1: it keys on `-quickurl`, which this argv does not carry. **If so, that is a real finding, not a test bug** — see Task 1a.

- [ ] **Step 5: Task 1a — make the daemon itself demand the red-confirm**

Part 1's `_TOOL_ATTACK_FLAGS` fires on `zaproxy -quickurl` (an active scan). The daemon argv has no `-quickurl`, so the danger gate will NOT fire on it, and `dangerous_ack` would be unenforced.

Add `-daemon` to the attack-flag set for `zaproxy`/`owasp-zap` in `backend/cockpit/allowlist.py`, with this reasoning in a comment:

```python
    # `-daemon` is here for a different reason than `-quickurl`. It launches no attack — it
    # starts a long-lived listener that RECORDS every request and response passing through it,
    # including credentials, session tokens and payloads in cleartext. The three existing
    # listener surfaces (sliver, tunnels, obfuscation) all demand the red-confirm for the same
    # shape of capability, and finding I2 of the 2026-07-27 gate audit exists because one of
    # them did not.
    "zaproxy": frozenset({"-quickurl", "-daemon"}),
    "owasp-zap": frozenset({"-quickurl", "-daemon"}),
```

Then re-run part 1's locks to prove nothing regressed:

```bash
cd backend && .venv/Scripts/python.exe test_zap_safety.py && .venv/Scripts/python.exe test_zap_proxy_safety.py
```

Expected: both pass. `test_zap_safety.py`'s recon case (`-zapit`) must still NOT fire — if it does, the flag set is too broad.

- [ ] **Step 6: Commit**

```bash
git add backend/cockpit/proxy.py backend/cockpit/allowlist.py backend/test_zap_proxy_safety.py
git commit -m "build #14 part 2: proxy models, argv and gate

The daemon argv is one derivation behind both the gate and the spawn.
-host 127.0.0.1 is the isolation property and a test pins it.

validate_start has NO engagement precondition, diverging from tunnels.py
deliberately: a pivot listener lives in the engage sandbox, so tunnels refuses
lab mode rather than fire an isolation gate about a container it is not in.
The proxy runs in whichever sandbox the operator is using, so lab mode's
isolation gate is the relevant condition.

Also: -daemon now joins -quickurl in _TOOL_ATTACK_FLAGS. Not because it
attacks, but because it starts a listener that records credentials and session
tokens in cleartext. Without it dangerous_ack would have been unenforced on
this path — the shape of gate-audit finding I2."
```

---

### Task 2: lifecycle — spawn, observe, stop

**Files:**
- Modify: `backend/cockpit/proxy.py`
- Modify: `backend/test_zap_proxy_safety.py`

**Interfaces:**
- Consumes: `lifecycle.exec_argv`, `lifecycle.spawn_watched`, `lifecycle.observe`, `Task 1`'s `server_argv_for`.
- Produces: `start_proxy(req) -> Proxy`, `stop_proxy(pid) -> Proxy`, `status() -> dict`, `list_proxies() -> list[Proxy]`.

- [ ] **Step 1: Write the failing test**

Append to `backend/test_zap_proxy_safety.py` (and add the call to `__main__`):

```python
def test_the_daemon_gets_no_stdin_writer() -> None:
    """A daemon needs no stdin, so it is spawned interactive=False and proc.stdin is None.
    lifecycle's own lock covers the mechanism; this asserts THIS caller opted out."""
    import inspect

    src = inspect.getsource(proxy.start_proxy)
    assert "interactive=False" in src, (
        "start_proxy does not spawn with interactive=False — a daemon needs no stdin, and an "
        "interactive spawn would hand it a pipe nobody should hold"
    )
    print("  the daemon is spawned with no stdin writer: PASS")


def test_a_refused_start_spawns_nothing() -> None:
    """*** NOTHING RUNS ON A REFUSAL. *** The gate must be checked BEFORE any spawn call."""
    import inspect

    src = inspect.getsource(proxy.start_proxy)
    gate_at = src.find("validate_start")
    spawn_at = src.find("spawn_watched")
    assert gate_at != -1, "start_proxy never calls validate_start"
    assert spawn_at != -1, "start_proxy never calls spawn_watched"
    assert gate_at < spawn_at, (
        "start_proxy spawns before it gates — a refused start would leave a live daemon"
    )
    print("  the gate is checked before anything spawns: PASS")
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd backend && .venv/Scripts/python.exe test_zap_proxy_safety.py
```

Expected: FAIL — `start_proxy does not spawn with interactive=False` (it still raises `NotImplementedError`).

- [ ] **Step 3: Implement the lifecycle**

Replace the placeholder `start_proxy` in `backend/cockpit/proxy.py`:

```python
def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _container_running(name: str) -> bool:
    import subprocess
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return name in out.stdout.split()


def _api_get(container: str, port: int, path: str, timeout: int = 10) -> str:
    """Read one of this module's fixed URLs, via docker exec. NEVER a socket from the backend.

    `path` is only ever one of the module constants above — no caller passes a computed value.
    """
    import subprocess
    url = f"http://{PROXY_HOST}:{port}{path}"
    try:
        out = subprocess.run(
            ["docker", "exec", container, "curl", "-s", "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout


def _wait_ready(container: str, port: int) -> bool:
    """Poll the version endpoint until the JVM answers. MEASURED at ~7s; polling beats sleeping
    a fixed time, because a loaded host is slower and a fast one should not be punished."""
    import time
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if '"version"' in _api_get(container, port, _VIEW_VERSION, timeout=3):
            return True
        time.sleep(1)
    return False


def start_proxy(req: ProxyStartRequest) -> Proxy:
    """Start the recording proxy in the sandbox. GATED — nothing spawns on a refusal."""
    from . import lifecycle

    rejected = validate_start(req)
    if rejected is not None:
        raise ProxyRefused(rejected.reason, gate=rejected.gate,
                           dangerous_flags=list(rejected.dangerous_flags))

    container = container_for(req)
    if not _container_running(container):
        raise ProxyRefused(
            f"sandbox '{container}' is not running — bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d)"
        )

    with _lock:
        if any(p.status != "down" for p in (_live.get(container, {}) or {}).values()):
            raise ProxyRefused(
                f"a proxy is already live in {container} — stop it first", gate="limit"
            )

    argv = server_argv_for(req)
    watched = lifecycle.spawn_watched(
        lifecycle.exec_argv(container, argv, interactive=False), interactive=False
    )
    ready = _wait_ready(container, req.port)
    live = lifecycle.observe(watched, container=container, port=req.port,
                             proto="tcp", settle=SETTLE_SECONDS)

    pid = f"zapproxy-{req.port}"
    model = Proxy(
        id=pid, container=container, port=req.port,
        status=live.status,
        liveness=live.detail + ("" if ready else " (API did not answer within the ready window)"),
        captured=0, started_at=_now(), engagement_id=req.engagement_id,
    )
    with _lock:
        _live.setdefault(container, {})[pid] = model
        _live[container][pid + ":watched"] = watched
    return model
```

Add `stop_proxy`, `list_proxies` and `status` following `tunnels.py`'s equivalents — stop is **not** gated, because refusing to stop a listener would be a gate that makes the system less safe.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd backend && .venv/Scripts/python.exe test_zap_proxy_safety.py && .venv/Scripts/python.exe test_lifecycle_safety.py
```

Expected: both pass. `test_lifecycle_safety.py` must stay green — this build adds a caller, not a new spawn mechanism.

- [ ] **Step 5: Commit**

```bash
git add backend/cockpit/proxy.py backend/test_zap_proxy_safety.py
git commit -m "build #14 part 2: proxy lifecycle — spawn, observe, stop

Reuses lifecycle.spawn_watched/observe rather than reimplementing
spawn-and-hope. interactive=False, so a daemon gets DEVNULL and proc.stdin is
None. Status is OBSERVED via ss, never assigned.

The readiness wait POLLS the version endpoint instead of sleeping a fixed
time: the JVM was measured at ~7s, but a loaded host is slower and a fast one
should not be punished. A daemon that never answers is reported as such rather
than being called listening.

Two source-level locks: the gate is checked before anything spawns, and the
spawn opts out of stdin explicitly."
```

---

### Task 3: history read-back and the parser

**Files:**
- Modify: `backend/cockpit/proxy.py`
- Create: `backend/test_zap_proxy.py`
- Create: `backend/test_support/zap_proxy_message_fixture.json`

**Interfaces:**
- Consumes: `RepeaterExchange`/`RepeaterRequest`/`RepeaterResponse` from `cockpit/repeater.py`.
- Produces: `parse_message(obj, container) -> RepeaterExchange | None`, `history(container, port, start, count) -> list[RepeaterExchange]`, `captured_count(container, port) -> int`.

- [ ] **Step 1: Capture a REAL message as the fixture**

Do not hand-write it. Part 1's whole lesson: a hermetic test that invents its input tests the invention.

```bash
docker exec hackpit-kali-sandbox sh -c '
nohup zaproxy -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true >/tmp/z.log 2>&1 &
for i in $(seq 1 60); do curl -s --max-time 2 http://127.0.0.1:8090/JSON/core/view/version/ >/dev/null 2>&1 && break; sleep 1; done
curl -s -o /dev/null -x http://127.0.0.1:8090 --max-time 20 "http://hackpit-lab-target:3000/rest/products/search?q=apple"
sleep 2
curl -s "http://127.0.0.1:8090/JSON/core/view/messages/?start=0&count=2"
' > backend/test_support/zap_proxy_message_fixture.json
docker exec hackpit-kali-sandbox pkill -f "zaproxy -daemon"
```

Verify it is real JSON with a `messages` array before continuing.

- [ ] **Step 2: Write the failing test**

Create `backend/test_zap_proxy.py`:

```python
"""ZAP proxy history parsing.  Run:  python test_zap_proxy.py

The fixture is a VERBATIM capture from a real ZAP 2.17.0 daemon proxying a real request inside
the Kali image. Every other input here is one this repo wrote, which is exactly the blind spot
that let the build #9 ingest gap survive a green suite.
"""

from __future__ import annotations

import json
from pathlib import Path

from cockpit import proxy

FIXTURE = Path(__file__).parent / "test_support" / "zap_proxy_message_fixture.json"


def _messages() -> list[dict]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["messages"]


def test_a_real_message_becomes_an_exchange() -> None:
    msgs = _messages()
    assert msgs, "the fixture carries no messages — recapture it"
    ex = proxy.parse_message(msgs[0], "hackpit-kali-sandbox")
    assert ex is not None, "a real ZAP message parsed to nothing"
    assert ex.request.method, f"no method parsed: {ex.request!r}"
    assert ex.request.url.startswith("http"), f"no url parsed: {ex.request.url!r}"
    assert ex.response.status is not None, "no status parsed from responseHeader"
    print(f"  a real message -> {ex.request.method} {ex.request.url[:48]} "
          f"-> {ex.response.status}: PASS")


def test_malformed_messages_never_raise() -> None:
    """A parser must never break a completed run."""
    for junk in ({}, {"requestHeader": ""}, {"requestHeader": "GARBAGE"},
                 {"requestHeader": "GET", "responseHeader": ""},
                 {"requestHeader": "GET http://x HTTP/1.1", "responseHeader": "nonsense"}):
        proxy.parse_message(junk, "c")   # must not raise
    print("  5 malformed messages parse without raising: PASS")


def test_bodies_are_kept_raw() -> None:
    """DECISION (2026-08-03, Zaid): store raw, redact only in reports. Redacting on ingest
    defeats the feature — the request that matters is usually the one carrying the token."""
    msg = dict(_messages()[0])
    msg["requestBody"] = "username=admin&password=hunter2"
    ex = proxy.parse_message(msg, "c")
    assert "hunter2" in ex.request.body, (
        "the captured body was redacted on ingest — that is the rejected design; redaction "
        "belongs at the REPORT boundary only"
    )
    print("  captured bodies are stored raw: PASS")


if __name__ == "__main__":
    test_a_real_message_becomes_an_exchange()
    test_malformed_messages_never_raise()
    test_bodies_are_kept_raw()
    print("ALL ZAP proxy history tests pass")
```

- [ ] **Step 3: Run it to verify it fails**

```bash
cd backend && .venv/Scripts/python.exe test_zap_proxy.py
```

Expected: `AttributeError: module 'cockpit.proxy' has no attribute 'parse_message'`

- [ ] **Step 4: Implement the parser and reader**

Add to `backend/cockpit/proxy.py`:

```python
def _first_line(raw: str) -> str:
    return (raw or "").replace("\r\n", "\n").split("\n", 1)[0].strip()


def _headers_from(raw: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in (raw or "").replace("\r\n", "\n").split("\n")[1:]:
        if not line.strip() or ":" not in line:
            continue
        name, _, value = line.partition(":")
        out.append((name.strip(), value.strip()))
    return out


def parse_message(obj: dict, container: str):
    """One ZAP message -> a RepeaterExchange. NEVER raises.

    MEASURED shape (ZAP 2.17.0): id, requestHeader, requestBody, responseHeader, responseBody,
    rtt, timestamp, type, tags, note, cookieParams. `requestHeader`'s first line is
    `METHOD URL HTTP/x`; `responseHeader`'s is `HTTP/x STATUS REASON`.
    """
    from .repeater import (RepeaterExchange, RepeaterHeader, RepeaterRequest,
                           RepeaterResponse, RepeaterResponseHeader)
    try:
        req_line = _first_line(str(obj.get("requestHeader") or ""))
        parts = req_line.split()
        if len(parts) < 2:
            return None
        method, url = parts[0], parts[1]

        status = None
        resp_line = _first_line(str(obj.get("responseHeader") or ""))
        resp_parts = resp_line.split()
        if len(resp_parts) >= 2 and resp_parts[1].isdigit():
            status = int(resp_parts[1])

        rtt = 0
        try:
            rtt = int(str(obj.get("rtt") or "0"))
        except ValueError:
            pass

        body = str(obj.get("responseBody") or "")
        return RepeaterExchange(
            id=f"zap-{obj.get('id', '')}",
            run_id=f"zap-{obj.get('id', '')}",
            request=RepeaterRequest(
                method=method, url=url,
                headers=[RepeaterHeader(name=n, value=v)
                         for n, v in _headers_from(str(obj.get("requestHeader") or ""))],
                # RAW. Redaction happens in report.py, never here — see spec §6.
                body=str(obj.get("requestBody") or ""),
            ),
            response=RepeaterResponse(
                status=status,
                headers=[RepeaterResponseHeader(name=n, value=v)
                         for n, v in _headers_from(str(obj.get("responseHeader") or ""))],
                body=body, size_bytes=len(body), time_ms=rtt,
            ),
            sent_at=str(obj.get("timestamp") or ""),
            container=container,
        )
    except Exception:  # noqa: BLE001 — a parser must never break a completed run
        return None


def captured_count(container: str, port: int) -> int:
    raw = _api_get(container, port, _VIEW_COUNT)
    try:
        return int(json.loads(raw).get("numberOfMessages", 0))
    except (ValueError, AttributeError, TypeError):
        return 0


def history(container: str, port: int, start: int = 0, count: int = 50):
    """Recent captured exchanges. READ-ONLY and UNGATED — a panel that refreshes cannot demand
    approval per refresh, and `lifecycle.port_is_bound()` sets the precedent with `ss`."""
    raw = _api_get(container, port, f"{_VIEW_MSGS}?start={int(start)}&count={int(count)}")
    try:
        msgs = json.loads(raw).get("messages") or []
    except (ValueError, AttributeError, TypeError):
        return []
    out = [parse_message(m, container) for m in msgs if isinstance(m, dict)]
    return [e for e in out if e is not None]
```

Add `import json` at the top of the module.

- [ ] **Step 5: Run the tests**

```bash
cd backend && .venv/Scripts/python.exe test_zap_proxy.py && .venv/Scripts/python.exe test_repeater.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add backend/cockpit/proxy.py backend/test_zap_proxy.py backend/test_support/zap_proxy_message_fixture.json
git commit -m "build #14 part 2: history read-back + message parser

Records are shaped as RepeaterExchange rather than a new model, so the
existing repeater UI renders them and a captured request can be replayed.

The fixture is a VERBATIM capture from a real ZAP 2.17.0 daemon proxying a
real request inside the Kali image — not hand-written. Part 1's lesson: a
hermetic test that invents its input tests the invention.

Bodies are stored RAW. A test asserts a planted credential survives ingest,
because redacting here was the rejected design (spec §6) and a future edit
'tightening' it would silently gut the feature."
```

---

### Task 4: the `proxy` flag on an exec request

**Files:**
- Modify: `backend/cockpit/models.py`, `backend/cockpit/executor.py`
- Modify: `backend/test_zap_proxy_safety.py`

**Interfaces:**
- Produces: `executor.apply_proxy(command, args, port) -> tuple[list[str], str]` — the rewritten args and a human-readable note.

- [ ] **Step 1: Write the failing test**

Append to `backend/test_zap_proxy_safety.py`:

```python
def test_the_proxy_flag_is_per_tool_and_never_silent() -> None:
    """Each tool spells its proxy flag differently. A tool we do not know is run UNCHANGED and
    the note SAYS SO — silently dropping the flag would produce a run the operator believes was
    captured and was not."""
    from cockpit import executor

    args, note = executor.apply_proxy("curl", ["http://x"], 8090)
    assert "-x" in args and "http://127.0.0.1:8090" in " ".join(args), args
    assert note, "a rewritten command produced no note"

    args, note = executor.apply_proxy("nuclei", ["-u", "http://x"], 8090)
    assert "-proxy" in args, args

    args, note = executor.apply_proxy("sqlmap", ["-u", "http://x"], 8090)
    assert any(a.startswith("--proxy=") for a in args), args

    # the honest case
    unknown_args, unknown_note = executor.apply_proxy("someunknowntool", ["-a"], 8090)
    assert unknown_args == ["-a"], f"an unknown tool's args were rewritten: {unknown_args}"
    assert "not" in unknown_note.lower(), (
        f"an unknown tool was left unproxied with no warning: {unknown_note!r}"
    )
    print("  per-tool proxy flags, and an unknown tool is left alone and reported: PASS")
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd backend && .venv/Scripts/python.exe test_zap_proxy_safety.py
```

Expected: `AttributeError: module 'cockpit.executor' has no attribute 'apply_proxy'`

- [ ] **Step 3: Implement**

In `backend/cockpit/executor.py`:

```python
#: How each tool spells "send your traffic through this proxy". Keyed on the normalised binary
#: name because the spelling is not guessable: curl/ffuf/wget use -x, nuclei -proxy, sqlmap
#: --proxy=. A tool absent from this map is run UNCHANGED and the caller is told.
_PROXY_FLAGS: dict[str, str] = {
    "curl": "-x", "wget": "-e", "ffuf": "-x",
    "nuclei": "-proxy", "sqlmap": "--proxy=",
    "feroxbuster": "--proxy", "gobuster": "--proxy", "wpscan": "--proxy",
}


def apply_proxy(command: str, args: list[str], port: int) -> tuple[list[str], str]:
    """Point one tool at the recording proxy. Returns (args, note).

    This is an ARGUMENT REWRITE on a request that still passes every gate — the same shape as
    tunnels.wrap_command, which introduces no new execution capability and no new gate. The
    rewritten argv is what gets classified AND what runs; there is no second derivation.
    """
    from .allowlist import _tool_name

    url = f"http://127.0.0.1:{port}"
    flag = _PROXY_FLAGS.get(_tool_name(command))
    if flag is None:
        return list(args), (
            f"{command} has no known proxy flag — run NOT captured, sent directly"
        )
    if flag.endswith("="):
        return [f"{flag}{url}", *args], f"{command} routed through the recording proxy"
    return [flag, url, *args], f"{command} routed through the recording proxy"
```

Add to `ExecRequest` in `backend/cockpit/models.py`:

```python
    proxy: bool = Field(
        False,
        description="Route this run through the recording proxy, so its requests and responses "
        "are captured. Adds the tool's proxy flag; introduces no new capability and does not "
        "change any gate. A tool with no known proxy flag runs UNCHANGED and the response says "
        "so, rather than pretending it was captured.",
    )
```

Wire it in `run_command` **before** the gate, so the argv that is classified is the argv that runs.

- [ ] **Step 4: Run the tests**

```bash
cd backend && .venv/Scripts/python.exe test_zap_proxy_safety.py && .venv/Scripts/python.exe test_cockpit.py && .venv/Scripts/python.exe test_secretargs.py
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add backend/cockpit/models.py backend/cockpit/executor.py backend/test_zap_proxy_safety.py
git commit -m "build #14 part 2: proxy flag on an exec request

An argument rewrite on an already-gated request — the same shape as
tunnels.wrap_command, which adds a prefix and introduces no new execution
capability and no new gate. The rewrite happens BEFORE the gate, so the argv
classified is the argv that runs.

A tool with no known proxy flag is run UNCHANGED and the note says so. Silently
dropping the flag would hand the operator a run they believe was captured and
was not, which is worse than not offering the option."
```

---

### Task 5: routes, state ingest, report redaction

**Files:**
- Modify: `backend/cockpit/router.py`, `backend/state/parsers.py`, `backend/report.py`
- Modify: `backend/test_zap_proxy.py`

**Interfaces:**
- Produces: `POST /cockpit/proxy`, `GET /cockpit/proxy`, `GET /cockpit/proxy/status`, `GET /cockpit/proxy/history`, `DELETE /cockpit/proxy/{pid}`.

- [ ] **Step 1: Write the failing tests**

Append to `backend/test_zap_proxy.py`:

```python
def test_captured_requests_become_endpoints() -> None:
    ex = proxy.parse_message(_messages()[0], "c")
    eps = proxy.endpoints_from([ex], session_id="s1", run_id="r1")
    assert eps and eps[0].url.startswith("http"), eps
    assert eps[0].method == ex.request.method
    print(f"  {len(eps)} captured request(s) -> Endpoint records: PASS")


def test_a_captured_secret_does_not_reach_a_report() -> None:
    """*** THE ONE PLACE REDACTION APPLIES. *** Bodies are raw in the store and the panel; a
    report is the artefact handed to a client or a grader."""
    from report import redact_captured_body

    raw = "username=admin&password=hunter2&session=abc123"
    out = redact_captured_body(raw)
    assert "hunter2" not in out, f"a password survived into report text: {out!r}"
    # positive control: the check can fail — a body with no secret is left readable
    plain = redact_captured_body("q=apple&page=2")
    assert "apple" in plain, f"redaction is blanking everything: {plain!r}"
    print("  a captured password is redacted in reports; ordinary params are not: PASS")
```

- [ ] **Step 2: Run to verify failure, then implement**

Add `endpoints_from` to `cockpit/proxy.py`:

```python
def endpoints_from(exchanges, session_id: str, run_id: str | None = None):
    """Captured requests -> Endpoint records. Existing model, no schema change."""
    from urllib.parse import urlparse, parse_qs
    from state.models import Endpoint

    out = []
    for ex in exchanges:
        if not ex or not ex.request.url.startswith("http"):
            continue
        parsed = urlparse(ex.request.url)
        out.append(Endpoint(
            session_id=session_id, url=ex.request.url,
            method=ex.request.method, status=ex.response.status,
            params=sorted(parse_qs(parsed.query).keys()),
            source_run_id=run_id,
        ))
    return out
```

Add `redact_captured_body` to `backend/report.py`, reusing the existing credential masking rather than inventing a second one. Mask the **values** of parameters whose names look secret (`password`, `passwd`, `pwd`, `token`, `secret`, `apikey`, `api_key`, `session`, `auth`, `authorization`, `cookie`) and leave everything else readable.

Add the five routes to `backend/cockpit/router.py`, following the tunnels block: `ProxyRefused.gate` maps a safety refusal to **403** and an availability problem to **409**, never collapsing both.

- [ ] **Step 3: Run the tests**

```bash
cd backend && .venv/Scripts/python.exe test_zap_proxy.py && .venv/Scripts/python.exe test_report_templates.py && .venv/Scripts/python.exe test_state.py
```

- [ ] **Step 4: Commit**

```bash
git add backend/cockpit/router.py backend/cockpit/proxy.py backend/report.py backend/test_zap_proxy.py
git commit -m "build #14 part 2: routes, endpoint ingest, report redaction

Captured requests become Endpoint records through the existing upsert — no
schema change.

Redaction lands ONLY in report.py, which is the decision from spec §6: the
panel and the store hold raw bodies because the request that matters is
usually the one carrying the token, and a report is the artefact handed to a
client. The test carries a positive control so a redactor that blanks
everything fails instead of looking cautious."
```

---

### Task 6: the `:proxy` screen

Ships **with** the endpoints. Part 1 of build #13 shipped four `/cockpit/exposure` endpoints with no caller, and closing that took a whole later build.

**Files:**
- Create: `frontend/src/app/proxy/page.tsx`
- Modify: whatever surface index lists the routes (match how `tunnels` and `exposure` are registered)

- [ ] **Step 1: Read two existing screens for the house style**

```bash
sed -n '1,80p' frontend/src/app/tunnels/page.tsx
sed -n '1,60p' frontend/src/app/exposure/page.tsx
```

- [ ] **Step 2: Build the screen**

Three regions, following the existing card idiom:

1. **Status rail** — container, port, observed status, captured count. Status text must come from the API's observed value, never assumed from a successful POST.
2. **Start/stop** — port input, engagement selector (optional, lab is valid), and **two separate explicit checkboxes** for `approved` and `dangerous_ack`. Never pre-ticked. The red-confirm copy must say what it is confirming: this records credentials and session tokens in cleartext.
3. **History table** — method, URL, status, size, time. Row expands to headers and body. A "replay in repeater" action hands the exchange to the existing repeater screen.

- [ ] **Step 3: Verify lint and build**

```bash
cd frontend && npm run lint && npm run build
```

Expected: build succeeds; eslint at the accepted baseline of 11 (do not "fix" pre-existing warnings in this build).

- [ ] **Step 4: Commit**

```bash
git add frontend/src/app/proxy/
git commit -m "build #14 part 2: the :proxy screen

Ships WITH its endpoints. Build #13 part 1 shipped four /cockpit/exposure
endpoints with no frontend caller and closing that took a whole later build.

Both gate fields are separate un-ticked checkboxes, and the red-confirm copy
states what it is confirming: the proxy records credentials and session tokens
in cleartext. Status is rendered from the API's OBSERVED value, never assumed
from a successful POST."
```

---

### Task 7: proof, suites, assessment

**Files:**
- Create: `docker/proof/zap_proxy_proof.sh`
- Modify: `backend/run_safety_tests.sh`, `.github/workflows/ci.yml`, `docs/ASSESSMENT-2026-07-26.md`

- [ ] **Step 1: Write the proof**

`docker/proof/zap_proxy_proof.sh`, reusing part 1's hard-won conventions:

- compare the running container's image ID against the built image **before** exec'ing into it
- `MSYS_NO_PATHCONV=1` on every container path
- pipe output to Python; never stage through a host `/tmp` file
- print the exit code but decide pass/fail on the **artefact**, never the code

Checks, in order:

1. the daemon starts and `core/view/version` answers via `docker exec`
2. **the API is UNREACHABLE from the host** — the load-bearing isolation check; a `curl` from the host must fail
3. `docker exec ... ss -lntuH` shows the listener bound to **127.0.0.1**, not `0.0.0.0`
4. a request proxied from inside the sandbox is captured (`numberOfMessages` increases)
5. the captured message pipes into `proxy.parse_message` and yields a `RepeaterExchange`
6. the daemon stops cleanly and the port is released

- [ ] **Step 2: Run it**

```bash
docker compose -f docker/docker-compose.yml up -d
sh docker/proof/zap_proxy_proof.sh
```

Expected: all checks pass. If check 2 ever passes-as-reachable, **stop** — that is the isolation property failing and nothing else in this build matters until it is understood.

- [ ] **Step 3: Wire the suites**

```sh
run_test test_zap_proxy.py "ZAP proxy history (real captured message -> RepeaterExchange / malformed never raises / bodies stay raw / endpoints / report redaction with a control)"

run_test test_zap_proxy_safety.py "ZAP proxy gating (approval + red-confirm with controls / gated argv == spawned argv / loopback-only bind / both modes / no stdin writer / gate before spawn / per-tool proxy flag)"
```

Update the hermetic file count in `.github/workflows/ci.yml` and add a NOT-run note for `zap_proxy_proof.sh`, explaining that host-unreachability cannot be asserted hermetically.

- [ ] **Step 4: Assessment**

Add a build #14 part 2 section recording: the measured finding that makes it safe (loopback + `docker exec`, with the host-unreachability result), the divergence from `tunnels.py` on lab mode and why it inverts, `-daemon` joining the attack flags and why, the raw-bodies decision and where redaction lives, and the fact that the read-only property is a **convention with nothing enforcing it** (both guards declined) plus the review rule.

```bash
python docs/build-assessment.py
grep -c "recording proxy" docs/ASSESSMENT-2026-07-26.html
```

Verify against the HTML — the PDF cannot be grepped.

- [ ] **Step 5: Full suite, commit, push, watch CI**

```bash
sh backend/run_safety_tests.sh
git add -A backend/ docker/ docs/ .github/
git commit   # message per the pattern above
git push origin main
```

Then poll CI to completion and report the conclusion. **If CI fails, diagnose the actual failure before assuming flakiness** — part 1's two "flakes" were both real defects.

## Definition of done

- [ ] `sh backend/run_safety_tests.sh` passes, two files larger than before.
- [ ] `sh docker/proof/zap_proxy_proof.sh` passes, **including host-unreachability**.
- [ ] A start without `dangerous_ack` is refused with nothing spawned; with it, the proxy comes up and status is observed.
- [ ] A `curl` or `ffuf` run with `proxy: true` appears in the history panel and its URL appears as an `Endpoint`.
- [ ] `:proxy` ships with its endpoints — no orphaned routes.
- [ ] Assessment updated and regenerated in the same commit, verified against the HTML.
- [ ] CI green.
