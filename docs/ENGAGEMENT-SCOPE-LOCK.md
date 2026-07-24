# Engagement SCOPE-LOCK

**Branch:** `engagement-scope-lock` (off `main`) · **Status:** S1–S2 done + proven; S3–S6 in progress · **Not pushed.**

Zaid's decision (supersedes the Wall-A-down flip): engagement mode gets a **real network floor** again, but as a **per-target SCOPE-LOCK**, and the guided loop becomes available on real targets — because the containment is now **network-enforced**, not "no floor at all." ("Wall A" is now a toggle: this is Wall A **UP**. If Zaid says "wall A down", revert to fully-open and drop the scope-lock — everything else stays.)

## The model (on real targets)

The floor is **three** things:

1. **SCOPE-LOCK (the containment).** Engagement egress is a **DEFAULT-DENY** firewall that allows **ONLY** the engagement's resolved authorized scope. The operator's own host/gateway, out-of-scope LAN, cloud metadata (`169.254.169.254` + link-local), IPv6 (unless the scope is v6), and the rest of the internet are **all dropped**. This **replaces isolation** on real targets. Network-enforced — the argv target-lock stays as cheap defense-in-depth but is explicitly **NOT** the bound.
2. **NEVER-AUTO-RUN (kept, still load-bearing).** Every command — manual **or loop-proposed** — needs an explicit **per-command human approval**. No batch, no approve-all, no auto-approve, even in the loop. **The loop DRAFTS; it never FIRES.** Enforced in code (`_validate_engagement` approval gate + `iter_run` belt-and-suspenders) and test.
3. **Heuristic red-confirm + argv-only exec.** Agent still has **zero** `:kali` path.

Because a hallucinated command physically cannot leave the scope, the guided loop (agent drafts commands) is acceptable on real targets — the human still approves every command before it runs.

## Mechanism (revived Wall-A sidecar, as a per-target ALLOW-list)

- **Firewall sidecar** (`docker/Dockerfile.firewall`, `scope_lock.sh`, `scope_lock_entrypoint.sh`): the `hackpit-engage-firewall` container is the **only** engagement box with `NET_ADMIN`. It **owns** the network namespace and installs **default-DENY** at start (fail-closed). The engage sandbox **shares** that netns (`network_mode: service:engage-firewall`), so it stays `cap_drop: ALL` + `no-new-privileges` and **cannot alter the rules or leave scope**.
- **Scope resolution** (`backend/cockpit/scope.py`): a scope is a **single host** (`scanme.nmap.org` / a URL / a bare IP) **or a CIDR** (`10.10.10.0/24`, for internal/AD work). Host → resolve to its v4+v6 IPs; CIDR → validate the range. **Fail-closed** on empty / malformed / unresolvable.
- **Apply on ENTER / clear on EXIT** (`router` → `sandbox.apply_scope` / `clear_scope`): on entry the backend programs `scope_lock.sh apply <resolved-scope>` into the firewall (v4 `iptables` / v6 `ip6tables`); on exit it resets to `deny`. The `EngagementRecord` carries `resolved_scope` + `scope_kind` (persisted).
- **DNS handling:** the scope host is **pre-resolved at entry** and an `/etc/hosts` mapping (`<ip> <host>`) is injected so tools resolve the name **locally, with no DNS egress hole**. It is written into the **firewall** container (the netns owner) because the sandbox's `/etc/hosts` is a **read-only bind mount** of it — written via `cat >` (not `sed -i`, which can't replace a bind-mounted inode). CIDR scopes need no DNS (tools use IPs).

## The gate (fail-closed) — `assert_scope_locked`

The engagement analog of `assert_isolation_proven`, re-checked **before every engagement exec** as the **first** engagement gate (`scope → target → approval → danger`). It refuses unless:

- the firewall sidecar **and** sandbox are running;
- the OUTPUT policy is **DROP** on v4 **and** v6 (default-deny);
- the ACCEPT destinations **match the resolved scope EXACTLY** (not broader — a widened/flushed/absent ruleset fails; loopback is the only non-scoped allow; a blanket ACCEPT fails).

So a real-target command can only run behind a **confirmed** network floor. Wired into `_validate_engagement` **before** approval.

## Proof (live, S2)

`docker/proof/engage_scope_proof.sh` applies a single-host scope (`scanme.nmap.org`) and, from the sandbox, verifies — **6 passed, 0 failed**:

| # | check | result |
|---|---|---|
| 1 | scope IP reachable (in scope) | **PASS** |
| 2 | operator host gateway not reachable | **PASS** |
| 2 | `host.docker.internal` not reachable | **PASS** |
| 3 | out-of-scope LAN `192.168.255.254` not reachable | **PASS** |
| 4 | cloud metadata `169.254.169.254` not reachable | **PASS** |
| 5 | unrelated public `8.8.8.8` not reachable | **PASS** |

Wired into `run_safety_tests.sh --with-proof` (replaces the deleted `engage_open_proof.sh`). Lab isolation proof stays **4/4**; full hermetic suite **6/6** green (incl. the new scope-lock tests and the belt-and-suspenders never-auto-run test).

## Never-auto-run in the loop (S3–S4)

The guided loop `POST /sessions/{id}/loop/propose` **proposes** a command (with rationale + gate pre-check) and returns it **without executing**. Running it is a separate `POST /cockpit/exec` that goes through `_validate_engagement` — **scope-lock → target-lock → NEVER-AUTO-RUN approval → danger** — so a loop-proposed command still requires the operator's explicit `approved=true`. There is **no auto-approve path** in engagement, and `iter_run` re-checks approval even on the prevalidated path (belt-and-suspenders), so the loop can never fire a command on its own.

**Test-locked:** `test_iter_run_prevalidated_still_needs_approval` (loop/prevalidated + `approved=false` → exactly one `rejected`/`approval`, nothing runs) + `test_never_auto_run_engagement` + `test_scope_lock_gate`.

## Increment status

- **S1 — scope-locked egress sidecar** — DONE + proven (commit `bf1d17d`).
- **S2 — scope-lock gate + proof (fail-closed)** — DONE + proven (commit `cbca582`).
- **S4a — honest scope-locked UI + status endpoint + this doc** — DONE (commit `8aee4f2`).
- **S3 — guided loop on engagement (UI + wiring)** — DONE (commit `3e0b976`). `CockpitLoop` takes an optional `engagementId`; when an engagement is active a loop/manual toggle (default manual) offers the loop, and every approved proposal routes through `_validate_engagement`. tsc clean; eslint at baseline; `next build` exit 0.
- **S4b — never-auto-run-in-loop lock** — DONE. Enforced in code (approval gate + `iter_run` belt-and-suspenders) and test-locked (`test_iter_run_prevalidated_still_needs_approval`: a loop/prevalidated engagement command with `approved=false` yields exactly one `rejected`/`approval` and runs nothing). The loop's only exec sets `approved:true` solely on the human's approve click.
- **S5 — tests all hold** — DONE. Full hermetic suite **6/6**; lab isolation proof **4/4**; scope-lock proof **6/6**; scope-lock fail-closed (no-scope / mismatch refuse, confirmed clears); lab mode byte-for-byte unchanged; agent zero `:kali` path; argv-only; heuristic red-confirm fires.
- **S6 — live e2e** — **DEFERRED** to a human-present session (never auto-run). Ready to run together vs `scanme.nmap.org` (scope = single host) and against a scoped CIDR, with the human approving each command.

**Not pushed** — Zaid reviews the scope-lock proof + that lab is untouched and never-auto-run holds in the loop.

## Safety gates (all hold)

- **Lab mode byte-for-byte unchanged** — isolation gate intact, proof **4/4**.
- **Engagement floor** — scope-lock (fail-closed, network-enforced) + never-auto-run (kept, enforced in the loop too) + heuristic + argv-only.
- Agent has **zero** `:kali` / auto path. The scope-lock is the bound; the argv target-lock is non-load-bearing DiD.
