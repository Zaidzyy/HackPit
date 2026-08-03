# Public C2 Redirector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a callback destination be a **remote host** — a VPS the operator already owns — so an implant inside an internet-facing target can reach a laptop behind NAT, without growing a second deploy path or softening one of part 1's invariants.

**Architecture:** Part 1's `ListenerProfile` gains a `destination` of `local` (unchanged, byte-identical) or `remote`. A remote profile renders a **redirector**: a stdlib-only TCP/UDP forwarder (`redirector/forward.py`) shipped to the configured VPS, which relays a public port to `127.0.0.1:<tunnel port>` and nowhere else. The operator dials the reverse tunnel outward with a command HackPit renders and does not run. The deploy reuses part 3's gated engine, generalised **once** into a private artifact-shipping function with two destination-free public wrappers.

**Tech Stack:** Python 3.14, FastAPI, pydantic v2, stdlib `socket`/`select`/`threading`, SSH via the existing executor path. No new third-party dependency.

## Global Constraints

- **No new third-party dependency.** The hermetic suite installs only `fastapi httpx pydantic pyyaml numpy`.
- **Tests are plain scripts, not pytest.** Each file defines `test_*()` functions, prints `  <description>: PASS` per check, and ends with an `if __name__ == "__main__":` block calling them in order.
- **Every new test file needs a `run_test` line in `backend/run_safety_tests.sh` AND a bump to the hardcoded count in `.github/workflows/ci.yml`** (currently **62**).
- **Part 1's local path must stay byte-identical.** `test_exposure.py` and `test_exposure_safety.py` pass unchanged; the `vmnet8-dns` preset still renders exactly the golden file.
- **The lab sandbox is never exposable**, local or remote. Structural.
- **A whole-tree guard firing means fix the PREDICATE, not join the allow-list.** Part 1 hit this (tunnel constants), part 2 hit it (WinRM transport), part 3 hit it twice (the `backend/oob` inertness split, the DNS-tunnel prose citation).
- **The deploy takes no destination.** `test_oob_deploy_safety.py` asserts this on the real signature; the new wrapper must satisfy the same assertion.
- **Every endpoint needs a real component caller.** Part 1's four `/cockpit/exposure` endpoints currently have none — this plan fixes that.
- **eslint stays at the accepted baseline of 11.** Route new state through an async callback, never an effect body.
- Commit messages end with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`. Branch: `main`.

## File Structure

| File | Responsibility |
|---|---|
| `redirector/forward.py` | **Create.** The deployable. Stdlib-only bounded forwarder, copied to the VPS. |
| `backend/cockpit/redirector.py` | **Create.** Pure rendering: forwarder argv, reverse-tunnel command, exposure summary. |
| `backend/cockpit/exposure.py` | **Modify.** `destination` field, remote validation branch, remote `describe`. |
| `backend/cockpit/executor.py` | **Modify.** Extract the shared artifact-deploy engine; add the redirector wrapper + stop. |
| `backend/cockpit/router.py` | **Modify.** Remote-profile endpoints alongside the existing four. |
| `backend/test_redirector.py` | **Create.** Rendering + the LIVE loopback forward. |
| `backend/test_redirector_safety.py` | **Create.** Bounded-forwarding invariants + no-agent-path + the deploy signature. |
| `backend/test_exposure.py` | **Modify.** Assert the local path is unchanged by the new field. |
| `backend/test_oob_deploy_safety.py` | **Modify.** Extend the signature assertion to both wrappers. |
| `frontend/src/components/ExposureScreen.tsx` | **Create.** The panel part 1 never got, with the remote option. |
| `frontend/src/app/exposure/page.tsx` | **Create.** Route. |
| `frontend/src/lib/api.ts`, `data.ts` | **Modify.** Client + surface tile. |
| `backend/run_safety_tests.sh`, `.github/workflows/ci.yml` | **Modify.** Two new files; count 62 → 64. |
| `docs/ASSESSMENT-2026-07-26.md` | **Modify.** Part 4 section, same commit as the code. |

---

### Task 1: The deployable — a bounded forwarder

**Files:** Create `redirector/forward.py`; test `backend/test_redirector.py`

**Interfaces:** `forward_tcp(listen_port, target_port)`, `forward_udp(...)`, `Redirector(ports).start()/stop()`, `main(argv)`

The destination is `127.0.0.1:<target_port>` — built inside the module from an integer, never from a hostname argument. There is no code path that connects anywhere else; `test_redirector_safety` asserts it over the AST.

- [ ] **Step 1: Write the failing test** — a real listener on an ephemeral port, a real client, bytes both ways.
- [ ] **Step 2: Implement** — accept loop per port, a thread per connection, `select` pump, bounded buffer, hard connection cap.
- [ ] **Step 3: Verify** — round trip passes; with nothing on the target port the client connection is accepted and closed, not hung.
- [ ] **Step 4: Commit**

### Task 2: Rendering — `backend/cockpit/redirector.py`

**Files:** Create `backend/cockpit/redirector.py`; test `backend/test_redirector.py`

**Interfaces:** `tunnel_port_for(port) -> int`, `reverse_tunnel_command(target, ports) -> list[str]`, `forwarder_command(ports) -> str`, `describe(profile) -> dict`

Pure — no socket, no subprocess. The reverse-tunnel command is rendered and **never run** (the DNS-tunnel one-liner boundary). Tunnel ports are derived deterministically from the public port so both sides agree without a shared config file.

- [ ] **Step 1: Write the failing test** — the rendered ssh command carries `-N -R 127.0.0.1:<tunnel>:127.0.0.1:<local>`, the configured user/host/port/key, and no secret.
- [ ] **Step 2: Implement**
- [ ] **Step 3: Verify** — `describe()` states in plain words what becomes publicly reachable and how to take it down.
- [ ] **Step 4: Commit**

### Task 3: `destination` on `ListenerProfile`

**Files:** Modify `backend/cockpit/exposure.py`, `backend/test_exposure.py`

- [ ] **Step 1: Write the failing test** — a `local` profile with the new field defaulted renders **byte-identically** to before (assert against the existing golden); a `remote` profile skips `address_is_live`, always demands the public acknowledgement, and refuses `docker compose`.
- [ ] **Step 2: Implement** — `destination: Literal["local","remote"] = "local"`, a `validate_remote` branch, `EXPOSABLE` unchanged.
- [ ] **Step 3: Verify** — `test_exposure.py` and `test_exposure_safety.py` pass unchanged.
- [ ] **Step 4: Commit**

### Task 4: One deploy engine, two destination-free wrappers

**Files:** Modify `backend/cockpit/executor.py`, `backend/test_oob_deploy_safety.py`

**Interfaces:** private `_deploy_artifact(*, approved, artifact)`, public `deploy_oob_canary(*, approved, restart)` and `deploy_c2_redirector(*, approved, restart)`, plus `stop_c2_redirector(*, approved)`

`artifact` is a module-level constant descriptor, never a caller's value — the public wrappers stay free of anything addressable so the existing signature assertion holds for both.

- [ ] **Step 1: Write the failing test** — the signature check runs over BOTH wrappers; an unapproved redirector deploy sends nothing; both address only the stored host.
- [ ] **Step 2: Implement** — extract the engine, keep the canary's behaviour identical.
- [ ] **Step 3: Verify** — `test_oob_deploy_safety.py` green; `stop` is as reachable as `start`.
- [ ] **Step 4: Commit**

### Task 5: Safety invariants — `backend/test_redirector_safety.py`

**Files:** Create `backend/test_redirector_safety.py`

Four invariants, each with a positive control:
1. **The forwarder relays to loopback and nowhere else** — AST over the real file: no `connect` to anything but a `127.0.0.1` literal, no hostname resolution, no `urllib`/`subprocess`/`eval`.
2. **No agent path** — whole-tree scan; only the executor and the router reach the deploy.
3. **The port set is enumerated** — no ranges, and the same refusal part 1 already gives.
4. **The deployable is stdlib-only** — it is copied to a bare VPS.

- [ ] **Step 1: Write the tests with their controls**
- [ ] **Step 2: Verify each control fires on a planted violation**
- [ ] **Step 3: Add both new files to `run_safety_tests.sh`, bump `ci.yml` 62 → 64**
- [ ] **Step 4: Commit**

### Task 6: Endpoints + the exposure panel

**Files:** Modify `backend/cockpit/router.py`, `frontend/src/lib/api.ts`, `frontend/src/lib/data.ts`; create `frontend/src/components/ExposureScreen.tsx`, `frontend/src/app/exposure/page.tsx`

The panel covers **all** exposure endpoints — part 1's four included, since they have no caller today — plus the remote destination, the rendered reverse-tunnel command with a copy button, deploy/stop behind an explicit approval, and the AUP consequence stated on screen.

- [ ] **Step 1: Endpoints** — remote apply/stop/describe next to the existing four.
- [ ] **Step 2: Client + panel**
- [ ] **Step 3: Verify** — `npm run build` clean, `npm run lint` still 11 errors, every endpoint has a caller.
- [ ] **Step 4: Commit**

### Task 7: Loopback proof, assessment, land

**Files:** Modify `docker/proof/redirector_loopback_proof.py` (create), `docs/ASSESSMENT-2026-07-26.md` + regenerate

- [ ] **Step 1:** A proof that starts the real forwarder, a real listener, and a real client on loopback and drives bytes through the whole chain.
- [ ] **Step 2:** Report NOT-RUN individually: public inbound reachability, one real implant session, the SSH transfer.
- [ ] **Step 3:** Assessment section — the AUP position stated plainly, per the spec's §2.
- [ ] **Step 4:** `python docs/build-assessment.py`, verify against the **HTML** and the page-count delta (never grep the PDF).
- [ ] **Step 5:** Full suite green, commit, push, confirm CI.
