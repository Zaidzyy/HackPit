# Cockpit — Session Log

*Running log of the unsupervised Cockpit build session(s). Newest entries at the bottom
of each section. Zaid reviews this + docs/cockpit-plan.md on return.*

---

## Session 2026-07-23 (unsupervised, Milestone 1)

### Context / grounding
- Companion is feature-complete. This session begins the **Cockpit** (live, human-approved
  execution against an isolated lab), per the "Cockpit: scope, then build Milestone 1" prompt.
- Read PROJECT_PLAN.md (locked decisions: Kali Docker sandbox, two-network isolation,
  human-in-the-loop, web module first, mechanisms-not-payloads, authorized/lab targets only).
- Grounded in the existing backend: `attack_path.py` (ordered grounded `{phase}-{n}` steps),
  `sessions.py` + `sessions.db` (per-step state), `llm.py` (provider-swappable), FastAPI `main.py`.

### Runtime reality found
- Docker CLI **29.1.3** + Compose **v5.0.1** installed. WSL2 **Ubuntu** is the default distro.
- **Docker Desktop daemon was NOT running** when checked (`docker info` failed on the pipe).
  → M1.2 config + proof scripts can be authored, but the isolation *proof* cannot be executed
  until the daemon is up. This is the gate before any execution code (M1.3).

### Phase 0 — scope & architecture ✅
- Wrote **`docs/cockpit-plan.md`**: reuse map, architecture (planner → orchestrator → exec →
  sandbox → live UI with 3 human control points), **safety-by-architecture** (3 independent
  layers + operational gates), phased roadmap (web first, each phase shippable), and the M1 spec.
- Recorded 6 assumed defaults + 6 open questions for Zaid at the top of the plan.

### M1.1 — Cockpit module scaffold (in progress)
- Created `backend/cockpit/` (interfaces, execution stubbed until M1.2/M1.3 proof):
  - `config.py` — hardcoded sandbox/lab/network constants + exec timeout (the target lock's source of truth).
  - `allowlist.py` — the M1 safe command set (nmap/curl/whatweb, recon-only) + **pure** validation
    (allowlisted command, no shell metachars, per-command arg rules). No execution.
  - `models.py` — Pydantic contracts (ExecRequest/Accepted/Rejected, RunRecord, Allowlist*).
  - `sandbox.py` — lifecycle interface; `is_sandbox_up()` / `assert_isolation_proven()` raise until M1.3.
  - `executor.py` — `check_target_lock()` (pure, real) + `run_command()` (raises NotImplementedError until M1.3).
  - `router.py` — FastAPI routes; `/cockpit/allowlist` is real (read-only), exec/stream return 501.
    **NOT mounted into main.py yet** (mounted in M1.3, after the isolation proof).
- Created `docker/README.md` (M1.2 lands the compose stack + proof here).

### M1.2 — Isolated Docker stack + isolation PROOF ✅ (HARD GATE PASSED)
- Started Docker Desktop (was down); daemon came up (linux engine, server 29.1.3).
- Authored `docker/docker-compose.yml` (two services on ONE `internal: true` network:
  `hackpit-kali-sandbox` + `hackpit-lab-target` = OWASP Juice Shop), `docker/Dockerfile.sandbox`
  (Debian-slim + nmap/curl/whatweb baked at build time; runtime egress-less; `cap_drop: ALL`,
  `no-new-privileges`, unprivileged user), and `docker/proof/isolation_proof.sh`.
- Build hiccup fixed: Debian ships a built-in `operator` user → renamed sandbox user to `sandbox`.
- **Isolation PROVEN** (`docker/proof/PROOF.md`, exit 0): sandbox → lab = HTTP 200; sandbox → public
  IP 1.1.1.1, → https://example.com, → external DNS, → host.docker.internal all FAIL.
  Structural evidence: the `internal: true` network installs no default route — the sandbox's
  routing table has only the on-link `172.23.0.0/16` route and no `0.0.0.0` gateway, so there is
  no path off the bridge by construction (not a toggleable filter).
- **Gate cleared:** execution code (M1.3) is now permitted to be wired.

### Open questions for Zaid
See docs/cockpit-plan.md §"Open questions for Zaid" (sandbox choice, lab target, allowlist scope,
frontier model/key, Docker daemon start, exec transport). Note: I started Docker Desktop myself and
ran the proof (open question #5 resolved for this session).
