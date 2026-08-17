---
description: Autonomous, hands-off pentest / bug-bounty engagement. Invoke once, answer a short scoping interview, then HackPit runs the entire loop itself — recon → rank → hunt every surface → validate → write the report — with NO per-command approval. Scope-safety is the only wall. Usage: /engage target.com [--goal ...] [--auth-file f.json] [--aggressive] [--time-box 2h]
---

# /engage — autonomous engagement

This is the hands-off front door to everything HackPit can do. You invoke it once,
it asks a short scoping interview, and then it **runs the whole assessment by itself**:
recon, ranking, hunting every relevant surface, chaining findings, validating them,
and writing the report — without stopping to ask permission at each step.

`/engage` is the deliberate opposite of the cockpit orchestrator loop (where a human
approves every command) and of `/autopilot` (which still checkpoints and always stops
before reporting). Here there is exactly **one** stop — the opening interview — and
after that it is silent until the engagement is done.

> Because the per-command human gate is removed on purpose, **scope-safety becomes the
> only wall.** The rails in the "Non-negotiable safety rails" section below are what
> keep an autonomous offensive run inside the lines. They are not optional and they are
> not checkpoints you can flag away — they are how this command stays legitimate.

## Usage

```
/engage target.com                                  # interview, then full autonomous run
/engage target.com --goal "bug bounty, focus IDOR + auth"
/engage target.com --auth-file .private/session.json --aggressive
/engage target.com --time-box 90m --safe
/engage program.txt                                 # one target per line
/engage target.com --dry-run                        # plan + scope only, execute nothing
```

Flags (all optional — anything missing is asked in the interview):

| Flag | Meaning |
|---|---|
| `--goal "..."` | Engagement objective + priority bug classes |
| `--auth-file <f>` / `--cookie` / `--bearer` | Authenticated identity to test as |
| `--scope "<a>,<b>"` / `--exclude "<a>"` | Scope allowlist / exclusions (else pulled from program) |
| `--aggressive` | Permit gated *confirm* steps + PUT/DELETE/PATCH (see rails). Default is safe/read-only |
| `--safe` | Force read-only: GET/HEAD/OPTIONS + detection-only, never a confirm/exploit step |
| `--time-box <dur>` | Wall-clock budget (e.g. `90m`, `2h`). Loop wraps up + reports when hit |
| `--dry-run` | Do the interview, build scope, print the plan — then stop without any outbound request |

## Step 0 — The interview (the one and only stop)

Before anything runs, ask the operator the scoping questions **in a single batched
`AskUserQuestion` call** (don't drip them one at a time — one stop, then hands-off).
Skip any question already answered by a flag.

1. **Target & scope** — root domain(s)/apps in scope, plus explicit exclusions.
   If a bug-bounty program is named, offer to load its scope with `/scope <program>`.
2. **Goal** — bug bounty vs. authorized pentest, and which bug classes to prioritize
   (IDOR/BAC, auth/session, injection, SSRF, business logic, cloud, AD, etc.).
3. **Authorization attestation** *(required — this is the ethical anchor)* — the
   operator confirms they are authorized to test this target (in-scope BBP, signed RoE,
   or owned lab). If they cannot attest, **stop here** and do not run.
4. **Identity** — unauthenticated only, or an auth session to run as? If IDOR/priv-esc
   is in scope, ask whether a second low-priv session is available for identity-diffing.
5. **Aggressiveness** — read-only detection only (default), or may it fire the *gated
   confirm* steps (smuggling socket confirm, cache poison confirm, race, exploit PoC)?
6. **Time box** — how long should it run before it wraps up and reports?

Echo the resolved plan back once, e.g.:

```
ENGAGEMENT PLAN — target.com
  Scope:      *.target.com, api.target.com   (excl. blog.target.com)
  Goal:       bug bounty — IDOR, auth, SSRF first
  Identity:   authed as id=b181f318fb10  (+ low-priv session for IDOR diff)
  Posture:    aggressive (confirm steps allowed; repeater stays human-only)
  Time box:   90m
  Reports:    written to findings/target.com/ — NOT auto-submitted
Starting autonomous run. I'll go quiet until it's done or something needs you.
```

Then proceed. **After this point, do not ask for per-command approval.** The only
things that can still surface to the human mid-run are the hard exceptions listed under
the rails (out-of-scope expansion request, repeated hard blocks, an external submission
— never routine command approval).

## Non-negotiable safety rails

These replace the human gate. They are enforced on every iteration.

1. **Scope-check every outbound request.** Build a `ScopeChecker` allowlist from the
   interview (see `/scope`, `scope_checker.py`). Before any request, verify the host is
   in scope; if not, **drop it and log** — do not ask, do not send. Filter every recon
   output file through the checker before it becomes a hunt target.
2. **Audit every request** to `hunt-memory/audit.jsonl` (ts, url, method, scope_check,
   status, finding_id, 12-char `session_id` hash). The run must be fully reconstructable
   afterward. Never write raw cookies/tokens/keys — only the session hash.
3. **`repeater` stays human-only.** The autonomous loop may drive the other surfaces
   (recon, discover, jsrecon, nuclei, intruder, smuggle, cache, race, credentials,
   tokens, codescan, oob, tunnels, c2, capture) but **never `:repeater`** — that is a
   human-only surface in HackPit's contract and is excluded from this path.
4. **Reports are written, never auto-submitted.** `/engage` produces report files on
   disk. Submitting to a bug-bounty platform, emailing a client, or any other external
   send is outward-facing and is **not** part of hands-off — leave it for the human.
5. **Method / posture guard.** Default `--safe` = GET/HEAD/OPTIONS and detection-only
   surfaces. `--aggressive` additionally permits the *gated confirm* steps and
   PUT/DELETE/PATCH, but only against confirmed in-scope hosts and only because the
   operator opted in during the interview. Never DoS, never touch excluded classes.
6. **Rate limits.** 1 req/sec for vuln testing, 10 req/sec for recon, unless the program
   specifies its own — then honor the program's.
7. **Circuit breaker.** 5 consecutive 403/429/timeout on one host → back off 60s, retry
   once, then skip the host and move on. If the *whole target* goes dark, pause and tell
   the human (this is an exception, not a routine checkpoint).

## The autonomous loop

Run this end-to-end. Reuse the existing HackPit surfaces and the bug-bounty command
engines — `/engage` is an orchestrator, not new capability.

```
1. SCOPE     Build + confirm the allowlist                     (≡ /scope)
2. RECON     Enumerate attack surface                          (≡ /recon ; hackpit_recon_surface)
                reuse recon/<target>/ cache if < 7 days old
3. RANK      Prioritize P1/P2/kill                             (recon-ranker agent  ≡ /surface)
4. HUNT      For each ranked target, autonomously:
               a. pick bug class from tech stack + URL + hunt memory
               b. run the matching surface(s) — via hackpit_surface /
                  hackpit_execute (MCP execute is authorized) or the
                  hexstrike-ai tools; /hunt, /jsrecon, /discover, /nuclei,
                  /intruder, /smuggle, /cache, /race, /credentials, /tokens,
                  /codescan, /oob, /tunnels, /c2, /capture as fits the goal
               c. on signal → walk the A→B chain table (/chain) to escalate
               d. no progress in ~5 min on a target → rotate to the next
5. VALIDATE  7-Question Gate + validator agent on every finding; KILL weak ones
6. REPORT    report-writer draft per validated finding → findings/<target>/
               (report.md, and report.pdf if the builder is available)
7. WRAP      When surface is exhausted or the time box hits, stop and summarize
```

Prefer the `mcp__hackpit__*` surfaces where a tool exists (they run under the
authorized `HACKPIT_MCP_EXECUTE=1` contract, no per-command gate). Fall back to the
`mcp__hexstrike-ai__*` tools and the `/`-command engines (`tools/recon_engine.sh`,
`tools/hunt.py`) for anything not exposed as an MCP surface. Keep engagement state and
governance current as findings land (`hackpit_engagement_state`).

For a run that should proceed without cluttering the main thread, the phases may be
dispatched to the existing agents (`recon-agent`, `recon-ranker`, `validator`,
`report-writer`) — but the loop itself does **not** hand control back to the human
between phases. That silence is the whole point.

## Output

When the run finishes (or the time box hits, or the surface is exhausted), print one
summary and hand over the report path — nothing in between.

```
ENGAGEMENT COMPLETE — target.com
════════════════════════════════
Duration:   88m (time-boxed 90m)     Posture: aggressive
Requests:   612 total  (612 in-scope, 0 sent out-of-scope, 4 dropped by scope-check)
Surfaces:   recon, discover, jsrecon, nuclei, intruder, oob, credentials
Findings:   3 validated · 2 killed · 1 partial (queued for next run)

  1. [HIGH]   IDOR — /api/v2/users/{id}/orders  (read+write, cross-account confirmed)
  2. [HIGH]   SSRF → cloud IMDS on /import?url=  (chained to creds)
  3. [MEDIUM] Open redirect on /auth/callback    (OAuth-theft chain candidate)

Reports:    findings/target.com/  (report.md ×3, report.pdf ×3)  — NOT submitted
Audit:      hunt-memory/audit.jsonl  (612 entries)
Next:       9 endpoints untested — /pickup target.com  ·  /remember to log patterns
```

Then auto-log a session summary to hunt memory (`/remember`, tagged `auto_logged`,
`session_summary`) so `/pickup` and the next `/engage` resume cleanly. Do **not**
submit, email, or otherwise externally send anything — that decision stays with the
human.

## When NOT to use this

- **You want to inspect between steps** → run the manual chain (`/recon` → `/hunt` →
  `/validate` → `/report`) or `/autopilot --paranoid` instead.
- **Human-approves-every-command engagement mode is required** → use the cockpit
  orchestrator loop, not `/engage`.
- **You're unsure you're authorized** → don't. The interview will stop you anyway.
