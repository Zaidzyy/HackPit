# Build queue #2 — web-core round 2 + capstone (7 specs)

Seven builds that close the remaining modern-web bug-bounty classes (the "we have it as a tool/KB, not as a surface" gaps) plus the cross-domain kill-chain capstone. Run **one per session**, own terminal, sequentially — each is its own commit (README + screenshot + assessment + regenerated PDF together). No hard dependency between them except the capstone (#7) is richest after #? cloud specs; any order otherwise works.

**Shared rules (baked into every §0):** no new gate — **per-command human approval is the only bound**; maximally open (Wall A down); maximally offensive (real tampered tokens / concurrent races / desync probes / poisoning to real targets) — but always through the gated **executor / repeater**, **scope-checked on the wire**, **stop ungated**, **hardcoded container** (the intruder/repeater containment); pure analysis cores execute nothing (the GraphQL model); graphs are **propose-only** (edge index, never a command). Single-branch repo (`main`). Each build: tests + `run_safety_tests.sh` green, `next build` exit 0, **look at the screen**, README + screenshot + `docs/ASSESSMENT-2026-07-26.md` + regen PDF **same commit**.

---

## Recommended order

| # | Spec file | What it adds | Model it copies |
|---|-----------|--------------|-----------------|
| 1 | `2026-08-07-token-workbench-spec.md` | **JWT / OAuth / OIDC / SAML** attack surface (decode/tamper/replay, alg-confusion, kid/jku, XSW, PKCE) | GraphQL core (pure module + repeater send) |
| 2 | `2026-08-07-race-singlepacket-spec.md` | **Single-packet / last-byte-sync race** tester | intruder (one gated job, containment) |
| 3 | `2026-08-07-request-smuggling-spec.md` | **CL.TE/TE.CL/CL.0/H2 desync** detector | nuclei job + repeater raw |
| 4 | `2026-08-07-cache-poisoning-spec.md` | **Cache poisoning / deception** (unkeyed-input probing) | nuclei job + intruder sweep |
| 5 | `2026-08-07-param-content-discovery-spec.md` | **arjun/x8/ffuf/paramspider → intruder/nuclei** hand-off | :recon job (scope-by-construction) |
| 6 | `2026-08-07-js-recon-secrets-spec.md` | **JS bundle → endpoints/params/secrets** → ranked surface | :recon job (scope-by-construction) |
| 7 | `2026-08-07-killchain-graph-spec.md` | **web → cloud → on-prem** stitched kill-chain graph (capstone) | ad/cloud edge-index orchestrator (read-and-stitch overlay) |

Order rationale: highest bug-bounty value first (token workbench), then the three request-level primitives (race/smuggling/cache), then the two recon feeders (discovery/JS — 5 before 6 since discovery is cheaper and both feed `:recon`), capstone last. If you're also running BUILD-QUEUE (the AD/cloud gap specs), do the SSRF→IMDS bridge + K8s graph **before** #7 here so the capstone has its cross-domain seams.

---

## What to say to each session

Open a fresh session in the repo and paste the matching line.

**Session 1 — Token workbench:**
> Read `docs/superpowers/specs/2026-08-07-token-workbench-spec.md` and build it end to end. Model it on the GraphQL core in `backend/cockpit/graphql.py` — a PURE analysis/tamper module that sends through the repeater. Follow §0 exactly. Tests + safety suite green, `next build` exit 0, screenshot of `/tokens` (synthetic token), README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 2 — Single-packet race tester:**
> Read `docs/superpowers/specs/2026-08-07-race-singlepacket-spec.md` and build it end to end. Model it on `backend/cockpit/intruder.py` — one gated job, hardcoded container, per-request scope check on the wire, ungated stop. Add the single-packet engine to arsenal + Dockerfile + proof (flag the image rebuild for me). Tests + safety green, `next build` exit 0, screenshot of `/race`, README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 3 — Request-smuggling detector:**
> Read `docs/superpowers/specs/2026-08-07-request-smuggling-spec.md` and build it end to end. Model the job on `backend/cockpit/nuclei.py`; detection is safe timing-differential by default, confirmation is a separate approve-each with a co-tenant warning. Add smuggler.py/h2csmuggler to arsenal + Dockerfile + proof (flag the rebuild). Follow §0. Tests + safety green, `next build` exit 0, screenshot of `/smuggle`, README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 4 — Cache poisoning / deception:**
> Read `docs/superpowers/specs/2026-08-07-cache-poisoning-spec.md` and build it end to end. Detection (unkeyed-input reflection + cacheability) is safe/default; the poison-confirmation is a separate approve-each with a co-user warning. Add wcvs to arsenal + Dockerfile + proof (flag the rebuild). Follow §0. Tests + safety green, `next build` exit 0, screenshot of `/cache`, README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 5 — Parameter / content discovery:**
> Read `docs/superpowers/specs/2026-08-07-param-content-discovery-spec.md` and build it end to end. Model it on `backend/cockpit/recon.py` — scope-safe by construction; discovered params/endpoints are suggestions handed to intruder/nuclei/repeater, never auto-fired. Watch the `state/parsers.py` urllib ban. Tests + safety green, `next build` exit 0, screenshot of `/recon` (discovery view), README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 6 — JS recon → secrets:**
> Read `docs/superpowers/specs/2026-08-07-js-recon-secrets-spec.md` and build it end to end. Model it on `:recon` — engagement-bound, scope-safe by construction, secrets → loot not finding text. Add the JS-recon toolchain (getjs/LinkFinder/SecretFinder/trufflehog/sourcemapper) to arsenal + Dockerfile + proof (flag the rebuild). Watch the `state/parsers.py` urllib ban. Tests + safety green, `next build` exit 0, screenshot of `/recon`, README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 7 — Cross-domain kill-chain graph (capstone):**
> Read `docs/superpowers/specs/2026-08-07-killchain-graph-spec.md` and build it end to end. It's a read-and-stitch overlay over `adgraph/` + `cloudgraph/` public dicts + web findings — do NOT deep-import either graph (keep them decoupled); reuse the edge-index orchestrator (picks an index, never a command; executes nothing by AST). Follow §0. Tests + safety green, `next build` exit 0, screenshot of `/cockpit/killchain?demo=1`, README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

---

## After each session
- `run_safety_tests.sh` green (known Windows-host exception: `test_redirector.py`, a UDP-port env limit — passes on CI/Linux).
- Commit on `main` with README + screenshot + assessment + regenerated PDF together.
- Image rebuilds (#2 engine, #3 smuggler/h2csmuggler, #4 wcvs, #6 JS toolchain) are your manual `docker build` step — the specs add catalog + Dockerfile + proof.
