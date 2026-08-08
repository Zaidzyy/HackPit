#!/usr/bin/env sh
# Re-verify the Cockpit SAFETY INVARIANTS in one command.
#
# Runs the hermetic safety-layer + composer regression tests (no Docker needed).
# Pass --with-proof to also run the live Docker isolation PROOF (needs the stack up:
#   docker compose -f docker/docker-compose.yml up -d).
#
# Invariants guarded (docs/cockpit-plan.md §c):
#   allowlist (recon-only, no metachars) -> target-lock (lab only) -> approval
#   (explicit) -> isolation (sandbox on internal-only networks). See test_cockpit.py.
#
# GATING. Every test runs through run_test(), which checks the interpreter's exit code
# EXPLICITLY and aborts the suite on the first non-zero. `set -e` below says the same
# thing, and on its own it does gate — but `set -e` is quietly suspended for any command
# in a pipeline, an `if`/`while` condition, or an `&&`/`||` chain, so a later edit as
# innocent as `"$PY" test_x.py | tee log` would disarm it with no visible change in
# output. A suite whose whole job is to prove safety controls fire must not depend on a
# guard that can be switched off by accident, so the check is written out per test and
# the failure is named loudly. A green run means all N files exited 0; there is no path
# on which a failing test still prints "passed".
#
# Usage:
#   sh backend/run_safety_tests.sh              # hermetic tests only
#   sh backend/run_safety_tests.sh --with-proof # + live isolation proof
set -e

cd "$(dirname "$0")"

# Prefer the backend venv interpreter; fall back to PATH python.
PY="${PY:-.venv/Scripts/python.exe}"
[ -x "$PY" ] || PY="$(command -v python3 || command -v python)"

FILES_RUN=0

# run_test <test-file> <description>
run_test() {
  _file="$1"
  _desc="$2"
  echo "== $_desc =="
  if "$PY" "$_file"; then
    FILES_RUN=$((FILES_RUN + 1))
  else
    _status=$?
    echo >&2
    echo "!! SAFETY SUITE FAILED" >&2
    echo "!!   test  : $_file (exit $_status)" >&2
    echo "!!   guards: $_desc" >&2
    echo "!! Aborting: $FILES_RUN file(s) had passed; the rest were NOT run." >&2
    echo "!! NOTHING in this run may be treated as passing." >&2
    exit "$_status"
  fi
}

# FIRST, deliberately. Ten human-only / decoupling locks rest on this scanner, and every one
# of them reports "no offenders" when it is working AND when it is broken. If the scanner
# cannot demonstrate that it catches a planted violation, nothing after this line means much.
run_test test_scans.py "shared source scanner (whole-tree sweep / path allow-lists / AST indirection / can-fail)"

run_test test_css_vocabulary.py "CSS VOCABULARY (every hp-* class a component uses EXISTS in globals.css — tsc, next build and eslint cannot see this, and it has now cost three builds: an invisible :proxy, and a phantom .hp-tn-start behind nine primary buttons)"

run_test test_kb_drift.py "KB DRIFT (the semantic index, the scripts index and the corpus report all still describe the LIVE KB — the scripts index once sat 126 entries stale and nothing noticed / every check has a control / absences reported, never silently green)"

run_test test_attack_path.py "attack-path composer regressions"

run_test test_attack_path_contract.py "/attack-path response contract (no composer field silently stripped / unknown request field refused)"

run_test test_target_substitution.py "target-substitution polish (range rewrite / foreign-host flag / target-lock backstop)"

run_test test_pacing_safety.py "run PACING (grants nothing / rewrite cancels a prevalidated verdict / ENGAGEMENT-ONLY, lab byte-identical / every unpaced path says so and reaches the start event / rate converted into each tool's own unit, never passed through / a subcommand tool's flag lands where it parses, in BOTH rewrites)"

run_test test_cockpit.py "cockpit safety-layer tests (allowlist / target / approval / isolation / order)"

run_test test_prevalidated_gates.py "prevalidated-path gate re-checks (approval AND danger re-checked in all 3 modes)"

run_test test_kali.py ":kali containment tests (human-only / hardcoded-open-container / no-isolation-gate / audit)"

run_test test_exploits.py "CVE -> exploit index (version comparison / tiered ranking / executes nothing)"

# Runs BEFORE the three fingerprint locks, for the same reason test_scans.py runs first: those
# three iterate a corpus that is the live KB locally and a committed projection of it in CI
# (`/data/` is gitignored). This proves the projection is complete, current and verdict-identical
# before anything depends on it — and reports NOT-RUN, loudly, for the checks that need the live KB.
run_test test_kb_fixture.py "KB fixture integrity (complete + current + verdict-identical to the live KB / can-fail)"

run_test test_fingerprint_versions.py "fingerprint self-match (D-A: every corpus fingerprint matches its own stored version / inclusive boundary / can-fail)"

run_test test_fingerprint_norm.py "fingerprint normalisation (D-B: vendor-prefixed banners resolve to the product / Tomcat != httpd / no collision / can-fail)"

run_test test_fingerprint_fallback.py "fingerprint fallback (uncovered services never claim a structured match / word-boundary / can-fail)"

run_test test_search_ranking.py "relevance-first KB ranking (substance-gated tier boost / completeness nudge)"

run_test test_terminal.py "raw PTY terminal containment (human-only / hardcoded open box / sentinel shell untouched)"

run_test test_session_engine.py "named-session ENGINE (Decepticon tmux port: named parallel sessions keep independent cwd / auto interactive-prompt detection flips a fixture session to 'interactive - awaiting input' for msfconsole/sliver/evil-winrm/REPLs / a foreground command past the 60s window is AUTO-BACKGROUNDED and a fast one returns [DONE] inline with its rc / a background completion notifies EXACTLY ONCE then is consumed / kill PRESERVES the session log / output tiers inline<=15K, >15K to scratch, >5M watchdog / wedge + pipe-degradation signatures detected from fixtures with the false cases rejected / unsafe names refused not sanitised)"

run_test test_session_engine_safety.py "named-session ENGINE SAFETY (§0: INPUT IS HUMAN-ONLY -- run_command AND send_input reachable ONLY from the router + this test across the WHOLE tree WITH A PLANTED CONTROL / NO is_input AUTONOMY: the executor/orchestrator/proposer expose no engine hook and import it nowhere / HARDCODED OPEN CONTAINER, the isolated sandbox never appears and no request field carries container/target/shell / NO NEW GATE and no isolation claim -- imports no executor/sandbox/isolation and names no gate symbol / the :kali sentinel stays pty-free AND tmux-free, the engine is a separate tmux surface / input is discrete send-keys, no held stdin writer)"

run_test test_winrm.py "WinRM Windows transport (profile CRUD / routes to WinRM / records mode=windows)"

run_test test_winrm_safety.py "WinRM SAFETY invariants (host-locked / no gate bypass / secret never leaks / no auto-run)"

run_test test_winrm_clixml.py "WinRM CLIXML noise (PROGRESS records stripped so a clean AD run stops reading as a failing one / a GENUINE ERROR still surfaces / warning+verbose+debug survive / an unparseable document is passed through, never swallowed)"

run_test test_secretargs.py "credential redaction in persisted run records (build #9 live-fire finding)"

run_test test_loop.py "orchestrator-loop tests (proposer cannot execute / no :kali path / gate pre-check)"

run_test test_reasoning.py "reasoning copilot (ledger / hypothesis schema / frontier / diagnosis / critic / specialist / retrieval / tier)"

run_test test_substrate.py "substrate coverage (Task 1: landmine!=runs / real-catalog pipeline / static Dockerfile coverage)"

run_test test_session.py "live-session tests (start is GATED / stdin HUMAN-ONLY / mode-bound / recorded)"

run_test test_engagement.py "engagement/report path tests (run recorded + report evidence + scope)"

run_test test_engagement_mode.py "engagement MODE tests (real-target: never-auto-run / explicit entry / no Wall-A gate / no autonomy)"

run_test test_scope.py "program-SCOPE model tests (parse / fail-closed / wildcard+CIDR matching / extraction)"

run_test test_engagement_scope.py "engagement SCOPE tests (in-scope passes / out-of-scope refused / expansion never widens)"

run_test test_governance.py "engagement GOVERNANCE (RoE/ConOps/Deconfliction/OPPLAN: the OPPLAN status STATE MACHINE rejects illegal transitions -- completed+cancelled are terminal, a pending->completed skip is refused, and a rejected transition writes nothing and does not bump the version / documents version on every save and RESET approval on edit, a v0 doc cannot be approved / objective add/expand-to-dotted-children/collapse/delete-with-descendants / technique ids are cleaned not invented / ATT&CK coverage renders a per-tactic grid and counts unmapped ids never dropping them / the RoE-vs-scope check is ADVISORY: an invalid/undeclared scope is FLAGGED and objectives keep mutating -- human approval stays the bound)"

run_test test_governance_safety.py "GOVERNANCE SAFETY (§0: governance.py + killchain.py + governance_draft.py make NO eval/exec/subprocess/socket/HTTP call by AST WITH A CONTROL / the pure data modules import nothing that executes or reaches the network / the drafter's only power is the LLM call (llm.chat/extract_json), never a command it runs / NO NEW GATE: no cockpit/executor/sandbox/orchestrator import and no gate symbol anywhere / GENERATION IS PROPOSE-ONLY: the drafter persists nothing and advances no objective by AST / THE RoE IS A FRAME NOT A VETO: the state machine governs objective status only, governance exposes no command/execute/gate symbol, and the advisory check flags every malformed scope without ever raising)"

run_test test_adgraph.py "AD graph parser + path tests (BloodHound -> graph -> route to Domain Admin)"

run_test test_adcs_graph.py "AD CS ESC1-8 graph tests (certipy find -> certtemplate/certauthority nodes + synthesized composite ESC edges / a low-priv enrollee reaches DA via ESC1 / ESC4+ESC7 two-hop reconfigure-then-abuse / every ESC edge runnable Linux + Windows + carries props / non-vulnerable template is CanEnroll context / BloodHound-only graph unchanged)"

run_test test_adgraph_collector.py "AD collector tests (argv-only / unapproved / scope-locked DC / failure / no exec)"

run_test test_adorch.py "AD orchestration tests (frontier / proposals / synthetic walk to Domain Admin)"

run_test test_adorch_safety.py "AD ORCHESTRATION safety (agent proposes only / never-auto-run / destructive red-confirm)"

run_test test_deleg_tickets.py "UNCONSTRAINED DELEGATION + TICKET FORGING (an unconstrained-delegation host synthesizes a routable TrustedForDelegation edge to Domain Admins and an owned low-priv admin routes AdminTo->host->TrustedForDelegation->DA / its technique carries a Linux krbrelayx path AND a native Rubeus/SpoolSample path, both destructive and both tripping the danger gate / krbrelayx+printerbug+PetitPotam+SpoolSample+Rubeus monitor all trip while Rubeus triage stays clean / GOLDEN is offered on the domain node ONLY once krbtgt is held (DCSync or captured DC TGT) and SILVER on a service node ONLY once its hash is held / NEITHER forging kind is an abusable edge, a graph edge, or a frontier candidate even with everything owned — persistence is never in the route-to-DA search)"

run_test test_adgraph_safety.py "AD graph SAFETY invariants (no exec in adgraph / zero :kali / collector+abuse gated / lab unchanged)"

run_test test_cloudgraph.py "cloud IAM graph tests (ScoutSuite/Prowler JSON -> privesc graph / BFS route to an admin principal / orchestrator edge-index proposal / advance requires an approved exit-0 run)"

run_test test_cloudgraph_safety.py "cloud IAM ORCHESTRATION safety (the model picks an INDEX never a command and an out-of-frontier pick is refused / the orchestrator executes nothing by AST and has zero :kali / never-auto-run: a proposed step submitted unapproved is refused / no second execution path, no batch / inherited-rights edges never acquire a command even from the KB grounder / ENUMERATION ADDS NO GATE: its argv builders execute nothing by AST, start reaches the executor gate before any spawn, approval + red-confirm default FALSE, it is engagement-bound and stop is ungated / lab unchanged)"

run_test test_cloud_imds.py "cloud SSRF→IMDS bridge parser (AWS v1+v2 / role listing / identity doc / Azure managed-identity JWT / GCP SA token+email / a captured body -> an OWNED node with the provider set / THE SECRET NEVER REACHES the finding or the API response / malformed+truncated bodies degrade to warnings, never crash / unknown provider + empty body raise / the IMDS request catalog is per-provider data incl. the IMDSv2 two-step)"

run_test test_killchain.py "CROSS-DOMAIN KILL-CHAIN overlay (three synthetic lane dicts MERGE into one graph with a domain tag + namespaced id on every node / the bridge catalog SYNTHESIZES all five seam kinds from the lane seam-declarations and a seam to a missing node is refused with a warning / BFS ROUTES web SSRF -> cloud ci-deployer -> on-prem SVC-SQL -> Domain Admins, crossing 2 seams over 3 lanes / the orchestrator returns an INDEX resolving to the real seam edge's KB/catalog crossing command, a within-lane hop DEFERS to its :cloud/:ad-graph view, an out-of-frontier pick is refused / advance moves the chain ONLY on an approved exit-0 run for a cross-domain hop and on the operator's word for a within-lane one)"

run_test test_killchain_safety.py "CROSS-DOMAIN KILL-CHAIN SAFETY (the model picks an INDEX never a command and an out-of-frontier pick is refused, a smuggled command field ignored / the orchestrator + service execute nothing by AST and have zero :kali / never-auto-run: a proposed seam step submitted unapproved is refused / advance is evidence-gated in source and the three routes execute nothing by AST with no run/batch path / READ-AND-STITCH: NO killchain module imports adgraph or cloudgraph -- it consumes public dicts, decoupling preserved -- and every overlay module executes nothing by AST WITH A POSITIVE CONTROL / lab unchanged)"

run_test test_detection.py "detection footprint tests (matching / ATT&CK / grounded+ai_suggested / tagging / report)"

run_test test_detection_safety.py "detection SAFETY invariants (no exec / read-only / cockpit untouched / describes-not-evades)"

run_test test_context_channel.py "Channel-2 context grounding (Channel-1 filters unchanged / leak guard / no-op / budget)"

run_test test_codescan.py ":code scan tests (normalisation / malformed output / merge / KB links / report)"

run_test test_codescan_safety.py ":code scan SAFETY invariants (static-only / orthogonal / bounded / read-only)"

run_test test_codescan_rules.py ":code scan bundled rules + ruleset picker (multi-language coverage / resolver)"

run_test test_ai_audit.py "AI code-audit fan-out (enumerate -> flows -> per-flow verify composes / a non-concrete claim is DOWNRANKED to a stub, never a finding / dedup collapses the same bug found via two flows / ranking is IMPACT_LEVELS worst-first / informational maps to state 'info' / patched-since audits ONLY the diff and an empty diff scans nothing and warns / the deterministic heuristic analyst maps 6 sample routes to 6 enclosing-route findings)"

run_test test_ai_audit_safety.py "AI code-audit SAFETY (§0: THE PROPOSER EXECUTES NOTHING -- ai_audit + routes make no eval/exec/subprocess/socket/HTTP call by AST, WITH A CONTROL that plants one / it reads source + calls the injected LLM agent, power from reading not running / NO NEW GATE: codescan imports no cockpit/executor/state and references no gate symbol, and the only launchable program is still runner._spawn's semgrep/bandit, exactly once / PoC IS DATA, approve-each, never auto-run / patched-since diff is INJECTED so codescan runs no git itself / persistence is an INJECTED sink so the engine imports no state / rule-mode scan unchanged)"

run_test test_web3_audit.py "WEB3 smart-contract audit playbooks (the three playbooks -- evm-external-flow / cosmos-abci-halt / anchor-solana -- register + language-scope, and each fans out over its bundled fixture into the EXPECTED concrete findings-or-stubs tagged with chain/contract/function, NO LLM: evm surfaces reentrancy/access-control/oracle loss-of-funds; cosmos maps the four panic classes to real ABCI methods as consensus-halts; anchor surfaces missing-owner/signer-spoof/overflow/CPI-confusion / a slither/mythril/echidna fixture output PARSES into normalized findings / the tool pass is PROPOSE-ONLY: approve-each command strings, never a run / KB grounding cites a web3 methodology entry / the router surfaces the playbook list, the per-playbook sample and the tool-pass proposal)"

run_test test_finding_pipeline.py "FINDING PIPELINE (dynamic schema validates a well-formed finding + rejects a malformed one, and is DYNAMIC -- custom fields declared, unknown keys preserved in extra / dedup is IDEMPOTENT: the same finding twice collapses to one 'merged 1' and a re-run over its own output is a fixed point that never re-inflates / different wordings of the same bug at the same file:line collapse while two distinct hosts do not / bug-bounty-payout and compliance rankers re-score the SAME fixture DIFFERENTLY and worst-first -- the missing-header the payout view sends to info is a medium control gap under compliance, which also caps a raw critical / validate + report post-scripts run IN-PROCESS / the PoC post-script is APPROVE-EACH: proposal only, executed:false / a concurrent double-run on one finding is refused by the lock)"

run_test test_finding_pipeline_safety.py "FINDING PIPELINE SAFETY (§0: the findings/ package EXECUTES NOTHING -- no eval/exec/compile/subprocess/socket/HTTP by AST, WITH A CONTROL that plants one / NO NEW GATE: it imports no cockpit/executor/engagement/sandbox/state/attack_path and names no gate symbol -- the dict->Finding bridge and the command-post-script->executor coupling live in the app layer / a COMMAND post-script is approve-each end to end: proposal, needs_approval, executed:false, never fired by the module OR the route / THE 3-SCHEMA-PLACES RULE: the structured fields survive BOTH the state route and the pipeline route, so no response_model strips them / persisting the pipeline collapses duplicates and stays idempotent -- the finding count never grows)"

run_test test_workflows.py "WORKFLOW BUILDER (open·kritt ported: {{repo}} + dotted {{steps.<id>.output...}} refs + per-run extra vars resolve and a miss renders empty / a batch step runs ONE task per item and siblings multiply, an empty list no-ops / depth=2 over a 2->2 expansion produces the 2/4/8 child-step shape, all bounded by MAX_SIBLINGS + the task ceiling / a workflow round-trips export->import with only the provenance flag flipping to inspect-before-run / a step output validates against BOTH the default finding-or-stub schema and a declared custom schema / the runner threads a step's output into the downstream prompt and same-bug siblings dedup+rank to one / a command step PROPOSES a rendered string and calls no agent / plan() computes the static fan-out shape without running / a forward batch reference is refused at build time)"

run_test test_workflows_safety.py "WORKFLOW BUILDER SAFETY (§0: AUTHORING EXECUTES NOTHING — create/edit/export/import/delete touch no agent, proven with a recording agent that fires ONLY on a real run / workflows.py + the routes make no eval/exec/subprocess/socket/HTTP call by AST WITH A PLANTED CONTROL / NO NEW GATE: codescan imports no cockpit/executor/state/sandbox and names no gate symbol, and the only launchable program is still runner._spawn's semgrep/bandit exactly once / A COMMAND STEP IS APPROVE-EACH: a proposal string, executed:false, no agent call / AN IMPORTED WORKFLOW IS NEVER AUTO-RUN: import stores it flagged inspect-before-run and runs nothing, only an explicit run fires WITH A CONTROL / a built-in is read-only and the store's version lock refuses a stale edit)"

run_test test_arsenal.py "tool arsenal tests (catalog / lookup / target-faithful render / provenance tags)"

run_test test_arsenal_safety.py "tool arsenal SAFETY invariants (executes nothing / NO gate bypassed / gates unchanged)"

run_test test_phase1_runtime.py "Phase-1 runtime (timeout clamp / background jobs / loot / tool reconciliation)"

run_test test_state.py "Phase-2 state (parsers / upserts / task tree / prompt grounding / executes-nothing)"

run_test test_zap.py "ZAP report parser (report dug out of progress noise / 4 risk codes / registry keys match program_name's .py spelling / -zap.json does not claim every json / detection covers the names that run)"

run_test test_zap_safety.py "ZAP gating split (active fires + passive does not, with both controls / verdict survives every spelling / proxychains cannot launder it / COMMAND and SCRIPT heuristics agree / EACH FLAG STATES ITS OWN REASON — -daemon no longer claims it sends injection payloads — and the script heuristic derives the reason, not just the flag / every attack flag is declared a real flag or a declared marker)"

run_test test_zap_proxy.py "ZAP recording proxy history (REAL captured message -> exchange / malformed response keeps the request / bodies stay RAW / endpoints + params / report redaction with a control / routes registered, history GET-only)"

run_test test_zap_proxy_safety.py "ZAP recording proxy GATING (approval + red-confirm with controls / gated argv == spawned argv / loopback by default and 0.0.0.0 ONLY when publish was asked for / publish is engagement-only / THE API KEY IS ENFORCED, absent from the gate surface and redacted in the record, with a control / lab declares the lab, engagement declares nothing / no stdin writer / gate before spawn / stop ungated / AJAX SPIDER: every crawl gate fires, the confirm states the BROWSER hazard not the scanner's, the scoped host is the crawled host, a target carrying '&' cannot set a crawl parameter, depth+duration are in the approved surface, the browser id is read BACK because an OK is not a result)"

run_test test_zap_scan.py "ZAP active-scan mapping (REAL API response -> alerts / High lands as high, not info / plugin ref matches parse_zap so one issue fingerprints once / attacked param survives as an endpoint / malformed never raises / THE REPORT PARSER AND THIS MAPPER ARE NOT INTERCHANGEABLE, with a control / RUNNING+PAUSED block a second scan, STOPPED does not)"

run_test test_zap_scan_safety.py "ZAP active-scan GATING (approval + red-confirm + off-lab target, each with a control / THE SCOPED HOST IS THE ATTACKED HOST / a target carrying '&recurse=true' cannot broaden the scan / non-http refused at construction / gate before ZAP is contacted / concurrency bound read from ZAP not local state / stop ungated / the action URL is built once and reached only from the gated start)"

run_test test_zap_scan_ingest.py "ZAP alert ingest ROUTE end-to-end (POST -> mapper -> SQLite -> read back, against a TEMP db so the operator's store is untouched / re-ingesting does not duplicate / scoped to one session / no session_id is a 422 not a silent no-op / the route executes nothing, by AST)"

run_test test_scope_hostcheck.py "Phase-3 scope host-check (no false-reject of files/versions; real hosts still caught)"

run_test test_credvault.py "Phase-3 credential vault (fills user/pass/hash/domain; wrong-kind + non-cred left alone)"

run_test test_corpora.py "Phase-4 corpus ingest (additive/byte-preserving/idempotent; no_merge; windows marked)"

run_test test_repeater.py "Phase-4 HTTP repeater (hardcoded container / argv-only / human-only / scope-checked)"

run_test test_lifecycle_safety.py "listener lifecycle SAFETY invariants (no stdin writer / status observed, never assigned)"

run_test test_tunnels.py "Phase-4 pivot/tunnels (human-only lifecycle / pure rewrite-before-approval / scope-by-hand)"

run_test test_report_templates.py "Phase-4 exam report templates (proof-flag capture / per-host table / CVSS 3.1 / template select)"

run_test test_scan_session_health.py "authenticated-scan SESSION EXPIRY (an expired session reports ZERO findings, which reads as 'the app is secure' — all four expiry shapes caught / a healthy scan NOT flagged / too little traffic is 'unknown', never 'ok' / the warning reaches the report / the detector only reads)"

run_test test_submission_fields.py "bug-bounty SUBMISSION fields (VRT priority is a LOOKUP, never derived from the CVSS score / a real CVSS-vs-VRT disagreement is surfaced / the known-issue check FLAGS and never suppresses, with the finding list proven unmutated / a zero-match run still reports that it ran)"

run_test test_sliver.py "Sliver C2 containment (human-only server lifecycle / GATED implant gen / <listener> verbatim)"

run_test test_sliver_safety.py "Sliver C2 SAFETY invariants (no agent path / gated-vs-human-only split / never executes what it builds)"

run_test test_obfuscation.py "DNS-tunnel obfuscation containment (human-only listener / client one-liner never delivered)"

run_test test_obfuscation_safety.py "DNS-tunnel SAFETY invariants (no agent path / one-liner never delivered / secret never crosses HTTP)"

run_test test_evasion.py "evasion engine (generate-only / gated / forced honest footprint)"

run_test test_evasion_safety.py "evasion engine SAFETY invariants (no agent path / never runs what it builds / footprint has no off switch)"

run_test test_exposure_safety.py "published-port exposure invariants (default publishes nothing / every bind IP-bound or acknowledged)"

run_test test_exposure.py "listener profiles (bind gates / ack rendering / observed state / vmnet8 preset equivalence)"

run_test test_proof_honesty.py "proof-harness HONESTY (an unfilled offensive slot reports NOT-RUN, never a fake pass)"

run_test test_home_summary.py "/home-summary launcher rail (no secret reaches the browser / status endpoint executes nothing)"

run_test test_operator.py "operator identity (config gitignored in a PUBLIC repo / OSID+email never reach the browser)"

run_test test_oob_tokens.py "OOB canary tokens (DNS-label-safe / CSPRNG / correlates to the step / executes nothing)"

run_test test_oob_server.py "OOB canary server (answers not NXDOMAIN / authenticated append-only reads / no execution, no forwarding)"

run_test test_oob_poll.py "OOB poll client + state ingest (correlation kept / nothing dropped / cursor monotonic / no redirect followed / poll_all sweeps both backends and isolates a backend failure)"
run_test test_oob_interactsh.py "OOB interact.sh backend (real RSA-OAEP+AES-CFB round-trip / secrets write-only / no redirect + no ambient proxy / suffix correlation / dedup by uid+timestamp / uncorrelated hit kept)"
run_test test_oob_autopoll.py "OOB auto-poll (setting round-trips with a floored interval / tick sweeps via poll_all with ALL sessions / read-only: reaches no execution or delivery surface)"
run_test test_oob_router.py "OOB router dual-backend surface (GET /oob carries both backends + autopoll / register / mint renders only configured backends / mint refused with no backend / autopoll floored)"

run_test test_oob_templates.py "OOB payload templates (token left of the zone per the server's own parser / renders and stops)"

run_test test_oob_deploy_safety.py "OOB deploy SAFETY invariants (signature carries NO destination / no agent path / refusal sends nothing / secret never in an argv)"
run_test test_oob_interactsh_safety.py "OOB interact.sh SAFETY invariants (no execution/delivery surface / no backend coupling to the repeater / poll refuses redirects + ambient proxy / session secrets never a key in the public view)"

run_test test_redirector.py "C2 redirector (LIVE loopback forward both ways / the two ends agree on the tunnel port / UDP gets socat, never a bogus ssh -R)"

run_test test_redirector_safety.py "C2 redirector SAFETY invariants (one loopback destination / no name resolution / remote ack unconditional / paths never half-mix)"

run_test test_bypass_header.py "WAF-bypass header (value on stdin only / never on a model or an argv / cleared before the kill)"

run_test test_shaping.py "payload shaping (markers stripped as the control / the SHAPED url is the scoped url / no gate anywhere)"

run_test test_auth_scan.py "scan policy + authenticated scanning (baseline-then-read-back / no password field exists / additive scan URL)"

run_test test_fronting.py "CDN fronting + the silent-empty sweep (unknown is a real answer / an unreadable read is not a zero)"

run_test test_cookiejar.py "repeater COOKIE JAR (the disclosure has NO value field, with a control / a cross-domain Set-Cookie is refused storage / host-only stays on its host / dot-anchored domains / an expired cookie DELETES / the operator's own Cookie wins and the suppression is named / ONE Cookie header on the wire, never two / no cookie reaches the run record, which report.py renders verbatim / no gate field, and the jar refuses nothing)"

run_test test_intercept.py "INTERCEPTION + history filtering (http-all is the only break type / 'held' from the MESSAGE, never the isBreakRequest SETTING / A DROP WITH NOTHING HELD WEDGES THE DAEMON, so neither release nor panic can send one / panic drops BEFORE switching off / continue stops breaking and step does not / an unreadable daemon is not a False, with a control / NO GATE on any intercept route / filter: 4 means 4xx, the host filter is the scope parser, has_param None is BOTH, and the scan walks the whole capture with truncated never silently false)"

run_test test_intruder.py "INTRUDER (the four gates each fire WITH A CONTROL and the ack clears danger / THE WHOLE PAYLOAD SET IS IN THE APPROVED SURFACE, so one carrying '| sh' at position 200 still trips the gate / sniper keeps the other positions BASELINE / the baseline request is sent FIRST / per-request scope check on the SUBSTITUTED url / the ceiling CAPS AND REPORTS rather than refusing / stop ungated / the run record carries no payloads / A PLAIN ffuf STILL NEEDS NO RED-CONFIRM -- this build added no confirm)"

run_test test_race.py "SINGLE-PACKET RACE (the four gates each fire WITH A CONTROL and the ack clears danger / THE WHOLE REQUEST + N ARE IN THE APPROVED SURFACE, so a body carrying '| sh' still trips the gate and nothing is truncated / both transports h2-single-packet + h1-last-byte build a complete surface / the engine runs argv-only with the request on STDIN, container is a code constant / scope is checked on the WIRE url BEFORE the batch fires and an off-scope host refuses all N / the ceiling CAPS AND REPORTS / an unknown mode falls back and says so / THE VERDICT flags a >1-winner cluster and ignores a lone winner + error rows / a confirmed race becomes a high Finding / stop ungated / the run record carries no body/headers / A PLAIN race STILL NEEDS NO RED-CONFIRM -- this build added no confirm)"

run_test test_smuggle.py "REQUEST SMUGGLING / DESYNC (the four gates each fire WITH A CONTROL and the ack clears danger / the argv carries the exact mutation set + stage, complete so a body carrying '| sh' still trips the gate, and mutations ride dot-free so a dotted CL.TE is not read as a host / DETECTION is safe-by-default timing-differential and CONFIRMATION is a SEPARATE self-approved stage carrying the co-tenant warning, pinned per route, and an unknown stage falls back to detect NEVER escalates / the engine runs argv-only with the request on STDIN, container is a code constant / scope is checked on the WIRE url BEFORE the sweep and an off-scope host refuses every mutation / a timing set becomes per-mutation verdicts with the threshold pinned and error rows excluded, and a smuggler.py transcript maps its hits too / a susceptible detection is a High Finding and a confirmed desync is Critical / stop ungated / the run record carries no body/headers / A PLAIN smuggle STILL NEEDS NO RED-CONFIRM -- this build added no confirm)"

run_test test_cache.py "WEB CACHE POISONING / DECEPTION (the four gates each fire WITH A CONTROL and the ack clears danger / the argv carries the exact candidate-input set + stage + --deception, complete so a body carrying '| sh' still trips the gate / DETECTION is safe-by-default reflection+cacheability and plants NOTHING, CONFIRMATION is a SEPARATE self-approved poison-plant stage carrying the co-user warning, pinned per route, and an unknown stage falls back to detect NEVER escalates / the engine runs argv-only with the request on STDIN, container is a code constant / scope is checked on the WIRE url BEFORE the sweep and an off-scope host refuses every input / reflected AND cacheable becomes a candidate with error rows excluded, a dynamic page cached under a static path is a deception hit, and a wcvs transcript maps its hits too / a candidate/deception is a High Finding and a confirmed poisoning is Critical / stop ungated / the run record carries no body/headers / A PLAIN cache probe STILL NEEDS NO RED-CONFIRM -- this build added no confirm)"

run_test test_credattack.py "CREDENTIAL attack planner (hash-mode detection: NTLM/SHA/bcrypt/kerberoast/AS-REP/NetNTLMv2, a miss is a miss not a wrong guess / spray argv is netexec with user+pass FILES and NO secret on the line / kerberos uses kerbrute and fills the realm via credvault / crack argv is hashcat -m <mode> with the hash in a file and the pot disabled / plan_crack groups by mode and skips plaintext / netexec [+] -> validated cred, [-] and informational dropped / hashcat hash:plain maps back to the SUBMITTED hash, case-folded and colon-safe, recovering the ACCOUNT not just the plaintext / a crack keeps the NT hash and adds a password)"

run_test test_credattack_safety.py "CREDENTIAL attack SAFETY (credattack.py EXECUTES NOTHING by AST / both start paths reach executor.validate_request via _gate before spawning / an unapproved spray is refused at the approval gate WITH A CONTROL / a crack is target-less so lab refuses it and an engagement is required / NO SECRET on the spray or crack argv — user/pass/hash lists go to loot files / both workers write those files before building the argv / approval + red-confirm default FALSE so an omitted field is refused / stop() is ungated)"

run_test test_nuclei.py "nuclei surface (argv: -u per target + -jsonl/-duc, severity filter drops a bogus value, tags/-t/-rate-limit / default target set SEEDS from state endpoints and an empty session WARNS rather than scanning nothing / JSONL -> Finding maps name/severity/matched-at/template-id/evidence, DEDUPES by (template-id, matched-at) and ranks most-severe first / parse_template_list counts installed templates)"

run_test test_nuclei_safety.py "nuclei SAFETY (THIS BUILD ADDS NO GATE: the pure half builds argv + parses JSON only by AST / start AND validate reach executor.validate_request via _gate BEFORE any sandbox resolution or spawn / every target rides as -u where the handrail reads it / LAB refuses a non-lab target at the target gate WITH A CONTROL and an unapproved scan at the approval gate WITH A CONTROL / approval + red-confirm default FALSE / stop() is ungated)"

run_test test_recon.py "guided recon surface (subfinder/dnsx/naabu/url-lister parsers -> Host/Service/Endpoint with query param NAMES mined not values / filter_in_scope keeps in-scope + drops/collects out-of-scope WITH A CONTROL / rank_surface orders a session's state by likely-exploitable — services + CVE-worthy stack + param-rich + auth surface + findings — states the WHY, hands off to nuclei, and is DETERMINISTIC)"

run_test test_recon_safety.py "recon SAFETY (THIS BUILD ADDS NO GATE: the argv builders + filter_in_scope + rank_surface execute nothing by AST / start_passive AND start_active reach executor.validate_request via _gate BEFORE any spawn / recon is ENGAGEMENT-BOUND — no engagement is refused / RECON CAN NEVER WIDEN BEYOND SCOPE: an out-of-scope discovery enters neither the allowed set nor the scanner's host file, end to end WITH A CONTROL / approval + red-confirm default FALSE / stop() is ungated)"

run_test test_discover.py "PARAMETER / CONTENT DISCOVERY (arjun/feroxbuster output -> Endpoint rows with discovered param/path NAMES not values, both arjun JSON shapes / per-mode argv: arjun -u <url> -m, ffuf gets a FUZZ keyword, paramspider is -d <domain> / THE CONTENT WORD LIST IS IN THE GATE SURFACE WHOLE — every word incl. one carrying '| sh', intruder-style, nothing truncated / filter_endpoints_in_scope keeps in-scope + drops/collects out-of-scope WITH A CONTROL / a discovered param yields a valid [[FUZZ]] intruder position + nuclei/repeater hand-offs / only interesting discoveries — an admin endpoint, a debug param — become low findings, boring ones do not)"

run_test test_discover_safety.py "discover SAFETY (THIS BUILD ADDS NO GATE: the argv builders + filter_endpoints_in_scope + gate_argv + findings + _mark_param execute nothing by AST / start AND validate reach executor.validate_request via _gate BEFORE any spawn / discovery is ENGAGEMENT-BOUND — no engagement is refused / TARGET SCOPE-LOCKED BY CONSTRUCTION: an out-of-scope target url is refused before the gate/spawn and an in-scope one passes WITH A CONTROL, and filter_endpoints_in_scope drops an out-of-scope discovery WITH A CONTROL / approval + red-confirm default FALSE / stop() is ungated)"

run_test test_jsrecon.py "JS RECON -> SECRETS/ENDPOINTS (the in-repo js-mine engine mines a JS blob: relative endpoints RESOLVE TO THE JS ORIGIN so they are scope-checkable, absolutes kept, param NAMES + AWS/Stripe/generic secrets found, and a .map recovers original source paths + comments / collect resolves every <script src> to absolute / parse_mine_output splits the engine JSON into Endpoint rows via parse_jsmine + secret dicts w/ source + source maps / filter_urls_in_scope AND filter_endpoints_in_scope keep in-scope + drop/collect out-of-scope WITH CONTROLS / A SECRET -> a Finding carrying TYPE+source+MASKED+loot path and NEVER the value, verified High + unverified Low, and the value is written ONLY to the loot file / gate_argv names js-mine + every operator host as -u)"

run_test test_jsrecon_safety.py "jsrecon SAFETY (THIS BUILD ADDS NO GATE: the argv/job-spec builders + both scope filters + parse_mine_output + the secret-finding builder execute nothing by AST / start AND validate reach executor.validate_request via _gate BEFORE any spawn / JS recon is ENGAGEMENT-BOUND — no engagement is refused / TARGET + NAMED JS URL SCOPE-LOCKED BY CONSTRUCTION: an out-of-scope target or js url is refused before the gate/spawn and an in-scope one passes WITH A CONTROL, and BOTH scope filters drop an out-of-scope URL WITH A CONTROL / A SECRET VALUE NEVER REACHES A FINDING with a PLANTED CONTROL but IS written to loot / approval + red-confirm default FALSE / stop() is ungated)"

run_test test_mcp_safety.py "MCP server THE LINE (every exposed tool enumerated: NONE can set an approval field at any depth, NONE has an open schema, NONE reaches an execution path -- each with a POSITIVE CONTROL that plants a violation and proves it is caught / an UNAUDITABLE handler is an offence, not a pass / exactly one write-shaped tool and it queues without running / approving a proposal executes nothing / the gate preview asks with both flags FALSE / the registry imports no MCP SDK so this runs in CI / the server REFUSES TO START on a violating surface)"

run_test test_graphql.py "GRAPHQL detection + round trip (recognised by BODY SHAPE not by path, with a control both ways / all four envelopes: json body, json BATCH, ?query= and application/graphql / arguments named field.argument, which is the spelling ZAP puts in its alerts / an ALIAS reports the real field / braces and # inside a string are not syntax / A MALFORMED OPERATION IS STILL GRAPHQL -- the envelope decides / a captured body splits and rebuilds byte-equal / one that will not split is kept RAW and says why / bad variables build NOTHING rather than something plausible / disabled vs http_error vs empty vs unparseable are four answers, because ZAP cannot tell them apart / the scan plan names the arguments and REQUIRES recurse)"

run_test test_graphql_safety.py "GRAPHQL containment (THIS BUILD ADDS NO GATE: a GraphQL scan is refused at the approval, danger and target gates IN TURN -- named per gate, because gate ORDER makes an off-lab control pass vacuously / six new routes reach no execution path, by AST / NO ARGUMENT VALUE reaches any model, endpoint record or detection result -- a GraphQL argument is routinely a token / the new modules never touch repeater.send / cockpit/graphql.py imports nothing that executes, by AST not substring / AN OUT-OF-SCOPE PROBE WARNS AND IS SENT and the warner cannot raise / a negative depth warns and is applied / SchemaImport.scannable is always False and carries the measured reason / the GraphQL filter is three-state and defaults to matching everything)"
run_test test_tokens.py "TOKEN WORKBENCH (JWT/OAuth/SAML analysis + tamper: a JWT decodes into header/claims/verdicts and an opaque string says why / alg=none strips the signature with the chosen case variant / RS256->HS256 confusion signs with the pasted PUBLIC key as the HMAC secret, recomputed from scratch / kid + jwk/jku/x5u injections land in the header and an unknown field builds NOTHING / edit-and-resign changes a claim and re-signs, bad claims JSON builds nothing / an AUTO-DETECTED token carries header params + claim NAMES + the non-secret timing claims, NEVER a claim value or the signature, found by SHAPE in Authorization/cookie/query/body / OAuth parses with PKCE seen and a callback reports its credential by NAME, redirect_uri/drop_state/PKCE-downgrade builders emit mutated requests / SAML parses + locates the signature on the assertion-vs-response and flags an unsigned one, and XSW1-8 + strip/comment/unsigned all produce WELL-FORMED, round-tripping XML)"

run_test test_tokens_safety.py "TOKEN WORKBENCH SAFETY (THIS BUILD ADDS NO GATE: cockpit/tokens.py imports nothing that executes and calls nothing that does, by AST WITH A PLANTED CONTROL / the pure core WARNS via a note and RAISES NOTHING -- a later tightening into a refusal is the regression / NAMES NEVER VALUES: TokenDetection cannot hold claims/signature/value and a secret in a claim value never reaches the serialized model -- a JWT claim is routinely a secret / THE REPEATER STAYS HUMAN-ONLY: the pure core imports no repeater and neither module references .send / THE CRACK IS THE ORDINARY GATED JOB: validate + start_crack reach executor.validate_request BEFORE the spawn (the _gate call precedes the Thread), approval + red-confirm default FALSE, it is engagement-bound and refuses with no engagement, and NO secret rides the argv -- the token goes to a loot file / stop() reaches no gate / the 8 decode/detect/tamper/oauth/saml/crack-preview routes reach no execution path by AST)"

run_test test_graphql_enum.py "GRAPHQL FIELD-SUGGESTION ENUMERATION (a parser per error-producing CORE, not per server brand -- Apollo IS graphql-js and Graphene sits on graphql-core / THE MEASUREMENT THAT JUSTIFIES IT: graphql-core is NOT byte-identical to graphql-js, it single-quotes where graphql-js double-quotes, so the parser everybody writes first returns ZERO against every Python GraphQL server and that looks exactly like a hardened one / a wrong-dialect message reads not_this_error and NEVER no_suggestion, so it cannot masquerade as a working defence / graphql-php and gqlparser ARE identical, from source, and share the parser while keeping their own fixtures / graphql-ruby backticks inside parentheses with NO Oxford comma where graphql-js has one / FIVE OUTCOMES and four of them are an empty list from a naive implementation: productive, suggestions_disabled (a DEFENCE), suggestions_unsupported (the core has no such feature), engine_unknown, failed / the dialect survives the JSON envelope it actually arrives in, which double-quoted cores do not without unescaping / a five-suggestion response is recorded as CUT OFF, not complete / bounds DESCRIBE the run and never refuse, and a stopped run keeps what it found / provenance says MINED, never introspected)"
if [ "$1" = "--with-proof" ]; then
  echo
  echo "== live Docker isolation PROOF (lab — must exit 0) =="
  sh ../docker/proof/isolation_proof.sh
  echo
  echo "== live Docker FULLY-OPEN proof (engagement — Wall A down, full reach — must exit 0) =="
  sh ../docker/proof/engage_open_proof.sh
  # Binds real sockets (udp/5353 + an ephemeral tcp port on loopback), which is why it is a
  # proof and not a hermetic test. It needs no Docker and no network beyond 127.0.0.1, and
  # it reports the two public-reachability checks as NOT-RUN until a VPS and zone exist.
  echo
  echo "== OOB canary LOOPBACK end-to-end proof (real sockets, no infrastructure — must exit 0) =="
  "$PY" ../docker/proof/oob_loopback_proof.py
  # Same shape: real sockets, no Docker, nothing beyond 127.0.0.1. A redirector relaying
  # 127.0.0.1:A -> 127.0.0.1:B IS the whole mechanism; only public reachability is NOT-RUN.
  echo
  echo "== C2 redirector LOOPBACK end-to-end proof (real sockets, no VPS — must exit 0) =="
  "$PY" ../docker/proof/redirector_loopback_proof.py
else
  echo
  echo "Hermetic safety tests passed ($FILES_RUN test files, every one exited 0)."
  echo "To also run the live isolation proof (needs the stack up):"
  echo "  sh backend/run_safety_tests.sh --with-proof"
fi
