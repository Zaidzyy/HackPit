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

run_test test_adgraph.py "AD graph parser + path tests (BloodHound -> graph -> route to Domain Admin)"

run_test test_adgraph_collector.py "AD collector tests (argv-only / unapproved / scope-locked DC / failure / no exec)"

run_test test_adorch.py "AD orchestration tests (frontier / proposals / synthetic walk to Domain Admin)"

run_test test_adorch_safety.py "AD ORCHESTRATION safety (agent proposes only / never-auto-run / destructive red-confirm)"

run_test test_adgraph_safety.py "AD graph SAFETY invariants (no exec in adgraph / zero :kali / collector+abuse gated / lab unchanged)"

run_test test_cloudgraph.py "cloud IAM graph tests (ScoutSuite/Prowler JSON -> privesc graph / BFS route to an admin principal / orchestrator edge-index proposal / advance requires an approved exit-0 run)"

run_test test_cloudgraph_safety.py "cloud IAM ORCHESTRATION safety (the model picks an INDEX never a command and an out-of-frontier pick is refused / the orchestrator executes nothing by AST and has zero :kali / never-auto-run: a proposed step submitted unapproved is refused / no second execution path, no batch / inherited-rights edges never acquire a command even from the KB grounder / ENUMERATION ADDS NO GATE: its argv builders execute nothing by AST, start reaches the executor gate before any spawn, approval + red-confirm default FALSE, it is engagement-bound and stop is ungated / lab unchanged)"

run_test test_cloud_imds.py "cloud SSRF→IMDS bridge parser (AWS v1+v2 / role listing / identity doc / Azure managed-identity JWT / GCP SA token+email / a captured body -> an OWNED node with the provider set / THE SECRET NEVER REACHES the finding or the API response / malformed+truncated bodies degrade to warnings, never crash / unknown provider + empty body raise / the IMDS request catalog is per-provider data incl. the IMDSv2 two-step)"

run_test test_detection.py "detection footprint tests (matching / ATT&CK / grounded+ai_suggested / tagging / report)"

run_test test_detection_safety.py "detection SAFETY invariants (no exec / read-only / cockpit untouched / describes-not-evades)"

run_test test_context_channel.py "Channel-2 context grounding (Channel-1 filters unchanged / leak guard / no-op / budget)"

run_test test_codescan.py ":code scan tests (normalisation / malformed output / merge / KB links / report)"

run_test test_codescan_safety.py ":code scan SAFETY invariants (static-only / orthogonal / bounded / read-only)"

run_test test_codescan_rules.py ":code scan bundled rules + ruleset picker (multi-language coverage / resolver)"

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

run_test test_credattack.py "CREDENTIAL attack planner (hash-mode detection: NTLM/SHA/bcrypt/kerberoast/AS-REP/NetNTLMv2, a miss is a miss not a wrong guess / spray argv is netexec with user+pass FILES and NO secret on the line / kerberos uses kerbrute and fills the realm via credvault / crack argv is hashcat -m <mode> with the hash in a file and the pot disabled / plan_crack groups by mode and skips plaintext / netexec [+] -> validated cred, [-] and informational dropped / hashcat hash:plain maps back to the SUBMITTED hash, case-folded and colon-safe, recovering the ACCOUNT not just the plaintext / a crack keeps the NT hash and adds a password)"

run_test test_credattack_safety.py "CREDENTIAL attack SAFETY (credattack.py EXECUTES NOTHING by AST / both start paths reach executor.validate_request via _gate before spawning / an unapproved spray is refused at the approval gate WITH A CONTROL / a crack is target-less so lab refuses it and an engagement is required / NO SECRET on the spray or crack argv — user/pass/hash lists go to loot files / both workers write those files before building the argv / approval + red-confirm default FALSE so an omitted field is refused / stop() is ungated)"

run_test test_nuclei.py "nuclei surface (argv: -u per target + -jsonl/-duc, severity filter drops a bogus value, tags/-t/-rate-limit / default target set SEEDS from state endpoints and an empty session WARNS rather than scanning nothing / JSONL -> Finding maps name/severity/matched-at/template-id/evidence, DEDUPES by (template-id, matched-at) and ranks most-severe first / parse_template_list counts installed templates)"

run_test test_nuclei_safety.py "nuclei SAFETY (THIS BUILD ADDS NO GATE: the pure half builds argv + parses JSON only by AST / start AND validate reach executor.validate_request via _gate BEFORE any sandbox resolution or spawn / every target rides as -u where the handrail reads it / LAB refuses a non-lab target at the target gate WITH A CONTROL and an unapproved scan at the approval gate WITH A CONTROL / approval + red-confirm default FALSE / stop() is ungated)"

run_test test_recon.py "guided recon surface (subfinder/dnsx/naabu/url-lister parsers -> Host/Service/Endpoint with query param NAMES mined not values / filter_in_scope keeps in-scope + drops/collects out-of-scope WITH A CONTROL / rank_surface orders a session's state by likely-exploitable — services + CVE-worthy stack + param-rich + auth surface + findings — states the WHY, hands off to nuclei, and is DETERMINISTIC)"

run_test test_recon_safety.py "recon SAFETY (THIS BUILD ADDS NO GATE: the argv builders + filter_in_scope + rank_surface execute nothing by AST / start_passive AND start_active reach executor.validate_request via _gate BEFORE any spawn / recon is ENGAGEMENT-BOUND — no engagement is refused / RECON CAN NEVER WIDEN BEYOND SCOPE: an out-of-scope discovery enters neither the allowed set nor the scanner's host file, end to end WITH A CONTROL / approval + red-confirm default FALSE / stop() is ungated)"

run_test test_mcp_safety.py "MCP server THE LINE (every exposed tool enumerated: NONE can set an approval field at any depth, NONE has an open schema, NONE reaches an execution path -- each with a POSITIVE CONTROL that plants a violation and proves it is caught / an UNAUDITABLE handler is an offence, not a pass / exactly one write-shaped tool and it queues without running / approving a proposal executes nothing / the gate preview asks with both flags FALSE / the registry imports no MCP SDK so this runs in CI / the server REFUSES TO START on a violating surface)"

run_test test_graphql.py "GRAPHQL detection + round trip (recognised by BODY SHAPE not by path, with a control both ways / all four envelopes: json body, json BATCH, ?query= and application/graphql / arguments named field.argument, which is the spelling ZAP puts in its alerts / an ALIAS reports the real field / braces and # inside a string are not syntax / A MALFORMED OPERATION IS STILL GRAPHQL -- the envelope decides / a captured body splits and rebuilds byte-equal / one that will not split is kept RAW and says why / bad variables build NOTHING rather than something plausible / disabled vs http_error vs empty vs unparseable are four answers, because ZAP cannot tell them apart / the scan plan names the arguments and REQUIRES recurse)"

run_test test_graphql_safety.py "GRAPHQL containment (THIS BUILD ADDS NO GATE: a GraphQL scan is refused at the approval, danger and target gates IN TURN -- named per gate, because gate ORDER makes an off-lab control pass vacuously / six new routes reach no execution path, by AST / NO ARGUMENT VALUE reaches any model, endpoint record or detection result -- a GraphQL argument is routinely a token / the new modules never touch repeater.send / cockpit/graphql.py imports nothing that executes, by AST not substring / AN OUT-OF-SCOPE PROBE WARNS AND IS SENT and the warner cannot raise / a negative depth warns and is applied / SchemaImport.scannable is always False and carries the measured reason / the GraphQL filter is three-state and defaults to matching everything)"
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
