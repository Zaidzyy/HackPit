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

run_test test_attack_path.py "attack-path composer regressions"

run_test test_target_substitution.py "target-substitution polish (range rewrite / foreign-host flag / target-lock backstop)"

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

run_test test_zap_safety.py "ZAP gating split (active fires + passive does not, with both controls / verdict survives every spelling / proxychains cannot launder it / COMMAND and SCRIPT heuristics agree)"

run_test test_zap_proxy.py "ZAP recording proxy history (REAL captured message -> exchange / malformed response keeps the request / bodies stay RAW / endpoints + params / report redaction with a control / routes registered, history GET-only)"

run_test test_zap_proxy_safety.py "ZAP recording proxy GATING (approval + red-confirm with controls / gated argv == spawned argv / loopback-only bind / lab declares the lab, engagement declares nothing / no stdin writer / gate before spawn / stop ungated / per-tool proxy flag, unknown tool untouched / the rewrite cancels a stale prevalidated verdict)"

run_test test_scope_hostcheck.py "Phase-3 scope host-check (no false-reject of files/versions; real hosts still caught)"

run_test test_credvault.py "Phase-3 credential vault (fills user/pass/hash/domain; wrong-kind + non-cred left alone)"

run_test test_corpora.py "Phase-4 corpus ingest (additive/byte-preserving/idempotent; no_merge; windows marked)"

run_test test_repeater.py "Phase-4 HTTP repeater (hardcoded container / argv-only / human-only / scope-checked)"

run_test test_lifecycle_safety.py "listener lifecycle SAFETY invariants (no stdin writer / status observed, never assigned)"

run_test test_tunnels.py "Phase-4 pivot/tunnels (human-only lifecycle / pure rewrite-before-approval / scope-by-hand)"

run_test test_report_templates.py "Phase-4 exam report templates (proof-flag capture / per-host table / CVSS 3.1 / template select)"

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

run_test test_oob_poll.py "OOB poll client + state ingest (correlation kept / nothing dropped / cursor monotonic / no redirect followed)"

run_test test_oob_templates.py "OOB payload templates (token left of the zone per the server's own parser / renders and stops)"

run_test test_oob_deploy_safety.py "OOB deploy SAFETY invariants (signature carries NO destination / no agent path / refusal sends nothing / secret never in an argv)"

run_test test_redirector.py "C2 redirector (LIVE loopback forward both ways / the two ends agree on the tunnel port / UDP gets socat, never a bogus ssh -R)"

run_test test_redirector_safety.py "C2 redirector SAFETY invariants (one loopback destination / no name resolution / remote ack unconditional / paths never half-mix)"

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
