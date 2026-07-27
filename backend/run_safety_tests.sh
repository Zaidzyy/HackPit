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
# Usage:
#   sh backend/run_safety_tests.sh              # hermetic tests only
#   sh backend/run_safety_tests.sh --with-proof # + live isolation proof
set -e

cd "$(dirname "$0")"

# Prefer the backend venv interpreter; fall back to PATH python.
PY="${PY:-.venv/Scripts/python.exe}"
[ -x "$PY" ] || PY="$(command -v python3 || command -v python)"

# FIRST, deliberately. Ten human-only / decoupling locks rest on this scanner, and every one
# of them reports "no offenders" when it is working AND when it is broken. If the scanner
# cannot demonstrate that it catches a planted violation, nothing after this line means much.
echo "== shared source scanner (whole-tree sweep / path allow-lists / AST indirection / can-fail) =="
"$PY" test_scans.py

echo "== attack-path composer regressions =="
"$PY" test_attack_path.py

echo "== target-substitution polish (range rewrite / foreign-host flag / target-lock backstop) =="
"$PY" test_target_substitution.py

echo "== cockpit safety-layer tests (allowlist / target / approval / isolation / order) =="
"$PY" test_cockpit.py

echo "== prevalidated-path gate re-checks (approval AND danger re-checked in all 3 modes) =="
"$PY" test_prevalidated_gates.py

echo "== :kali containment tests (human-only / hardcoded-open-container / no-isolation-gate / audit) =="
"$PY" test_kali.py

echo "== CVE -> exploit index (version comparison / tiered ranking / executes nothing) =="
"$PY" test_exploits.py

echo "== relevance-first KB ranking (substance-gated tier boost / completeness nudge) =="
"$PY" test_search_ranking.py

echo "== raw PTY terminal containment (human-only / hardcoded open box / sentinel shell untouched) =="
"$PY" test_terminal.py

echo "== WinRM Windows transport (profile CRUD / routes to WinRM / records mode=windows) =="
"$PY" test_winrm.py

echo "== WinRM SAFETY invariants (host-locked / no gate bypass / secret never leaks / no auto-run) =="
"$PY" test_winrm_safety.py

echo "== orchestrator-loop tests (proposer cannot execute / no :kali path / gate pre-check) =="
"$PY" test_loop.py

echo "== live-session tests (start is GATED / stdin HUMAN-ONLY / mode-bound / recorded) =="
"$PY" test_session.py

echo "== engagement/report path tests (run recorded + report evidence + scope) =="
"$PY" test_engagement.py

echo "== engagement MODE tests (real-target: never-auto-run / explicit entry / no Wall-A gate / no autonomy) =="
"$PY" test_engagement_mode.py

echo "== program-SCOPE model tests (parse / fail-closed / wildcard+CIDR matching / extraction) =="
"$PY" test_scope.py

echo "== engagement SCOPE tests (in-scope passes / out-of-scope refused / expansion never widens) =="
"$PY" test_engagement_scope.py

echo "== AD graph parser + path tests (BloodHound -> graph -> route to Domain Admin) =="
"$PY" test_adgraph.py

echo "== AD collector tests (argv-only / unapproved / scope-locked DC / failure / no exec) =="
"$PY" test_adgraph_collector.py

echo "== AD orchestration tests (frontier / proposals / synthetic walk to Domain Admin) =="
"$PY" test_adorch.py

echo "== AD ORCHESTRATION safety (agent proposes only / never-auto-run / destructive red-confirm) =="
"$PY" test_adorch_safety.py

echo "== AD graph SAFETY invariants (no exec in adgraph / zero :kali / collector+abuse gated / lab unchanged) =="
"$PY" test_adgraph_safety.py

echo "== detection footprint tests (matching / ATT&CK / grounded+ai_suggested / tagging / report) =="
"$PY" test_detection.py

echo "== detection SAFETY invariants (no exec / read-only / cockpit untouched / describes-not-evades) =="
"$PY" test_detection_safety.py

echo "== Channel-2 context grounding (Channel-1 filters unchanged / leak guard / no-op / budget) =="
"$PY" test_context_channel.py

echo "== :code scan tests (normalisation / malformed output / merge / KB links / report) =="
"$PY" test_codescan.py

echo "== :code scan SAFETY invariants (static-only / orthogonal / bounded / read-only) =="
"$PY" test_codescan_safety.py

echo "== :code scan bundled rules + ruleset picker (multi-language coverage / resolver) =="
"$PY" test_codescan_rules.py

echo "== tool arsenal tests (catalog / lookup / target-faithful render / provenance tags) =="
"$PY" test_arsenal.py

echo "== tool arsenal SAFETY invariants (executes nothing / NO gate bypassed / gates unchanged) =="
"$PY" test_arsenal_safety.py

echo "== Phase-1 runtime (timeout clamp / background jobs / loot / tool reconciliation) =="
"$PY" test_phase1_runtime.py

echo "== Phase-2 state (parsers / upserts / task tree / prompt grounding / executes-nothing) =="
"$PY" test_state.py

echo "== Phase-3 scope host-check (no false-reject of files/versions; real hosts still caught) =="
"$PY" test_scope_hostcheck.py

echo "== Phase-3 credential vault (fills user/pass/hash/domain; wrong-kind + non-cred left alone) =="
"$PY" test_credvault.py

echo "== Phase-4 corpus ingest (additive/byte-preserving/idempotent; no_merge; windows marked) =="
"$PY" test_corpora.py

echo "== Phase-4 HTTP repeater (hardcoded container / argv-only / human-only / scope-checked) =="
"$PY" test_repeater.py

echo "== listener lifecycle SAFETY invariants (no stdin writer / status observed, never assigned) =="
"$PY" test_lifecycle_safety.py

echo "== Phase-4 pivot/tunnels (human-only lifecycle / pure rewrite-before-approval / scope-by-hand) =="
"$PY" test_tunnels.py

echo "== Phase-4 exam report templates (proof-flag capture / per-host table / CVSS 3.1 / template select) =="
"$PY" test_report_templates.py

echo "== Sliver C2 containment (human-only server lifecycle / GATED implant gen / <listener> verbatim) =="
"$PY" test_sliver.py

echo "== Sliver C2 SAFETY invariants (no agent path / gated-vs-human-only split / never executes what it builds) =="
"$PY" test_sliver_safety.py

echo "== DNS-tunnel obfuscation containment (human-only listener / client one-liner never delivered) =="
"$PY" test_obfuscation.py

echo "== DNS-tunnel SAFETY invariants (no agent path / one-liner never delivered / secret never crosses HTTP) =="
"$PY" test_obfuscation_safety.py

echo "== evasion engine (generate-only / gated / forced honest footprint) =="
"$PY" test_evasion.py

echo "== evasion engine SAFETY invariants (no agent path / never runs what it builds / footprint has no off switch) =="
"$PY" test_evasion_safety.py

if [ "$1" = "--with-proof" ]; then
  echo
  echo "== live Docker isolation PROOF (lab — must exit 0) =="
  sh ../docker/proof/isolation_proof.sh
  echo
  echo "== live Docker FULLY-OPEN proof (engagement — Wall A down, full reach — must exit 0) =="
  sh ../docker/proof/engage_open_proof.sh
else
  echo
  echo "Hermetic safety tests passed."
  echo "To also run the live isolation proof (needs the stack up):"
  echo "  sh backend/run_safety_tests.sh --with-proof"
fi
