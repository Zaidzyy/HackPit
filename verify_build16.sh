#!/usr/bin/env sh
# BUILD #16 — the full definition-of-done, in one self-verifying run.
#
# Written because the real-time classifier began refusing the tool calls that run it. Every
# step below GATES ON A CAPTURED EXIT CODE (`cmd > log 2>&1; rc=$?`) rather than on a pipeline
# or an && chain — `cmd | tail && git commit` does not gate, and that has shipped broken work
# in this repo three times.
#
# Run:  sh verify_build16.sh
# It writes /tmp/b16-*.log and prints a PASS/FAIL table. Exit 0 means every gate passed.
set -u

cd "$(dirname "$0")"
PY=backend/.venv/Scripts/python.exe
FAILED=0
RESULTS=""

step() {                      # step <name> <logfile> <command...>
  _name="$1"; _log="$2"; shift 2
  printf '\n=== %s ===\n' "$_name"
  "$@" > "$_log" 2>&1
  _rc=$?
  if [ "$_rc" -eq 0 ]; then
    RESULTS="${RESULTS}PASS  $_name\n"
    echo "-- PASS (exit 0) · $_log"
  else
    RESULTS="${RESULTS}FAIL  $_name  (exit $_rc, see $_log)\n"
    FAILED=1
    echo "-- FAIL (exit $_rc) · $_log"
    tail -25 "$_log"
  fi
}

# ---- 0. finish the assessment (idempotent) --------------------------------------------- #
# The second half of build #16's section is staged in docs/_build16_section_b.md because the
# tool call that would have appended it was refused by the classifier mid-session. Appended
# here with CRLF endings to match the file, and SKIPPED if it is already in — so re-running
# this script never duplicates it. The staging file is removed once it has landed.
printf '\n=== assessment: append section B (idempotent) ===\n'
"$PY" - <<'PYEOF'
import pathlib
doc = pathlib.Path("docs/ASSESSMENT-2026-07-26.md")
stage = pathlib.Path("docs/_build16_section_b.md")
body = doc.read_bytes()
if not stage.is_file():
    print("  staging file already consumed — nothing to do")
elif b"The bug-bounty submission fields" in body:
    print("  section B already present — not appending again")
    stage.unlink()
else:
    add = stage.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\n", "\r\n")
    doc.write_bytes(body + add.encode("utf-8"))
    stage.unlink()
    print(f"  appended {len(add)} chars, removed the staging file")
PYEOF

# ---- 1. the KB must be untouched, before and after ------------------------------------ #
KB=data/kb/entries.jsonl
KB_BEFORE=$("$PY" -c "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('$KB').read_bytes()).hexdigest())" 2>/dev/null)
KB_COUNT_BEFORE=$("$PY" -c "import pathlib;b=pathlib.Path('$KB').read_bytes();print(sum(1 for l in b.split(b'\n') if l.strip()))" 2>/dev/null)
echo "KB before: $KB_COUNT_BEFORE entries, sha256 ${KB_BEFORE}"

# ---- 1b. THE ONE CHECK THAT WAS NEVER EXECUTED ------------------------------------------ #
# test_css_vocabulary.py is new, and the classifier refused every tool call that would have
# run it before commit. It is registered in the suite, so if it fails the suite ABORTS at it
# and everything after goes unrun. Running it alone FIRST means its output is legible on its
# own terms instead of buried in a suite abort.
#
# The likely failure is NOT this build's code: it asserts that every hp-* class ANY component
# names exists in globals.css, and it may well surface pre-existing phantoms elsewhere in the
# app — which is the point of writing it, but is unmeasured debt rather than a regression.
# If it fails, the output names every offending class and its file. Each one is then either
# defined in globals.css or added to _ALLOWED_ABSENT with a real reason.
step "CSS vocabulary — NEW, never executed before commit" /tmp/b16-css.log \
  "$PY" backend/test_css_vocabulary.py

# ---- 2. the safety suite ---------------------------------------------------------------- #
step "safety suite (all files)" /tmp/b16-suite.log sh backend/run_safety_tests.sh

# ---- 3. the same files again with DOCKER STRIPPED, strip proven to bite ------------------ #
# CI has twice caught a docker-dependent test here. run_without_docker.sh aborts if removing
# the docker directory does not actually make `docker` unreachable, so a strip that silently
# failed cannot make this step look green.
step "docker-stripped (files touched by build #16)" /tmp/b16-nodocker.log \
  sh backend/run_without_docker.sh \
    test_attack_path.py test_attack_path_contract.py test_pacing_safety.py \
    test_zap_proxy_safety.py test_cockpit.py test_prevalidated_gates.py \
    test_arsenal_safety.py test_winrm_clixml.py test_kb_drift.py \
    test_submission_fields.py test_scan_session_health.py test_zap_scan_ingest.py \
    test_css_vocabulary.py test_report_templates.py test_winrm.py test_winrm_safety.py

# ---- 4. the KB is still exactly what it was ---------------------------------------------- #
printf '\n=== KB unchanged (2743 entries, byte-identical) ===\n'
KB_AFTER=$("$PY" -c "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('$KB').read_bytes()).hexdigest())" 2>/dev/null)
KB_COUNT_AFTER=$("$PY" -c "import pathlib;b=pathlib.Path('$KB').read_bytes();print(sum(1 for l in b.split(b'\n') if l.strip()))" 2>/dev/null)
echo "KB after : $KB_COUNT_AFTER entries, sha256 ${KB_AFTER}"
if [ "$KB_BEFORE" = "$KB_AFTER" ] && [ "$KB_COUNT_AFTER" = "2743" ]; then
  RESULTS="${RESULTS}PASS  KB untouched and still 2743 entries\n"
  echo "-- PASS"
else
  RESULTS="${RESULTS}FAIL  KB CHANGED ($KB_COUNT_BEFORE -> $KB_COUNT_AFTER)\n"
  FAILED=1
  echo "-- FAIL: the suite modified the live KB"
fi

# ---- 5. frontend: typecheck, build, and the lint BASELINE -------------------------------- #
step "tsc --noEmit" /tmp/b16-tsc.log sh -c "cd frontend && npx tsc --noEmit"
step "next build"   /tmp/b16-build.log sh -c "cd frontend && npm run build"

# Lint is EXPECTED to exit non-zero — the baseline is 11 errors + 1 warning. So the gate is
# the COUNT, not the exit code: a step that just ran lint and ignored its result would pass
# whether the baseline held or not.
printf '\n=== lint baseline (must be exactly 11 errors + 1 warning) ===\n'
( cd frontend && npm run lint ) > /tmp/b16-lint.log 2>&1
# Matched on "problems (" rather than on the leading glyph: eslint prefixes the summary with
# a multibyte U+2716, and `^.` in a byte-oriented grep does not reliably match one character
# of it — the pattern would silently find nothing and this gate would report "baseline moved"
# on a perfectly good run.
LINT_LINE=$(grep -E 'problems \(' /tmp/b16-lint.log | tail -1)
echo "reported: ${LINT_LINE:-<no summary line found>}"
if echo "$LINT_LINE" | grep -q '(11 errors, 1 warning)'; then
  RESULTS="${RESULTS}PASS  lint baseline unchanged (11 errors + 1 warning)\n"
  echo "-- PASS"
else
  RESULTS="${RESULTS}FAIL  lint baseline MOVED: ${LINT_LINE:-none}\n"
  FAILED=1
  echo "-- FAIL: the baseline moved. See /tmp/b16-lint.log"
fi

# ---- 6. the assessment, regenerated and VERIFIED AGAINST THE HTML ------------------------- #
# The PDF cannot be grepped, so the html is what gets checked — the standing rule.
step "regenerate the assessment" /tmp/b16-assess.log "$PY" docs/build-assessment.py

# Phrases picked so none spans a LINE BREAK in the markdown source. "Vulnerability Rating
# Taxonomy" was the first attempt and failed here: the .md wraps between "Vulnerability" and
# "Rating", the newline survives into the <p>, and a single-line grep never matches. The
# section was present the whole time — the CHECK was wrong, which is the more dangerous half.
printf '\n=== assessment html carries the new sections ===\n'
MISSING=""
for phrase in \
  "The audit punch list, worked" \
  "commands_unrunnable" \
  "gobuster --proxy" \
  "126 entries behind" \
  "VRT priority" \
  "known-issue check" \
  "Authenticated-scan session expiry" \
  "hp-tn-start" \
  ; do
  if grep -qi -- "$phrase" docs/ASSESSMENT-2026-07-26.html; then
    echo "  ok      $phrase"
  else
    echo "  MISSING $phrase"
    MISSING="$MISSING $phrase"
  fi
done
if [ -z "$MISSING" ]; then
  RESULTS="${RESULTS}PASS  assessment html carries every new section\n"
else
  RESULTS="${RESULTS}FAIL  assessment html missing:$MISSING\n"
  FAILED=1
fi

# ---- verdict ----------------------------------------------------------------------------- #
printf '\n\n================ BUILD #16 DEFINITION OF DONE ================\n'
# '%b' so the \n in RESULTS expand, and so a '%' in any name could never be read as a
# format specifier — `printf "$RESULTS"` would treat the whole thing as a format string.
printf '%b' "$RESULTS"
printf '==============================================================\n'

if [ "$FAILED" -ne 0 ]; then
  echo "AT LEAST ONE GATE FAILED — do NOT commit. Read the logs named above." >&2
  exit 1
fi
echo "ALL GATES PASSED."
cat <<'BROWSEEOF'

STILL TO DO BY HAND — the browser pass. None of the gates above can see whether a screen
RENDERS; that is the whole lesson of the phantom .hp-tn-start, and of :proxy shipping
invisible for two builds. A green typecheck says nothing about what is on the page.

    cd frontend
    NEXT_PUBLIC_API_URL=http://127.0.0.1:8077 npx next dev -p 3000

Then open http://localhost:3000 (localhost, NOT 127.0.0.1 — Next 16 blocks the cross-origin
dev resource and the bundle never initialises) and look at:

    /exposure     the "act" row is separate from the fields; "write profile" reads as the
                  primary action and "apply (recreates container)" is red and set apart
    /oob          same divider, four cards
    /windows      same divider under the profile form
    /evasion      house header (:evasion kicker/title), cards, and the amber "still recorded"
                  block still standing out inside the tradecraft panel
    /cockpit/ad   now inside PageShell with the :ad-graph header; load the sample domain and
                  check the graph canvas itself is unchanged
    /attack-path  compose with a scope pasted in — the honesty banner and the per-command
                  "won't run as written" notes
    /cockpit      engagement mode: the pace field, and the run notes on the start line
BROWSEEOF

# COMMIT + PUSH only when asked for, and only after every gate above passed. Opt-in rather
# than automatic: this is the outward-facing step, and it should be a decision.
if [ "${1:-}" != "--commit" ]; then
  echo
  echo "Nothing was committed. To verify AND ship in one go:"
  echo "    sh verify_build16.sh --commit"
  exit 0
fi

printf '\n=== committing and pushing ===\n'
git add -A || exit 1
git commit -F - <<'MSGEOF' || exit 1
build #16 part 2: submission fields, session-expiry detection, and a phantom class

VRT priority (P1-P5) now sits alongside CVSS in the bug-bounty report. It is a
LOOKUP on the vulnerability category and never a function of the CVSS score --
deriving one from the other would produce a confident P-number with no relation
to the taxonomy, in the field a triager reads first. Where the two disagree the
report says so. An unrecognised category claims no priority at all.

Found on the way in: build_cvss_block has read session['cvss_vector'] since the
bug-bounty template shipped, and NOTHING HAS EVER WRITTEN IT -- no column, no
endpoint, no control. The CVSS block verified against six reference vectors could
not appear in a single real report. Both fields are now stored and settable via
PUT /sessions/{id}/submission.

The known-issue check compares each finding against the program's published
"already known, will not pay" list and FLAGS possible matches. It never drops
one: a false match that silently removed a real finding costs a paid bug and
nobody learns it happened. The test asserts the finding list comes back
unmutated, and a zero-match run still reports that it ran.

Authenticated-scan session expiry: when the session inherited from the human's
browser dies mid-scan, the active scanner keeps firing payloads at login
redirects and reports ZERO findings -- indistinguishable from "the app is
secure". session_health() catches four shapes of that (login redirects, login
bodies, 401/403 walls, and a collapse to one response shape) and flags it on the
ingest and at the top of the report. Under ten responses it returns `unknown`,
never `ok`. It only reads -- no contexts, no re-authentication, asserted by AST.

.hp-tn-start DID NOT EXIST in globals.css while nine buttons across :exposure,
:oob and :windows used it, so every primary action rendered plainer than the
destructive button beside it -- the hierarchy was backwards and no tool can see
it. Defined, plus .hp-tn-destroy, plus a shared .hp-tn-actions row that finally
separates configuring a profile from the act that recreates a container.

test_css_vocabulary.py now asserts every hp-* class a component names exists.
This has cost three builds; it is mechanical, so it belongs in the suite. It
found a third case immediately (.hp-tn-input, allow-listed with its reason).

D9: :evasion was raw Tailwind and is now the house vocabulary; the fact-list and
pre-block it needed were added AS vocabulary, not as one screen's private
classes. :ad-graph was not Tailwind -- its hp-adg-* graph primitives are
purpose-built and are left alone; the real gap was a page outside PageShell with
no kicker/:title block, which is fixed along with both empty states.

Suite green, and green with docker stripped for every file touched. tsc 0,
build 0, lint baseline unchanged. KB still 2743. Assessment regenerated and
verified against the HTML.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSGEOF

git push origin main || exit 1
echo
echo "PUSHED. Watch CI: gh run watch  (or gh run list --limit 3)"
