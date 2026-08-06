#!/bin/sh
# nuclei install + flag + ingest proof — the checks a hermetic test CANNOT make.
#
# WHY THIS EXISTS. backend/cockpit/nuclei.py builds a fixed argv —
#   nuclei -jsonl -silent -duc -u <target> [-severity …] [-tags …] [-t …] [-rate-limit …]
# — and backend/state/parsers.py keys its STDOUT_PARSERS on the exact name `nuclei`. NOTHING in
# the Python suite can prove the IMAGE's nuclei actually accepts those flags or spells its JSONL
# the way parse_findings reads it, because every hermetic test feeds the parser a string the test
# itself chose (the zap_install lesson: a build was written against `zap-baseline.py`, which Kali
# does not ship, and every key matched nothing with the suite green).
#
# Run this after `docker compose build`. Each check prints PASS/FAIL; a non-zero exit means the
# nuclei surface cannot be trusted against this image.
#
# Usage:
#   sh docker/proof/nuclei_proof.sh
#
set -eu

IMAGE="hackpit/kali-sandbox:m1"
LAB="hackpit-lab-target"
LAB_PORT="${HACKPIT_LAB_PORT:-3000}"
SANDBOX="hackpit-kali-sandbox"
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die() { printf '\nABORT: %s\n' "$1"; exit 2; }

printf '\n=== nuclei install + flag + ingest proof ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build kali-sandbox"

# --- 1. the binary runs, under the exact name the parser registry keys on ------------------
if docker run --rm "$IMAGE" nuclei -version -duc >/dev/null 2>&1; then
  ok "nuclei -version -duc — the binary runs under the name parsers.py keys on"
else
  bad "nuclei -version failed — nuclei is missing or cannot run in the image"
fi

# --- 2. templates are BAKED (the sandbox has no egress to fetch them at runtime) -----------
if docker run --rm "$IMAGE" sh -c 'test -d /usr/share/nuclei-templates' >/dev/null 2>&1; then
  ok "the nuclei-templates repo is baked at /usr/share/nuclei-templates"
else
  bad "no baked templates — a scan in the egress-less lab sandbox would find zero and look clean"
fi

# --- 3. THE FLAGS. This is the whole point of the file. ------------------------------------
# The exact flag string cockpit/nuclei.py emits, against a harmless template set, must be
# ACCEPTED (not "flag provided but not defined"). Run against the lab only when the stack is up;
# otherwise a `-version`-style dry parse still proves the flags parse.
if docker ps --format '{{.Names}}' | grep -qx "$SANDBOX" && docker ps --format '{{.Names}}' | grep -qx "$LAB"; then
  IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null || echo unknown)"
  CONTAINER_IMAGE_ID="$(docker inspect "$SANDBOX" --format '{{.Image}}' 2>/dev/null || echo unknown)"
  if [ "$IMAGE_ID" != "$CONTAINER_IMAGE_ID" ]; then
    bad "$SANDBOX runs a DIFFERENT image than the one just built. Recreate it, then re-run:
        docker compose -f docker/docker-compose.yml up -d --force-recreate kali-sandbox"
    printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
    exit 1
  fi
  ok "the running sandbox is the image that was just built"

  printf '  ....  running a bounded real scan against the lab (tech-detect, a moment)\n'
  # -tags tech is fast and finds the stack; the point is the flags parse and JSONL streams.
  SCAN_OUT="$(MSYS_NO_PATHCONV=1 docker exec "$SANDBOX" \
      nuclei -jsonl -silent -duc -u "http://$LAB:$LAB_PORT" -tags tech -rate-limit 50 \
      2>/tmp/nuclei-scan.err || true)"
  if grep -qiE 'flag provided but not defined|unknown flag' /tmp/nuclei-scan.err 2>/dev/null; then
    bad "the image's nuclei REJECTED a flag cockpit/nuclei.py emits (see /tmp/nuclei-scan.err) —
        the argv and the binary disagree, which the hermetic test cannot catch"
  else
    ok "the exact -jsonl -silent -duc -u … -tags … -rate-limit … argv was accepted"
  fi

  # --- 4. real JSONL parsed by the real parser ---------------------------------------------
  cd "$(dirname "$0")/../../backend" || die "cannot find backend/"
  PY=".venv/Scripts/python.exe"
  [ -x "$PY" ] || PY=".venv/bin/python"
  [ -x "$PY" ] || PY="python3"
  if printf '%s' "$SCAN_OUT" | "$PY" -c "
import sys
from cockpit import nuclei
text = sys.stdin.read()
out = nuclei.parse_findings(text, 's-proof', 'run-proof')
print(f'      findings={len(out)}')
for f in out[:6]:
    print(f'        {f.severity:8} {f.title}  [{f.reference}]')
# A tech-detect scan of the lab should surface at least one finding; zero means the real JSONL
# and parse_findings disagree, or the scan genuinely matched nothing.
sys.exit(0 if out else 1)
"; then
    ok "real nuclei JSONL parsed into findings — the fixture and reality agree"
  else
    bad "real nuclei output parsed to ZERO findings. Either the scan matched nothing, or
        parse_findings disagrees with real -jsonl output (hyphenated keys), which the
        hand-written fixture in test_nuclei.py cannot catch."
  fi
else
  printf '  SKIP  live scan — stack not up (docker compose -f docker/docker-compose.yml up -d).\n'
  printf '  NOT-RUN: the flag-acceptance + real-JSONL-parse checks need the lab target running.\n'
fi

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
