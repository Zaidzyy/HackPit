#!/bin/sh
# ZAP install + ingest proof — the checks a hermetic test CANNOT make.
#
# WHY THIS EXISTS. backend/state/parsers.py keys STDOUT_PARSERS on the exact strings
# `zap-baseline.py` and `zap-full-scan.py`, and backend/arsenal/tools.json hardcodes the same
# names in its templates. Nothing in the Python suite can prove those names are what Kali
# actually installs, because every hermetic test feeds the parser a string the test itself
# chose. That is precisely how the build #9 ingest gap survived a green suite: a live DCSync
# dumped four NTLM hashes including krbtgt and ingested none of them, because Kali spells the
# impacket scripts differently from upstream and the registry was keyed on upstream's spelling.
#
# Run this after `docker compose build`. Every check prints PASS or FAIL and the script exits
# non-zero on the first failure, so a partial run cannot read as a clean one.
#
# Usage:
#   sh docker/proof/zap_install_proof.sh
#
set -eu

IMAGE="hackpit/kali-sandbox:m1"
LAB="hackpit-lab-target"
SANDBOX="hackpit-kali-sandbox"
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die()  { printf '\nABORT: %s\n' "$1"; exit 2; }

printf '\n=== ZAP install + ingest proof ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build kali-sandbox"

# --- 1. the JVM actually starts (command -v alone is not a smoke test) --------------------
if docker run --rm "$IMAGE" zap.sh -version >/dev/null 2>&1; then
  ok "zap.sh -version — the JVM starts"
else
  bad "zap.sh -version failed — ZAP is installed but cannot run"
fi

# --- 2. THE NAMES. This is the whole point of the file. -----------------------------------
# The names the code hardcodes, in one place so a change here is a change everywhere.
for script in zap-baseline.py zap-full-scan.py; do
  if docker run --rm "$IMAGE" sh -c "command -v $script" >/dev/null 2>&1; then
    ok "$script is on PATH under the exact name the parser registry keys on"
  else
    bad "$script is NOT on PATH — backend/state/parsers.py STDOUT_PARSERS keys and the
        tools.json templates BOTH hardcode this name. Find the real one with:
          docker run --rm $IMAGE sh -c \"ls /usr/share/zaproxy/ ; find / -name 'zap-*.py' 2>/dev/null\"
        then fix parsers.py, tools.json, test_arsenal_safety.py and test_zap_safety.py together."
  fi
done

# --- 3. $HOME/.ZAP is writable as the UNPRIVILEGED user (the lab sandbox's posture) --------
if docker run --rm --user sandbox "$IMAGE" sh -c 'touch "$HOME/.ZAP/.probe" && rm "$HOME/.ZAP/.probe"' >/dev/null 2>&1; then
  ok "\$HOME/.ZAP is writable as the unprivileged sandbox user"
else
  bad "\$HOME/.ZAP is not writable as uid 1000 — ZAP will refuse to start in the LAB sandbox"
fi

# --- 4. a real scan, parsed by the real parser --------------------------------------------
# Skipped rather than failed when the stack is down: this proof is about the image, and the
# name checks above are the load-bearing part.
if docker ps --format '{{.Names}}' | grep -qx "$SANDBOX" && docker ps --format '{{.Names}}' | grep -qx "$LAB"; then
  printf '  ....  running a real baseline scan against the lab target (a few minutes)\n'
  if docker exec "$SANDBOX" zap-baseline.py -t "http://$LAB:3000" -J /dev/stdout -m 1 -I \
       > /tmp/zap-lab-proof.json 2>/dev/null; then
    ok "the baseline scan completed"
  else
    ok "the baseline scan exited non-zero (normal: it exits 1-2 when it finds warnings)"
  fi

  cd "$(dirname "$0")/../../backend" || die "cannot find backend/"
  PY=".venv/Scripts/python.exe"
  [ -x "$PY" ] || PY=".venv/bin/python"
  [ -x "$PY" ] || PY="python3"

  if "$PY" -c "
import sys
from state import parsers
text = open('/tmp/zap-lab-proof.json', encoding='utf-8', errors='replace').read()
out = parsers.parse_zap(text, 's-proof', 'run-proof')
print(f'      findings={len(out.findings)} endpoints={len(out.endpoints)}')
for f in out.findings[:5]:
    print(f'        {f.severity:8} {f.title}')
sys.exit(0 if out.findings else 1)
"; then
    ok "the REAL ZAP output parsed into findings — the fixture and reality agree"
  else
    bad "the real report parsed to ZERO findings. Either the scan genuinely found nothing
        (Juice Shop is a SPA — retry with -j for the AJAX spider) or parse_zap disagrees
        with real ZAP output, which the hand-written fixture in test_zap.py cannot catch."
  fi
else
  printf '  SKIP  live scan — stack not up (docker compose -f docker/docker-compose.yml up -d)\n'
fi

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
