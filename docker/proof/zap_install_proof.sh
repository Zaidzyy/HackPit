#!/bin/sh
# ZAP install + ingest proof — the checks a hermetic test CANNOT make.
#
# WHY THIS EXISTS, and it already paid for itself. backend/state/parsers.py keys
# STDOUT_PARSERS on the exact string `zaproxy`, and backend/arsenal/tools.json hardcodes the
# same name in its templates. Nothing in the Python suite can prove that is what Kali actually
# installs, because every hermetic test feeds the parser a string the test itself chose.
#
# The FIRST version of this build was written against upstream's documented scan scripts,
# `zap-baseline.py` and `zap-full-scan.py`. Kali ships NEITHER — they exist only inside OWASP's
# own Docker image. Every key would have matched nothing, forever, with the suite green. That
# is the build #9 ingest gap exactly: a live DCSync dumped four NTLM hashes including krbtgt
# and ingested none of them, because Kali spells the impacket scripts differently from upstream.
# The image build caught it here because this file checks the names against the image.
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
if docker run --rm "$IMAGE" zaproxy -cmd -version >/dev/null 2>&1; then
  ok "zaproxy -cmd -version — the JVM starts"
else
  bad "zaproxy -cmd -version failed — ZAP is installed but cannot run"
fi

# --- 2. THE NAMES. This is the whole point of the file. -----------------------------------
# The names the code hardcodes, in one place so a change here is a change everywhere.
for prog in zaproxy owasp-zap; do
  if docker run --rm "$IMAGE" sh -c "command -v $prog" >/dev/null 2>&1; then
    ok "$prog is on PATH under the exact name the parser registry keys on"
  else
    bad "$prog is NOT on PATH — backend/state/parsers.py STDOUT_PARSERS keys and the
        tools.json templates BOTH hardcode this name. List what the package really ships:
          docker run --rm $IMAGE dpkg -L zaproxy | grep -E 'bin/|[.]sh$'
        then fix parsers.py, tools.json, detection/catalog.py, test_arsenal_safety.py and
        test_zap_safety.py TOGETHER — they all carry the same string."
  fi
done

# the scripts Kali does NOT ship: assert their absence, so a future image that starts shipping
# them is noticed deliberately rather than silently changing which branch of the code is live
for absent in zap-baseline.py zap-full-scan.py; do
  if docker run --rm "$IMAGE" sh -c "command -v $absent" >/dev/null 2>&1; then
    bad "$absent now EXISTS in the image. It did not when this build was written, and the
        catalog/registry were rewritten around that fact. Decide deliberately which interface
        to use rather than leaving two live."
  else
    ok "$absent is absent, as measured when this build was written"
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
  printf '  ....  running a real ACTIVE scan against the lab target (several minutes)\n'
  # Written INSIDE the container, then copied out — `-quickout` needs a real path, and a
  # `docker exec ... > file` redirect on the host would capture progress chatter as well.
  docker exec "$SANDBOX" rm -f /tmp/zap-proof.json >/dev/null 2>&1 || true
  if docker exec "$SANDBOX" zaproxy -cmd -quickurl "http://$LAB:3000" \
       -quickout /tmp/zap-proof.json >/dev/null 2>&1; then
    ok "the scan completed"
  else
    ok "the scan exited non-zero (it does that when it finds alerts)"
  fi
  docker exec "$SANDBOX" cat /tmp/zap-proof.json > /tmp/zap-lab-proof.json 2>/dev/null \
    || bad "no report was written inside the container"

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
        (Juice Shop is a SPA — the traditional spider finds little) or parse_zap disagrees
        with real ZAP output, which the hand-written fixture in test_zap.py cannot catch."
  fi
else
  printf '  SKIP  live scan — stack not up (docker compose -f docker/docker-compose.yml up -d)\n'
fi

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
