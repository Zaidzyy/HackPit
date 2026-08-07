#!/bin/sh
# Web3 / smart-contract tooling install proof — the checks a hermetic test CANNOT make.
#
# WHY THIS EXISTS. backend/arsenal/tools.json and backend/codescan/web3_tools.py both hardcode the
# binary names the /code-scan web3 audit playbooks propose as an approve-each tool pass: `slither`,
# `myth` (the `mythril` package ships the `myth` entrypoint — kali-sandbox image trap), `echidna`,
# `forge` + `cast`, `semgrep`, `gosec` + `go`, and `cargo` + `clippy` for Rust/Anchor. Nothing in
# the Python suite can prove that is what the image actually installs — every hermetic test feeds
# the parser a string it chose itself (the ZAP `zap-baseline.py` and build #9 impacket-name gaps).
# This file checks the names against the built image and, when the stack is up, that they resolve
# in the long-lived engage container.
#
# Run this after `docker compose build`. Every check prints PASS or FAIL and the script exits
# non-zero on the first failure, so a partial run cannot read as a clean one.
#
# Usage:
#   sh docker/proof/web3_install_proof.sh
#
set -eu

IMAGE="hackpit/kali-sandbox:m1"
ENGAGE="hackpit-engage-sandbox"
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die() { printf '\nABORT: %s\n' "$1"; exit 2; }

printf '\n=== web3 / smart-contract tooling install proof ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build engage-sandbox"

# --- 1. THE NAMES. The exact binaries the catalog templates + web3_tools.py hardcode. ------
# `myth` is deliberately not `mythril` and `slither` not `slither-analyzer` — the packages ship
# those entrypoints, and the templates call them (kali-sandbox image trap).
for prog in slither myth echidna forge cast semgrep gosec go cargo; do
  if docker run --rm "$IMAGE" sh -c "command -v $prog" >/dev/null 2>&1; then
    ok "$prog is on PATH under the exact name the catalog templates + web3_tools.py hardcode"
  else
    bad "$prog is NOT on PATH. tools.json templates and codescan/web3_tools.py both call this
        name. List what the package really ships, then fix the name in BOTH places together:
          docker run --rm $IMAGE sh -c 'ls -l /opt/*/bin | grep -iE \"slither|myth|semgrep\"'"
  fi
done

# --- 2. command -v is not a smoke test — each tool must actually START ----------------------
smoke() { # $1 = binary, $2..$n = version/help args
  bin="$1"; shift
  if docker run --rm "$IMAGE" "$bin" "$@" >/dev/null 2>&1; then
    ok "$bin $* — the tool starts"
  else
    bad "$bin $* failed — installed but cannot run"
  fi
}
smoke slither --version
smoke myth version
smoke echidna --version
smoke forge --version
smoke cast --version
smoke semgrep --version
smoke gosec --version
smoke go version
smoke cargo --version

# --- 3. every argv[0] the WEB3 catalog templates hardcode resolves in the container ---------
# Reads the real tools.json so a template that names a binary the image lacks is caught here,
# not at run time against a contract.
cd "$(dirname "$0")/../../backend" || die "cannot find backend/"
PY=".venv/Scripts/python.exe"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
HEADS="$("$PY" -c "
import json
cat=json.load(open('arsenal/tools.json'))
heads=set()
for t in cat['tools']:
    if t.get('category')=='web3':
        for tpl in t.get('templates',[]):
            parts=tpl['template'].split()
            if parts: heads.add(parts[0])
print(' '.join(sorted(heads)))
")"
for h in $HEADS; do
  if docker run --rm "$IMAGE" sh -c "command -v $h" >/dev/null 2>&1; then
    ok "web3 template head '$h' resolves in the image"
  else
    bad "web3 template head '$h' does NOT resolve — a catalogued web3 invocation would fail"
  fi
done

# --- 4. the launcher accepts the invocation inside the LONG-LIVED engage container ----------
# The container is not the image: `docker compose up -d` does not recreate a running container
# just because its image was rebuilt (the ZAP proof learned this the hard way).
if docker ps --format '{{.Names}}' | grep -qx "$ENGAGE"; then
  IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null || echo unknown)"
  CONTAINER_IMAGE_ID="$(docker inspect "$ENGAGE" --format '{{.Image}}' 2>/dev/null || echo unknown)"
  if [ "$IMAGE_ID" != "$CONTAINER_IMAGE_ID" ]; then
    bad "$ENGAGE is running a DIFFERENT image than the one just verified. Recreate it:
          docker compose -f docker/docker-compose.yml up -d --force-recreate engage-sandbox"
  else
    ok "the running engage sandbox is the image that was just built and verified"
    for prog in slither myth echidna forge cast semgrep gosec; do
      if docker exec "$ENGAGE" sh -c "command -v $prog" >/dev/null 2>&1; then
        ok "docker exec $ENGAGE $prog — resolves in the running container (this is what a tool pass runs)"
      else
        bad "docker exec $ENGAGE $prog — missing in the running container"
      fi
    done
  fi
else
  printf '  SKIP  live exec — engage sandbox not up (docker compose -f docker/docker-compose.yml up -d)\n'
fi

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
