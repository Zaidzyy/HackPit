#!/bin/sh
# JS-recon engine + toolchain install proof — the checks a hermetic test CANNOT make.
#
# WHY THIS EXISTS. The :jsrecon job invokes `js-mine --job-stdin` inside the engagement sandbox, and
# the arsenal names getjs/subjs/LinkFinder/SecretFinder/trufflehog/gitleaks/sourcemapper for manual
# use. Nothing in the Python suite can prove those names resolve in the BUILT image or that the engine
# actually imports — every hermetic test imports the engine's pure functions from the repo, never from
# the image (the ZAP `zap-baseline.py` and build #9 impacket-name gaps). This file checks the names
# against the built image and the LONG-LIVED engage container, and proves the engine loads and honours
# the stdin contract.
#
# Run this after `docker compose build`. Every check prints PASS or FAIL and the script exits non-zero
# on the first failure, so a partial run cannot read as a clean one.
#
# Usage:
#   sh docker/proof/jsrecon_install_proof.sh
set -eu

IMAGE="hackpit/kali-sandbox:m1"
ENGAGE="hackpit-engage-sandbox"
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die() { printf '\nABORT: %s\n' "$1"; exit 2; }

printf '\n=== JS-recon (js-mine) install proof ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build engage-sandbox"

# --- 1. THE NAME the :jsrecon job's docker exec hardcodes resolves on PATH ---------------------
if docker run --rm "$IMAGE" sh -c "command -v js-mine" >/dev/null 2>&1; then
  ok "js-mine is on PATH under the exact name backend/cockpit/jsrecon.py invokes"
else
  bad "js-mine is NOT on PATH — the :jsrecon job's 'docker exec … js-mine' would fail"
fi

# --- 2. command -v is not a smoke test — the engine must actually MINE (build #4's lesson) -----
if docker run --rm "$IMAGE" js-mine --selftest 2>&1 | grep -qi 'js-mine ok'; then
  ok "js-mine --selftest loads and mines its planted endpoint/param/secret + source map"
else
  bad "js-mine --selftest did NOT pass — the engine cannot even mine its own fixture"
fi

# --- 3. it runs the SAME argv the backend runs: --job-stdin, a mine job on stdin ---------------
# Feed a tiny mine job with an unresolvable host so nothing leaves the box, and assert the engine
# answers with well-formed JSON carrying a results array (an error row is a valid result here — the
# point is that the stdin contract works, not that a fake host answers).
JOB='{"action":"mine","js_urls":["http://127.0.0.1:1/x.js"],"maps":false,"verify":false,"timeout":2}'
if printf '%s' "$JOB" | docker run --rm -i "$IMAGE" js-mine --job-stdin 2>/dev/null \
     | grep -q '"results"'; then
  ok "js-mine --job-stdin reads a mine job on stdin and emits a results JSON (the backend contract)"
else
  bad "js-mine --job-stdin did not honour the mine stdin contract"
fi

# --- 4. the collect action answers on its own contract too ------------------------------------
JOB2='{"action":"collect","seed_urls":["http://127.0.0.1:1/"],"timeout":2}'
if printf '%s' "$JOB2" | docker run --rm -i "$IMAGE" js-mine --job-stdin 2>/dev/null \
     | grep -q '"js_urls"'; then
  ok "js-mine --action collect emits a js_urls JSON (the collect-from-a-page contract)"
else
  bad "js-mine --action collect did not honour the collect stdin contract"
fi

# --- 5. the external tools the arsenal names resolve on PATH ----------------------------------
for t in getjs subjs LinkFinder SecretFinder trufflehog gitleaks sourcemapper; do
  if docker run --rm "$IMAGE" sh -c "command -v $t" >/dev/null 2>&1; then
    ok "$t resolves on PATH (the arsenal names it for manual JS mining)"
  else
    # getjs is best-effort in the image (its module path is unstable); note it, do not fail on it.
    if [ "$t" = "getjs" ]; then
      printf '  NOTE  getjs is optional (best-effort install) — subjs covers JS URL collection\n'
    else
      bad "$t did not resolve on PATH — the arsenal names it"
    fi
  fi
done

# --- 6. the engine resolves inside the LONG-LIVED engage container ---------------------------
# The container is not the image: `docker compose up -d` does not recreate a running container just
# because its image was rebuilt (the ZAP proof learned this the hard way).
if docker ps --format '{{.Names}}' | grep -qx "$ENGAGE"; then
  IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null || echo unknown)"
  CONTAINER_IMAGE_ID="$(docker inspect "$ENGAGE" --format '{{.Image}}' 2>/dev/null || echo unknown)"
  if [ "$IMAGE_ID" != "$CONTAINER_IMAGE_ID" ]; then
    bad "$ENGAGE is running a DIFFERENT image than the one just verified. Recreate it:
          docker compose -f docker/docker-compose.yml up -d --force-recreate engage-sandbox"
  else
    ok "the running engage sandbox is the image that was just built and verified"
    if docker exec "$ENGAGE" sh -c "command -v js-mine" >/dev/null 2>&1; then
      ok "docker exec $ENGAGE js-mine — resolves in the running container (this is what a :jsrecon job runs)"
    else
      bad "docker exec $ENGAGE js-mine — missing in the running container"
    fi
  fi
else
  printf '  SKIP  live exec — engage sandbox not up (docker compose -f docker/docker-compose.yml up -d)\n'
fi

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
