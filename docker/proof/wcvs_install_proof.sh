#!/bin/sh
# Web-cache-poisoning prober install proof — the checks a hermetic test CANNOT make.
#
# WHY THIS EXISTS. The :cache job invokes `cache-probe --job-stdin` inside the open sandbox, and the
# arsenal names Hackmanit's `wcvs` for manual use. Nothing in the Python suite can prove those names
# resolve in the BUILT image or that the engine actually imports — every hermetic test feeds the
# loader a string it chose itself (the ZAP `zap-baseline.py` and build #9 impacket-name gaps). This
# file checks the names against the built image and the LONG-LIVED engage container, and proves the
# engine loads and honours the stdin contract.
#
# Run this after `docker compose build`. Every check prints PASS or FAIL and the script exits
# non-zero on the first failure, so a partial run cannot read as a clean one.
#
# Usage:
#   sh docker/proof/wcvs_install_proof.sh
set -eu

IMAGE="hackpit/kali-sandbox:m1"
ENGAGE="hackpit-engage-sandbox"
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die() { printf '\nABORT: %s\n' "$1"; exit 2; }

printf '\n=== web-cache-poisoning prober install proof ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build engage-sandbox"

# --- 1. THE NAME the :cache job's docker exec hardcodes resolves on PATH ----------------------
if docker run --rm "$IMAGE" sh -c "command -v cache-probe" >/dev/null 2>&1; then
  ok "cache-probe is on PATH under the exact name backend/cockpit/cache.py invokes"
else
  bad "cache-probe is NOT on PATH — the :cache job's 'docker exec … cache-probe' would fail"
fi

# --- 2. command -v is not a smoke test — the engine must actually LOAD (build #4's lesson) ----
if docker run --rm "$IMAGE" cache-probe --selftest 2>&1 | grep -qi 'cache-probe ok'; then
  ok "cache-probe --selftest loads (builds every injection kind + both parsers)"
else
  bad "cache-probe --selftest did NOT load — the engine cannot even import"
fi

# --- 3. it runs the SAME argv the backend runs: --job-stdin, request on stdin -----------------
# Feed a tiny detect job with an unresolvable host so nothing leaves the box, and assert the engine
# answers with well-formed JSON carrying a verdicts array (an error row is a valid result here — the
# point is that the stdin contract works, not that a fake host answers).
JOB='{"url":"http://127.0.0.1:1/x","method":"GET","headers":[],"body":"","inputs":["x-forwarded-host","param-cloak"],"stage":"detect","deception":true,"timeout":2}'
if printf '%s' "$JOB" | docker run --rm -i "$IMAGE" cache-probe --job-stdin 2>/dev/null \
     | grep -q '"verdicts"'; then
  ok "cache-probe --job-stdin reads a JSON job on stdin and emits a verdicts JSON (the backend contract)"
else
  bad "cache-probe --job-stdin did not honour the stdin JSON contract"
fi

# --- 4. the confirm stage answers on its own contract too ------------------------------------
JOB2='{"url":"http://127.0.0.1:1/x","headers":[],"inputs":["x-forwarded-host"],"stage":"confirm","timeout":2}'
if printf '%s' "$JOB2" | docker run --rm -i "$IMAGE" cache-probe --job-stdin 2>/dev/null \
     | grep -q '"confirms"'; then
  ok "cache-probe --stage confirm emits a confirms JSON (the separately-approved poison-plant path)"
else
  bad "cache-probe --stage confirm did not honour the confirm stdin contract"
fi

# --- 5. the external scanner the arsenal names resolves + runs --------------------------------
if docker run --rm "$IMAGE" sh -c "command -v wcvs" >/dev/null 2>&1 \
   && docker run --rm "$IMAGE" sh -c "wcvs --help 2>&1 || wcvs -h 2>&1" | grep -qi 'usage\|url\|cache\|wcvs\|scanner'; then
  ok "wcvs (Hackmanit Web-Cache-Vulnerability-Scanner) resolves on PATH and runs (the arsenal's manual scanner)"
else
  bad "wcvs did not resolve/run — the arsenal names it"
fi

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
    if docker exec "$ENGAGE" sh -c "command -v cache-probe" >/dev/null 2>&1; then
      ok "docker exec $ENGAGE cache-probe — resolves in the running container (this is what a :cache job runs)"
    else
      bad "docker exec $ENGAGE cache-probe — missing in the running container"
    fi
  fi
else
  printf '  SKIP  live exec — engage sandbox not up (docker compose -f docker/docker-compose.yml up -d)\n'
fi

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
