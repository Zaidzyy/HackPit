#!/bin/sh
# Single-packet race client install proof — the checks a hermetic test CANNOT make.
#
# WHY THIS EXISTS. The :race job invokes `race-singlepacket --job-stdin` inside the open sandbox.
# Nothing in the Python suite can prove that name resolves in the built image or that its h2
# framing library actually imports — every hermetic test feeds the loader a string it chose itself
# (the ZAP `zap-baseline.py` and build #9 impacket-name gaps). This file checks the name against
# the built image and the LONG-LIVED engage container, and proves the client loads.
#
# Run this after `docker compose build`. Every check prints PASS or FAIL and the script exits
# non-zero on the first failure, so a partial run cannot read as a clean one.
#
# Usage:
#   sh docker/proof/race_install_proof.sh
set -eu

IMAGE="hackpit/kali-sandbox:m1"
ENGAGE="hackpit-engage-sandbox"
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die() { printf '\nABORT: %s\n' "$1"; exit 2; }

printf '\n=== single-packet race client install proof ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build engage-sandbox"

# --- 1. THE NAME the :race job's docker exec hardcodes resolves on PATH ----------------------
if docker run --rm "$IMAGE" sh -c "command -v race-singlepacket" >/dev/null 2>&1; then
  ok "race-singlepacket is on PATH under the exact name backend/cockpit/race.py invokes"
else
  bad "race-singlepacket is NOT on PATH — the :race job's 'docker exec … race-singlepacket' would fail"
fi

# --- 2. command -v is not a smoke test — the client must actually LOAD (build #4's lesson) ---
if docker run --rm "$IMAGE" race-singlepacket --selftest 2>&1 | grep -qi 'race-singlepacket ok'; then
  ok "race-singlepacket --selftest loads (both transports; h1-last-byte is stdlib, h2 via the venv)"
else
  bad "race-singlepacket --selftest did NOT load — the client cannot even import"
fi

# --- 3. the HTTP/2 single-packet mode's framing library is really in the venv ----------------
# h1-last-byte works without it, but the DEFAULT mode is h2-single-packet, so a missing h2 would
# silently degrade every default run to an error row. Assert the import in the venv directly.
# NB: pass the absolute venv path INSIDE `sh -c` with a leading `exec`, not as a bare argv
# token — Git Bash / MSYS rewrites a lone `/opt/...` argument into `C:/Program Files/Git/opt/...`
# before docker sees it, which made this the only check that false-FAILed on Windows.
if docker run --rm "$IMAGE" sh -c 'exec /opt/race/venv/bin/python3 -c "import h2"' >/dev/null 2>&1; then
  ok "the h2 framing library imports inside /opt/race/venv (the h2-single-packet default transport)"
else
  bad "h2 does NOT import inside /opt/race/venv — the h2-single-packet default would error on every run"
fi

# --- 4. it runs the SAME argv the backend runs: --job-stdin, request on stdin -----------------
# Feed a tiny job with an unresolvable host so nothing leaves the box, and assert the client
# answers with well-formed JSON carrying a results array (an error row is a valid result here —
# the point is that the stdin contract works, not that a fake host answers).
JOB='{"url":"http://127.0.0.1:1/x","method":"GET","headers":[],"body":"","mode":"h1-last-byte","count":2,"timeout":2}'
if printf '%s' "$JOB" | docker run --rm -i "$IMAGE" race-singlepacket --job-stdin 2>/dev/null \
     | grep -q '"results"'; then
  ok "race-singlepacket --job-stdin reads a JSON job on stdin and emits a results JSON (the backend contract)"
else
  bad "race-singlepacket --job-stdin did not honour the stdin JSON contract"
fi

# --- 5. the launcher resolves inside the LONG-LIVED engage container --------------------------
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
    if docker exec "$ENGAGE" sh -c "command -v race-singlepacket" >/dev/null 2>&1; then
      ok "docker exec $ENGAGE race-singlepacket — resolves in the running container (this is what a :race job runs)"
    else
      bad "docker exec $ENGAGE race-singlepacket — missing in the running container"
    fi
  fi
else
  printf '  SKIP  live exec — engage sandbox not up (docker compose -f docker/docker-compose.yml up -d)\n'
fi

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
