#!/bin/sh
# Request-smuggling prober install proof — the checks a hermetic test CANNOT make.
#
# WHY THIS EXISTS. The :smuggle job invokes `smuggle-probe --job-stdin` inside the open sandbox, and
# the arsenal names `smuggler.py` and `h2csmuggler` for manual use. Nothing in the Python suite can
# prove those names resolve in the BUILT image or that the h2 framing library actually imports —
# every hermetic test feeds the loader a string it chose itself (the ZAP `zap-baseline.py` and
# build #9 impacket-name gaps). This file checks the names against the built image and the
# LONG-LIVED engage container, and proves the engine loads and honours the stdin contract.
#
# Run this after `docker compose build`. Every check prints PASS or FAIL and the script exits
# non-zero on the first failure, so a partial run cannot read as a clean one.
#
# Usage:
#   sh docker/proof/smuggle_install_proof.sh
set -eu

IMAGE="hackpit/kali-sandbox:m1"
ENGAGE="hackpit-engage-sandbox"
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die() { printf '\nABORT: %s\n' "$1"; exit 2; }

printf '\n=== request-smuggling prober install proof ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build engage-sandbox"

# --- 1. THE NAME the :smuggle job's docker exec hardcodes resolves on PATH -------------------
if docker run --rm "$IMAGE" sh -c "command -v smuggle-probe" >/dev/null 2>&1; then
  ok "smuggle-probe is on PATH under the exact name backend/cockpit/smuggle.py invokes"
else
  bad "smuggle-probe is NOT on PATH — the :smuggle job's 'docker exec … smuggle-probe' would fail"
fi

# --- 2. command -v is not a smoke test — the engine must actually LOAD (build #4's lesson) ---
if docker run --rm "$IMAGE" smuggle-probe --selftest 2>&1 | grep -qi 'smuggle-probe ok'; then
  ok "smuggle-probe --selftest loads (builds every h1 mutation template + both parsers)"
else
  bad "smuggle-probe --selftest did NOT load — the engine cannot even import"
fi

# --- 3. the HTTP/2 downgrade variants' framing library is really in the venv -----------------
# The h1 mutations are pure stdlib; H2.CL/H2.TE/H2.0 need h2. A missing h2 does not break detection
# (it degrades H2.* to an honest inconclusive note) but the DEFAULT install must carry it. NB: pass
# the absolute venv path INSIDE `sh -c` with a leading `exec`, not as a bare argv token — Git Bash /
# MSYS rewrites a lone `/opt/...` argument before docker sees it (the race proof's Windows gotcha).
if docker run --rm "$IMAGE" sh -c 'exec /opt/smuggle/venv/bin/python3 -c "import h2, hyperframe"' >/dev/null 2>&1; then
  ok "h2 + hyperframe import inside /opt/smuggle/venv (the H2.* downgrade variants + h2csmuggler)"
else
  bad "h2/hyperframe do NOT import inside /opt/smuggle/venv — H2.* would be inconclusive on every run"
fi

# --- 4. it runs the SAME argv the backend runs: --job-stdin, request on stdin -----------------
# Feed a tiny detect job with an unresolvable host so nothing leaves the box, and assert the engine
# answers with well-formed JSON carrying a verdicts array (an error row is a valid result here — the
# point is that the stdin contract works, not that a fake host answers).
JOB='{"url":"http://127.0.0.1:1/x","method":"POST","headers":[],"body":"x=1","mutations":["CL.TE","TE.CL"],"stage":"detect","timeout":2}'
if printf '%s' "$JOB" | docker run --rm -i "$IMAGE" smuggle-probe --job-stdin 2>/dev/null \
     | grep -q '"verdicts"'; then
  ok "smuggle-probe --job-stdin reads a JSON job on stdin and emits a verdicts JSON (the backend contract)"
else
  bad "smuggle-probe --job-stdin did not honour the stdin JSON contract"
fi

# --- 5. the confirm stage answers on its own contract too ------------------------------------
JOB2='{"url":"http://127.0.0.1:1/x","headers":[],"mutations":["CL.TE"],"stage":"confirm","timeout":2}'
if printf '%s' "$JOB2" | docker run --rm -i "$IMAGE" smuggle-probe --job-stdin 2>/dev/null \
     | grep -q '"confirms"'; then
  ok "smuggle-probe --stage confirm emits a confirms JSON (the separately-approved confirmation path)"
else
  bad "smuggle-probe --stage confirm did not honour the confirm stdin contract"
fi

# --- 6. the external CL/TE and h2c tools the arsenal names resolve + load --------------------
if docker run --rm "$IMAGE" sh -c "command -v smuggler.py" >/dev/null 2>&1 \
   && docker run --rm "$IMAGE" smuggler.py -h 2>&1 | grep -qi 'smuggler\|usage\|-u'; then
  ok "smuggler.py (defparam) resolves on PATH and runs -h (the arsenal's manual CL/TE prober)"
else
  bad "smuggler.py did not resolve/run — the arsenal names it"
fi
if docker run --rm "$IMAGE" sh -c "command -v h2csmuggler" >/dev/null 2>&1 \
   && docker run --rm "$IMAGE" h2csmuggler -h 2>&1 | grep -qi 'usage\|h2c\|-x\|smuggl'; then
  ok "h2csmuggler (BishopFox) resolves on PATH and runs -h (the arsenal's h2c-upgrade smuggler)"
else
  bad "h2csmuggler did not resolve/run — the arsenal names it"
fi

# --- 7. the engine resolves inside the LONG-LIVED engage container ---------------------------
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
    if docker exec "$ENGAGE" sh -c "command -v smuggle-probe" >/dev/null 2>&1; then
      ok "docker exec $ENGAGE smuggle-probe — resolves in the running container (this is what a :smuggle job runs)"
    else
      bad "docker exec $ENGAGE smuggle-probe — missing in the running container"
    fi
  fi
else
  printf '  SKIP  live exec — engage sandbox not up (docker compose -f docker/docker-compose.yml up -d)\n'
fi

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
