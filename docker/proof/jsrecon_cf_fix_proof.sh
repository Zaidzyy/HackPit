#!/usr/bin/env bash
# Proof for the :jsrecon Cloudflare-403 fix (docker/js_mine.py now fetches via curl-impersonate).
#
# 1) Rebuilds hackpit/kali-sandbox:m1 — the build itself GATES on `js-mine --selftest` (Dockerfile
#    line ~1148), so a broken engine fails the build.
# 2) Runs the in-container probe: the real collect -> mine pipeline against the in-scope Fishbowl
#    bundle. Endpoints > 0 proves the JA3/Cloudflare wall that made :jsrecon return [] is cleared.
#
# The probe is piped in over stdin (python3 - < file) rather than volume-mounted, to dodge
# Windows/MSYS path-rewriting on -v mounts. Read-only recon, in the authorized program scope.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"   # -> repo/docker
cd "$here" || { echo "cannot cd to docker/"; exit 1; }

echo "== 1/2  rebuild hackpit/kali-sandbox:m1 (build-time js-mine --selftest gates it) =="
docker compose -f docker-compose.yml build engage-sandbox || { echo ">> BUILD FAILED"; exit 1; }

echo ""
echo "== 2/2  live collect->mine proof inside the fresh image =="
docker run --rm -i hackpit/kali-sandbox:m1 python3 - < "$here/proof/jsrecon_cf_probe.py"
rc=$?

echo ""
echo "== proof exit: $rc  (0 = PASS: Cloudflare cleared, endpoints mined) =="
exit $rc
