#!/usr/bin/env bash
# Proof for the :recon/nuclei "templates are not installed" fix.
#
# ROOT CAUSE: nuclei v3 resolves templates at $HOME/nuclei-templates, but the image only
# symlinked the baked set into $HOME/.local/nuclei-templates — and NOTHING into /root (the
# engage sandbox runs as root). So nuclei found nothing, tried to install (no egress), and
# exited 1 with "no templates provided for scan". FIX: symlink the baked templates into BOTH
# $HOME/nuclei-templates and $HOME/.local/nuclei-templates for BOTH root and sandbox, gated at
# build time by `test -d $HOME/nuclei-templates/http`.
#
# This rebuilds the image (also carries the js-mine CF fix, cached) and proves at RUNTIME, with
# NO NETWORK, that nuclei resolves + validates the baked templates as ROOT — i.e. exactly the
# engage sandbox. --network none is the point: before the fix, with no egress nuclei could not
# install and failed; after it, the baked set is used offline.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; cd "$here" || { echo "cannot cd to docker/"; exit 1; }

echo "== 1/2  rebuild hackpit/kali-sandbox:m1 (build-time nuclei symlink gate must pass) =="
docker compose -f docker-compose.yml build engage-sandbox || { echo ">> BUILD FAILED"; exit 1; }

echo ""
echo "== 2/2  runtime proof — nuclei loads baked templates OFFLINE, as root (the engage sandbox) =="
out=$(docker run --rm --network none --user root hackpit/kali-sandbox:m1 bash -lc '
  set -e
  echo "HOME=$HOME uid=$(id -u)"
  echo "symlink:"; ls -ld "$HOME/nuclei-templates" || true
  test -d "$HOME/nuclei-templates/http" && echo "http_category_present: OK"
  echo "nuclei -validate (no target, no egress):"
  DISABLE_UPDATE_CHECK=true nuclei -validate -t http/misconfiguration/ -silent 2>&1 | tail -4
' 2>&1)
echo "$out"
echo "---"
if echo "$out" | grep -qiE "not installed|could not find template|no templates provided"; then
  echo ">> RESULT: FAIL — nuclei still cannot find templates"; exit 1
fi
if echo "$out" | grep -qi "http_category_present: OK"; then
  echo ">> RESULT: PASS — nuclei resolves + validates baked templates offline (no egress)"; exit 0
fi
echo ">> RESULT: INCONCLUSIVE — inspect the output above"; exit 2
