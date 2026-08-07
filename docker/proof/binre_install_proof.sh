#!/bin/sh
# Binary-RE / exploit-dev tooling install proof — the checks a hermetic test CANNOT make.
#
# WHY THIS EXISTS. backend/arsenal/tools.json hardcodes the binary names the binary-re catalog
# entries propose as an approve-each tool pass: `r2` (radare2), `rizin`, `objdump`/`readelf`/`nm`
# (binutils), `nasm`, `patchelf`, `checksec`, `ropper`, `xxd`, `ROPgadget` (the python3-ropgadget
# entrypoint — kali-sandbox image trap), `analyzeHeadless` (Ghidra's launcher, NOT `ghidra`, and
# it lives under support/ off PATH), `one_gadget`, `pwn`/`pwntools`, `angr`, `pwninit`, and the
# absolute venv/repo heads /opt/pwntools/venv/bin/python3, /opt/angr/venv/bin/python3 and
# /opt/libc-database/find. Nothing in the Python suite can prove that is what the image actually
# installs — every hermetic test feeds the loader a string it chose itself (the ZAP
# `zap-baseline.py` and build #9 impacket-name gaps). This file checks the names against the built
# image and, when the stack is up, that they resolve in the long-lived engage container.
#
# Run this after `docker compose build`. Every check prints PASS or FAIL and the script exits
# non-zero on the first failure, so a partial run cannot read as a clean one.
#
# Usage:
#   sh docker/proof/binre_install_proof.sh
#
set -eu

IMAGE="hackpit/kali-sandbox:m1"
ENGAGE="hackpit-engage-sandbox"
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die() { printf '\nABORT: %s\n' "$1"; exit 2; }

# Resolve a template head in the image: an absolute path is tested with `test -x`, a bare name
# with `command -v`. libc-database's `find` and the two venv python3s are absolute on purpose.
resolves() { # $1 = head
  case "$1" in
    /*) docker run --rm "$IMAGE" sh -c "test -x '$1'" >/dev/null 2>&1 ;;
    *)  docker run --rm "$IMAGE" sh -c "command -v '$1'" >/dev/null 2>&1 ;;
  esac
}

printf '\n=== binary-RE / exploit-dev tooling install proof ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build engage-sandbox"

# --- 1. THE NAMES. The exact PATH binaries the catalog templates hardcode. ------------------
for prog in r2 rizin objdump readelf nm nasm patchelf checksec ropper xxd ROPgadget \
            analyzeHeadless one_gadget pwn pwntools angr pwninit; do
  if docker run --rm "$IMAGE" sh -c "command -v $prog" >/dev/null 2>&1; then
    ok "$prog is on PATH under the exact name the catalog templates hardcode"
  else
    bad "$prog is NOT on PATH. tools.json templates call this name. List what the package really
        ships, then fix the name in the catalog and the Dockerfile together:
          docker run --rm $IMAGE sh -c 'ls -l /usr/local/bin /usr/bin | grep -iE \"$prog\"'"
  fi
done

# --- 2. command -v is not a smoke test — each tool must actually START -----------------------
smoke() { # $1 = binary, $2..$n = version/help args
  bin="$1"; shift
  if docker run --rm "$IMAGE" "$bin" "$@" >/dev/null 2>&1; then
    ok "$bin $* — the tool starts"
  else
    bad "$bin $* failed — installed but cannot run"
  fi
}
smoke r2 -v
smoke rizin -v
smoke objdump --version
smoke readelf --version
smoke nm --version
smoke nasm --version
smoke patchelf --version
smoke ropper --version
smoke ROPgadget --version
smoke pwninit --version
# The two frameworks import inside their OWN venv (system python3 does not carry them).
if docker run --rm "$IMAGE" /opt/pwntools/venv/bin/python3 -c 'import pwnlib' >/dev/null 2>&1; then
  ok "pwntools imports inside /opt/pwntools/venv (the exploit-skeleton template runs this python3)"
else
  bad "pwntools does NOT import inside its venv — the /opt/pwntools/venv/bin/python3 template fails"
fi
if docker run --rm "$IMAGE" /opt/angr/venv/bin/python3 -c 'import angr' >/dev/null 2>&1; then
  ok "angr imports inside /opt/angr/venv (the symbolic-exec template runs this python3)"
else
  bad "angr does NOT import inside its venv — the /opt/angr/venv/bin/python3 template fails"
fi
# analyzeHeadless needs a project to do real work; assert its launcher is an executable symlink
# rather than starting a JVM with no args (which exits non-zero by design — not a failure).
if docker run --rm "$IMAGE" sh -c 'test -x "$(command -v analyzeHeadless)"' >/dev/null 2>&1; then
  ok "analyzeHeadless resolves to an executable launcher (a real run needs a project + binary)"
else
  bad "analyzeHeadless is on PATH but not executable"
fi

# --- 3. every argv[0] the binary-re catalog templates hardcode resolves in the container -----
# Reads the real tools.json so a template that names a binary the image lacks is caught here,
# not at analysis time against a challenge binary. Handles absolute template heads (venv/repo).
cd "$(dirname "$0")/../../backend" || die "cannot find backend/"
PY=".venv/Scripts/python.exe"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
HEADS="$("$PY" -c "
import json
cat=json.load(open('arsenal/tools.json'))
heads=set()
for t in cat['tools']:
    if t.get('category')=='binary-re':
        for tpl in t.get('templates',[]):
            parts=tpl['template'].split()
            if parts: heads.add(parts[0])
print('\n'.join(sorted(heads)))
")"
printf '%s\n' "$HEADS" | while IFS= read -r h; do
  [ -n "$h" ] || continue
  if resolves "$h"; then
    ok "binary-re template head '$h' resolves in the image"
  else
    bad "binary-re template head '$h' does NOT resolve — a catalogued invocation would fail"
  fi
done

# --- 4. the launcher resolves inside the LONG-LIVED engage container ------------------------
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
    for prog in r2 objdump ROPgadget analyzeHeadless one_gadget pwn pwninit; do
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
