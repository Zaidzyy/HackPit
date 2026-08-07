#!/bin/sh
# Forensics / CTF tooling install proof — the checks a hermetic test CANNOT make.
#
# WHY THIS EXISTS. backend/arsenal/tools.json hardcodes the binary names the forensics-ctf catalog
# entries propose as an approve-each tool pass: `vol`/`vol.py` (the volatility3 entrypoint, in its
# own venv — kali-sandbox image trap), `binwalk`, `foremost`, `scalpel`, `steghide`, `zsteg`,
# `stegseek`, `exiftool` (the libimage-exiftool-perl package ships it), `bulk_extractor` (the
# `bulk-extractor` package ships the underscored binary), and `testdisk`/`photorec` (one package,
# two binaries). Nothing in the Python suite can prove that is what the image actually installs —
# every hermetic test feeds the loader a string it chose itself (the ZAP `zap-baseline.py` and
# build #9 impacket-name gaps). This file checks the names against the built image and, when the
# stack is up, that they resolve in the long-lived engage container.
#
# Run this after `docker compose build`. Every check prints PASS or FAIL and the script exits
# non-zero on the first failure, so a partial run cannot read as a clean one.
#
# Usage:
#   sh docker/proof/forensics_install_proof.sh
#
set -eu

IMAGE="hackpit/kali-sandbox:m1"
ENGAGE="hackpit-engage-sandbox"
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
die() { printf '\nABORT: %s\n' "$1"; exit 2; }

resolves() { # $1 = template head (absolute -> test -x, bare name -> command -v)
  case "$1" in
    /*) docker run --rm "$IMAGE" sh -c "test -x '$1'" >/dev/null 2>&1 ;;
    *)  docker run --rm "$IMAGE" sh -c "command -v '$1'" >/dev/null 2>&1 ;;
  esac
}

printf '\n=== forensics / CTF tooling install proof ===\n\n'

docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not built. Run: docker compose -f docker/docker-compose.yml build engage-sandbox"

# --- 1. THE NAMES. The exact PATH binaries the catalog templates hardcode. ------------------
for prog in vol vol.py binwalk foremost scalpel steghide zsteg stegseek exiftool \
            bulk_extractor testdisk photorec; do
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
smoke vol -h
smoke binwalk --help
smoke foremost -V
smoke steghide --version
smoke exiftool -ver
# bulk_extractor -h prints its banner but exits non-zero, so grep the banner instead of the code.
if docker run --rm "$IMAGE" sh -c "bulk_extractor -h 2>&1 | grep -qi bulk_extractor"; then
  ok "bulk_extractor — the tool starts"
else
  bad "bulk_extractor failed — installed but cannot run"
fi
# zsteg / stegseek print their banner without a clean exit code; grep the banner instead.
if docker run --rm "$IMAGE" sh -c "zsteg --help 2>&1 | grep -qi zsteg"; then
  ok "zsteg — the tool starts"
else
  bad "zsteg failed — installed but cannot run"
fi
if docker run --rm "$IMAGE" sh -c "stegseek 2>&1 | grep -qi stegseek"; then
  ok "stegseek — the tool starts"
else
  bad "stegseek failed — installed but cannot run"
fi
# testdisk / photorec are ncurses tools with no clean --version; assert they are executable.
for prog in testdisk photorec; do
  if docker run --rm "$IMAGE" sh -c "test -x \"\$(command -v $prog)\"" >/dev/null 2>&1; then
    ok "$prog resolves to an executable (interactive ncurses tool — no batch --version)"
  else
    bad "$prog is on PATH but not executable"
  fi
done

# --- 3. every argv[0] the forensics-ctf catalog templates hardcode resolves in the container -
cd "$(dirname "$0")/../../backend" || die "cannot find backend/"
PY=".venv/Scripts/python.exe"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
# space-joined + \r-stripped (Windows python emits CRLF); a `for` loop keeps the counters
# in THIS shell — a `| while` runs in a subshell and silently loses every ok/bad.
HEADS="$("$PY" -c "
import json
cat=json.load(open('arsenal/tools.json'))
heads=set()
for t in cat['tools']:
    if t.get('category')=='forensics-ctf':
        for tpl in t.get('templates',[]):
            parts=tpl['template'].split()
            if parts: heads.add(parts[0])
print(' '.join(sorted(heads)))
" | tr -d '\r')"
for h in $HEADS; do
  [ -n "$h" ] || continue
  if resolves "$h"; then
    ok "forensics-ctf template head '$h' resolves in the image"
  else
    bad "forensics-ctf template head '$h' does NOT resolve — a catalogued invocation would fail"
  fi
done

# --- 4. the launcher resolves inside the LONG-LIVED engage container ------------------------
if docker ps --format '{{.Names}}' | grep -qx "$ENGAGE"; then
  IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null || echo unknown)"
  CONTAINER_IMAGE_ID="$(docker inspect "$ENGAGE" --format '{{.Image}}' 2>/dev/null || echo unknown)"
  if [ "$IMAGE_ID" != "$CONTAINER_IMAGE_ID" ]; then
    bad "$ENGAGE is running a DIFFERENT image than the one just verified. Recreate it:
          docker compose -f docker/docker-compose.yml up -d --force-recreate engage-sandbox"
  else
    ok "the running engage sandbox is the image that was just built and verified"
    for prog in vol binwalk foremost steghide zsteg exiftool bulk_extractor testdisk; do
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
