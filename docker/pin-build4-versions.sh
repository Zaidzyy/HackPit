#!/bin/sh
# Pin the unpinned installs in Dockerfile.sandbox's build-#4 layer (review finding M2).
#
# WHY THIS IS A SCRIPT AND NOT AN EDIT. Pinning needs the real upstream values — dnscat2 has no
# release tags, so it needs a commit SHA, and the four gems plus donut-shellcode need their
# current versions. Those have to be resolved from the network. The review session that found
# M2 could not reach the network, and writing plausible-looking version numbers into a
# Dockerfile is worse than leaving it unpinned: an invented SHA fails the build at best and
# pins the wrong tree at worst. So it resolves them here, at a moment when the network works.
#
# Run from anywhere:   sh docker/pin-build4-versions.sh
# It rewrites docker/Dockerfile.sandbox IN PLACE, refuses if the expected lines are not found
# exactly as shipped, and verifies its own result before exiting 0.
#
# It does NOT rebuild the image. After it succeeds, the next `docker build` produces a
# reproducible layer; the already-built hackpit-kali:build4 is unaffected until then.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DF="$ROOT/docker/Dockerfile.sandbox"
test -f "$DF" || { echo "FAIL: $DF not found"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "FAIL: need $1 on PATH"; exit 1; }; }
need curl
need python3

# --- resolve ----------------------------------------------------------------
echo "resolving upstream versions..."

DNSCAT2_COMMIT=$(curl -fsSL -H 'User-Agent: hackpit-pin' \
    'https://api.github.com/repos/iagox86/dnscat2/commits?per_page=1' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["sha"])')
case "$DNSCAT2_COMMIT" in
    ????????????????????????????????????????) : ;;
    *) echo "FAIL: dnscat2 commit does not look like a 40-char sha: '$DNSCAT2_COMMIT'"; exit 1 ;;
esac

gem_version() {
    curl -fsSL "https://rubygems.org/api/v1/gems/$1.json" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])'
}
TROLLOP=$(gem_version trollop)
SALSA20=$(gem_version salsa20)
SHA3=$(gem_version sha3)
ECDSA=$(gem_version ecdsa)

DONUT=$(curl -fsSL 'https://pypi.org/pypi/donut-shellcode/json' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["version"])')

for v in "$TROLLOP" "$SALSA20" "$SHA3" "$ECDSA" "$DONUT"; do
    test -n "$v" || { echo "FAIL: an upstream version resolved to empty"; exit 1; }
done

echo "  dnscat2         $DNSCAT2_COMMIT"
echo "  trollop         $TROLLOP"
echo "  salsa20         $SALSA20"
echo "  sha3            $SHA3"
echo "  ecdsa           $ECDSA"
echo "  donut-shellcode $DONUT"

# --- rewrite ----------------------------------------------------------------
# Every substitution below asserts it actually matched, so a Dockerfile that has drifted from
# what this script expects fails loudly instead of being silently half-pinned.
DNSCAT2_COMMIT="$DNSCAT2_COMMIT" TROLLOP="$TROLLOP" SALSA20="$SALSA20" SHA3="$SHA3" \
ECDSA="$ECDSA" DONUT="$DONUT" DF="$DF" python3 - <<'PY'
import os, re, sys

df = os.environ["DF"]
src = open(df, encoding="utf-8").read()
orig = src

def sub(pattern, repl, what):
    global src
    new, n = re.subn(pattern, repl, src, count=1)
    if n != 1:
        sys.exit(f"FAIL: could not find the {what} line to pin "
                 f"(matched {n} times) — Dockerfile.sandbox has drifted; pin it by hand")
    src = new

commit = os.environ["DNSCAT2_COMMIT"]

# 1. dnscat2: shallow clone of master -> full clone + detached checkout of a fixed commit.
sub(r"    git clone --depth 1 https://github\.com/iagox86/dnscat2\.git /opt/dnscat2; \\\n",
    '    git clone https://github.com/iagox86/dnscat2.git /opt/dnscat2; \\\n'
    '    git -C /opt/dnscat2 checkout --detach "${DNSCAT2_COMMIT}"; \\\n',
    "dnscat2 clone")

# 2. the ARG that carries it, declared just above the RUN.
sub(r"(RUN set -eux; \\\n    git clone https://github\.com/iagox86/dnscat2\.git)",
    f"ARG DNSCAT2_COMMIT={commit}\n\\1",
    "dnscat2 ARG insertion point")

# 3. the four gems.
gems = " ".join(f"{g}:{os.environ[e]}" for g, e in
                (("trollop", "TROLLOP"), ("salsa20", "SALSA20"),
                 ("sha3", "SHA3"), ("ecdsa", "ECDSA")))
sub(r"    gem install --no-document trollop salsa20 sha3 ecdsa; \\\n",
    f"    gem install --no-document {gems}; \\\n",
    "gem install")

# 4. donut-shellcode.
sub(r"pip install --no-cache-dir -q donut-shellcode;",
    f"pip install --no-cache-dir -q donut-shellcode=={os.environ['DONUT']};",
    "donut-shellcode pip install")

# 5. the comment that says this block is unpinned is no longer true.
sub(r"#\n# NOT PINNED, and that is a known reproducibility gap \(review finding M2, still open\):"
    r".*?# docker/pin-build4-versions\.sh, which resolves them and rewrites this block in place\.\n",
    "# Pinned by docker/pin-build4-versions.sh: dnscat2 has no release tags, so the client is\n"
    "# built from a fixed commit, and the four gems plus donut-shellcode carry exact versions.\n"
    "# Re-run that script to move the pins forward.\n",
    "M2 comment")

if src == orig:
    sys.exit("FAIL: nothing changed")
open(df, "w", encoding="utf-8", newline="\n").write(src)
print("Dockerfile.sandbox rewritten")
PY

# --- verify -----------------------------------------------------------------
echo "verifying..."
grep -q "^ARG DNSCAT2_COMMIT=" "$DF"       || { echo "FAIL: DNSCAT2_COMMIT ARG missing"; exit 1; }
grep -q 'checkout --detach' "$DF"          || { echo "FAIL: dnscat2 checkout missing"; exit 1; }
grep -q 'trollop:' "$DF"                   || { echo "FAIL: gems not pinned"; exit 1; }
grep -q 'donut-shellcode==' "$DF"          || { echo "FAIL: donut-shellcode not pinned"; exit 1; }
grep -q 'git clone --depth 1 https://github.com/iagox86' "$DF" \
    && { echo "FAIL: the unpinned shallow clone is still there"; exit 1; }

# The Dockerfile lint test in the suite asserts pinning + non-suppressed smoke tests.
"$ROOT/backend/.venv/Scripts/python.exe" "$ROOT/backend/test_evasion.py" \
    || "$ROOT/backend/.venv/bin/python" "$ROOT/backend/test_evasion.py"

echo
echo "OK — build-#4 installs pinned. Commit docker/Dockerfile.sandbox."
echo "The image is NOT rebuilt; hackpit-kali:build4 is unchanged until you rebuild."
