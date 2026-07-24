#!/bin/sh
# SCOPE-LOCK — the per-engagement egress allow-list for the engagement sandbox's shared netns.
#
# This REPLACES the old Wall-A denylist (default-ACCEPT, drop RFC1918). The model is now
# DEFAULT-DENY: nothing leaves the netns except loopback and the ONE authorized engagement
# scope. The operator's host/gateway, any LAN outside scope, cloud metadata (169.254/16),
# IPv6 (unless the scope is v6), and the entire rest of the internet are dropped by the
# default policy — no explicit denylist to keep in sync.
#
# Everything the engagement sandbox sends is generated in THIS netns, so it hits these OUTPUT
# rules. A packet to a scope IP is ACCEPTed (and NAT'd out via the gateway — it only TRANSITS
# the gateway); every other destination hits the default DROP.
#
# Usage (run inside the NET_ADMIN firewall sidecar):
#   scope_lock.sh deny                          -> default-DENY, NO scope (fail-closed; entry state)
#   scope_lock.sh apply <ip|cidr> [<ip|cidr>..] -> default-DENY + ALLOW only the given scope(s)
#
# The backend applies `apply <resolved-scope>` on engagement ENTER and `deny` on EXIT, and
# re-reads `iptables -S OUTPUT` (assert_scope_locked) before every engagement exec so a flushed
# or widened ruleset fails the gate.
set -eu

# Reset one family to default-DENY: drop everything, allow only loopback (incl. Docker's
# embedded DNS at 127.0.0.11, which is loopback — but note we inject /etc/hosts for the scope
# name so no external DNS egress is needed or opened).
lock_family() {
  fw="$1"
  command -v "$fw" >/dev/null 2>&1 || return 0
  "$fw" -P OUTPUT DROP 2>/dev/null || return 0   # v6 may be disabled in the netns -> skip
  "$fw" -F OUTPUT
  "$fw" -A OUTPUT -o lo -j ACCEPT
}

cmd="${1:-deny}"
lock_family iptables
lock_family ip6tables

if [ "$cmd" = "apply" ]; then
  shift
  [ "$#" -gt 0 ] || { echo "[scope-lock] ERROR: apply needs at least one scope token" >&2; exit 2; }
  for scope in "$@"; do
    case "$scope" in
      *:*) ip6tables -A OUTPUT -d "$scope" -j ACCEPT ;;   # IPv6 address / CIDR
      *)   iptables  -A OUTPUT -d "$scope" -j ACCEPT ;;    # IPv4 address / CIDR
    esac
  done
  echo "[scope-lock] applied scope allow-list: $*"
else
  echo "[scope-lock] default-DENY installed; NO scope reachable (fail-closed)."
fi

echo "[scope-lock] v4 OUTPUT:"; iptables -S OUTPUT
if command -v ip6tables >/dev/null 2>&1; then
  echo "[scope-lock] v6 OUTPUT:"; ip6tables -S OUTPUT 2>/dev/null || echo "  (ip6tables unavailable)"
fi
