#!/bin/sh
# Entrypoint for the engagement SCOPE-LOCK firewall sidecar.
#
# Installs the DEFAULT-DENY posture immediately (fail-closed: nothing is reachable until the
# backend applies an engagement scope), then holds the network namespace open so the engage
# sandbox — which SHARES this netns (`network_mode: service:engage-firewall`) and runs
# cap_drop:ALL — inherits the filter and cannot alter it.
#
# The backend programs the per-engagement allow-list at ENTER time via:
#   docker exec <firewall> scope_lock.sh apply <resolved-scope...>
# and resets it to deny on EXIT:
#   docker exec <firewall> scope_lock.sh deny
set -eu

/usr/local/bin/scope_lock.sh deny

echo "[scope-lock] netns held open; awaiting an engagement scope (default-DENY until then)."
exec sleep infinity
