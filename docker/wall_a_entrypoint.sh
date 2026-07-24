#!/bin/sh
# WALL A — the egress filter for the engagement sandbox's shared network namespace.
#
# Installs OUTPUT DROP rules for the operator's host + LAN + link-local/metadata, leaving
# the public internet reachable, then holds the namespace open. Everything the engagement
# sandbox sends is generated in THIS netns, so it hits these OUTPUT rules.
#
# The DROP rules match on DESTINATION address:
#   - a packet to a PUBLIC IP (e.g. 45.33.32.156) is ACCEPTed and NAT'd out via the bridge
#     gateway — it only TRANSITS the gateway, its destination is public;
#   - a packet whose DESTINATION is the gateway/host, the LAN, or 169.254.x is DROPped.
# So "reach the internet, never turn inward" holds without breaking NAT egress.
set -eu

# Blocked destinations (keep in lockstep with backend cockpit/config.py WALL_A_BLOCKED).
BLOCK="169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

# Default-accept policy; loopback + the embedded DNS resolver (127.0.0.11) stay reachable.
iptables -P OUTPUT ACCEPT
iptables -F OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT

# Wall A: drop the inward destinations. 127.0.0.11 (Docker embedded DNS) is loopback, so it
# is already allowed above and is NOT in any blocked range.
for net in $BLOCK; do
  iptables -A OUTPUT -d "$net" -j DROP
done

echo "[wall-a] installed OUTPUT DROP for: $BLOCK"
echo "[wall-a] internet reachable; host/LAN/metadata blocked. holding netns open."
iptables -S OUTPUT

# Hold the namespace open so the sandbox can keep sharing it.
exec sleep infinity
