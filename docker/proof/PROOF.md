# Isolation Proof — HackPit Cockpit sandbox (M1.2)

**Result: ✅ ISOLATION PROVEN.** Recorded 2026-07-23 (UTC) on Docker Desktop 29.1.3
(linux engine, WSL2). Re-run any time with `sh docker/proof/isolation_proof.sh`.

This is the hard gate from `docs/cockpit-plan.md §c Layer 1`: execution code (M1.3)
may be wired **only** because these checks pass. If any regressed, execution must NOT
be wired.

## What was proven
The Kali sandbox (`hackpit-kali-sandbox`) and the lab (`hackpit-lab-target`, OWASP
Juice Shop) share one Docker network declared `internal: true`. On that network:

| # | Check | Expected | Observed |
|---|-------|----------|----------|
| 1 | sandbox → lab (`curl http://hackpit-lab-target:3000/`) | reachable | **HTTP 200** ✅ |
| 2a | sandbox → public IP (`curl http://1.1.1.1/`) | blocked | failed ✅ |
| 2b | sandbox → public host (`curl https://example.com/`) | blocked | failed ✅ |
| 2c | sandbox → external DNS (`getent hosts example.com`) | no resolve | did not resolve ✅ |
| 3 | sandbox → host (`curl http://host.docker.internal/`) | blocked | failed ✅ |

`ca-certificates` is installed in the sandbox, so check 2b fails for lack of a **route**,
not a missing trust root — a fair egress test.

## Why it holds (structural, not filtered)
`docker network inspect hackpit-cockpit_hackpit-isolated`:

```
Internal=true  Driver=bridge
Subnet=172.23.0.0/16  Gateway=172.23.0.1   (reserved, NOT installed as a route)
Containers: hackpit-kali-sandbox=172.23.0.2/16  hackpit-lab-target=172.23.0.3/16
```

The sandbox's kernel routing table (`/proc/net/route`) contains **only** the on-link
subnet route and **no default route**:

```
Iface  Destination  Gateway   Mask       (decoded)
eth0   000017AC     00000000  0000FFFF   172.23.0.0/16 on-link, gateway 0.0.0.0 (none)
```

Because the network is `internal: true`, Docker installs **no default gateway and no
NAT**. There is literally no route off the bridge — the sandbox can address the lab
(same /16) and nothing else. Egress to host/internet is absent by construction, not
blocked by a rule that could be toggled.

## Hardening beyond the network
The sandbox also runs `cap_drop: [ALL]`, `no-new-privileges:true`, and as an
unprivileged user (`sandbox`), per `docker/docker-compose.yml`.

## Reproduce
```
docker compose -f docker/docker-compose.yml up -d --build
sh docker/proof/isolation_proof.sh      # exits 0 only if all checks hold
docker compose -f docker/docker-compose.yml down -v
```

## Raw proof transcript
```
== HackPit Cockpit isolation proof ==
sandbox=hackpit-kali-sandbox  lab=hackpit-lab-target:3000  2026-07-23T19:01:00Z

-- 1. sandbox -> lab  (MUST succeed) --
     HTTP status from lab: 200
  [PASS] sandbox reached the lab (HTTP 200)

-- 2. sandbox -> internet  (MUST fail) --
  [PASS] sandbox could not reach public IP 1.1.1.1
  [PASS] sandbox could not reach https://example.com
     [note] external DNS did not resolve

-- 3. sandbox -> host  (MUST fail) --
  [PASS] sandbox could not reach host.docker.internal

== result: 4 passed, 0 failed ==
ISOLATION PROVEN — safe to wire execution (M1.3).
```
