# HackPit Cockpit — sandbox & lab (Docker)

This directory holds the **isolated two-container stack** the Cockpit executes against.
It is created in **M1.2** and is the hard safety gate for everything after it.

## What lands here in M1.2
- `docker-compose.yml` — two services on one `internal: true` network:
  - `hackpit-kali-sandbox` — the Kali container the backend `docker exec`s into.
  - `hackpit-lab-target` — the self-hosted vulnerable app (OWASP Juice Shop; DVWA fallback).
- `proof/` — the isolation-proof harness + its recorded evidence:
  - sandbox **CAN** reach the lab (`curl http://hackpit-lab-target:3000`).
  - sandbox **CANNOT** reach the internet.
  - sandbox **CANNOT** reach the host.

## Isolation model
The shared network is declared `internal: true`, so Docker attaches **no gateway** —
there is no NAT and no route off the bridge. The sandbox reaches the lab only because
both sit on that one network; it has no path to host or internet by construction.

## Status
- **M1.1:** scaffold only (this README). No compose file, no containers yet.
- **M1.2:** stack + proof. **Requires the Docker daemon running** (Docker Desktop /
  the WSL2 engine). If the proof cannot be run or does not pass, execution is NOT wired.

Nothing in the running app touches Docker until M1.3, and M1.3 is gated on the M1.2 proof.
