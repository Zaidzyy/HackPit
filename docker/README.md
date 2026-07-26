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

## Sandbox image
`Dockerfile.sandbox` builds **one** image (`hackpit/kali-sandbox:m1`) used by all three
sandbox containers. It is based on `kalilinux/kali-rolling` + `kali-linux-headless`, with
SecLists, the Kali `wordlists` set and the nuclei template repo baked in (the lab sandbox has
no egress, so nothing can be fetched at runtime). Expect a ~8–10 GB image and a long cold
build. PowerShell/.NET tooling (PowerView, Rubeus, Mimikatz, SharpHound) is deliberately
absent — it cannot run on Linux.

## Privilege model
The image's default user is the unprivileged `sandbox`. Elevation lives in the compose
service, not in the image:

| Container | User | Capabilities | Devices | Loot mount |
|---|---|---|---|---|
| `hackpit-kali-sandbox` (lab) | `sandbox` | `cap_drop: ALL` | none | **none** |
| `hackpit-kali-open` (`:kali`) | `sandbox` | `cap_drop: ALL` | none | `/loot` |
| `hackpit-engage-sandbox` | **root** | `ALL` dropped, then Docker's default set + `NET_ADMIN` added | `/dev/net/tun` | `/loot` |

Only the engagement sandbox is elevated, and it is the one that never runs unattended —
every command on it is human-approved. The `cap_add` list is written out in full in
`docker-compose.yml` rather than achieved by deleting `cap_drop: ALL`: same result, but the
privilege boundary is stated in the file instead of inherited from a Docker default. It
covers raw sockets (`-sS`/`-sU`/`-O`, masscan, tcpdump), privileged-port binds (responder,
ntlmrelayx, low-port listeners), VPN, and ordinary root file work including `apt-get`.
`SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE` and `SYS_TIME` are still withheld.

## Loot
`backend/data/engagements` is bind-mounted to `/loot` in the engagement and `:kali`
sandboxes, so `nmap -oA`, `ffuf -o`, `nuclei -o` and downloads survive `docker compose down`.
Each engagement works in `/loot/<engagement_id>` and `:kali` in `/loot/kali`, set per command
with `docker exec -w` — the parent is mounted once because a bind mount is fixed when a
container is created, and these containers are long-lived and shared across engagements.

The isolated lab sandbox deliberately gets **no** mount: it is the container the safety layer
leans on and the host for unattended agent runs, so it is given no writable host directory.
Lab output lives in the run record. See `backend/cockpit/loot.py`.

## Isolation model
The shared network is declared `internal: true`, so Docker attaches **no gateway** —
there is no NAT and no route off the bridge. The sandbox reaches the lab only because
both sit on that one network; it has no path to host or internet by construction.

## Status
- **M1.1:** scaffold only (this README). No compose file, no containers yet.
- **M1.2:** stack + proof. **Requires the Docker daemon running** (Docker Desktop /
  the WSL2 engine). If the proof cannot be run or does not pass, execution is NOT wired.

Nothing in the running app touches Docker until M1.3, and M1.3 is gated on the M1.2 proof.
