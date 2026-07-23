# HackPit Docs

Project documentation lives here (architecture notes, design decisions,
runbooks). Populated as the project grows.

## Cockpit (live, human-approved execution vs an isolated lab)

- [`cockpit-plan.md`](cockpit-plan.md) — Phase-0 scope, architecture, and safety-by-design.
  **Status: M1 (execution) + M2 (cinematic UI) + M3 (engagement integration) complete.**
- [`COCKPIT-SESSION-LOG.md`](COCKPIT-SESSION-LOG.md) — per-increment build + verification log
  for the unsupervised Cockpit sessions.

Safety invariants that hold across all Cockpit work: four independent gates (allowlist → target
lock → approval → isolation), recon-only allowlist, lab-only target, no autonomy. M3 only *records*
what M1 already runs and adds planning-side scope + reporting; it does not touch the execution path.
