# HackPit Docs

Project documentation lives here (architecture notes, design decisions,
runbooks). Populated as the project grows.

## Cockpit (live, human-approved execution vs an isolated lab)

- [`cockpit-plan.md`](cockpit-plan.md) — Phase-0 scope, architecture, and safety-by-design.
  **Status: M1 (execution) + M2 (cinematic UI) + M3 (engagement integration) complete.**
- [`COCKPIT-SESSION-LOG.md`](COCKPIT-SESSION-LOG.md) — per-increment build + verification log
  for the unsupervised Cockpit sessions.
- [`ENGAGEMENT-LOOP-REAL-TARGET.md`](ENGAGEMENT-LOOP-REAL-TARGET.md) — the guided loop on a REAL
  authorized target: the program-scope model (hosts, `*.wildcards`, CIDRs, `!exclusions`), the
  scope-aware proposer + target-lock, recon-driven expansion, the network posture (Wall A DOWN),
  the never-auto-run proof, and the honest UI.
- [`AD-GRAPH.md`](AD-GRAPH.md) — the AD attack-path graph: BloodHound collection → typed graph →
  route to Domain Admin → animated cockpit UI with KB-grounded, gated abuse steps. Collector +
  parser + path engine + walk-the-path wiring; every AD command routes through the gated executor.
  Built against synthetic data; live collection/execution deferred to an AD lab.
- [`C2-SESSION-PANEL.md`](C2-SESSION-PANEL.md) — the live session panel: catch and drive ONE
  interactive shell by hand. Session-START is a gated command (approve + heuristic red-confirm +
  mode gate); a live session's stdin is HUMAN-ONLY (source-scan locked, like `:kali`); containment
  is the mode it started in (lab isolation / engagement scope-lock); the transcript is recorded to
  the report. LAB e2e verified; engagement e2e deferred to a human-present session.

Safety invariants that hold across all Cockpit work: four independent gates (allowlist → target
lock → approval → isolation), recon-only allowlist, lab-only target, no autonomy. M3 only *records*
what M1 already runs and adds planning-side scope + reporting; it does not touch the execution path.

**Re-verify the safety invariants in one command** (they are regression-locked by automated tests
that fail loudly if the model is weakened — see `backend/README.md`):

```sh
sh backend/run_safety_tests.sh              # hermetic: the four gates + composer + engagement/report
sh backend/run_safety_tests.sh --with-proof # + the live Docker isolation proof (stack must be up)
```
