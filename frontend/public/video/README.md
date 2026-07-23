# Cockpit video backdrops

Decorative amber loops behind the cockpit command-center (M2). Placed here locally;
the `.mp4` files are **gitignored** (they're large — ~22MB total) so the repo stays
code-only. The UI degrades gracefully to a CSS gradient when a file is absent, so
nothing breaks without them.

Expected files (drop them in this folder):

| File | Role |
|------|------|
| `hero-loop.mp4` | ambient page background behind the cockpit |
| `cockpit-map.mp4` | darkened backdrop behind the attack-map centerpiece |
| `waveform.mp4` | accent texture under the live-execution panel |
| `reticle.mp4` | optional crosshair-assemble sting (loading / intro) |

All are treated as decorative: muted, looped, `playsinline`, lazy-loaded, and paused
(showing the fallback) under `prefers-reduced-motion`.

**Committing them:** Zaid's call — either commit directly, move to Git LFS, or serve
from a CDN. Until then they live only on the local machine and the fallback covers CI.
