<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.
<!-- END:nextjs-agent-rules -->

# Lint baseline (accepted — do NOT "fix" blindly)

`npm run lint` reports **11** `react-hooks/set-state-in-effect` errors + warnings. These are an **accepted pre-existing baseline** (CI in `.github/workflows/ci.yml` fails only if the error count rises *above* 11). They are deliberate, correct patterns (matchMedia init, fetch-reset on dep change, reveal animations) that Next 16's stricter `eslint-config-next` flags. **`next build` passes (exit 0)** — Turbopack build does not run ESLint — so only `npm run lint` is affected, not the production build. Auto-fixing risks breaking the reveal/data-load animations; defer to a deliberate, tested hooks refactor.

**Adding code that auto-loads/polls in an effect:** routing the `setState` into an async callback (`void load()`) does **not** dodge this rule — Next 16 flags *calling* a setState-carrying callback from an effect regardless of the `await`. When the pattern is deliberate (a deep-link auto-load, a status poll), pin a `// eslint-disable-next-line react-hooks/set-state-in-effect` on that exact line with a one-line justification, so the counted baseline stays at 11 and the CI gate stays tight for genuinely careless new effects. See `TokenCrackPanel`, `CockpitKillchain`, `CockpitCloudGraph` for the established form.
