<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.
<!-- END:nextjs-agent-rules -->

# Lint baseline (accepted — do NOT "fix" blindly)

`npm run lint` reports 10 `react-hooks/set-state-in-effect` errors + 1 `react-hooks/refs` warning. These are an **accepted pre-existing baseline** (present on `main`; byte-identical). They are deliberate, correct patterns (matchMedia init, fetch-reset on dep change, reveal animations) that Next 16's stricter `eslint-config-next` flags. **`next build` passes (exit 0)** — Turbopack build does not run ESLint — so only `npm run lint` is affected, not the production build. Auto-fixing risks breaking the reveal/data-load animations; defer to a deliberate, tested hooks refactor. When adding code, route new `setState` through async callbacks (not the effect body) so the count stays at baseline.
