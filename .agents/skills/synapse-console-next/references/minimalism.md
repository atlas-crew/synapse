# Minimalism Policy

The Synapse console-next SPA is deliberately dependency-light. This is not stylistic — it's a shipping constraint.

## Why

- **Embedded in the Rust binary.** Every KB of JS is a KB in the shipped `synapse-waf` binary.
- **Air-gapped deployments.** No CDN fallback. Every dep is bundled.
- **Startup latency.** The admin port may be opened before much of the WAF is ready. A fast-loading console is a diagnostic tool, not a flagship UI.
- **Long-lived on-prem deploys.** Fewer deps = fewer CVEs to chase years after release.

## Allowed

- React + React DOM.
- Tailwind (content-purged, PostCSS).
- A tiny router (e.g. `wouter`) if routing is needed. Avoid full React Router.
- Native `fetch` for admin API calls.
- `zustand` if shared state is unavoidable.

## Discouraged

- Design systems from the Fleet dashboard (`@/ui`, Apparatus tokens). Keep console-next visually distinct and lightweight.
- Chart libraries (Recharts, Chart.js). If you need a chart, consider whether the data belongs on the Fleet dashboard instead.
- Data-grid libraries. Hand-roll tables.
- i18n frameworks. Single-language (English) is fine for the sensor-local console.
- State-management frameworks beyond `zustand` + local state.

## Before Adding a Dependency

1. Can it be a 30-line hand-written helper instead?
2. Is the feature needed on the sensor-local console, or would it fit better on the Fleet dashboard?
3. What does it add to the bundle size?

If adding is still the right call, document the reason in the commit and keep an eye on bundle size via the sync-check script.
