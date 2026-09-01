# Testing

This document records the public-repository preparation gates. Results must reflect commands actually executed; historical baselines are not silently promoted to current passes.

## Required gates

| Gate | Command or method | Result |
|---|---|---|
| Unit/integration suite | `npm test` | PASS — 587 passed, 10 skipped |
| Lint | `npm run lint` | PASS |
| TypeScript | `npm run typecheck` | PASS |
| Monorepo build | `npm run build` | PASS — Worker command used `--dry-run`; no deploy |
| Web production build | `npm run web:build` | PASS |
| Web E2E | `npm run web:e2e` | PASS — 5 passed, 1 offline-real scenario skipped by this configuration |
| Web security | `npm run web:security` | PASS — no violations |
| Production dependency audit | `npm run audit:prod` | PASS — 0 vulnerabilities |
| Repository secret scan | curated candidate-file scan | PASS — 256 text files, 0 real credentials |
| Existing APK | verifier + Android signature tool | PASS — preserved, signed, no secret markers |

## Behavioral invariants

- missing evidence is not a warning or failure;
- unavailable is not a failure;
- not checked is not a warning;
- zero negative evidence is not presented as multiple risks;
- risk and analysis coverage remain independent;
- offline mode never fabricates or replays a new analysis;
- public production results use real providers, not fixtures.

## Visual coverage

The public screenshots cover desktop and mobile home states, real desktop and mobile analysis results, conclusion strength, coverage explanation and the complete mobile PWA page. Responsive validation targets mobile, tablet and desktop widths in both light and dark themes.

## Physical confirmation

Automated PWA and Android verification does not replace the final physical device check. Until that check is complete, the project remains **READY FOR FINAL PHYSICAL CONFIRMATION**, not `FINAL PRODUCTION VALIDATED`.

## Current execution notes

The workspace test total is the sum reported by the API (136), Web (291), Worker (127) and Core (33) suites. Skips are explicit conditional/live cases, not hidden failures. The Web E2E run performed a genuine Worker analysis and exercised responsive, accessibility, history, copy and offline-cache behavior. The dedicated network-offline scenario is maintained separately and was skipped by the normal Web E2E configuration; previously captured validation evidence is not counted as a new execution here.

The secret scan reported four assigned values, all confined to test fixtures or local-only test configuration. Their values were not printed or copied into documentation. No Cloudflare token, VirusTotal key, GitHub token, private key, personal path or replacement character was found in the candidate public text files.
