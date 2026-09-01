# Contributing

Thank you for helping improve EDY ScanURL Family. Contributions should preserve the product’s defensive, consumer-friendly purpose.

## Before opening a change

1. Create a focused branch from the current `main` branch.
2. Install dependencies with `npm ci` using Node.js 24.17.0 or newer.
3. Keep risk, coverage and source availability semantically independent.
4. Add or update tests for functional changes.
5. Run lint, TypeScript, tests, build and the production dependency audit.

## Pull requests

Explain the user problem, the proposed change and how it was validated. Include screenshots for visible changes at mobile and desktop widths. Do not recalibrate score weights, providers or risk/coverage behavior without a dedicated design note and regression tests.

## Test data and privacy

Use fixtures for deterministic tests. Real public-domain checks must be controlled, rate-limited and clearly identified. Never commit browsing history, personal URLs, credentials, tokens, `.env` files, keystores, logs containing identifiers or screenshots with sensitive data.

## Security changes

Security-sensitive findings should follow [SECURITY.md](SECURITY.md), not a public issue. Changes to authentication, SSRF controls, cache behavior or secret handling require focused security tests.
