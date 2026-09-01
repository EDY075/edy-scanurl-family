# Deployment

## Public production

- Web/PWA: [edy-scanurl-family.pages.dev](https://edy-scanurl-family.pages.dev/)
- API: Cloudflare Worker over HTTPS, configured in the production frontend.
- Plan target: Cloudflare Free, with no paid upgrade or billing requirement assumed by this repository.

Current classification: **FINAL WEB BUILD DEPLOYED — READY FOR FINAL PHYSICAL CONFIRMATION**.

`FINAL PRODUCTION VALIDATED` is intentionally not used until the final physical device confirmation is complete.

## Separation of responsibilities

Cloudflare Pages serves versioned static frontend assets. Cloudflare Workers performs defensive network checks, server-only VirusTotal access, abuse controls and result sanitization. The Android APK uses the same public HTTPS API and contains no deployment or administrative credential.

## Release controls

Deployment requires explicit owner authorization. This public document intentionally omits account identifiers, API tokens, secret values, signing credentials and one-click deployment instructions.

A controlled release must verify:

1. lint, TypeScript, tests and production build;
2. dependency and secret scans;
3. public CSP, CORS and service worker behavior;
4. real analyses without mocked production results;
5. Worker health and versioned API schema;
6. final physical PWA and Android confirmation.

## Android artifacts

The signed release APK is intentionally excluded from Git history. If authorized later, publish the already verified file as a GitHub Release asset and record its filename, byte size, version and SHA-256. Do not rebuild or resign it as part of a documentation-only release.

## Rollback

Keep frontend and Worker releases independently reversible. Never place credentials in a rollback artifact. A service-disable mechanism should remain available for abuse response without deleting source or public documentation.
