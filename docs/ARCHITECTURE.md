# Architecture

EDY ScanURL Family is an independent, defensive application with one shared product experience across Web/PWA and Android.

## Runtime topology

```text
React Web/PWA ─┐
Desktop PWA ───┼── HTTPS ── Cloudflare Worker API ── public technical sources
Mobile PWA ────┤                    │
Android app ───┘                    └── VirusTotal (server-side secret)
```

The public frontend is hosted on Cloudflare Pages. The production API is a separate Cloudflare Worker. Android embeds the same approved Web experience through Capacitor and points to the public HTTPS API.

## Main components

- `apps/web`: React, TypeScript, Vite and PWA resources.
- `apps/worker`: Family Worker, request policy, providers and public API contract.
- `apps/api`: preserved Node backend for local development and compatibility; it is not required by the public Family runtime.
- `packages/core`: shared evidence, score, risk and coverage models.
- `android`: Capacitor Android wrapper and native security configuration.
- `tests`: browser and end-to-end regression scenarios.

## Analysis pipeline

1. Input is normalized to a supported HTTP(S) target.
2. The domain is validated and reduced to its registrable form when appropriate.
3. Private, loopback, link-local and cloud-metadata destinations are rejected.
4. Providers collect bounded technical and public evidence.
5. Evidence is classified as positive, warning, negative, missing, unavailable or not checked.
6. Risk and coverage are calculated independently.
7. The API returns a sanitized, versioned result for presentation.

Missing, unavailable and not-checked states do not become risk by themselves. Low coverage can coexist with no relevant negative evidence.

## PWA behavior

The service worker caches the static application shell and selected public assets. Analysis responses, authentication material and secrets are excluded from runtime caching. Offline mode can reopen the shell but cannot create a new analysis.

## State and privacy

Optional history and theme preference live on the user device. The server does not persist browsing history. Rate-limiting state uses the Worker-compatible binding configured for the Family service and is not exposed to clients.

## Compatibility

The public API contract remains backward-compatible with approved clients. The Node and Worker implementations are separate so the original backend can remain preserved while the Family production runtime stays compatible with Cloudflare Workers Free.
