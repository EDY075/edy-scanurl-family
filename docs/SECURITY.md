# Security architecture

## Trust boundaries

The browser and Android client are untrusted presentation layers. All external network intelligence and VirusTotal access occur in the Cloudflare Worker. Public clients never receive provider credentials or deployment authority.

## Request controls

- only supported HTTP(S) inputs are accepted;
- URLs and hostnames are normalized before use;
- localhost, private, loopback, link-local and cloud metadata ranges are blocked;
- redirects are bounded and each destination remains subject to policy;
- external requests use timeouts and response-size limits;
- rate limiting constrains device/IP abuse;
- the service can be disabled without exposing an administrative endpoint to clients.

## Secret handling

VirusTotal and Cloudflare credentials remain provider-side secrets. They are excluded from Git, `.env.example`, client bundles, Android assets, service worker caches, screenshots, reports and logs. Public configuration contains only the authorized HTTPS API origin.

## Data minimization

The server does not retain browsing history. Logs are minimal and sanitized. Caches may contain public analysis data only; sensitive headers, authentication material and per-user history are excluded.

## Browser security

The production frontend uses a restrictive Content Security Policy, HTTPS-only API connectivity and explicit CORS behavior. User-provided text is rendered as data, not executable markup. The service worker caches the static shell but does not replay an old analysis as a new result.

## Android security

The release wrapper disables cleartext traffic and backups and is built as non-debuggable. No VirusTotal key, Cloudflare token, private key, keystore or administrative URL belongs in the APK.

## Responsible disclosure

See the repository-level [Security policy](../SECURITY.md) for private reporting guidance.
