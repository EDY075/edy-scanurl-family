# Changelog

All notable public changes to EDY ScanURL Family are documented here.

## [Unreleased]

- Final physical confirmation on desktop/mobile devices.
- Optional publication of the existing signed APK as a GitHub Release asset, subject to separate authorization.

## [0.1.0] - 2026-08-31

### Added

- Independent Family edition for Web, Desktop PWA, Mobile PWA and Android/Capacitor.
- Public Cloudflare Pages frontend and separate Cloudflare Worker API.
- Simple Portuguese recommendations, evidence grouping and local optional history.
- Dark, light and system themes.
- Offline PWA shell with safe blocking of new scans while offline.
- Real DNS, RDAP, public-source and server-side VirusTotal integrations.

### Changed

- Risk and analysis coverage are presented independently.
- Missing, unavailable and not-checked evidence remains neutral.
- Technical copy now uses “Força da conclusão” and explains weighted coverage.

### Security

- Added SSRF protection, rate limiting, request limits, sanitized logging and server-only secrets.
- Prevented analysis responses and credentials from being cached by the service worker.
