# Security policy

## Supported version

Security fixes target the current `main` branch and the latest published Web/PWA build. Android release artifacts are supported only when their checksum is listed in the project documentation.

## Reporting a vulnerability

Do not publish exploit details, credentials, tokens, personal data or a live vulnerable URL in a public issue. Use a private GitHub Security Advisory after the repository is created, or another private channel explicitly published by the maintainers.

Include the affected component, reproduction steps using non-sensitive test data, observed impact and suggested mitigation. The maintainers will acknowledge the report, validate it and communicate remediation status through the same private channel.

## Scope

Reports are welcome for the Web/PWA, Cloudflare Worker API, Android wrapper, authentication flow, SSRF defenses, service worker cache and accidental secret exposure. Automated tests must avoid disruptive traffic and must not target third-party stores without authorization.

## Secrets

Never include Cloudflare tokens, VirusTotal keys, signing material, `.env` files, private keys or production credentials in reports, commits, screenshots or logs. If exposure is suspected, revoke or rotate the credential through its provider before sharing sanitized evidence.
