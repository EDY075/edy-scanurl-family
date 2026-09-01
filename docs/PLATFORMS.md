# Platform inventory

## Supported experiences

| Platform | Implementation | Status |
|---|---|---|
| Web | React/Vite on Cloudflare Pages | Production |
| Desktop Browser | Responsive Web application | Supported |
| Desktop PWA | Manifest + service worker + standalone display | Supported; final physical confirmation pending |
| Mobile Web | Mobile-first responsive layout | Supported |
| Mobile PWA | Installable Web app and offline shell | Supported |
| Android | Capacitor package `com.edy.scanurl.family` | Signed release exists; final physical confirmation pending |
| iPhone/iPad | Browser/PWA experience | Web/PWA only |

## Explicit non-support

- There is no native Windows executable or separate desktop wrapper.
- There is no native macOS package.
- There is no native iOS project or App Store package.
- The server does not run on the user’s computer and the public app does not require a LAN address.

## PWA capabilities

The manifest uses `display: standalone`, root scope and root start URL. The service worker provides an offline shell, avoids analysis-response caching and recovers without reinstalling after connectivity returns.

## Android inventory

- app name: `EDY ScanURL Family`;
- application ID: `com.edy.scanurl.family`;
- versionName: `1.0`;
- versionCode: `1`;
- share target: Android `ACTION_SEND` for plain-text links;
- network security: cleartext disabled;
- backup: disabled;
- release build: non-debuggable;
- APK: 3,395,141 bytes;
- SHA-256: `689ccdd7d821b241d0440e588f76390008e746336d8b55db4e4428f9593ed535`.

The APK is a release artifact, not a source file. It remains outside Git and is eligible only for a separately authorized GitHub Release.
