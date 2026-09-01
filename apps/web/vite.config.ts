import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";
import { DEFAULT_API_ORIGIN } from "./src/web-pwa/services/api-origin.js";

// Explicit legacy review/native builds retain their original entry and output.
const webPwa = process.env.VITE_FAMILY_BROWSER_REVIEW === undefined;
const publicOrigin = new URL(
  process.env.VITE_API_BASE_URL ?? DEFAULT_API_ORIGIN,
).origin;
if (!publicOrigin.startsWith("https://"))
  throw new Error("The public API requires HTTPS.");
const siteOrigin = process.env.VITE_WEB_PUBLIC_ORIGIN;
if (
  siteOrigin &&
  (new URL(siteOrigin).origin !== siteOrigin ||
    !/^https:\/\/[a-z0-9.-]+$/.test(siteOrigin))
)
  throw new Error(
    "The public site origin must be an exact trusted HTTPS origin.",
  );
const socialMetadata = `<meta property="og:type" content="website" /><meta property="og:title" content="EDY ScanURL Family" /><meta property="og:description" content="Antes de comprar, verifique o site. Mais clareza. Menos risco." /><meta name="twitter:title" content="EDY ScanURL Family" /><meta name="twitter:description" content="Antes de comprar, verifique o site. Mais clareza. Menos risco." />${siteOrigin ? `<meta name="twitter:card" content="summary_large_image" /><meta property="og:url" content="${siteOrigin}/" /><meta property="og:image" content="${siteOrigin}/og.png" /><meta name="twitter:image" content="${siteOrigin}/og.png" /><meta property="og:image:alt" content="EDY ScanURL Family. Antes de comprar, verifique o site. Mais clareza. Menos risco." />` : '<meta name="twitter:card" content="summary" />'}`;
const policy = `default-src 'self'; base-uri 'none'; object-src 'none'; form-action 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' ${publicOrigin}; manifest-src 'self'; worker-src 'self'`;
const securityHeaders = {
  "Content-Security-Policy": `${policy}; frame-ancestors 'none'`,
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cache-Control": "no-cache",
};

// Developer-only preview routing; never read or bundled by the client/APK.
const familyProxy =
  process.env.EDY_WEB_LOCAL_WORKER === "true"
    ? { target: "http://127.0.0.1:8790", changeOrigin: true }
    : process.env.FAMILY_WORKER_REVIEW === "true"
    ? {
        target: publicOrigin,
        changeOrigin: true,
        headers: { Origin: "https://localhost" },
      }
    : { target: "http://127.0.0.1:8788", changeOrigin: false };

export default defineConfig({
  plugins: [
    {
      name: "web-response-headers",
      generateBundle() {
        if (webPwa) this.emitFile({ type: 'asset', fileName: 'robots.txt', source: 'User-agent: *\nAllow: /\n' });
        if (webPwa)
          this.emitFile({
            type: "asset",
            fileName: "_headers",
            source: `/*\n${Object.entries(securityHeaders)
              .map(([name, value]) => `  ${name}: ${value}`)
              .join(
                "\n",
              )}\n\n/assets/*\n  Cache-Control: public, max-age=31536000, immutable\n`,
          });
      },
    },
    {
      name: "family-web-entry",
      transformIndexHtml: {
        order: "pre",
        handler: (html) =>
          webPwa
            ? html
                .replace("/src/main.tsx", "/src/web-pwa/main.tsx")
                .replace("</head>", `${socialMetadata}</head>`)
                .replace(
                  /(<meta http-equiv="Content-Security-Policy" content=")[^"]+/,
                  `$1${policy}`,
                )
            : html,
      },
    },
    react(),
    VitePWA({
      registerType: webPwa ? 'prompt' : 'autoUpdate',
      includeAssets: [
        "favicon-concept04.svg",
        "favicon-concept04-16.png",
        "favicon-concept04-32.png",
        "favicon-concept04-48.png",
        "apple-touch-icon-concept04.png",
        "pwa-concept04-monochrome.svg",
      ],
      manifest: {
        name: "EDY ScanURL Family",
        short_name: "EDY Family",
        description: "Ajuda para conferir uma loja antes de comprar.",
        theme_color: "#0f1412",
        background_color: webPwa ? "#0b1414" : "#f6f4ee",
        display: "standalone",
        id: "/",
        scope: "/",
        orientation: "any",
        start_url: "/",
        lang: "pt-BR",
        categories: ["shopping", "security", "utilities"],
        icons: [
          {
            src: "/pwa-concept04-192.png",
            sizes: "192x192",
            type: "image/png",
            purpose: "any",
          },
          {
            src: "/pwa-concept04-512.png",
            sizes: "512x512",
            type: "image/png",
            purpose: "any",
          },
          {
            src: "/pwa-concept04-maskable-192.png",
            sizes: "192x192",
            type: "image/png",
            purpose: "maskable",
          },
          {
            src: "/pwa-concept04-maskable-512.png",
            sizes: "512x512",
            type: "image/png",
            purpose: "maskable",
          },
          {
            src: "/pwa-concept04.svg",
            sizes: "any",
            type: "image/svg+xml",
            purpose: "any",
          },
          {
            src: "/pwa-concept04-maskable.svg",
            sizes: "any",
            type: "image/svg+xml",
            purpose: "maskable",
          },
          {
            src: "/pwa-concept04-monochrome.svg",
            sizes: "any",
            type: "image/svg+xml",
            purpose: "monochrome",
          },
        ],
      },
      workbox: {
        navigateFallbackDenylist: [
          /^\/api\//,
          /^\/family(?:\/|$)/,
          /^\/health(?:\/|$)/,
        ],
        runtimeCaching: [],
      },
    }),
  ],
  build: {
    outDir: webPwa
      ? process.env.VITE_WEB_LOCAL_PROXY === "true"
        ? "dist-web-local"
        : "dist-web"
      : "dist",
  },
  server: {
    port: 4180,
    strictPort: true,
    proxy: { "/family": familyProxy, "/health": familyProxy },
  },
  preview: {
    port: 4180,
    strictPort: true,
    headers: webPwa ? securityHeaders : {},
    proxy: { "/family": familyProxy, "/health": familyProxy },
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    css: true,
  },
});
