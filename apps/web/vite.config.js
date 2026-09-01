var _a;
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';
import { DEFAULT_API_ORIGIN } from './src/web-pwa/services/api-origin';
// Explicit legacy review/native builds retain their original entry and output.
var webPwa = process.env.VITE_FAMILY_BROWSER_REVIEW === undefined;
var publicOrigin = new URL((_a = process.env.VITE_API_BASE_URL) !== null && _a !== void 0 ? _a : DEFAULT_API_ORIGIN).origin;
if (!publicOrigin.startsWith('https://'))
    throw new Error('The public API requires HTTPS.');
var policy = "default-src 'self'; base-uri 'none'; object-src 'none'; form-action 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' ".concat(publicOrigin, "; manifest-src 'self'; worker-src 'self'");
var securityHeaders = { 'Content-Security-Policy': "".concat(policy, "; frame-ancestors 'none'"), 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()', 'Cache-Control': 'no-cache' };
// Developer-only preview routing; never read or bundled by the client/APK.
var familyProxy = process.env.FAMILY_WORKER_REVIEW === 'true'
    ? { target: publicOrigin, changeOrigin: true, headers: { Origin: 'https://localhost' } }
    : { target: 'http://127.0.0.1:8788', changeOrigin: false };
export default defineConfig({
    plugins: [
        { name: 'family-web-entry', transformIndexHtml: { order: 'pre', handler: function (html) { return webPwa ? html.replace('/src/main.tsx', '/src/web-pwa/main.tsx').replace(/(<meta http-equiv="Content-Security-Policy" content=")[^"]+/, "$1".concat(policy)) : html; } } },
        react(),
        VitePWA({
            registerType: 'autoUpdate',
            includeAssets: ['favicon-concept04.svg', 'favicon-concept04-16.png', 'favicon-concept04-32.png', 'favicon-concept04-48.png', 'apple-touch-icon-concept04.png', 'pwa-concept04-monochrome.svg'],
            manifest: {
                name: 'EDY ScanURL Family',
                short_name: 'EDY Family',
                description: 'Ajuda para conferir uma loja antes de comprar.',
                theme_color: '#0f1412',
                background_color: webPwa ? '#0b1414' : '#f6f4ee',
                display: 'standalone',
                id: '/',
                scope: '/',
                orientation: 'any',
                start_url: '/',
                lang: 'pt-BR',
                categories: ['shopping', 'security', 'utilities'],
                icons: [
                    { src: '/pwa-concept04-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
                    { src: '/pwa-concept04-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
                    { src: '/pwa-concept04-maskable-192.png', sizes: '192x192', type: 'image/png', purpose: 'maskable' },
                    { src: '/pwa-concept04-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
                    { src: '/pwa-concept04.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
                    { src: '/pwa-concept04-maskable.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'maskable' },
                    { src: '/pwa-concept04-monochrome.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'monochrome' }
                ]
            },
            workbox: {
                navigateFallbackDenylist: [/^\/api\//, /^\/family(?:\/|$)/, /^\/health(?:\/|$)/],
                runtimeCaching: []
            }
        })
    ],
    build: { outDir: webPwa ? process.env.VITE_WEB_LOCAL_PROXY === 'true' ? 'dist-web-local' : 'dist-web' : 'dist' },
    server: {
        port: 4180,
        strictPort: true,
        proxy: { '/family': familyProxy, '/health': familyProxy }
    },
    preview: {
        port: 4180,
        strictPort: true,
        headers: webPwa ? securityHeaders : {},
        proxy: { '/family': familyProxy, '/health': familyProxy }
    },
    test: {
        environment: 'jsdom',
        setupFiles: './src/test/setup.ts',
        css: true
    }
});
