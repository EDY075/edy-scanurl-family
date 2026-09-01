// QA-only local runtime. No remote management API, deployment or secrets.
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { createServer } from 'node:http';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
const bundle = await build({ entryPoints: [resolve(root, 'apps/worker/src/index.ts')], bundle: true, write: false, format: 'esm', platform: 'browser', target: 'es2022' });
const runtime = new Miniflare(convertV4MiniflareOptions({
  host: '127.0.0.1', port: 0, cf: false,
  durableObjectsPersist: resolve(root, '.cache/web-pwa-local-worker'),
  workers: [{ name: 'family-local',
  modules: true, script: bundle.outputFiles[0].text, compatibilityDate: '2026-08-22',
  durableObjects: { FAMILY: { className: 'FamilyCoordinator', useSQLite: true } },
  bindings: {
    SERVICE_ENABLED: 'true', VIRUSTOTAL_ENABLED: 'false', ALLOW_BROWSER_REVIEW: 'false',
    // Public test fixture, not a production credential. Same as isolated unit tests.
    RATE_LIMIT_SECRET: 'local-test-rate-limit-secret-with-32-bytes',
  }, }],
}));
// The local transport dispatches in workerd under the normal HTTPS audience.
// Only provider fetches leave this machine; application requests stay local.
const audience = 'https://edy-scanurl-family-api.edy-scanurl-family-worker.workers.dev';
const reviewOrigins = new Set(['http://127.0.0.1:4181', 'http://127.0.0.1:4182']);
const server = createServer(async (request, response) => {
  try {
    if (request.headers.host !== '127.0.0.1:8790' || (request.headers.origin && !reviewOrigins.has(request.headers.origin))) { response.writeHead(403).end(); return; }
    if (request.method === 'POST' && !request.headers['content-type']?.startsWith('application/json')) { response.writeHead(415).end(); return; }
    const path = request.url ?? '/';
    if (!/^\/(?:health|family\/v1\/)/.test(path)) { response.writeHead(404).end(); return; }
    let size = 0; const chunks = [];
    for await (const chunk of request) { size += chunk.length; if (size > 4096) { response.writeHead(413).end(); return; } chunks.push(chunk); }
    const headers = new Headers();
    for (const name of ['content-type', 'x-family-device', 'x-family-challenge', 'x-family-signature']) {
      const value = request.headers[name]; if (typeof value === 'string') headers.set(name, value);
    }
    headers.set('Origin', 'https://localhost');
    const result = await runtime.dispatchFetch(`${audience}${path}`, {
      method: request.method, headers,
      ...(request.method === 'POST' ? { body: Buffer.concat(chunks) } : {}),
    });
    response.writeHead(result.status, Object.fromEntries(result.headers));
    response.end(Buffer.from(await result.arrayBuffer()));
  } catch { response.writeHead(503, { 'Content-Type': 'application/json' }).end('{"code":"LOCAL_RUNTIME_UNAVAILABLE"}'); }
});
server.requestTimeout = 25_000;
server.listen(8790, '127.0.0.1', () => console.log('REAL local Worker: http://127.0.0.1:8790 — VT not consulted; production untouched.'));
async function stop() { server.close(); await runtime.dispose(); }
process.once('SIGINT', () => { void stop(); });
process.once('SIGTERM', () => { void stop(); });
