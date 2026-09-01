import { randomUUID } from 'node:crypto';
import { createApp } from '../../apps/api/dist/src/app.js';

const fakeOrchestrator = {
  create: () => ({ scanId: randomUUID(), status: 'QUEUED', progress: { completed: 0, total: 0, current: 'QUEUED' } }),
  get: () => undefined,
};
const app = createApp({ orchestrator: fakeOrchestrator });
const checks = [];

function assert(name, condition, detail) {
  checks.push({ name, pass: Boolean(condition), detail });
  if (!condition) throw new Error(`${name}: ${detail}`);
}

try {
  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address();
  if (!address || typeof address === 'string') throw new Error('DAST_LISTENER_UNAVAILABLE');
  const base = `http://127.0.0.1:${address.port}`;

  const health = await fetch(`${base}/health`);
  assert('security headers', health.headers.get('x-content-type-options') === 'nosniff' && health.headers.get('cache-control') === 'no-store, private', `status=${health.status}`);

  const cors = await fetch(`${base}/health`, { headers: { origin: 'https://unapproved.example' } });
  assert('CORS fail closed', cors.status === 403 && (await cors.json()).code === 'ORIGIN_NOT_ALLOWED', `status=${cors.status}`);

  const injection = '<script>alert(1)</script>';
  const xss = await fetch(`${base}/api/v1/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: injection }) });
  const xssBody = await xss.text();
  assert('input reflection', xss.status === 400 && !xssBody.includes(injection), `status=${xss.status}`);

  const privateTarget = await fetch(`${base}/api/v1/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'http://127.0.0.1/latest/meta-data' }) });
  assert('SSRF literal IP', privateTarget.status === 400 && (await privateTarget.json()).reason === 'IP_LITERAL', `status=${privateTarget.status}`);

  const malformed = await fetch(`${base}/api/v1/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' });
  const malformedBody = await malformed.text();
  assert('malformed JSON', malformed.status === 400 && !/stack|SyntaxError/i.test(malformedBody), `status=${malformed.status}`);

  const oversized = await fetch(`${base}/api/v1/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: `https://${'a'.repeat(17_000)}.example` }) });
  assert('body limit', oversized.status === 413 && (await oversized.json()).code === 'PAYLOAD_TOO_LARGE', `status=${oversized.status}`);

  const rateResponses = [];
  for (let index = 0; index < 13; index += 1) {
    rateResponses.push(await fetch(`${base}/api/v1/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'https://example.com/' }) }));
  }
  const lastRate = rateResponses.at(-1);
  assert('per-IP rate limit', lastRate?.status === 429 && Number(lastRate.headers.get('retry-after')) >= 1, `status=${lastRate?.status ?? 0}`);

  process.stdout.write(`${JSON.stringify({ status: 'PASS', checks }, null, 2)}\n`);
} finally {
  await app.close();
}
