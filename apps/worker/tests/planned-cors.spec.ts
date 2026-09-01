import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import worker from '../src/index';
import type { Env } from '../src/types';
import planned from '../../../docs/web-pwa/planned-origin.json';

// Planning only: no deploy, remote configuration, identity storage or secrets.
const origin = planned.PLANNED_ORIGIN;
const audience = 'https://edy-scanurl-family-api.edy-scanurl-family-worker.workers.dev';
const bindings = { ...(env as unknown as Env), WEB_ALLOWED_ORIGINS: origin, ALLOW_BROWSER_REVIEW: 'false' };
const request = (path: string, init: RequestInit = {}, source = origin) => {
  const headers = new Headers(init.headers); headers.set('Origin', source);
  return worker.fetch(new Request(audience + path, { ...init, headers }), bindings);
};
const required = ['content-type', 'x-family-device', 'x-family-challenge', 'x-family-signature'];
function assertCors(response: Response) {
  expect(response.headers.get('Access-Control-Allow-Origin')).toBe(origin);
  expect(response.headers.get('Vary')?.split(',').map(value => value.trim())).toContain('Origin');
  expect(response.headers.get('Access-Control-Allow-Methods')?.split(',').map(value => value.trim())).toEqual(['GET', 'POST', 'OPTIONS']);
  expect(response.headers.get('Access-Control-Allow-Headers')?.toLowerCase().split(',').map(value => value.trim())).toEqual(required);
  expect(response.headers.get('Access-Control-Allow-Credentials')).toBeNull();
  expect(response.headers.get('Access-Control-Expose-Headers')).toBe('Retry-After');
}

describe('planned Pages origin — actual local Worker CORS', () => {
  it('allows the planned production origin on actual GET health', async () => {
    const response = await request('/health');
    expect(response.status).toBe(200); assertCors(response);
    expect(response.headers.get('Cache-Control')).toContain('no-store');
  });
  it('permits complete browser preflight for signed POST scans', async () => {
    const response = await request('/family/v1/scans', { method: 'OPTIONS', headers: { 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': required.join(', ') } });
    expect(response.status).toBe(204); assertCors(response);
  });
  it('returns CORS headers on an actual POST without bypassing authentication', async () => {
    const response = await request('/family/v1/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://example.com/' }) });
    expect(response.status).toBe(403); assertCors(response);
  });
  it.each([['GET', '/health'], ['OPTIONS', '/family/v1/scans'], ['POST', '/family/v1/scans']])('denies unauthorized %s %s without CORS authorization', async (method, path) => {
    const response = await request(path, { method, ...(method === 'POST' ? { body: '{}' } : {}) }, 'https://example-attacker.invalid');
    expect(response.status).toBe(403);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
    expect(response.headers.get('Access-Control-Allow-Credentials')).toBeNull();
  });
  it('keeps DEV origins separate from planned production policy', async () => {
    const response = await request('/health', {}, 'http://127.0.0.1:4182');
    expect(response.status).toBe(403);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
  });
});

it.runIf((env as unknown as { EDY_CORS_LIVE?: string }).EDY_CORS_LIVE === 'true')('completes a signed real-source scan with planned Origin on local workerd', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const enrolled = await request('/family/v1/enroll', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKeySpki: base64(spki) }) });
  expect(enrolled.status).toBe(200); assertCors(enrolled);
  const identity = await object(enrolled);
  if (typeof identity.deviceId !== 'string') throw new Error('LOCAL_TEST_IDENTITY_INVALID');
  async function signed(method: 'GET' | 'POST', path: string, body: string) {
    const bodyHash = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)));
    const challengeResponse = await request('/family/v1/challenge', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ deviceId: identity.deviceId, method, path, bodyHash }) });
    expect(challengeResponse.status).toBe(200); assertCors(challengeResponse);
    const challenge = await object(challengeResponse);
    if (typeof challenge.message !== 'string' || typeof challenge.challengeId !== 'string') throw new Error('LOCAL_TEST_CHALLENGE_INVALID');
    expect(challenge.message.split('\n')[1]).toBe(audience);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(challenge.message)));
    const response = await request(path, { method, headers: { 'Content-Type': 'application/json', 'X-Family-Device': String(identity.deviceId), 'X-Family-Challenge': challenge.challengeId, 'X-Family-Signature': base64(der(raw)) }, ...(method === 'POST' ? { body } : {}) });
    assertCors(response); return response;
  }
  const created = await signed('POST', '/family/v1/scans', JSON.stringify({ url: 'https://example.com/' }));
  expect(created.status).toBe(202);
  const createdBody = await object(created);
  if (typeof createdBody.scanId !== 'string') throw new Error('LOCAL_TEST_SCAN_ID_INVALID');
  const result = await signed('GET', `/family/v1/scans/${createdBody.scanId}`, '');
  expect(result.status).toBe(200);
  const job = await object(result);
  expect(job.status).toBe('SUCCEEDED');
  const report = job.report as { mode: string; domain: string; technical: { virusTotal?: { state: string } }; scannedAt: string };
  expect(report.mode).toBe('real'); expect(report.domain).toBe('example.com');
  expect(report.technical.virusTotal?.state).toBe('DISABLED_NO_CREDENTIALS');
  // Public QA receipt only; never write keys, ids, challenges or signatures.
  const headers: Record<string, string> = {};
  result.headers.forEach((value, name) => { if (name.startsWith('access-control-') || name === 'vary') headers[name] = value; });
  await expect(JSON.stringify({ kind: 'REAL_LOCAL_CORS_WORKER', at: report.scannedAt, origin, domain: report.domain, enrollment: enrolled.status, scanPost: created.status, reportGet: result.status, headers, vt: report.technical.virusTotal?.state }, null, 2)).toMatchFileSnapshot('../../../docs/web-pwa/evidence-review/cors-planned-real.json');
}, 30_000);

async function object(response: Response): Promise<Record<string, unknown>> { return await response.json(); }
function hex(value: ArrayBuffer) { return [...new Uint8Array(value)].map(byte => byte.toString(16).padStart(2, '0')).join(''); }
function base64(value: Uint8Array) { return btoa(String.fromCharCode(...value)); }
function der(raw: Uint8Array) {
  const integer = (part: Uint8Array) => { let start = 0; while (start < part.length - 1 && part[start] === 0) start++; const value = [...part.slice(start)]; if ((value[0] ?? 0) >= 128) value.unshift(0); return [2, value.length, ...value]; };
  const sequence = [...integer(raw.slice(0, 32)), ...integer(raw.slice(32))]; return new Uint8Array([0x30, sequence.length, ...sequence]);
}
