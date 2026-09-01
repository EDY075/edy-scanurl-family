/* eslint-disable @typescript-eslint/no-deprecated -- SELF is the stable typed service binding in the installed Workers test runtime. */
import { SELF, env, runInDurableObject } from 'cloudflare:test';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { Env } from '../src/types';

const ORIGIN = 'https://edy-scanurl-family-api.test';

describe('Family Worker signed flow', () => {
  beforeAll(() => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL): Promise<Response> => {
      const url = new URL(input instanceof Request ? input.url : input instanceof URL ? input.href : input);
      if (url.hostname === 'cloudflare-dns.com') {
        const type = url.searchParams.get('type');
        const answer = type === 'A' ? [{ type: 1, data: '93.184.216.34' }] : type === 'AAAA' ? []
          : type === 'NS' ? [{ type: 2, data: 'a.iana-servers.net.' }] : type === 'MX' ? [{ type: 15, data: '0 .' }]
            : type === 'CAA' ? [{ type: 257, data: '0 issue "letsencrypt.org"' }] : [{ type: 43, data: '1 13 2 ABCD' }];
        return Promise.resolve(Response.json({ Status: 0, AD: true, Answer: answer }));
      }
      if (url.href === 'https://data.iana.org/rdap/dns.json') return Promise.resolve(Response.json({ services: [[['com'], ['https://rdap.test/']]] }));
      if (url.href === 'https://rdap.test/domain/example.com') return Promise.resolve(Response.json({ events: [{ eventAction: 'registration', eventDate: '1995-08-14T00:00:00Z' }], nameservers: [{ ldhName: 'a.iana-servers.net' }], status: ['active'] }));
      if (url.href === 'https://example.com/') return Promise.resolve(new Response('<!doctype html><title>Example Store</title><p>Contato: ajuda@example.com</p><a href="/privacy">Política de privacidade</a><p>Termos de uso. Entrega e frete.</p>', { headers: { 'content-type': 'text/html; charset=utf-8', 'strict-transport-security': 'max-age=31536000', 'content-security-policy': "default-src 'none'", 'x-content-type-options': 'nosniff' } }));
      if (url.href === 'https://example.com/privacy') return Promise.resolve(new Response('<!doctype html><p>Política de privacidade e termos.</p>', { headers: { 'content-type': 'text/html' } }));
      throw new Error(`UNMOCKED:${url.origin}${url.pathname}`);
    }));
  });
  afterAll(() => vi.unstubAllGlobals());

  it('rejects oversized streaming bodies without trusting Content-Length', async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(4097)); controller.close(); },
    });
    const response = await workerFetch(`${ORIGIN}/family/v1/enroll`, { method: 'POST', body });
    expect(response.status).toBe(413);
    expect(await response.json()).toMatchObject({ code: 'PAYLOAD_TOO_LARGE' });
  });

  it('keeps active quotas when housekeeping removes expired windows', async () => {
    const bindings = env as unknown as Env;
    const stub = bindings.FAMILY.get(bindings.FAMILY.idFromName('quota-retention-test'));
    await runInDurableObject(stub, async (instance, state) => {
      const now = Date.now();
      const active = `3600000:${String(Math.floor(now / 3_600_000))}`;
      const quota = state.storage.sql;
      for (let i = 0; i < 2001; i++) quota.exec('INSERT INTO rates(k,window,n) VALUES(?,?,?)', `test:${String(i)}`, active, 12);
      quota.exec('INSERT INTO rates(k,window,n) VALUES(?,?,?)', 'expired', '3600000:1', 12);
      vi.spyOn(Math, 'random').mockReturnValue(0);
      try { await (instance as { alarm(): Promise<void> }).alarm(); }
      finally { vi.restoreAllMocks(); }
      expect(quota.exec<{ n: number }>('SELECT COUNT(*) AS n FROM rates WHERE window=?', active).one().n).toBe(2001);
      expect(quota.exec<{ n: number }>('SELECT COUNT(*) AS n FROM rates WHERE k=?', 'expired').one().n).toBe(0);
    });
  });

  it('uses a rolling VirusTotal minute even across a clock-minute boundary', async () => {
    const bindings = env as unknown as Env;
    const stub = bindings.FAMILY.get(bindings.FAMILY.idFromName('vt-sliding-test'));
    await runInDurableObject(stub, (instance) => {
      const quota = instance as unknown as { reserveVirusTotal(now: number, amount: number): boolean };
      const base = Math.floor(Date.now() / 60_000) * 60_000;
      for (let i = 0; i < 4; i++) expect(quota.reserveVirusTotal(base + 59_900, 1)).toBe(true);
      expect(quota.reserveVirusTotal(base + 60_100, 1)).toBe(false);
      expect(quota.reserveVirusTotal(base + 119_899, 1)).toBe(false);
      expect(quota.reserveVirusTotal(base + 119_900, 1)).toBe(true);
      return Promise.resolve();
    });
  });

  it('enforces the aggregate family daily budget across devices', async () => {
    const bindings = env as unknown as Env;
    const stub = bindings.FAMILY.get(bindings.FAMILY.idFromName('global-quota-test'));
    await runInDurableObject(stub, (instance) => {
      const quota = instance as unknown as { takeRate(key: string, period: number, maximum: number, now: number): void };
      const now = Date.now();
      for (let i = 0; i < 100; i++) quota.takeRate('family:scan-day', 86_400_000, 100, now);
      expect(() => quota.takeRate('family:scan-day', 86_400_000, 100, now)).toThrow(/RATE_LIMITED/);
      return Promise.resolve();
    });
  });

  it('allows at most two simultaneous scans and releases both slots', async () => {
    const bindings = env as unknown as Env;
    const stub = bindings.FAMILY.get(bindings.FAMILY.idFromName('concurrency-test'));
    await runInDurableObject(stub, async (instance) => {
      const coordinator = instance as unknown as {
        authenticate(request: Request, raw: string, now: number): Promise<string>;
        executeScan(raw: string, owner: string, ip: string, now: number): Promise<Response>;
        createScan(request: Request, ip: string, now: number): Promise<Response>;
      };
      const finish: ((response: Response) => void)[] = [];
      vi.spyOn(coordinator, 'authenticate').mockResolvedValue('test-owner');
      vi.spyOn(coordinator, 'executeScan').mockImplementation(() => new Promise<Response>((resolve) => { finish.push(resolve); }));
      const request = () => new Request(`${ORIGIN}/family/v1/scans`, { method: 'POST', body: '{}' });
      try {
        const first = coordinator.createScan(request(), 'ip:1', Date.now());
        const second = coordinator.createScan(request(), 'ip:2', Date.now());
        await vi.waitFor(() => { expect(finish.length).toBe(2); });
        await expect(coordinator.createScan(request(), 'ip:3', Date.now())).rejects.toThrow(/FAMILY_BUSY/);
        finish[0]?.(Response.json({ ok: true })); finish[1]?.(Response.json({ ok: true }));
        await Promise.all([first, second]);
        const third = coordinator.createScan(request(), 'ip:3', Date.now());
        await vi.waitFor(() => { expect(finish.length).toBe(3); });
        finish[2]?.(Response.json({ ok: true }));
        expect((await third).status).toBe(200);
      } finally { vi.restoreAllMocks(); }
    });
  });

  it('does not let old registrations permanently fill 20 device slots', async () => {
    const bindings = env as unknown as Env;
    const stub = bindings.FAMILY.get(bindings.FAMILY.idFromName('enrollment-lifetime-test'));
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const publicKeySpki = toBase64(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)));
    await runInDurableObject(stub, async (instance, state) => {
      for (let i = 0; i < 20; i++) state.storage.sql.exec('INSERT INTO devices(id,spki,created_at) VALUES(?,?,?)', `test:${String(i)}`, publicKeySpki, Date.now());
      const response = await (instance as { fetch(request: Request): Promise<Response> }).fetch(new Request(`${ORIGIN}/family/v1/enroll`, { method: 'POST', body: JSON.stringify({ publicKeySpki }) }));
      expect(response.status).toBe(200);
      expect(state.storage.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM devices').one().n).toBe(21);
      const deviceId = hex(await crypto.subtle.digest('SHA-256', await crypto.subtle.exportKey('spki', pair.publicKey)));
      state.storage.sql.exec('UPDATE devices SET created_at=? WHERE id=?', Date.now() - 31 * 86_400_000, deviceId);
      vi.spyOn(Math, 'random').mockReturnValue(1);
      try {
        const expired = await (instance as { fetch(request: Request): Promise<Response> }).fetch(new Request(`${ORIGIN}/family/v1/challenge`, {
          method: 'POST', headers: { 'X-EDY-Audience': ORIGIN },
          body: JSON.stringify({ deviceId, method: 'POST', path: '/family/v1/scans', bodyHash: '0'.repeat(64) }),
        }));
        expect(expired.status).toBe(403);
        expect(await expired.json()).toMatchObject({ code: 'FAMILY_DEVICE_NOT_APPROVED' });
        expect(state.storage.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM devices WHERE id=?', deviceId).one().n).toBe(1);
      } finally { vi.restoreAllMocks(); }
      state.storage.sql.exec('UPDATE devices SET created_at=? WHERE id=?', Date.now() - 31 * 86_400_000, 'test:0');
      vi.spyOn(Math, 'random').mockReturnValue(0);
      try { await (instance as { alarm(): Promise<void> }).alarm(); }
      finally { vi.restoreAllMocks(); }
      expect(state.storage.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM devices WHERE id=?', 'test:0').one().n).toBe(0);
    });
  });

  it('auto-enrolls, verifies a one-time device signature and returns then deletes a real report', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const publicKeySpki = toBase64(spki); const deviceId = hex(await crypto.subtle.digest('SHA-256', spki));
    const enrollment = await workerFetch(`${ORIGIN}/family/v1/enroll`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ publicKeySpki }) });
    const enrollmentBody = await enrollment.json();
    expect(enrollment.status, JSON.stringify(enrollmentBody)).toBe(200); expect(enrollmentBody).toMatchObject({ deviceId, status: 'ACTIVE' });

    const scanBody = JSON.stringify({ url: 'https://example.com/private/order?token=secret' });
    const created = await signed(pair.privateKey, deviceId, 'POST', '/family/v1/scans', scanBody);
    expect(created.status).toBe(202);
    const createdBody = await responseRecord(created); const scanId = typeof createdBody.scanId === 'string' ? createdBody.scanId : '';
    expect(scanId).toMatch(/^[a-f0-9-]{36}$/);
    const result = await signed(pair.privateKey, deviceId, 'GET', `/family/v1/scans/${scanId}`, '');
    expect(result.status).toBe(200);
    expect(await result.json()).toMatchObject({ status: 'SUCCEEDED', report: { mode: 'real', inputUrl: 'https://example.com/', technical: { virusTotal: { state: 'DISABLED_NO_CREDENTIALS' } } } });
    const replay = await signed(pair.privateKey, deviceId, 'GET', `/family/v1/scans/${scanId}`, '');
    expect(replay.status).toBe(404);
  });

  it('rejects SSRF before any target request', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)); const publicKeySpki = toBase64(spki); const deviceId = hex(await crypto.subtle.digest('SHA-256', spki));
    await workerFetch(`${ORIGIN}/family/v1/enroll`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ publicKeySpki }) });
    const response = await signed(pair.privateKey, deviceId, 'POST', '/family/v1/scans', JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data/' }));
    expect(response.status).toBe(400); expect(await response.json()).toMatchObject({ code: 'SCAN_REJECTED' });
  });

  it('rate-limits repeated enrollment attempts from one IP', async () => {
    const responses: Response[] = [];
    for (let attempt = 0; attempt < 9; attempt += 1) {
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
      responses.push(await workerFetch(`${ORIGIN}/family/v1/enroll`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'CF-Connecting-IP': '203.0.113.77' },
        body: JSON.stringify({ publicKeySpki: toBase64(spki) }),
      }));
    }
    expect(responses.slice(0, 8).every((response) => response.status === 200)).toBe(true);
    expect(responses[8]?.status).toBe(429);
  });
});

async function signed(key: CryptoKey, deviceId: string, method: 'GET' | 'POST', path: string, body: string): Promise<Response> {
  const bodyHash = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)));
  const challengeResponse = await workerFetch(`${ORIGIN}/family/v1/challenge`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ deviceId, method, path, bodyHash }) });
  expect(challengeResponse.status).toBe(200);
  const challenge = await responseRecord(challengeResponse);
  if (typeof challenge.challengeId !== 'string' || typeof challenge.message !== 'string') throw new Error('INVALID_CHALLENGE_TEST_RESPONSE');
  expect(challenge.message.split('\n')[4]).toMatch(/^[a-zA-Z0-9_-]{32,100}$/);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(challenge.message)));
  return workerFetch(`${ORIGIN}${path}`, { method, headers: { 'content-type': 'application/json', 'X-Family-Device': deviceId, 'X-Family-Challenge': challenge.challengeId, 'X-Family-Signature': toBase64(rawToDer(raw)) }, ...(method === 'POST' ? { body } : {}) });
}
function workerFetch(url: string, init?: RequestInit): Promise<Response> { return SELF.fetch(new Request(url, init)); }
async function responseRecord(response: Response): Promise<Record<string, unknown>> { const value: unknown = await response.json(); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('INVALID_TEST_RESPONSE'); return value as Record<string, unknown>; }
function rawToDer(raw: Uint8Array): Uint8Array { const integer = (part: Uint8Array) => { let index = 0; while (index < part.length - 1 && part[index] === 0) index += 1; const value = [...part.slice(index)]; if ((value[0] ?? 0) >= 128) value.unshift(0); return [2, value.length, ...value]; }; const sequence = [...integer(raw.slice(0, 32)), ...integer(raw.slice(32))]; return new Uint8Array([0x30, sequence.length, ...sequence]); }
function toBase64(value: Uint8Array): string { let text = ''; for (const byte of value) text += String.fromCharCode(byte); return btoa(text); }
function hex(value: ArrayBuffer): string { return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, '0')).join(''); }
