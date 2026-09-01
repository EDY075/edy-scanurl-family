import { collectScanEvidence } from './providers';
import { buildScanReport } from './report';
import { normalizeTarget, SafeScanError } from './security';
import type { Env, ScanJob } from './types';

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };
const DEVICE_ID = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const SCAN_PATH = /^\/family\/v1\/scans\/[a-f0-9-]{36}$/;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    const cors = allowedOrigin(origin, env);
    if (origin && !cors) return hardened(json({ code: 'ORIGIN_NOT_ALLOWED' }, 403));
    if (request.method === 'OPTIONS' && url.pathname.startsWith('/family/v1/')) return hardened(corsHeaders(new Response(null, { status: 204 }), cors));
    if (url.pathname === '/health' && request.method === 'GET') return hardened(corsHeaders(json({ status: env.SERVICE_ENABLED === 'true' ? 'ok' : 'disabled', mode: 'FAMILY_WORKER', persistence: 'durable-object-sqlite', authentication: 'DEVICE_SIGNATURE' }, env.SERVICE_ENABLED === 'true' ? 200 : 503), cors));
    if (env.SERVICE_ENABLED !== 'true') return hardened(corsHeaders(json({ code: 'SERVICE_DISABLED' }, 503), cors));
    if (!env.RATE_LIMIT_SECRET || env.RATE_LIMIT_SECRET.length < 32) return hardened(corsHeaders(json({ code: 'SERVICE_CONFIGURATION_INVALID' }, 503), cors));
    if (!isRoute(request.method, url.pathname)) return hardened(corsHeaders(json({ code: 'NOT_FOUND' }, 404), cors));
    const headers = new Headers(request.headers);
    headers.set('X-EDY-Audience', url.origin);
    headers.set('X-EDY-IP', request.headers.get('CF-Connecting-IP') ?? 'local');
    headers.delete('CF-Connecting-IP');
    const coordinator = env.FAMILY.get(env.FAMILY.idFromName('family-v1'));
    try {
      const response = await coordinator.fetch(new Request(request, { headers }));
      return hardened(corsHeaders(response, cors));
    } catch { return hardened(corsHeaders(json({ code: 'FAMILY_UNAVAILABLE' }, 503), cors)); }
  },
} satisfies ExportedHandler<Env>;

export class FamilyCoordinator implements DurableObject {
  private readonly sql: SqlStorage;
  private readonly rateKey: Promise<CryptoKey>;
  private activeScans = 0;

  constructor(private readonly state: DurableObjectState, private readonly env: Env) {
    this.sql = state.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, spki TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY, device_id TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, body_hash TEXT NOT NULL, message TEXT NOT NULL, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS rates(k TEXT NOT NULL, window TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY(k,window));
      CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, owner TEXT NOT NULL, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS vt_quota(window TEXT PRIMARY KEY, n INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS vt_calls(at_ms INTEGER NOT NULL, n INTEGER NOT NULL);
    `);
    if (!this.sql.exec('SELECT window FROM vt_quota WHERE window=?', 'migration:sliding-v1').toArray()[0]) {
      // Conservatively bridge older fixed-minute accounting during upgrade.
      if (this.sql.exec('SELECT window FROM vt_quota WHERE window LIKE ? AND n>0 LIMIT 1', 'm:%').toArray()[0]) this.sql.exec('INSERT INTO vt_calls(at_ms,n) VALUES(?,4)', Date.now());
      this.sql.exec('INSERT INTO vt_quota(window,n) VALUES(?,1)', 'migration:sliding-v1');
    }
    this.rateKey = crypto.subtle.importKey('raw', new TextEncoder().encode(env.RATE_LIMIT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  }

  async fetch(request: Request): Promise<Response> {
    const now = Date.now(); this.cleanup(now);
    const url = new URL(request.url);
    const ipKey = `ip:${await this.ipDigest(request.headers.get('X-EDY-IP') ?? 'unknown')}`;
    try {
      if (url.pathname === '/family/v1/enroll' && request.method === 'POST') return await this.enroll(request, ipKey, now);
      if (url.pathname === '/family/v1/challenge' && request.method === 'POST') return await this.challenge(request, ipKey, now);
      if (url.pathname === '/family/v1/scans' && request.method === 'POST') return await this.createScan(request, ipKey, now);
      if (SCAN_PATH.test(url.pathname) && request.method === 'GET') return await this.getScan(request, now);
      return json({ code: 'NOT_FOUND' }, 404);
    } catch (error) {
      if (error instanceof FamilyWorkerError) return json({ code: error.code }, error.status, error.status === 429 ? { 'Retry-After': String(error.retryAfter) } : undefined);
      if (error instanceof SafeScanError) {
        const sourceFailure = /^DNS_(?:HTTP_|RUNTIME_|INVALID_|SOURCE_|NO_PUBLIC_ADDRESS)/.test(error.code);
        return json({ code: sourceFailure ? 'SOURCE_UNAVAILABLE' : 'SCAN_REJECTED', reason: error.code }, sourceFailure ? 503 : 400);
      }
      return json({ code: 'FAMILY_UNAVAILABLE' }, 503);
    }
  }

  private async enroll(request: Request, ipKey: string, now: number): Promise<Response> {
    // The app rechecks enrollment on launch and before scanning. Bound all calls,
    // while keeping the stricter quota for genuinely new device keys.
    this.takeRate(`${ipKey}:enroll-ingress`, 3_600_000, 120, now);
    this.takeRate(`${ipKey}:enroll-ingress-day`, 86_400_000, 500, now);
    const body = await requestJson(request);
    const spki = typeof body.publicKeySpki === 'string' ? body.publicKeySpki : '';
    if (!spki || spki.length > 256 || !/^[A-Za-z0-9+/]+={0,2}$/.test(spki)) throw new FamilyWorkerError('INVALID_REQUEST', 400);
    const bytes = decodeBase64(spki);
    if (bytes.byteLength < 64 || bytes.byteLength > 128) throw new FamilyWorkerError('INVALID_DEVICE_KEY', 400);
    try { await crypto.subtle.importKey('spki', bytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']); }
    catch { throw new FamilyWorkerError('INVALID_DEVICE_KEY', 400); }
    const deviceId = await sha256Hex(bytes);
    const existing = this.sql.exec<{ id: string }>('SELECT id FROM devices WHERE id=? AND created_at>=?', deviceId, now - 30 * 86_400_000).toArray()[0];
    if (!existing) {
      this.takeRate(`${ipKey}:new-device`, 3_600_000, 8, now);
      this.takeRate(`${ipKey}:new-device-day`, 86_400_000, 20, now);
      // Public automatic onboarding cannot prove family membership. Bound new
      // identities per day, not with permanent slots that an attacker can fill.
      this.takeRate('family:new-device-day', 86_400_000, 40, now);
      this.sql.exec('INSERT INTO devices(id,spki,created_at) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET created_at=excluded.created_at', deviceId, spki, now);
    }
    return json({ deviceId, status: 'ACTIVE' });
  }

  private async challenge(request: Request, ipKey: string, now: number): Promise<Response> {
    this.takeRate(`${ipKey}:challenge`, 3_600_000, 180, now);
    const body = await requestJson(request);
    const deviceId = typeof body.deviceId === 'string' ? body.deviceId : '';
    const method = body.method === 'GET' || body.method === 'POST' ? body.method : '';
    const path = typeof body.path === 'string' ? body.path : '';
    const bodyHash = typeof body.bodyHash === 'string' ? body.bodyHash : '';
    if (!DEVICE_ID.test(deviceId) || !HASH.test(bodyHash) || !allowedSignedPath(method, path)) throw new FamilyWorkerError('INVALID_REQUEST', 400);
    if (!this.sql.exec<{ id: string }>('SELECT id FROM devices WHERE id=? AND created_at>=?', deviceId, now - 30 * 86_400_000).toArray()[0]) throw new FamilyWorkerError('FAMILY_DEVICE_NOT_APPROVED', 403);
    this.takeRate(`device:${deviceId}:challenge`, 3_600_000, 180, now);
    const challengeId = crypto.randomUUID();
    const audience = request.headers.get('X-EDY-Audience') ?? '';
    if (!/^https:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(audience) && !(this.env.ALLOW_BROWSER_REVIEW === 'true' && /^http:\/\/127\.0\.0\.1:\d+$/.test(audience))) throw new FamilyWorkerError('FAMILY_AUDIENCE_INVALID', 503);
    // Keep the existing Android protocol: line 5 is a random nonce, not a date.
    const nonce = hex(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const message = ['EDY-FAMILY-V1', audience, deviceId, challengeId, nonce, method, path, bodyHash].join('\n');
    this.sql.exec('INSERT INTO challenges(id,device_id,method,path,body_hash,message,expires_at) VALUES(?,?,?,?,?,?,?)', challengeId, deviceId, method, path, bodyHash, message, now + 90_000);
    return json({ challengeId, message, expiresAt: new Date(now + 90_000).toISOString() });
  }

  private async createScan(request: Request, ipKey: string, now: number): Promise<Response> {
    const raw = await requestText(request);
    const owner = await this.authenticate(request, raw, now);
    if (this.activeScans >= 2) throw new FamilyWorkerError('FAMILY_BUSY', 429, 15);
    this.activeScans += 1;
    try { return await this.executeScan(raw, owner, ipKey, now); }
    finally { this.activeScans -= 1; }
  }

  private async executeScan(raw: string, owner: string, ipKey: string, now: number): Promise<Response> {
    this.takeRate('family:scan-day', 86_400_000, 100, now);
    this.takeRate(`${ipKey}:scan`, 3_600_000, 20, now);
    this.takeRate(`${ipKey}:scan-day`, 86_400_000, 60, now);
    this.takeRate(`device:${owner}:scan`, 3_600_000, 12, now);
    this.takeRate(`device:${owner}:scan-day`, 86_400_000, 40, now);
    let body: Record<string, unknown>;
    try { body = JSON.parse(raw) as Record<string, unknown>; } catch { throw new FamilyWorkerError('INVALID_REQUEST', 400); }
    if (typeof body.url !== 'string' || Object.keys(body).length !== 1) throw new FamilyWorkerError('INVALID_REQUEST', 400);
    const target = normalizeTarget(body.url);
    const scanId = crypto.randomUUID();
    const vtAllowed = () => this.reserveVirusTotal(Date.now(), 1);
    let job: ScanJob;
    try {
      const collected = await collectScanEvidence(target.url.toString(), this.env, undefined, vtAllowed);
      const report = buildScanReport(scanId, collected);
      job = { scanId, status: 'SUCCEEDED', progress: { completed: 5, total: 5, current: 'COMPLETE' }, report };
    } catch (error) {
      if (error instanceof SafeScanError) throw error;
      job = { scanId, status: 'FAILED', progress: { completed: 0, total: 5, current: 'FAILED' }, error: 'SOURCE_COLLECTION_FAILED' };
    }
    this.sql.exec('INSERT INTO jobs(id,owner,payload,expires_at) VALUES(?,?,?,?)', scanId, owner, JSON.stringify(job), now + 10 * 60_000);
    if (await this.state.storage.getAlarm() === null) await this.state.storage.setAlarm(Date.now() + 60_000);
    return json({ scanId, status: 'QUEUED' }, 202);
  }

  private async getScan(request: Request, now: number): Promise<Response> {
    const raw = '';
    const owner = await this.authenticate(request, raw, now);
    const scanId = new URL(request.url).pathname.split('/').at(-1) ?? '';
    if (!UUID.test(scanId)) throw new FamilyWorkerError('INVALID_SCAN_ID', 400);
    const row = this.sql.exec<{ owner: string; payload: string }>('SELECT owner,payload FROM jobs WHERE id=?', scanId).toArray()[0];
    if (row?.owner !== owner) throw new FamilyWorkerError('SCAN_NOT_FOUND', 404);
    this.sql.exec('DELETE FROM jobs WHERE id=?', scanId);
    return new Response(row.payload, { status: 200, headers: JSON_HEADERS });
  }

  private async authenticate(request: Request, rawBody: string, now: number): Promise<string> {
    const deviceId = request.headers.get('X-Family-Device') ?? '';
    const challengeId = request.headers.get('X-Family-Challenge') ?? '';
    const signature = request.headers.get('X-Family-Signature') ?? '';
    if (!DEVICE_ID.test(deviceId) || !UUID.test(challengeId) || signature.length < 80 || signature.length > 104) throw new FamilyWorkerError('FAMILY_SIGNATURE_REJECTED', 403);
    const row = this.sql.exec<{ device_id: string; method: string; path: string; body_hash: string; message: string; expires_at: number }>('SELECT device_id,method,path,body_hash,message,expires_at FROM challenges WHERE id=?', challengeId).toArray()[0];
    this.sql.exec('DELETE FROM challenges WHERE id=?', challengeId);
    if (row?.device_id !== deviceId || row.expires_at < now || row.method !== request.method || row.path !== new URL(request.url).pathname || row.body_hash !== await sha256Hex(new TextEncoder().encode(rawBody))) throw new FamilyWorkerError('FAMILY_SIGNATURE_REJECTED', 403);
    const device = this.sql.exec<{ spki: string }>('SELECT spki FROM devices WHERE id=? AND created_at>=?', deviceId, now - 30 * 86_400_000).toArray()[0];
    if (!device) throw new FamilyWorkerError('FAMILY_DEVICE_NOT_APPROVED', 403);
    let verified = false;
    try {
      const key = await crypto.subtle.importKey('spki', decodeBase64(device.spki), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      verified = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRawSignature(decodeBase64(signature)), new TextEncoder().encode(row.message));
    } catch { verified = false; }
    if (!verified) throw new FamilyWorkerError('FAMILY_SIGNATURE_REJECTED', 403);
    // Legacy created_at column stores the last proven possession timestamp.
    // Public enrollment alone does not extend an existing identity's lease.
    this.sql.exec('UPDATE devices SET created_at=? WHERE id=?', now, deviceId);
    return deviceId;
  }

  private takeRate(key: string, period: number, maximum: number, now: number): void {
    const window = `${String(period)}:${String(Math.floor(now / period))}`;
    const row = this.sql.exec<{ n: number }>('SELECT n FROM rates WHERE k=? AND window=?', key, window).toArray()[0];
    const count = row?.n ?? 0;
    if (count >= maximum) throw new FamilyWorkerError('RATE_LIMITED', 429, Math.max(1, Math.ceil((period - now % period) / 1000)));
    if (row) this.sql.exec('UPDATE rates SET n=n+1 WHERE k=? AND window=?', key, window);
    else this.sql.exec('INSERT INTO rates(k,window,n) VALUES(?,?,1)', key, window);
  }

  private reserveVirusTotal(now: number, amount: number): boolean {
    const day = `d:${new Date(now).toISOString().slice(0, 10)}`;
    this.sql.exec('DELETE FROM vt_calls WHERE at_ms<=?', now - 60_000);
    const minuteUsed = this.sql.exec<{ n: number }>('SELECT COALESCE(SUM(n),0) AS n FROM vt_calls').one().n;
    const dayUsed = this.sql.exec<{ n: number }>('SELECT n FROM vt_quota WHERE window=?', day).toArray()[0]?.n ?? 0;
    if (minuteUsed + amount > 4 || dayUsed + amount > 500) return false;
    this.sql.exec('INSERT INTO vt_calls(at_ms,n) VALUES(?,?)', now, amount);
    this.sql.exec('INSERT INTO vt_quota(window,n) VALUES(?,?) ON CONFLICT(window) DO UPDATE SET n=n+excluded.n', day, amount);
    return true;
  }

  private async ipDigest(value: string): Promise<string> {
    const bytes = await crypto.subtle.sign('HMAC', await this.rateKey, new TextEncoder().encode(value.slice(0, 80)));
    return hex(bytes).slice(0, 32);
  }

  private cleanup(now: number): void {
    this.sql.exec('DELETE FROM challenges WHERE expires_at < ?', now);
    this.sql.exec('DELETE FROM jobs WHERE expires_at < ?', now);
    // Keep only current and immediately previous windows without storing raw IP values.
    if (Math.random() < 0.02) {
      const activeWindows = [3_600_000, 86_400_000].flatMap((period) => [0, 1].map((offset) => `${String(period)}:${String(Math.floor(now / period) - offset)}`));
      // Never evict a live quota just because other clients inserted newer rows.
      this.sql.exec('DELETE FROM rates WHERE window NOT IN (?,?,?,?)', ...activeWindows);
      this.sql.exec('DELETE FROM vt_quota WHERE window NOT IN (?,?)', 'migration:sliding-v1', `d:${new Date(now).toISOString().slice(0, 10)}`);
      this.sql.exec('DELETE FROM vt_calls WHERE at_ms<=?', now - 60_000);
      this.sql.exec('DELETE FROM devices WHERE created_at<?', now - 30 * 86_400_000);
    }
  }

  async alarm(): Promise<void> {
    this.cleanup(Date.now());
    if (this.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM jobs').one().n > 0) {
      await this.state.storage.setAlarm(Date.now() + 60_000);
    }
  }
}

class FamilyWorkerError extends Error {
  constructor(readonly code: string, readonly status = 403, readonly retryAfter = 60) { super(code); }
}

function allowedOrigin(origin: string | null, env: Env): string | undefined {
  if (!origin) return undefined;
  if (origin === 'https://localhost') return origin;
  if ((env.WEB_ALLOWED_ORIGINS ?? '').split(',').some(value => {
    const candidate = value.trim();
    try { const url = new URL(candidate); return url.protocol === 'https:' && !url.username && !url.password && !url.port && url.hostname.includes('.') && url.origin === candidate && candidate === origin; } catch { return false; }
  })) return origin;
  if (env.ALLOW_BROWSER_REVIEW === 'true' && /^http:\/\/127\.0\.0\.1:\d+$/.test(origin)) return origin;
  return undefined;
}
function corsHeaders(response: Response, origin?: string): Response {
  if (!origin) return response;
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin); headers.set('Vary', 'Origin'); headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, X-Family-Device, X-Family-Challenge, X-Family-Signature');
  headers.set('Access-Control-Expose-Headers', 'Retry-After');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
function hardened(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set('Cache-Control', 'no-store, private'); headers.set('X-Content-Type-Options', 'nosniff'); headers.set('Referrer-Policy', 'no-referrer');
  headers.set('Cross-Origin-Resource-Policy', 'same-site'); headers.delete('Server');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
function isRoute(method: string, path: string): boolean { return method === 'POST' && ['/family/v1/enroll', '/family/v1/challenge', '/family/v1/scans'].includes(path) || method === 'GET' && SCAN_PATH.test(path); }
function allowedSignedPath(method: string, path: string): boolean { return method === 'POST' && path === '/family/v1/scans' || method === 'GET' && SCAN_PATH.test(path); }
function json(body: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = new Headers(JSON_HEADERS);
  if (extra) new Headers(extra).forEach((value, name) => headers.set(name, value));
  return Response.json(body, { status, headers });
}
async function requestJson(request: Request): Promise<Record<string, unknown>> { const text = await requestText(request); try { const value = JSON.parse(text) as unknown; if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(); return value as Record<string, unknown>; } catch { throw new FamilyWorkerError('INVALID_REQUEST', 400); } }
async function requestText(request: Request): Promise<string> {
  const maximum = 4096;
  const length = Number(request.headers.get('Content-Length') ?? '0');
  if (length > maximum) throw new FamilyWorkerError('PAYLOAD_TOO_LARGE', 413);
  if (!request.body) return '';
  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let total = 0; let text = ''; let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => { reject(new FamilyWorkerError('REQUEST_TIMEOUT', 408)); }, 5_000);
  });
  try {
    for (;;) {
      const chunk = await Promise.race([reader.read(), deadline]);
      if (chunk.done) break;
      total += chunk.value.byteLength;
      if (total > maximum) throw new FamilyWorkerError('PAYLOAD_TOO_LARGE', 413);
      text += decoder.decode(chunk.value, { stream: true });
    }
    return text + decoder.decode();
  } finally {
    clearTimeout(timer);
    void reader.cancel().catch(() => undefined);
  }
}
function decodeBase64(value: string): Uint8Array<ArrayBuffer> { try { const binary = atob(value); const buffer = new ArrayBuffer(binary.length); const bytes = new Uint8Array(buffer); for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index); return bytes; } catch { throw new FamilyWorkerError('INVALID_ENCODING', 400); } }
function derToRawSignature(der: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  if (der.length === 64) return der;
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2 || der[2] !== 0x02) throw new Error('INVALID_DER');
  const rLength = der[3] ?? 0; const rStart = 4; const sMarker = rStart + rLength;
  if (der[sMarker] !== 0x02) throw new Error('INVALID_DER');
  const sLength = der[sMarker + 1] ?? 0; const sStart = sMarker + 2;
  if (sStart + sLength !== der.length || rLength < 1 || rLength > 33 || sLength < 1 || sLength > 33) throw new Error('INVALID_DER');
  const result = new Uint8Array(new ArrayBuffer(64));
  const r = der.slice(rStart + (rLength === 33 ? 1 : 0), rStart + rLength); const s = der.slice(sStart + (sLength === 33 ? 1 : 0), sStart + sLength);
  result.set(r, 32 - r.length); result.set(s, 64 - s.length); return result;
}
async function sha256Hex(value: BufferSource): Promise<string> { return hex(await crypto.subtle.digest('SHA-256', value)); }
function hex(value: ArrayBuffer): string { return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, '0')).join(''); }
