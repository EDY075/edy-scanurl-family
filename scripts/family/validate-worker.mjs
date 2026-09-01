import { webcrypto } from 'node:crypto';

const apiOrigin = process.argv[2];
if (!/^https:\/\/[a-z0-9.-]+\.workers\.dev$/i.test(apiOrigin ?? '')) throw new Error('INVALID_WORKER_ORIGIN');
const encoder = new TextEncoder();
const base64 = (value) => Buffer.from(value).toString('base64');
const hex = (value) => Buffer.from(value).toString('hex');

const healthResponse = await fetch(`${apiOrigin}/health`, { redirect: 'error', cache: 'no-store' });
const health = await healthResponse.json();
if (healthResponse.status !== 200 || health.status !== 'ok' || health.mode !== 'FAMILY_WORKER') throw new Error('WORKER_HEALTH_FAILED');
if (!/no-store/.test(healthResponse.headers.get('cache-control') ?? '')) throw new Error('WORKER_CACHE_POLICY_FAILED');

const evilOrigin = await fetch(`${apiOrigin}/health`, { headers: { Origin: 'https://evil.example' }, redirect: 'error' });
if (evilOrigin.status !== 403) throw new Error('WORKER_CORS_FAILED');

const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey));
const deviceId = hex(await webcrypto.subtle.digest('SHA-256', spki));
const enroll = await jsonFetch('/family/v1/enroll', { method: 'POST', body: JSON.stringify({ publicKeySpki: base64(spki) }) });
if (enroll.status !== 200 || enroll.data.deviceId !== deviceId || enroll.data.status !== 'ACTIVE') throw new Error('WORKER_ENROLL_FAILED');

const scanBody = JSON.stringify({ url: 'https://example.com/private/order?token=privacy-canary#secret' });
const created = await signed('POST', '/family/v1/scans', scanBody);
if (created.status !== 202 || typeof created.data.scanId !== 'string') throw new Error(`WORKER_SCAN_CREATE_FAILED:${created.status}:${String(created.data.code ?? '')}:${String(created.data.reason ?? '')}`);
const result = await signed('GET', `/family/v1/scans/${created.data.scanId}`, '');
if (result.status !== 200 || result.data.status !== 'SUCCEEDED') throw new Error('WORKER_SCAN_RESULT_FAILED');
const report = result.data.report;
if (report?.mode !== 'real' || report?.inputUrl !== 'https://example.com/') throw new Error('WORKER_REAL_SCAN_FAILED');
const vtState = report?.technical?.virusTotal?.state;
if (!['AVAILABLE', 'PARTIAL', 'NO_DATA'].includes(vtState)) throw new Error(`WORKER_VT_FAILED:${String(vtState)}`);
const responseText = JSON.stringify(result.data);
if (/VIRUSTOTAL_API_KEY|RATE_LIMIT_SECRET|CLOUDFLARE_API_TOKEN|EDY-ScanURL-Family-Deploy/i.test(responseText)) throw new Error('WORKER_SECRET_DISCLOSURE');

const consumed = await signed('GET', `/family/v1/scans/${created.data.scanId}`, '');
if (consumed.status !== 404) throw new Error('WORKER_RESULT_RETENTION_FAILED');

const privateTarget = await signed('POST', '/family/v1/scans', JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data/' }));
if (privateTarget.status !== 400 || privateTarget.data.code !== 'SCAN_REJECTED') throw new Error('WORKER_SSRF_FAILED');

console.log(JSON.stringify({
  status: 'PASS',
  apiOrigin,
  unauthenticatedHealth: true,
  corsRejected: true,
  signedDeviceFlow: true,
  realScan: true,
  normalizedInput: report.inputUrl,
  virusTotalState: vtState,
  ssrfRejected: true,
  resultConsumedOnce: true,
  noSecretMarkers: true,
}));

async function jsonFetch(path, init) {
  const response = await fetch(`${apiOrigin}${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
    redirect: 'error',
    cache: 'no-store',
  });
  const text = await response.text();
  let data = {};
  try { data = JSON.parse(text); } catch { throw new Error(`WORKER_NON_JSON:${response.status}`); }
  return { status: response.status, data };
}

async function signed(method, path, body) {
  const bodyHash = hex(await webcrypto.subtle.digest('SHA-256', encoder.encode(body)));
  const challenge = await jsonFetch('/family/v1/challenge', {
    method: 'POST',
    body: JSON.stringify({ deviceId, method, path, bodyHash }),
  });
  if (challenge.status !== 200 || typeof challenge.data.message !== 'string' || typeof challenge.data.challengeId !== 'string') throw new Error('WORKER_CHALLENGE_FAILED');
  if (!/^[a-zA-Z0-9_-]{32,100}$/.test(challenge.data.message.split('\n')[4])) throw new Error('ANDROID_NONCE_CONTRACT_FAILED');
  const raw = new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, encoder.encode(challenge.data.message)));
  return jsonFetch(path, {
    method,
    body: method === 'POST' ? body : undefined,
    headers: {
      'X-Family-Device': deviceId,
      'X-Family-Challenge': challenge.data.challengeId,
      'X-Family-Signature': base64(rawToDer(raw)),
    },
  });
}

function rawToDer(raw) {
  const integer = (part) => {
    let index = 0;
    while (index < part.length - 1 && part[index] === 0) index += 1;
    const value = [...part.slice(index)];
    if ((value[0] ?? 0) >= 128) value.unshift(0);
    return [2, value.length, ...value];
  };
  const sequence = [...integer(raw.slice(0, 32)), ...integer(raw.slice(32))];
  return new Uint8Array([0x30, sequence.length, ...sequence]);
}
