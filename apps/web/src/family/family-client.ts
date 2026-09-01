import type { ScanReport } from '../types';
import { familyIdentity, familyRequest, listenSharedText, nativeClipboard, nativeSharedText, sha256, signFamilyChallenge, type DeviceIdentity, type FamilyResponse } from './family-native';

export interface FamilyAvailability { state: 'READY' | 'PENDING' | 'REVOKED' | 'UNCONFIGURED' | 'OFFLINE'; deviceId?: string }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('scan_failed');
  return value as Record<string, unknown>;
}
function accepted(response: FamilyResponse): Record<string, unknown> {
  const body = record(response.data);
  if (response.status >= 200 && response.status < 300) return body;
  const code = typeof body.code === 'string' ? body.code : '';
  if (response.status === 429) throw new Error('rate_limited');
  if (code.includes('REVOKED')) throw new Error('device_revoked');
  if (/PENDING|NOT_APPROVED/.test(code)) throw new Error('device_pending');
  if (/SCAN_REJECTED|INVALID_TARGET/.test(code)) throw new Error('scan_rejected');
  if (response.status >= 500) throw new Error('offline');
  throw new Error('scan_failed');
}
async function enrollment(): Promise<{ identity: DeviceIdentity; state: string }> {
  const identity = await familyIdentity();
  if (!identity.configured) throw new Error('not_activated');
  const response = accepted(await familyRequest({ method: 'POST', path: '/family/v1/enroll', body: JSON.stringify({ publicKeySpki: identity.publicKeySpki }) }));
  if (response.deviceId !== identity.deviceId || !['ACTIVE', 'PENDING', 'REVOKED'].includes(String(response.status))) throw new Error('scan_failed');
  return { identity, state: String(response.status) };
}
export async function getFamilyAvailability(): Promise<FamilyAvailability> {
  try {
    const { identity, state } = await enrollment();
    return { state: state === 'ACTIVE' ? 'READY' : state === 'REVOKED' ? 'REVOKED' : 'PENDING', deviceId: identity.deviceId };
  } catch (error) {
    return { state: error instanceof Error && error.message === 'not_activated' ? 'UNCONFIGURED' : 'OFFLINE' };
  }
}
async function signedRequest(identity: DeviceIdentity, method: 'GET' | 'POST', path: string, body: string) {
  const bodyHash = await sha256(body);
  const challenge = accepted(await familyRequest({ method: 'POST', path: '/family/v1/challenge', body: JSON.stringify({ deviceId: identity.deviceId, method, path, bodyHash }) }));
  if (typeof challenge.message !== 'string' || typeof challenge.challengeId !== 'string') throw new Error('scan_failed');
  const lines = challenge.message.split('\n');
  if (lines.length !== 8 || lines[0] !== 'EDY-FAMILY-V1' || lines[2] !== identity.deviceId || lines[3] !== challenge.challengeId || lines[5] !== method || lines[6] !== path || lines[7] !== bodyHash) throw new Error('scan_failed');
  const signature = await signFamilyChallenge(challenge.message);
  return accepted(await familyRequest({ method, path, body, headers: {
    'X-Family-Device': identity.deviceId, 'X-Family-Challenge': challenge.challengeId, 'X-Family-Signature': signature,
  } }));
}
export function storeOrigin(input: string): string {
  const value = input.trim();
  if (!value || value.length > 2048 || /\s/.test(value)) throw new Error('scan_rejected');
  let url: URL;
  try { url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(value) ? value : `https://${value}`); }
  catch { throw new Error('scan_rejected'); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || !url.hostname.includes('.') || (url.port && !['80', '443'].includes(url.port))) throw new Error('scan_rejected');
  // Only the store origin leaves the device: no order IDs, tracking or fragments.
  return `${url.origin}/`;
}
export async function requestFamilyScan(input: string, onProgress: (step: number) => void): Promise<ScanReport> {
  const url = storeOrigin(input);
  let active;
  try { active = await enrollment(); } catch (error) {
    if (error instanceof Error && ['not_activated', 'rate_limited'].includes(error.message)) throw error;
    throw new Error('offline');
  }
  if (active.state === 'REVOKED') throw new Error('device_revoked');
  if (active.state !== 'ACTIVE') throw new Error('device_pending');
  const created = await signedRequest(active.identity, 'POST', '/family/v1/scans', JSON.stringify({ url }));
  if (typeof created.scanId !== 'string' || !/^[a-f0-9-]{36}$/.test(created.scanId)) throw new Error('scan_failed');
  for (let attempt = 0; attempt < 60; attempt += 1) {
    await new Promise((resolve) => window.setTimeout(resolve, 1500));
    const snapshot = await signedRequest(active.identity, 'GET', `/family/v1/scans/${created.scanId}`, '');
    if (snapshot.progress) {
      const progress = record(snapshot.progress);
      if (typeof progress.completed === 'number' && typeof progress.total === 'number' && progress.total > 0) onProgress(Math.min(100, Math.floor(progress.completed / progress.total * 100)));
    }
    if (snapshot.status === 'SCAN_REJECTED') throw new Error('scan_rejected');
    if (snapshot.status === 'FAILED') throw new Error('scan_failed');
    if (snapshot.status === 'SUCCEEDED') {
      const report = record(snapshot.report);
      if (report.mode !== 'real' || typeof report.domain !== 'string' || !['BUY', 'CAUTION', 'DO_NOT_BUY', 'INSUFFICIENT_DATA'].includes(String(report.verdict))
        || !Array.isArray(report.checks) || !Array.isArray(report.sources) || typeof report.coverage !== 'number' || !report.technical) throw new Error('scan_failed');
      return report as unknown as ScanReport;
    }
  }
  throw new Error('scan_timeout');
}
export const readPastedLink = nativeClipboard;
export const takeSharedLink = nativeSharedText;
export const onSharedLink = listenSharedText;
