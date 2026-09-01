import { Capacitor, registerPlugin, type PluginListenerHandle } from '@capacitor/core';

export interface DeviceIdentity { publicKeySpki: string; deviceId: string; configured: boolean }
export interface FamilyResponse { status: number; data: unknown }
export interface FamilyRequest { method: 'GET' | 'POST'; path: string; body: string; headers?: Record<string, string> }
interface FamilyDevicePlugin {
  getIdentity(): Promise<DeviceIdentity>;
  signChallenge(options: { message: string }): Promise<{ signature: string }>;
  request(options: FamilyRequest): Promise<FamilyResponse>;
  readClipboard(): Promise<{ text: string }>;
  takeSharedLink(): Promise<{ text: string }>;
  addListener(name: 'sharedLink', callback: (event: { text: string }) => void): Promise<PluginListenerHandle>;
}
const plugin = registerPlugin<FamilyDevicePlugin>('FamilyDevice');
export const nativeFamily = Capacitor.isNativePlatform();
// Developer-only browser review. Final APK builds explicitly disable this flag.
const browserReview = import.meta.env.DEV || import.meta.env.VITE_FAMILY_BROWSER_REVIEW === 'true';
let browserIdentity: Promise<{ identity: DeviceIdentity; key: CryptoKey }> | undefined;

function base64(data: ArrayBuffer | Uint8Array<ArrayBuffer>): string {
  return btoa(String.fromCharCode(...new Uint8Array(data)));
}
export async function sha256(text: string): Promise<string> {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
}
function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, '0')).join('');
}
async function browserKeys(): Promise<{ identity: DeviceIdentity; key: CryptoKey }> {
  const pair = await new Promise<CryptoKeyPair>((resolve, reject) => {
    const request = indexedDB.open('edy-family-device-review', 1);
    request.onupgradeneeded = () => { request.result.createObjectStore('keys'); };
    request.onerror = () => { reject(new Error('device_key_unavailable')); };
    request.onsuccess = () => {
      const db = request.result;
      const read = db.transaction('keys').objectStore('keys').get('identity') as IDBRequest<CryptoKeyPair | undefined>;
      read.onerror = () => { db.close(); reject(new Error('device_key_unavailable')); };
      read.onsuccess = () => {
        if (read.result) { db.close(); resolve(read.result); return; }
        void crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']).then((newPair) => {
          const transaction = db.transaction('keys', 'readwrite');
          transaction.objectStore('keys').put(newPair, 'identity');
          transaction.oncomplete = () => { db.close(); resolve(newPair); };
          transaction.onerror = () => { db.close(); reject(new Error('device_key_unavailable')); };
        }).catch(() => { db.close(); reject(new Error('device_key_unavailable')); });
      };
    };
  });
  const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
  return { identity: { publicKeySpki: base64(spki), deviceId: hex(await crypto.subtle.digest('SHA-256', spki)), configured: true }, key: pair.privateKey };
}
function reviewIdentity() {
  browserIdentity ??= browserKeys();
  return browserIdentity;
}
export async function familyIdentity(): Promise<DeviceIdentity> {
  if (nativeFamily) return plugin.getIdentity();
  if (!browserReview) return { deviceId: '', publicKeySpki: '', configured: false };
  return (await reviewIdentity()).identity;
}
export function rawSignatureToDer(raw: ArrayBuffer): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(raw);
  if (bytes.length !== 64) throw new Error('invalid_signature');
  const integer = (half: Uint8Array) => {
    let offset = 0;
    while (offset < half.length - 1 && half[offset] === 0) offset += 1;
    const value = [...half.slice(offset)];
    if ((value[0] ?? 0) >= 128) value.unshift(0);
    return [2, value.length, ...value];
  };
  const sequence = [...integer(bytes.slice(0, 32)), ...integer(bytes.slice(32))];
  return new Uint8Array([0x30, sequence.length, ...sequence]);
}
export async function signFamilyChallenge(message: string): Promise<string> {
  if (nativeFamily) return (await plugin.signChallenge({ message })).signature;
  if (!browserReview) throw new Error('not_activated');
  const { key } = await reviewIdentity();
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(message));
  return base64(rawSignatureToDer(signature));
}
export async function familyRequest(options: FamilyRequest): Promise<FamilyResponse> {
  if (nativeFamily) return plugin.request(options);
  if (!browserReview) throw new Error('not_activated');
  if (!/^\/family\/v1\/(?:enroll|challenge|scans(?:\/[a-f0-9-]{36})?)$/.test(options.path)) throw new Error('request_rejected');
  const response = await fetch(options.path, {
    method: options.method,
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...(options.method === 'POST' ? { body: options.body } : {}),
    credentials: 'omit', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(20_000),
  });
  const text = await response.text();
  if (text.length > 2 * 1024 * 1024) throw new Error('response_too_large');
  return { status: response.status, data: JSON.parse(text) as unknown };
}
export async function nativeClipboard(): Promise<string> {
  return nativeFamily ? (await plugin.readClipboard()).text : navigator.clipboard.readText();
}
export async function nativeSharedText(): Promise<string> {
  return nativeFamily ? (await plugin.takeSharedLink()).text : '';
}
export function listenSharedText(callback: (text: string) => void): () => void {
  if (!nativeFamily) return () => undefined;
  let disposed = false;
  let listener: PluginListenerHandle | undefined;
  void plugin.addListener('sharedLink', ({ text }) => { if (!disposed) callback(text); }).then((handle) => {
    if (disposed) void handle.remove(); else listener = handle;
  });
  return () => { disposed = true; void listener?.remove(); };
}
