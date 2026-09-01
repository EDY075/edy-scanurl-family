import ipaddr from 'ipaddr.js';
import { getDomain } from 'tldts';

const BLOCKED_NAMES = new Set([
  'localhost', 'localhost.localdomain', 'metadata', 'metadata.google.internal',
  'instance-data', 'metadata.azure.internal', 'metadata.aws.internal',
]);
const BLOCKED_RANGES = new Set([
  'unspecified', 'broadcast', 'multicast', 'linkLocal', 'loopback', 'private',
  'reserved', 'carrierGradeNat', 'uniqueLocal', 'ipv4Mapped', 'rfc6052',
  '6to4', 'teredo', 'benchmarking', 'amt', 'as112v4',
]);
const MAX_BODY_BYTES = 512 * 1024;
const MAX_SUBREQUESTS = 32;
const ACTION_PATH = /(?:^|\/)(?:login|signin|sign-in|logout|logoff|cart|carrinho|checkout|order|orders|pedido|pedidos|delete|remove|api|download|downloads|search|busca|oauth|auth|admin|account|conta|unsubscribe)(?:[/.?;_-]|$)/i;

export class SafeScanError extends Error {
  constructor(readonly code: string, message = code) {
    super(message);
    this.name = 'SafeScanError';
  }
}

export interface SafeTarget { origin: string; domain: string; url: URL }

export function normalizeTarget(input: string): SafeTarget {
  const value = input.trim();
  if (!value || value.length > 2_048 || /\s/.test(value)) throw new SafeScanError('MALFORMED_URL');
  let url: URL;
  try { url = new URL(/^[a-z][a-z\d+.-]*:/i.test(value) ? value : `https://${value}`); }
  catch { throw new SafeScanError('MALFORMED_URL'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new SafeScanError('UNSUPPORTED_PROTOCOL');
  if (url.username || url.password) throw new SafeScanError('CREDENTIAL_URL');
  if (url.port && !['80', '443'].includes(url.port)) throw new SafeScanError('UNSUPPORTED_PORT');
  const domain = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!domain || BLOCKED_NAMES.has(domain) || domain.endsWith('.localhost') || domain.endsWith('.local') || domain.endsWith('.internal')) throw new SafeScanError('INTERNAL_HOSTNAME');
  if (ipaddr.isValid(domain)) throw new SafeScanError('IP_LITERAL');
  if (!domain.includes('.') || domain.length > 253 || !domain.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new SafeScanError('INVALID_PUBLIC_DOMAIN');
  url.username = ''; url.password = ''; url.pathname = '/'; url.search = ''; url.hash = '';
  return { origin: url.origin, domain, url };
}

export function classifyAddress(address: string): { allowed: boolean; range: string } {
  try {
    const parsed = ipaddr.parse(address);
    if (parsed.toString() === '168.63.129.16') return { allowed: false, range: 'cloudInfrastructure' };
    if (parsed.kind() === 'ipv6' && (parsed as ipaddr.IPv6).isIPv4MappedAddress()) return { allowed: false, range: 'ipv4Mapped' };
    const range = parsed.range();
    return { allowed: !BLOCKED_RANGES.has(range), range };
  } catch { return { allowed: false, range: 'invalid' }; }
}

export function assertPublicAddresses(addresses: readonly string[]): void {
  if (addresses.length === 0) throw new SafeScanError('DNS_NO_PUBLIC_ADDRESS');
  const blocked = addresses.map((address) => ({ address, ...classifyAddress(address) })).filter((item) => !item.allowed);
  if (blocked.length) throw new SafeScanError('EGRESS_BLOCKED', `EGRESS_BLOCKED:${blocked.map((item) => item.range).join(',')}`);
}

export class SubrequestBudget {
  private used = 0;
  private readonly deadline = AbortSignal.timeout(15_000);
  // Workers' native fetch rejects a class instance as `this`. Preserve the
  // platform call context; storing the bare function as a method breaks egress.
  constructor(private readonly fetchImpl: typeof fetch = (input, init) => fetch(input, init)) {}
  get count(): number { return this.used; }
  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    if (this.deadline.aborted) throw new SafeScanError('SCAN_DEADLINE_EXCEEDED');
    if (this.used >= MAX_SUBREQUESTS) throw new SafeScanError('SUBREQUEST_BUDGET_EXCEEDED');
    this.used += 1;
    const signal = AbortSignal.any([this.deadline, ...(init?.signal ? [init.signal] : [])]);
    return this.fetchImpl(input, { ...init, signal });
  }
}

interface DnsJsonAnswer { type?: unknown; data?: unknown }
interface DnsJson { Status?: unknown; AD?: unknown; Answer?: unknown }

export async function resolvePublicHost(hostname: string, budget: SubrequestBudget): Promise<{ a: string[]; aaaa: string[] }> {
  const [a, aaaa] = await Promise.all([doh(hostname, 'A', budget), doh(hostname, 'AAAA', budget)]);
  const addresses = [...a.answers, ...aaaa.answers];
  assertPublicAddresses(addresses);
  return { a: a.answers, aaaa: aaaa.answers };
}

export async function doh(hostname: string, type: 'A' | 'AAAA' | 'NS' | 'MX' | 'CAA' | 'DS', budget: SubrequestBudget): Promise<{ answers: string[]; authenticated: boolean }> {
  const response = await budget.fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`, {
    method: 'GET', headers: { Accept: 'application/dns-json' }, redirect: 'manual', signal: AbortSignal.timeout(4_000),
  });
  if (!response.ok) throw new SafeScanError(`DNS_HTTP_${String(response.status)}`);
  const body = await readJsonBounded(response, 128 * 1024) as DnsJson;
  if (body.Status !== 0 && body.Status !== 3) throw new SafeScanError('DNS_INVALID_RESPONSE');
  const expected = ({ A: 1, NS: 2, MX: 15, AAAA: 28, DS: 43, CAA: 257 } as const)[type];
  const answers = Array.isArray(body.Answer) ? body.Answer.flatMap((raw) => {
    if (!raw || typeof raw !== 'object') return [];
    const answer = raw as DnsJsonAnswer;
    return answer.type === expected && typeof answer.data === 'string' ? [answer.data.replace(/\.$/, '').slice(0, 500)] : [];
  }).slice(0, 30) : [];
  return { answers, authenticated: body.AD === true };
}

export async function safePageFetch(start: URL, budget: SubrequestBudget, options: { maxRedirects?: number; maxBytes?: number } = {}): Promise<{ response: Response; body: string; finalUrl: URL; redirects: number }> {
  const maxRedirects = options.maxRedirects ?? 2;
  const registrable = getDomain(start.hostname, { allowPrivateDomains: false });
  if (!registrable) throw new SafeScanError('INVALID_PUBLIC_DOMAIN');
  let current = new URL(start);
  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    normalizeTarget(current.toString());
    if (!isPassivePageUrl(current)) throw new SafeScanError('URL_POLICY_BLOCKED');
    current.search = ''; current.hash = '';
    await resolvePublicHost(current.hostname, budget);
    const response = await budget.fetch(current, {
      method: 'GET', headers: { Accept: 'text/html,application/xhtml+xml;q=0.9', 'User-Agent': 'EDY-ScanURL-Family/1.0 defensive-link-check' },
      redirect: 'manual', signal: AbortSignal.timeout(5_000),
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      await response.body?.cancel();
      if (redirects === maxRedirects) throw new SafeScanError('TOO_MANY_REDIRECTS');
      const location = response.headers.get('location');
      if (!location) throw new SafeScanError('INVALID_REDIRECT');
      const next = new URL(location, current);
      const nextTarget = normalizeTarget(next.toString());
      if (current.protocol === 'https:' && next.protocol !== 'https:') throw new SafeScanError('HTTPS_DOWNGRADE_BLOCKED');
      if (!isPassivePageUrl(next)) throw new SafeScanError('URL_POLICY_BLOCKED');
      if (getDomain(nextTarget.domain, { allowPrivateDomains: false }) !== registrable) throw new SafeScanError('CROSS_DOMAIN_REDIRECT_BLOCKED');
      next.search = ''; next.hash = '';
      current = next;
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new SafeScanError(`HTTP_STATUS_${String(response.status)}`);
    }
    const contentType = response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() ?? '';
    if (!['text/html', 'application/xhtml+xml'].includes(contentType)) {
      await response.body?.cancel();
      throw new SafeScanError('UNSUPPORTED_CONTENT_TYPE');
    }
    const body = await readTextBounded(response, options.maxBytes ?? MAX_BODY_BYTES);
    return { response, body, finalUrl: current, redirects };
  }
  throw new SafeScanError('TOO_MANY_REDIRECTS');
}

/** Restrict every discovered path and redirect before any DNS or HTTP request. */
export function isPassivePageUrl(url: URL): boolean {
  let path = url.pathname;
  for (let depth = 0; depth < 8; depth += 1) {
    for (const char of path) if (char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127) return false;
    if (path.includes('\\') || ACTION_PATH.test(path)) return false;
    if (!path.includes('%')) return true;
    try { path = decodeURIComponent(path); } catch { return false; }
  }
  return false;
}

export async function readTextBounded(response: Response, maximum: number): Promise<string> {
  const announced = Number(response.headers.get('content-length') ?? '0');
  if (Number.isFinite(announced) && announced > maximum) throw new SafeScanError('RESPONSE_TOO_LARGE');
  if (!response.body) throw new SafeScanError('EMPTY_RESPONSE');
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: false });
  let text = ''; let size = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maximum) throw new SafeScanError('RESPONSE_TOO_LARGE');
      text += decoder.decode(chunk.value, { stream: true });
    }
    return text + decoder.decode();
  } finally { await reader.cancel().catch(() => undefined); }
}

export async function readJsonBounded(response: Response, maximum: number): Promise<unknown> {
  const text = await readTextBounded(response, maximum);
  try { return JSON.parse(text) as unknown; }
  catch { throw new SafeScanError('INVALID_JSON'); }
}

export function canonicalBase64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
