import { getDomain } from 'tldts';
import { extractCnpj, mergeCnpj } from './company-evidence';
import { assertPublicAddresses, canonicalBase64Url, doh, isPassivePageUrl, normalizeTarget, readJsonBounded, safePageFetch, SafeScanError, SubrequestBudget } from './security';
import type { CrawlReceipt, DnsData, Env, HttpData, RdapData, ScanEvidence, VirusTotalData, VirusTotalObjectReport } from './types';

interface RdapBootstrap { services?: unknown }

export async function collectScanEvidence(input: string, env: Env, budget = new SubrequestBudget(), vtAllowed: boolean | (() => boolean) = true): Promise<ScanEvidence> {
  const target = normalizeTarget(input);
  const dns = await collectDns(target.domain, budget);
  const [rdap, http, virusTotal] = await Promise.all([
    collectRdap(target.domain, budget),
    collectHttp(target.url, budget),
    collectVirusTotal(target.origin, target.domain, env, budget, vtAllowed),
  ]);
  return { target: { origin: target.origin, domain: target.domain }, dns, rdap, http, virusTotal, subrequests: budget.count };
}

export async function collectDns(domain: string, budget: SubrequestBudget): Promise<DnsData> {
  const started = Date.now();
  const registrable = getDomain(domain, { allowPrivateDomains: false }) ?? domain;
  const results = await Promise.all(['A', 'AAAA', 'NS', 'MX', 'CAA', 'DS'].map(async (type) => {
    // Reachability belongs to the exact requested host. Registration-level
    // records belong to the registrable domain; asking them on `www` commonly
    // returns only a CNAME and used to create false missing evidence.
    const queryDomain = type === 'A' || type === 'AAAA' ? domain : registrable;
    try { return { type, result: await doh(queryDomain, type as 'A' | 'AAAA' | 'NS' | 'MX' | 'CAA' | 'DS', budget) }; }
    catch (error) { return { type, result: { answers: [], authenticated: false }, error: error instanceof SafeScanError ? error.code : error instanceof Error ? `DNS_RUNTIME_${error.name.replace(/[^A-Za-z]/g, '').toUpperCase() || 'ERROR'}` : 'DNS_SOURCE_UNAVAILABLE' }; }
  }));
  const byType = new Map(results.map((entry) => [entry.type, entry.result]));
  const a = byType.get('A')?.answers ?? [];
  const aaaa = byType.get('AAAA')?.answers ?? [];
  if (a.length + aaaa.length === 0) {
    const addressError = results.find((entry) => (entry.type === 'A' || entry.type === 'AAAA') && entry.error)?.error;
    throw new SafeScanError(addressError ?? 'DNS_NO_PUBLIC_ADDRESS');
  }
  // Reuse the same strict address classification used by guarded HTTP before any target fetch.
  assertPublicAddresses([...a, ...aaaa]);
  return {
    status: results.some((entry) => entry.error) ? 'limited' : 'available',
    failedQueries: results.filter((entry) => entry.error).map((entry) => entry.type),
    durationMs: Date.now() - started,
    a,
    aaaa,
    ns: byType.get('NS')?.answers ?? [],
    mx: (byType.get('MX')?.answers ?? []).flatMap((value) => {
      const match = /^(\d+)\s+(.+)$/.exec(value);
      return match ? [{ priority: Number(match[1]), exchange: (match[2] ?? '').replace(/\.$/, '') }] : [];
    }),
    caa: byType.get('CAA')?.answers ?? [],
    dnssec: results.some((entry) => entry.type === 'DS' && entry.error) ? 'UNKNOWN'
      : (byType.get('DS')?.answers.length ?? 0) > 0 ? 'SIGNED' : 'NOT_OBSERVED',
  };
}

export async function collectRdap(domain: string, budget: SubrequestBudget): Promise<RdapData> {
  const started = Date.now();
  try {
    const registrable = getDomain(domain, { allowPrivateDomains: false });
    if (!registrable) throw new SafeScanError('RDAP_INVALID_DOMAIN');
    const bootstrapResponse = await budget.fetch('https://data.iana.org/rdap/dns.json', {
      headers: { Accept: 'application/json' }, redirect: 'manual', signal: AbortSignal.timeout(4_000),
    });
    if (!bootstrapResponse.ok) throw new SafeScanError('RDAP_BOOTSTRAP_UNAVAILABLE');
    const bootstrap = await readJsonBounded(bootstrapResponse, 512 * 1024) as RdapBootstrap;
    const tld = registrable.split('.').at(-1) ?? '';
    const services = Array.isArray(bootstrap.services) ? bootstrap.services : [];
    let base: string | undefined;
    for (const item of services) {
      if (!Array.isArray(item) || !Array.isArray(item[0]) || !Array.isArray(item[1])) continue;
      if (!(item[0] as unknown[]).some((value) => typeof value === 'string' && value.toLowerCase() === tld)) continue;
      base = (item[1] as unknown[]).find((value): value is string => typeof value === 'string' && value.startsWith('https://'));
      if (base) break;
    }
    if (!base) throw new SafeScanError('RDAP_SERVICE_NOT_FOUND');
    const provider = new URL(base);
    if (provider.protocol !== 'https:' || provider.username || provider.password || provider.port || !provider.hostname.includes('.')) throw new SafeScanError('RDAP_SERVICE_INVALID');
    const url = new URL(`domain/${encodeURIComponent(registrable)}`, base.endsWith('/') ? base : `${base}/`);
    const response = await budget.fetch(url, {
      headers: { Accept: 'application/rdap+json,application/json' }, redirect: 'manual', signal: AbortSignal.timeout(5_000),
    });
    if (response.status === 404) {
      await response.body?.cancel();
      return { status: 'limited', nameservers: [], statuses: [], sourceUrl: url.toString(), reason: 'RDAP_NO_DATA', attempted: true, durationMs: Date.now() - started };
    }
    if (!response.ok) throw new SafeScanError(`RDAP_HTTP_${String(response.status)}`);
    const body = await readJsonBounded(response, 512 * 1024);
    if (!record(body)) throw new SafeScanError('RDAP_INVALID_RESPONSE');
    const events = Array.isArray(body.events) ? body.events.filter(record) : [];
    const event = (name: string) => {
      const item = events.find((entry) => entry.eventAction === name);
      return typeof item?.eventDate === 'string' && Number.isFinite(Date.parse(item.eventDate)) ? new Date(item.eventDate).toISOString() : undefined;
    };
    const nameservers = Array.isArray(body.nameservers) ? body.nameservers.flatMap((item) => record(item) && typeof item.ldhName === 'string' ? [item.ldhName.toLowerCase().replace(/\.$/, '')] : []).slice(0, 20) : [];
    const entities = Array.isArray(body.entities) ? body.entities.filter(record) : [];
    const registrarEntity = entities.find((item) => Array.isArray(item.roles) && item.roles.includes('registrar'));
    const registrar = registrarEntity ? vcardName(registrarEntity.vcardArray) : undefined;
    const statuses = Array.isArray(body.status) ? body.status.filter((item): item is string => typeof item === 'string').slice(0, 20) : [];
    const registrationDate = event('registration');
    const updatedDate = event('last changed') ?? event('last update of RDAP database');
    return {
      status: 'available', nameservers, statuses, sourceUrl: url.toString(), attempted: true, durationMs: Date.now() - started,
      ...(registrationDate ? { registrationDate } : {}),
      ...(updatedDate ? { updatedDate } : {}),
      ...(registrar ? { registrar: registrar.slice(0, 200) } : {}),
    };
  } catch (error) {
    return { status: 'unavailable', nameservers: [], statuses: [], reason: errorCode(error, 'RDAP_UNAVAILABLE'), attempted: true, durationMs: Date.now() - started };
  }
}

export async function collectHttp(url: URL, budget: SubrequestBudget): Promise<HttpData> {
  const started = Date.now();
  const manifest: CrawlReceipt[] = [];
  try {
    const home = await safePageFetch(url, budget);
    manifest.push({ page: 0, attempted: true, outcome: 'FETCHED', reason: 'HOMEPAGE_FETCHED', durationMs: Date.now() - started });
    const combined = [home.body];
    const pages = [{ body: home.body, url: home.finalUrl }];
    const discovery = relevantSameOriginLinks(home.body, home.finalUrl);
    let selected = 0;
    for (const [index, child] of discovery.links.entries()) {
      const page = index + 1;
      if (!isPassivePageUrl(child) || selected >= 2) {
        manifest.push({ page, attempted: false, outcome: 'SKIPPED', reason: !isPassivePageUrl(child) ? 'URL_POLICY_BLOCKED' : 'CRAWL_PAGE_LIMIT', durationMs: 0 });
        continue;
      }
      selected += 1;
      const pageStarted = Date.now();
      try {
        const fetched = await safePageFetch(child, budget, { maxRedirects: 1, maxBytes: 256 * 1024 });
        combined.push(fetched.body);
        pages.push({ body: fetched.body, url: fetched.finalUrl });
        manifest.push({ page, attempted: true, outcome: 'FETCHED', reason: 'RELEVANT_PAGE_FETCHED', durationMs: Date.now() - pageStarted });
      } catch (error) {
        manifest.push({ page, attempted: true, outcome: 'FAILED', reason: errorCode(error, 'HTTP_SOURCE_UNAVAILABLE'), durationMs: Date.now() - pageStarted });
      }
    }
    const source = combined.join('\n').slice(0, 900_000);
    const visible = visibleText(source);
    const lower = visible.toLocaleLowerCase('pt-BR');
    const candidates = mergeCnpj(pages.flatMap((page) => extractCnpj(page.body, page.url, 9)), 9);
    const cnpjTruncated = candidates.length > 8;
    const cnpjObservations = candidates.sort((a, b) => Number(b.checksum === 'INVALID') - Number(a.checksum === 'INVALID')).slice(0, 8);
    const cnpjClaims = cnpjObservations.filter((item) => item.checksum === 'VALID').map((item) => item.value);
    const visibleEmails = [...visible.matchAll(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi)].map((match) => match[0].toLowerCase());
    const visiblePhones = [...visible.matchAll(/(?:\+?55\s*)?(?:\(?\d{2}\)?\s*)?(?:9\s*)?\d{4}[-\s]?\d{4}/g)].map((match) => match[0].replace(/\s+/g, ' ').trim());
    const structuredByPage = pages.map((page) => structuredOrganizationEvidence(page.body));
    const companyNames = unique(structuredByPage.flatMap((item) => item.names)).slice(0, 20);
    const emails = unique([...visibleEmails, ...structuredByPage.flatMap((item) => item.emails)]).slice(0, 20);
    const phones = unique([...visiblePhones, ...structuredByPage.flatMap((item) => item.phones)]).slice(0, 20);
    const socialLinks = unique([...source.matchAll(/https?:\/\/(?:www\.)?(?:instagram|facebook|linkedin|youtube|tiktok)\.com\/[^\s"'<>]+/gi)].map((match) => match[0])).slice(0, 20);
    const paymentMethods = ['pix', 'boleto', 'visa', 'mastercard', 'paypal', 'mercado pago'].filter((name) => lower.includes(name));
    const observedPolicies = combined.map(confirmedPolicies);
    for (const [index, structured] of structuredByPage.entries()) {
      if (structured.hasContact && observedPolicies[index]) observedPolicies[index].contact = true;
    }
    const policies = Object.fromEntries(Object.keys(observedPolicies[0] ?? {}).map((key) => [key, observedPolicies.some((page) => page[key]) ]));
    const policyEvidence = Object.keys(policies).filter((key) => policies[key]).map((id) => ({ id, sourceUrls: pages.filter((_, index) => observedPolicies[index]?.[id]).map((page) => `${page.url.origin}${page.url.pathname}`) }));
    const securityHeaders = {
      hsts: home.response.headers.has('strict-transport-security'),
      csp: home.response.headers.has('content-security-policy'),
      frameProtection: home.response.headers.has('x-frame-options') || /frame-ancestors/i.test(home.response.headers.get('content-security-policy') ?? ''),
      referrerPolicy: home.response.headers.has('referrer-policy'),
      permissionsPolicy: home.response.headers.has('permissions-policy'),
      noSniff: /nosniff/i.test(home.response.headers.get('x-content-type-options') ?? ''),
    };
    return {
      status: cnpjTruncated || discovery.truncated || manifest.some((page) => page.outcome !== 'FETCHED') ? 'limited' : 'available',
      httpsValidated: home.finalUrl.protocol === 'https:', finalOrigin: home.finalUrl.origin,
      redirects: home.redirects, headers: Object.entries(securityHeaders).filter(([, present]) => present).map(([name]) => name),
      securityHeaders, pagesFetched: combined.length, pagesDiscovered: discovery.links.length + 1,
      cnpjClaims, cnpjObservations, cnpjTruncated, policyEvidence, companyNames, emails, phones, socialLinks, paymentMethods, policies,
      attempted: true, durationMs: Date.now() - started, crawlManifest: manifest,
      pagesSkipped: manifest.filter((page) => page.outcome === 'SKIPPED').length, discoveryTruncated: discovery.truncated,
    };
  } catch (error) {
    return {
      status: 'unavailable', httpsValidated: false, redirects: 0, headers: [],
      securityHeaders: { hsts: false, csp: false, frameProtection: false, referrerPolicy: false, permissionsPolicy: false, noSniff: false },
      pagesFetched: 0, pagesDiscovered: 0, cnpjClaims: [], companyNames: [], emails: [], phones: [], socialLinks: [], paymentMethods: [],
      policies: { about: false, privacy: false, terms: false, returns: false, refund: false, shipping: false, legal: false, contact: false },
      reason: errorCode(error, 'HTTP_SOURCE_UNAVAILABLE'),
      attempted: true, durationMs: Date.now() - started, pagesSkipped: 0, discoveryTruncated: false,
      crawlManifest: [{ page: 0, attempted: true, outcome: 'FAILED', reason: errorCode(error, 'HTTP_SOURCE_UNAVAILABLE'), durationMs: Date.now() - started }],
    };
  }
}

export async function collectVirusTotal(origin: string, domain: string, env: Env, budget: SubrequestBudget, allowed: boolean | (() => boolean) = true): Promise<VirusTotalData> {
  const started = Date.now();
  if (env.VIRUSTOTAL_ENABLED !== 'true' || !env.VIRUSTOTAL_API_KEY) return { status: 'unavailable', state: 'DISABLED_NO_CREDENTIALS', reason: 'VIRUSTOTAL_SECRET_NOT_CONFIGURED', attempted: false, durationMs: 0 };
  if (allowed === false) return { status: 'unavailable', state: 'RATE_LIMITED', reason: 'VIRUSTOTAL_LOCAL_RATE_LIMIT', attempted: false, durationMs: 0 };
  const registrable = getDomain(domain, { allowPrivateDomains: false });
  if (!registrable) return { status: 'unavailable', state: 'FAILED', reason: 'VIRUSTOTAL_INVALID_DOMAIN', attempted: false, durationMs: 0 };
  let normalizedOrigin: string;
  try {
    const target = normalizeTarget(origin);
    if (target.origin !== origin || target.domain !== domain) throw new Error('IDENTITY_MISMATCH');
    normalizedOrigin = target.origin;
  } catch { return { status: 'unavailable', state: 'FAILED', reason: 'VIRUSTOTAL_INVALID_ORIGIN', attempted: false, durationMs: 0 }; }
  const expectedUrl = `${normalizedOrigin}/`;
  const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expectedUrl)))].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  const domainReport = await vtLookup('domains', encodeURIComponent(registrable), env.VIRUSTOTAL_API_KEY, budget, { id: registrable }, allowed);
  const stop = ['RATE_LIMITED', 'TIMED_OUT'].includes(domainReport.state) || domainReport.errorCode === 'VIRUSTOTAL_CREDENTIALS_REJECTED';
  const urlReport = stop ? { state: domainReport.state, cache: 'MISS', errorCode: 'VIRUSTOTAL_SKIPPED_AFTER_TERMINAL', attempted: false } as VirusTotalObjectReport
    : await vtLookup('urls', canonicalBase64Url(expectedUrl), env.VIRUSTOTAL_API_KEY, budget, { id: hash, url: expectedUrl }, allowed);
  const available = [domainReport, urlReport].filter((item) => item.state === 'AVAILABLE').length;
  const state: VirusTotalData['state'] = available === 2 ? 'AVAILABLE' : available === 1 ? 'PARTIAL'
    : domainReport.state === 'NO_DATA' && urlReport.state === 'NO_DATA' ? 'NO_DATA'
      : domainReport.state === 'RATE_LIMITED' || urlReport.state === 'RATE_LIMITED' ? 'RATE_LIMITED'
        : domainReport.state === 'TIMED_OUT' || urlReport.state === 'TIMED_OUT' ? 'TIMED_OUT' : 'FAILED';
  return {
    status: available === 2 ? 'available' : available === 1 || state === 'NO_DATA' ? 'limited' : 'unavailable', state,
    reason: state === 'AVAILABLE' ? 'VIRUSTOTAL_READ_ONLY_REPORTS_AVAILABLE' : `VIRUSTOTAL_${state}`,
    domain: domainReport, url: urlReport,
    attempted: domainReport.attempted === true || urlReport.attempted === true, durationMs: Date.now() - started,
    sourceUrl: `https://www.virustotal.com/gui/domain/${encodeURIComponent(registrable)}`,
  };
}

async function vtLookup(kind: 'domains' | 'urls', id: string, key: string, budget: SubrequestBudget, expected: { id: string; url?: string }, allowed: boolean | (() => boolean)): Promise<VirusTotalObjectReport> {
  let response: Response | undefined;
  let attempted = false;
  try {
    // Synchronous quota reservation immediately before each network GET. No await
    // may separate this hook from fetch: DNS/hash work must not age a reservation.
    if (!(typeof allowed === 'function' ? allowed() : allowed)) return { state: 'RATE_LIMITED', cache: 'MISS', errorCode: 'VIRUSTOTAL_LOCAL_RATE_LIMIT', attempted: false };
    attempted = true;
    response = await budget.fetch(`https://www.virustotal.com/api/v3/${kind}/${id}`, {
      method: 'GET', headers: { Accept: 'application/json', 'x-apikey': key }, redirect: 'manual', signal: AbortSignal.timeout(5_000),
    });
    if (response.status === 404) return { state: 'NO_DATA', cache: 'MISS', errorCode: 'VIRUSTOTAL_NOT_FOUND', attempted };
    if (response.status === 429) return { state: 'RATE_LIMITED', cache: 'MISS', errorCode: 'VIRUSTOTAL_REMOTE_RATE_LIMIT', attempted, ...retryAfter(response.headers.get('retry-after')) };
    if (response.status === 401 || response.status === 403) return { state: 'FAILED', cache: 'MISS', errorCode: 'VIRUSTOTAL_CREDENTIALS_REJECTED', attempted };
    if (!response.ok) return { state: response.status === 408 || response.status === 504 ? 'TIMED_OUT' : 'FAILED', cache: 'MISS', errorCode: `VIRUSTOTAL_HTTP_${String(response.status)}`, attempted };
    if (response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') return { state: 'FAILED', cache: 'MISS', errorCode: 'VIRUSTOTAL_INVALID_CONTENT_TYPE', attempted };
    const body = await readJsonBounded(response, 1024 * 1024);
    if (!record(body) || !record(body.data) || body.data.id !== expected.id || body.data.type !== (kind === 'domains' ? 'domain' : 'url') || !record(body.data.attributes) || !validVtAttributes(body.data.attributes, expected.url)) return { state: 'FAILED', cache: 'MISS', errorCode: 'VIRUSTOTAL_INVALID_RESPONSE', attempted };
    return { ...sanitizeVirusTotal(expected.id, kind === 'domains' ? 'domain' : 'url', body.data.attributes), attempted };
  } catch (error) {
    const timeout = error instanceof Error && ['AbortError', 'TimeoutError'].includes(error.name);
    return { state: timeout ? 'TIMED_OUT' : 'FAILED', cache: 'MISS', errorCode: timeout ? 'VIRUSTOTAL_TIMED_OUT' : error instanceof SafeScanError ? error.code === 'RESPONSE_TOO_LARGE' ? 'VIRUSTOTAL_RESPONSE_TOO_LARGE' : 'VIRUSTOTAL_INVALID_RESPONSE' : 'VIRUSTOTAL_NETWORK_FAILURE', attempted };
  } finally {
    if (response?.body) void response.body.cancel().catch(() => undefined);
  }
}

function validVtAttributes(attributes: Record<string, unknown>, expectedUrl?: string): boolean {
  const stats = attributes.last_analysis_stats;
  if (!record(stats) || Object.keys(stats).length > 32) return false;
  if (!['harmless', 'undetected', 'suspicious', 'malicious', 'timeout'].every((key) => Object.hasOwn(stats, key))) return false;
  if (!Object.values(stats).every((value) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 100_000)) return false;
  for (const key of ['last_analysis_date', 'first_submission_date', 'last_submission_date', 'creation_date']) {
    const value = attributes[key];
    if (value !== undefined && (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > Math.floor(Date.now() / 1000) + 300)) return false;
  }
  if (expectedUrl && attributes.url !== undefined) {
    if (typeof attributes.url !== 'string' || attributes.url.length > 2_048) return false;
    try { if (new URL(attributes.url).href !== expectedUrl) return false; } catch { return false; }
  }
  const engines = attributes.last_analysis_results;
  if (engines !== undefined) {
    if (!record(engines) || Object.keys(engines).length > 300) return false;
    const categories = new Set(['harmless', 'undetected', 'suspicious', 'malicious', 'timeout', 'confirmed-timeout', 'failure', 'type-unsupported']);
    const observed = new Map<string, number>();
    for (const [name, value] of Object.entries(engines)) {
      if (!name || name.length > 120 || !record(value) || typeof value.category !== 'string' || !categories.has(value.category)) return false;
      if (value.result !== undefined && value.result !== null && (typeof value.result !== 'string' || value.result.length > 240)) return false;
      observed.set(value.category, (observed.get(value.category) ?? 0) + 1);
    }
    for (const [category, count] of observed) if (typeof stats[category] !== 'number' || stats[category] < count) return false;
  }
  return true;
}

function sanitizeVirusTotal(id: string, objectType: string, attributes: Record<string, unknown>): VirusTotalObjectReport {
  const rawStats = record(attributes.last_analysis_stats) ? attributes.last_analysis_stats : {};
  const harmless = count(rawStats.harmless); const undetected = count(rawStats.undetected); const suspicious = count(rawStats.suspicious); const malicious = count(rawStats.malicious); const timeout = count(rawStats.timeout) + count(rawStats['confirmed-timeout']);
  const known = new Set(['harmless', 'undetected', 'suspicious', 'malicious', 'timeout', 'confirmed-timeout']);
  const other = Object.entries(rawStats).reduce((sum, [key, value]) => sum + (known.has(key) ? 0 : count(value)), 0);
  const stats = { harmless, undetected, suspicious, malicious, timeout, other, total: harmless + undetected + suspicious + malicious + timeout + other };
  const lastAnalysisAt = unixDate(attributes.last_analysis_date);
  const firstSubmissionAt = unixDate(attributes.first_submission_date);
  const lastSubmissionAt = unixDate(attributes.last_submission_date);
  const creationAt = unixDate(attributes.creation_date);
  const rawEngines = record(attributes.last_analysis_results) ? attributes.last_analysis_results : {};
  const engines = Object.entries(rawEngines).slice(0, 80).flatMap(([engine, value]) => {
    if (!record(value) || typeof value.category !== 'string') return [];
    return [{ engine: engine.slice(0, 120), category: value.category.slice(0, 60), ...(typeof value.result === 'string' ? { result: value.result.slice(0, 240) } : {}) }];
  });
  return {
    state: 'AVAILABLE', cache: 'MISS', id: id.slice(0, 500), objectType: objectType.slice(0, 30), stats,
    ...(engines.length ? { engines } : {}),
    ...(lastAnalysisAt ? { lastAnalysisAt, freshness: Date.now() - Date.parse(lastAnalysisAt) <= 90 * 86_400_000 ? 'FRESH' : 'STALE' } : { freshness: 'UNKNOWN' }),
    ...(firstSubmissionAt ? { firstSubmissionAt } : {}),
    ...(lastSubmissionAt ? { lastSubmissionAt } : {}),
    ...(creationAt ? { creationAt } : {}),
    ...(typeof attributes.registrar === 'string' ? { registrar: attributes.registrar.slice(0, 200) } : {}),
    ...(typeof attributes.reputation === 'number' && Number.isFinite(attributes.reputation) ? { reputation: attributes.reputation } : {}),
    whoisStatus: typeof attributes.whois === 'string' ? 'PRIVACY_REDACTED' : 'UNAVAILABLE',
    ...(typeof attributes.last_final_url === 'string' ? safeOriginField(attributes.last_final_url) : {}),
    ...(typeof attributes.last_http_response_code === 'number' ? { lastHttpResponseCode: Math.trunc(attributes.last_http_response_code) } : {}),
  };
}

function relevantSameOriginLinks(html: string, base: URL): { links: URL[]; truncated: boolean } {
  const seen = new Set<string>(); const result: URL[] = [];
  // Preserve the same two-child limit, but prefer pages likely to identify the
  // seller over navigation order. No extra request or guessed URL is added.
  const priority = (url: URL) => /contato|contact/i.test(url.pathname) ? 0 : /privacidade|privacy/i.test(url.pathname) ? 1 : /sobre|about|quem-somos|empresa/i.test(url.pathname) ? 2 : 3;
  const sorted = () => result.sort((left, right) => priority(left) - priority(right));
  const relevant = (value: string) => /(contato|contact|fale conosco|atendimento|sobre|about|quem somos|quem-somos|empresa|privacidade|privacy|termos|terms|troca|devol|return|reembolso|refund|entrega|shipping|frete)/i.test(value);
  const add = (href: string, label: string) => {
    try {
      const url = new URL(href, base);
      if (url.origin !== base.origin || !relevant(`${url.pathname} ${label}`)) return false;
      url.search = ''; url.hash = '';
      if (!seen.has(url.href)) {
        if (result.length >= 32) return true;
        seen.add(url.href); result.push(url);
      }
    } catch { /* Ignore malformed declarations from the untrusted page. */ }
    return false;
  };
  for (const match of html.slice(0, 900_000).matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi)) {
    const attributes = match[1] ?? '';
    const href = /\bhref\s*=\s*["']([^"'#]+)["']/i.exec(attributes)?.[1];
    if (!href) continue;
    const aria = /\baria-label\s*=\s*["']([^"']+)["']/i.exec(attributes)?.[1] ?? '';
    const label = visibleText(`${aria} ${match[2] ?? ''}`).slice(0, 240);
    if (add(href, label)) return { links: sorted(), truncated: true };
  }
  return { links: sorted(), truncated: false };
}

interface StructuredOrganizationEvidence { names: string[]; emails: string[]; phones: string[]; hasContact: boolean }

/** Bounded, zero-request JSON-LD extraction from organization-shaped nodes. */
function structuredOrganizationEvidence(html: string): StructuredOrganizationEvidence {
  const names: string[] = []; const emails: string[] = []; const phones: string[] = [];
  let hasContact = false; let bytes = 0; let blocks = 0; let nodes = 0;
  const organizationTypes = new Set(['organization', 'localbusiness', 'store', 'corporation']);
  const strings = (value: unknown): string[] => typeof value === 'string' ? [value] : Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
  const visit = (value: unknown, depth = 0): void => {
    if (depth > 8 || nodes >= 256 || value === null || typeof value !== 'object') return;
    nodes += 1;
    if (Array.isArray(value)) { for (const item of value.slice(0, 64)) visit(item, depth + 1); return; }
    const item = value as Record<string, unknown>;
    const types = strings(item['@type']).map((type) => type.toLowerCase());
    if (types.some((type) => organizationTypes.has(type))) {
      for (const name of [...strings(item.legalName), ...strings(item.name)]) if (name.length >= 2 && name.length <= 160) names.push(name.trim());
      const contacts = [item, ...((Array.isArray(item.contactPoint) ? item.contactPoint : [item.contactPoint]).filter((entry): entry is Record<string, unknown> => record(entry)))];
      for (const contact of contacts) {
        for (const email of strings(contact.email)) if (/^[^\s@]{1,64}@[^\s@]{1,190}$/.test(email)) emails.push(email.toLowerCase());
        for (const phone of strings(contact.telephone)) if (/^[+()\d\s.-]{7,32}$/.test(phone)) phones.push(phone.trim());
      }
      const address = item.address;
      const addressObjects = (Array.isArray(address) ? address : [address]).filter((entry): entry is Record<string, unknown> => record(entry));
      const hasAddress = addressObjects.some((entry) => ['streetAddress', 'addressLocality', 'addressRegion', 'postalCode', 'addressCountry'].some((key) => strings(entry[key]).some(Boolean)));
      hasContact ||= emails.length > 0 || phones.length > 0 || hasAddress;
    }
    for (const child of Object.values(item).slice(0, 64)) visit(child, depth + 1);
  };
  for (const match of html.slice(0, 900_000).matchAll(/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script\s*>/gi)) {
    if (++blocks > 8) break;
    const raw = (match[1] ?? '').trim();
    bytes += raw.length;
    if (!raw || raw.length > 64 * 1024 || bytes > 256 * 1024) continue;
    try { visit(JSON.parse(raw)); } catch { /* Malformed structured data is neutral. */ }
  }
  return { names: unique(names).slice(0, 20), emails: unique(emails).slice(0, 20), phones: unique(phones).slice(0, 20), hasContact };
}

function visibleText(html: string): string {
  return html.replace(/<(script|style|noscript|iframe|object|embed)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&(?:nbsp|#160);/gi, ' ').replace(/\s+/g, ' ').trim();
}

function confirmedPolicies(html: string): Record<string, boolean> {
  // Navigation and link labels are declarations, not evidence of policy content.
  const text = visibleText(html.replace(/<(nav|header|footer|a|form)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' '));
  const substantial = text.split(/\s+/).length >= 35;
  return {
    about: substantial && /\b(?:quem somos|sobre n[oó]s|nossa hist[oó]ria|about us)\b/i.test(text),
    privacy: substantial && /dados pessoais|prote[cç][aã]o de dados|data protection|privacy policy|\blgpd\b/i.test(text),
    terms: substantial && /termos de uso|terms of (?:use|service)|condi[cç][oõ]es (?:de uso|gerais)/i.test(text),
    returns: substantial && /prazo.{0,40}(?:troca|devolu)|pol[ií]tica.{0,30}(?:troca|devolu)|return policy/i.test(text),
    refund: substantial && /reembolso|estorno|refund policy/i.test(text),
    shipping: substantial && /prazo.{0,40}(?:entrega|envio)|pol[ií]tica.{0,30}(?:frete|entrega|envio)|shipping policy|delivery time/i.test(text),
    legal: substantial && /raz[aã]o social|nome empresarial/i.test(text),
    contact: substantial && /contato|fale conosco|atendimento|contact/i.test(text) && /@|telefone|endere[cç]o/i.test(text),
  };
}

function vcardName(value: unknown): string | undefined {
  if (!Array.isArray(value) || !Array.isArray(value[1])) return undefined;
  for (const entry of value[1]) if (Array.isArray(entry) && entry[0] === 'fn' && typeof entry[3] === 'string') return entry[3];
  return undefined;
}
function safeOriginField(value: string): { finalOrigin?: string } {
  try { const target = normalizeTarget(value); return { finalOrigin: target.origin }; } catch { return {}; }
}
function retryAfter(value: string | null): { retryAfterSeconds?: number } {
  const numeric = Number(value); return value && Number.isFinite(numeric) && numeric >= 0 ? { retryAfterSeconds: Math.ceil(numeric) } : {};
}
function unixDate(value: unknown): string | undefined {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? new Date(value * 1000).toISOString() : undefined;
}
function count(value: unknown): number { return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.trunc(value) : 0; }
function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function unique(values: string[]): string[] { return [...new Set(values.filter(Boolean))]; }
function errorCode(error: unknown, fallback: string): string { return error instanceof SafeScanError ? error.code : fallback; }
