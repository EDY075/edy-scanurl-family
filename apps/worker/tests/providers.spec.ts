import { describe, expect, it, vi } from 'vitest';
import { collectDns, collectHttp, collectRdap, collectVirusTotal } from '../src/providers';
import { SubrequestBudget } from '../src/security';
import type { Env } from '../src/types';

const vtEnv = { VIRUSTOTAL_ENABLED: 'true', VIRUSTOTAL_API_KEY: 'synthetic-test-only' } as Env;
const origin = 'https://example.com';
const substantive = 'Esta página apresenta informações públicas detalhadas sobre nossa loja e explica aos clientes como os seus pedidos e solicitações são tratados pela equipe responsável durante todo o processo de atendimento antes e depois de qualquer compra. ';
const page = (html: string, status = 200) => new Response(html, { status, headers: { 'content-type': 'text/html' } });
const inputUrl = (input: RequestInfo | URL) => new URL(input instanceof Request ? input.url : String(input));

function pages(handler: (url: URL) => Response | Promise<Response>): SubrequestBudget {
  return new SubrequestBudget((input) => {
    const url = inputUrl(input);
    if (url.hostname === 'cloudflare-dns.com') return Promise.resolve(Response.json({ Status: 0, Answer: url.searchParams.get('type') === 'A' ? [{ type: 1, data: '93.184.216.34' }] : [] }));
    return Promise.resolve(handler(url));
  });
}

async function urlHash(value: string): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}
interface VtFixture { data: { id: string; type: string; attributes: Record<string, unknown> } }
async function vtFixture(url: URL): Promise<VtFixture> {
  const domain = url.pathname.includes('/domains/');
  return { data: {
    id: domain ? 'example.com' : await urlHash(`${origin}/`), type: domain ? 'domain' : 'url',
    attributes: { last_analysis_stats: { harmless: 10, undetected: 20, malicious: 0, suspicious: 0, timeout: 0 }, last_analysis_date: Math.floor(Date.now() / 1000) - 60, ...(domain ? {} : { url: `${origin}/` }) },
  } };
}

describe('Worker public evidence collection', () => {
  it('marks the distinct-CNPJ limit explicitly and keeps observed invalid digits', async () => {
    const body = Array.from({ length: 10 }, (_, index) => `CNPJ ${String(11222333000180 + index)}`).join(' ');
    const result = await collectHttp(new URL(origin), pages(() => page(body)));
    expect(result.cnpjObservations).toHaveLength(8);
    expect(result.cnpjTruncated).toBe(true);
    expect(result.status).toBe('limited');
    expect(result.cnpjObservations?.some((item) => item.checksum === 'INVALID')).toBe(true);
  });
  it('prioritizes discovered contact/privacy pages inside the existing two-child budget', async () => {
    const visited: string[] = [];
    await collectHttp(new URL(origin), pages((url) => {
      visited.push(url.pathname);
      return page(url.pathname === '/' ? '<a href="/quem-somos">Sobre</a><a href="/shipping">Frete</a><a href="/privacy">Privacidade</a><a href="/contato">Contato</a>' : 'CNPJ 11222333000181');
    }));
    expect(visited).toEqual(['/', '/contato', '/privacy']);
  });
  it('discovers an important page from accessible anchor text without guessing a URL or adding a page', async () => {
    const visited: string[] = [];
    const result = await collectHttp(new URL(origin), pages((url) => {
      visited.push(url.pathname);
      return page(url.pathname === '/' ? '<a href="/central/ajuda">Fale conosco</a>' : `${substantive} Telefone (11) 4000-4000 para atendimento.`);
    }));
    expect(visited).toEqual(['/', '/central/ajuda']);
    expect(result.pagesFetched).toBe(2);
  });
  it('uses bounded Organization JSON-LD as self-declared contact evidence without inventing official identity', async () => {
    const structured = JSON.stringify({ '@context': 'https://schema.org', '@type': 'Organization', name: 'Loja de Exemplo', telephone: '+55 11 4000-4000', email: 'ajuda@example.com', address: { '@type': 'PostalAddress', addressLocality: 'São Paulo' } });
    const result = await collectHttp(new URL(origin), pages(() => page(`<script type="application/ld+json">${structured}</script><main>Página pública.</main>`)));
    expect(result.companyNames).toEqual(['Loja de Exemplo']);
    expect(result.emails).toContain('ajuda@example.com');
    expect(result.phones).toContain('+55 11 4000-4000');
    expect(result.policies.contact).toBe(true);
    expect(result.policyEvidence).toContainEqual({ id: 'contact', sourceUrls: ['https://example.com/'] });
    expect(result.cnpjClaims).toEqual([]);
  });
  it('ignores generic product JSON-LD names as company and contact evidence', async () => {
    const structured = JSON.stringify({ '@type': 'Product', name: 'Produto popular', offers: { telephone: '+55 11 4000-4000' } });
    const result = await collectHttp(new URL(origin), pages(() => page(`<script type="application/ld+json">${structured}</script>`)));
    expect(result.companyNames).toEqual([]);
    expect(result.policies.contact).toBe(false);
  });
  it('retains page-level CNPJ and policy provenance without extra requests', async () => {
    const budget = pages((url) => url.pathname === '/' ? page('<footer>CNPJ 11222333000181</footer><a href="/contato">Contato</a>') : page(`<main>${substantive} Fale conosco pelo telefone. CNPJ 11222333000181</main>`));
    const result = await collectHttp(new URL(origin), budget);
    expect(result.cnpjClaims).toEqual(['11222333000181']);
    expect(result.cnpjObservations?.[0]?.provenance).toHaveLength(2);
    expect(result.policyEvidence).toContainEqual({ id: 'contact', sourceUrls: ['https://example.com/contato'] });
    expect(result.pagesFetched).toBe(2);
    expect(budget.count).toBeLessThanOrEqual(6);
  });
  it.each([403, 404, 429, 500, 503])('does not parse HTTP %s into positive content', async (status) => {
    const result = await collectHttp(new URL(origin), pages(() => page(`${substantive} Política de privacidade e proteção de dados pessoais. Prazo de entrega. Política de troca.`, status)));
    expect(result.status).toBe('unavailable');
    expect(result.pagesFetched).toBe(0);
    expect(Object.values(result.policies).some(Boolean)).toBe(false);
    expect(result.reason).toBe(`HTTP_STATUS_${String(status)}`);
    expect(result.crawlManifest).toMatchObject([{ attempted: true, outcome: 'FAILED', reason: result.reason }]);
  });

  it('does not confirm linked/unread policy pages and records every failed or skipped page', async () => {
    const result = await collectHttp(new URL(origin), pages((url) => url.pathname === '/' ? page(`<main>${substantive}</main><footer><a href='/privacy'>Política de privacidade</a><a href='/returns'>Política de troca</a><a href='/shipping'>Prazo de entrega</a></footer>`) : page('Unavailable', 503)));
    expect(result.status).toBe('limited');
    expect(result.pagesFetched).toBe(1);
    expect(result.pagesDiscovered).toBe(4);
    expect(result.pagesSkipped).toBe(1);
    expect(Object.values(result.policies).some(Boolean)).toBe(false);
    expect(result.crawlManifest?.map((entry) => entry.outcome)).toEqual(['FETCHED', 'FAILED', 'FAILED', 'SKIPPED']);
    expect(result.crawlManifest?.at(-1)).toMatchObject({ attempted: false, reason: 'CRAWL_PAGE_LIMIT' });
  });

  it('requires substantive consulted policy content, not keyword-only text', async () => {
    const short = await collectHttp(new URL(origin), pages(() => page('Política de privacidade. Trocas e devoluções. Frete. Contato.')));
    expect(Object.values(short.policies).some(Boolean)).toBe(false);
    const result = await collectHttp(new URL(origin), pages((url) => url.pathname === '/' ? page('<a href="/privacy">Política de privacidade</a>') : page(`<main>${substantive} Proteção de dados pessoais conforme LGPD.</main>`)));
    expect(result.policies.privacy).toBe(true);
    expect(result.pagesFetched).toBe(2);
  });

  it('filters action paths in the frontier without consuming page slots or fetching them', async () => {
    const visited: string[] = [];
    const result = await collectHttp(new URL(origin), pages((url) => {
      visited.push(url.pathname);
      return page(url.pathname === '/' ? '<a href="/%2563heckout/privacy">Política</a><a href="/privacy">Privacidade</a>' : `${substantive} Proteção de dados pessoais.`);
    }));
    expect(visited).toEqual(['/', '/privacy']);
    expect(result.crawlManifest).toContainEqual(expect.objectContaining({ attempted: false, outcome: 'SKIPPED', reason: 'URL_POLICY_BLOCKED' }));
  });

  it('does not treat IDs in script JSON as CNPJ site claims', async () => {
    const result = await collectHttp(new URL(origin), pages(() => page('<script>{"productId":"11222333000181"}</script><p>Public text</p>')));
    expect(result.cnpjClaims).toEqual([]);
  });

  it('keeps failed DS lookup UNKNOWN and successful authenticated denial distinct', async () => {
    const makeBudget = (failure: boolean) => new SubrequestBudget((input) => {
      const type = inputUrl(input).searchParams.get('type');
      return Promise.resolve(type === 'DS' && failure ? new Response(null, { status: 503 }) : Response.json({ Status: 0, AD: true, Answer: type === 'A' ? [{ type: 1, data: '93.184.216.34' }] : [] }));
    });
    expect(await collectDns('example.com', makeBudget(true))).toMatchObject({ status: 'limited', dnssec: 'UNKNOWN', failedQueries: ['DS'] });
    expect(await collectDns('example.com', makeBudget(false))).toMatchObject({ status: 'available', dnssec: 'NOT_OBSERVED' });
  });
  it('queries reachability on the exact host and registration DNS on the registrable domain', async () => {
    const queries: { name: string | null; type: string | null }[] = [];
    const budget = new SubrequestBudget((input) => {
      const url = inputUrl(input); const name = url.searchParams.get('name'); const type = url.searchParams.get('type');
      queries.push({ name, type });
      return Promise.resolve(Response.json({ Status: 0, Answer: type === 'A' ? [{ type: 1, data: '93.184.216.34' }] : type === 'NS' ? [{ type: 2, data: 'ns.example.com.' }] : [] }));
    });
    const result = await collectDns('www.example.com', budget);
    expect(queries.filter((item) => ['A', 'AAAA'].includes(item.type ?? '')).every((item) => item.name === 'www.example.com')).toBe(true);
    expect(queries.filter((item) => ['NS', 'MX', 'CAA', 'DS'].includes(item.type ?? '')).every((item) => item.name === 'example.com')).toBe(true);
    expect(result.ns).toEqual(['ns.example.com']);
    expect(budget.count).toBe(6);
  });
  it('requests RDAP for the registrable domain instead of the www host', async () => {
    const calls: string[] = [];
    const budget = new SubrequestBudget((input) => {
      const url = inputUrl(input); calls.push(url.href);
      if (url.hostname === 'data.iana.org') return Promise.resolve(Response.json({ services: [[['com'], ['https://rdap.example/']]] }));
      return Promise.resolve(Response.json({ events: [{ eventAction: 'registration', eventDate: '2000-01-01T00:00:00Z' }], nameservers: [{ ldhName: 'NS.EXAMPLE.COM' }], status: ['active'] }));
    });
    const result = await collectRdap('www.example.com', budget);
    expect(calls.at(-1)).toBe('https://rdap.example/domain/example.com');
    expect(result).toMatchObject({ status: 'available', registrationDate: '2000-01-01T00:00:00.000Z', nameservers: ['ns.example.com'] });
    expect(budget.count).toBe(2);
  });
});

describe('Worker VirusTotal fail-closed adapter', () => {
  it('validates both identities and calls the quota hook immediately before each GET', async () => {
    const order: string[] = [];
    const budget = new SubrequestBudget(async (input, init) => {
      order.push('fetch');
      const url = inputUrl(input);
      expect(url.hostname).toBe('www.virustotal.com');
      expect(init?.method).toBe('GET'); expect(init?.redirect).toBe('manual');
      return Response.json(await vtFixture(url));
    });
    const result = await collectVirusTotal(origin, 'example.com', vtEnv, budget, () => { order.push('reserve'); return true; });
    expect(order).toEqual(['reserve', 'fetch', 'reserve', 'fetch']);
    expect(result).toMatchObject({ state: 'AVAILABLE', attempted: true, domain: { state: 'AVAILABLE', objectType: 'domain' }, url: { state: 'AVAILABLE', objectType: 'url' } });
  });

  it('does not send a GET when reservation is denied', async () => {
    const fetcher = vi.fn(() => Promise.resolve(Response.json({})));
    const result = await collectVirusTotal(origin, 'example.com', vtEnv, new SubrequestBudget(fetcher), () => false);
    expect(fetcher).not.toHaveBeenCalled(); expect(result).toMatchObject({ state: 'RATE_LIMITED', attempted: false });
  });

  it('returns partial evidence when the second GET reservation is denied', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => Response.json(await vtFixture(inputUrl(input))));
    let reservations = 0;
    const result = await collectVirusTotal(origin, 'example.com', vtEnv, new SubrequestBudget(fetcher), () => ++reservations === 1);
    expect(fetcher).toHaveBeenCalledOnce(); expect(result).toMatchObject({ state: 'PARTIAL', domain: { state: 'AVAILABLE' }, url: { state: 'RATE_LIMITED', attempted: false } });
  });

  it.each(['wrong-id', 'wrong-type', 'missing-type', 'missing-stats', 'string-stats', 'negative-stats', 'fraction-stats', 'missing-malicious', 'future-date', 'invalid-engine', 'inconsistent-engine'])('rejects malformed schema: %s', async (mode) => {
    const result = await collectVirusTotal(origin, 'example.com', vtEnv, new SubrequestBudget(async (input) => {
      const body = await vtFixture(inputUrl(input));
      const attrs = body.data.attributes;
      if (mode === 'wrong-id') body.data.id = 'different.invalid';
      if (mode === 'wrong-type') body.data.type = 'file';
      if (mode === 'missing-type') body.data.type = '';
      if (mode === 'missing-stats') delete attrs.last_analysis_stats;
      if (['string-stats', 'negative-stats', 'fraction-stats', 'missing-malicious'].includes(mode)) {
        const stats = attrs.last_analysis_stats as Record<string, unknown>;
        if (mode === 'missing-malicious') delete stats.malicious;
        else stats.malicious = mode === 'string-stats' ? '7' : mode === 'negative-stats' ? -1 : 0.5;
      }
      if (mode === 'future-date') attrs.last_analysis_date = Math.floor(Date.now() / 1000) + 86_400;
      if (mode === 'invalid-engine') attrs.last_analysis_results = { engine: { category: 1 } };
      if (mode === 'inconsistent-engine') attrs.last_analysis_results = { engine: { category: 'malicious', result: 'phishing' } };
      return Response.json(body);
    }));
    expect(result.state).toBe('FAILED'); expect(result.domain).toMatchObject({ state: 'FAILED', errorCode: 'VIRUSTOTAL_INVALID_RESPONSE' });
    expect(result.domain?.stats).toBeUndefined();
  });

  it('rejects a URL report with the expected hash but another URL attribute', async () => {
    const result = await collectVirusTotal(origin, 'example.com', vtEnv, new SubrequestBudget(async (input) => {
      const body = await vtFixture(inputUrl(input));
      if (body.data.type === 'url') body.data.attributes.url = `${origin}/private?token=wrong`;
      return Response.json(body);
    }));
    expect(result.url).toMatchObject({ state: 'FAILED', errorCode: 'VIRUSTOTAL_INVALID_RESPONSE' });
  });

  it.each([[401, 'FAILED'], [429, 'RATE_LIMITED'], [504, 'TIMED_OUT']] as const)('short-circuits after terminal HTTP %s', async (status, state) => {
    const fetcher = vi.fn(() => Promise.resolve(new Response(null, { status })));
    const result = await collectVirusTotal(origin, 'example.com', vtEnv, new SubrequestBudget(fetcher));
    expect(result.state).toBe(state); expect(fetcher).toHaveBeenCalledOnce();
    expect(result.url).toMatchObject({ attempted: false, errorCode: 'VIRUSTOTAL_SKIPPED_AFTER_TERMINAL' });
  });

  it('keeps two 404 reports NO_DATA rather than failure or safe verdict', async () => {
    const result = await collectVirusTotal(origin, 'example.com', vtEnv, new SubrequestBudget(() => Promise.resolve(new Response(null, { status: 404 }))));
    expect(result).toMatchObject({ state: 'NO_DATA', status: 'limited', attempted: true });
  });

  it('rejects oversized streamed JSON without relying on Content-Length', async () => {
    const result = await collectVirusTotal(origin, 'example.com', vtEnv, new SubrequestBudget(() => Promise.resolve(new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(1_048_577)); controller.close(); } }), { headers: { 'content-type': 'application/json' } }))));
    expect(result.domain).toMatchObject({ state: 'FAILED', errorCode: 'VIRUSTOTAL_RESPONSE_TOO_LARGE' });
  });
});
