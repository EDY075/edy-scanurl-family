import { describe, expect, it, vi } from 'vitest';
import { assertPublicAddresses, classifyAddress, isPassivePageUrl, normalizeTarget, safePageFetch, SubrequestBudget } from '../src/security';

describe('Worker SSRF boundary', () => {
  it('invokes the platform fetch without a class instance as its receiver', async () => {
    vi.stubGlobal('fetch', function (this: unknown) {
      if (this instanceof SubrequestBudget) throw new TypeError('Illegal invocation');
      return Promise.resolve(new Response('ok'));
    });
    try {
      const response = await new SubrequestBudget().fetch('https://example.com/');
      expect(await response.text()).toBe('ok');
    } finally { vi.unstubAllGlobals(); }
  });
  it.each([
    'http://127.0.0.1/', 'http://[::1]/', 'http://169.254.169.254/latest/meta-data/',
    'https://metadata.google.internal/', 'https://localhost/', 'https://test.local/',
    'file:///etc/passwd', 'https://user:pass@example.com/', 'https://example.com:8443/',
  ])('rejects %s', (value) => { expect(() => normalizeTarget(value)).toThrow(); });

  it('keeps only the public origin', () => {
    expect(normalizeTarget('https://example.com/order/123?token=secret#part')).toMatchObject({ origin: 'https://example.com', domain: 'example.com' });
    expect(normalizeTarget('https://example.com/order/123?token=secret#part').url.toString()).toBe('https://example.com/');
  });

  it.each(['10.0.0.1', '127.0.0.1', '169.254.169.254', '100.64.0.1', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1'])('classifies %s as blocked', (address) => {
    expect(classifyAddress(address).allowed).toBe(false);
  });

  it('fails closed on mixed public/private DNS answers', () => {
    expect(() => assertPublicAddresses(['93.184.216.34', '127.0.0.1'])).toThrow(/EGRESS_BLOCKED/);
  });

  it('blocks a cross-domain redirect before following it', async () => {
    const calls: string[] = [];
    const fakeFetch = (input: RequestInfo | URL): Promise<Response> => {
      const url = new URL(input instanceof Request ? input.url : input instanceof URL ? input.href : input); calls.push(url.toString());
      if (url.hostname === 'cloudflare-dns.com') return Promise.resolve(Response.json({ Status: 0, Answer: [{ type: url.searchParams.get('type') === 'AAAA' ? 28 : 1, data: url.searchParams.get('type') === 'AAAA' ? '2606:2800:220:1:248:1893:25c8:1946' : '93.184.216.34' }] }));
      return Promise.resolve(new Response('', { status: 302, headers: { Location: 'https://evil.example.net/' } }));
    };
    await expect(safePageFetch(new URL('https://example.com/'), new SubrequestBudget(fakeFetch))).rejects.toThrow(/CROSS_DOMAIN_REDIRECT_BLOCKED/);
    expect(calls.some((value) => value.startsWith('https://evil.example.net/'))).toBe(false);
  });

  it('enforces the internal subrequest budget below the platform limit', async () => {
    const budget = new SubrequestBudget(() => Promise.resolve(new Response('ok')));
    for (let index = 0; index < 32; index += 1) await budget.fetch('https://example.com/');
    await expect(budget.fetch('https://example.com/')).rejects.toThrow(/SUBREQUEST_BUDGET_EXCEEDED/);
  });

  it('propagates the global 15-second deadline to the real fetch signal and prevents later requests', async () => {
    vi.useFakeTimers();
    const deadline = new AbortController();
    const timeout = vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
      setTimeout(() => deadline.abort(new DOMException('global deadline', 'TimeoutError')), milliseconds);
      return deadline.signal;
    });
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new Error('transport aborted')), { once: true });
    }));
    try {
      const budget = new SubrequestBudget(fetcher);
      const pending = expect(budget.fetch('https://example.com/', { signal: new AbortController().signal })).rejects.toThrow('transport aborted');
      expect(timeout).toHaveBeenCalledWith(15_000);
      await vi.advanceTimersByTimeAsync(15_000);
      await pending;
      expect(fetcher.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
      await expect(budget.fetch('https://example.com/next')).rejects.toThrow('SCAN_DEADLINE_EXCEEDED');
      expect(fetcher).toHaveBeenCalledOnce();
    } finally { vi.restoreAllMocks(); vi.useRealTimers(); }
  });

  it.each(['/checkout/privacy', '/%63heckout/privacy', '/%2563heckout/privacy', '/checkout;sid=1/privacy', '/contact/%255ccheckout', '/about/%xx', '/contact/%25252525252525252563heckout'])('rejects passive crawl action/ambiguous path %s before requests', async (path) => {
    const fetcher = vi.fn(() => Promise.resolve(new Response('unexpected')));
    const url = new URL(`https://example.com${path}`);
    expect(isPassivePageUrl(url)).toBe(false);
    await expect(safePageFetch(url, new SubrequestBudget(fetcher))).rejects.toThrow('URL_POLICY_BLOCKED');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    ['http://example.com/privacy', 'HTTPS_DOWNGRADE_BLOCKED'],
    ['https://example.com/%2563heckout/privacy', 'URL_POLICY_BLOCKED'],
  ])('rejects redirect to %s without following', async (location, code) => {
    const targets: string[] = [];
    const canceled = vi.fn();
    const fetcher = (input: RequestInfo | URL) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.hostname === 'cloudflare-dns.com') return Promise.resolve(Response.json({ Status: 0, Answer: url.searchParams.get('type') === 'A' ? [{ type: 1, data: '93.184.216.34' }] : [] }));
      targets.push(url.href);
      return Promise.resolve(new Response(new ReadableStream({ cancel: canceled }), { status: 302, headers: { location } }));
    };
    await expect(safePageFetch(new URL('https://example.com/'), new SubrequestBudget(fetcher))).rejects.toThrow(code);
    expect(targets).toEqual(['https://example.com/']);
    expect(canceled).toHaveBeenCalledOnce();
  });

  it('preserves passive redirect paths while stripping query and fragment', async () => {
    const targets: string[] = [];
    const fetcher = (input: RequestInfo | URL) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.hostname === 'cloudflare-dns.com') return Promise.resolve(Response.json({ Status: 0, Answer: url.searchParams.get('type') === 'A' ? [{ type: 1, data: '93.184.216.34' }] : [] }));
      targets.push(url.href);
      return Promise.resolve(targets.length === 1 ? new Response(null, { status: 302, headers: { location: '/privacy?secret=discard#fragment' } }) : new Response('<p>privacy content</p>', { headers: { 'content-type': 'text/html' } }));
    };
    const result = await safePageFetch(new URL('https://example.com/'), new SubrequestBudget(fetcher));
    expect(targets).toEqual(['https://example.com/', 'https://example.com/privacy']);
    expect(result.finalUrl.pathname).toBe('/privacy');
  });
});
