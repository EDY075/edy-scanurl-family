import { describe, expect, it, vi } from "vitest";
import { VirusTotalProvider, type VirusTotalFetch } from "../src/providers/virus-total.js";

const context = {
  scanId: "scan-vt",
  domain: "shop.example.com",
  targetUrl: "https://shop.example.com/private/order/42?token=secret#receipt",
};

function vtResponse(attributes: Record<string, unknown> = {}, id = "example.com", type = "domain"): Response {
  return new Response(JSON.stringify({ data: { id, type, attributes } }), {
    status: 200,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function vtLookupResponse(input: string, attributes: Record<string, unknown> = {}): Response {
  return input.includes("/urls/") ? vtResponse(attributes, "synthetic-url-id", "url") : vtResponse(attributes);
}

function mockFetch(handler: (input: string, init: RequestInit) => Response | Promise<Response>): VirusTotalFetch {
  return vi.fn((input: string, init: RequestInit) => Promise.resolve(handler(input, init)));
}

function cleanAttributes(): Record<string, unknown> {
  return {
    last_analysis_date: Math.floor(Date.now() / 1000),
    last_analysis_stats: { harmless: 12, undetected: 60, suspicious: 0, malicious: 0, timeout: 1 },
    last_analysis_results: {
      EngineA: { category: "harmless", result: "clean", method: "blacklist", engine_version: "1.0", engine_update: "20260830" },
      EngineB: { category: "undetected", result: null, method: "blacklist" },
    },
    reputation: 2,
    categories: { vendor: "shopping" },
  };
}

describe("VirusTotalProvider read-only adapter", () => {
  it("looks up only the registrable domain and normalized origin without exposing path, query or credentials", async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const fetchImpl = mockFetch((input, init) => {
      calls.push({ url: input, init });
      return vtLookupResponse(input, cleanAttributes());
    });
    const result = await new VirusTotalProvider({ apiKey: "test-key", fetchImpl }).execute(context);

    expect(result.status).toBe("SUCCEEDED");
    expect(calls).toHaveLength(2);
    expect(calls.every((call) => call.init?.method === "GET" && call.init.redirect === "error")).toBe(true);
    expect(calls[0]?.url).toBe("https://www.virustotal.com/api/v3/domains/example.com");
    const encodedOrigin = calls[1]?.url.split("/").at(-1) ?? "";
    expect(Buffer.from(encodedOrigin, "base64url").toString("utf8")).toBe("https://shop.example.com/");
    expect(JSON.stringify(calls)).not.toContain("private");
    expect(JSON.stringify(calls)).not.toContain("secret");
    expect(result.data).toMatchObject({ disclosure: "REGISTRABLE_DOMAIN_AND_NORMALIZED_ORIGIN_ONLY", registrableDomain: "example.com", normalizedOrigin: "https://shop.example.com/" });
  });

  it("preserves malicious and suspicious engine facts without multiplying provider authority", async () => {
    const attributes = cleanAttributes();
    attributes.last_analysis_stats = { harmless: 4, undetected: 50, suspicious: 2, malicious: 3, timeout: 1 };
    attributes.last_analysis_results = {
      Alpha: { category: "malicious", result: "phishing" },
      Beta: { category: "malicious", result: "malware" },
      Gamma: { category: "suspicious", result: "suspicious" },
    };
    const provider = new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch((input) => vtLookupResponse(input, attributes)) });
    const result = await provider.execute(context);
    expect(result.data?.domain.stats).toMatchObject({ malicious: 3, suspicious: 2, timeout: 1, total: 60 });
    expect(result.data?.domain.engines).toHaveLength(3);
  });

  it("classifies remote rate limiting without retrying", async () => {
    const fetchImpl = mockFetch(() => new Response("{}", { status: 429, headers: { "content-type": "application/json", "retry-after": "60" } }));
    const result = await new VirusTotalProvider({ apiKey: "test-key", fetchImpl }).execute(context);
    expect(result).toMatchObject({ status: "RATE_LIMITED", errorCode: "VIRUSTOTAL_RATE_LIMITED" });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(result.data?.domain.retryAfterSeconds).toBe(60);
  });

  it("classifies a missing domain and URL report as NO_DATA, never PASS", async () => {
    const provider = new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch(() => new Response("{}", { status: 404, headers: { "content-type": "application/json" } })) });
    const result = await provider.execute(context);
    expect(result).toMatchObject({ status: "NO_DATA", errorCode: "VIRUSTOTAL_NO_REPORT" });
    expect(result.data?.domain.state).toBe("NO_DATA");
    expect(result.data?.url.state).toBe("NO_DATA");
  });

  it("marks old reports partial and redacts WHOIS content", async () => {
    const old = { ...cleanAttributes(), last_analysis_date: 1_577_836_800, whois: "Registrant Name: Private Person\nAdmin Email: hidden@example.com" };
    const provider = new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch((input) => vtLookupResponse(input, old)) });
    const result = await provider.execute(context);
    expect(result).toMatchObject({ status: "PARTIAL", errorCode: "VIRUSTOTAL_STALE_REPORT" });
    expect(result.data?.domain).toMatchObject({ freshness: "STALE", whoisStatus: "PRIVACY_REDACTED" });
    expect(JSON.stringify(result)).not.toContain("hidden@example.com");
  });

  it("accepts a valid report with optional fields missing", async () => {
    const provider = new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch((input) => vtLookupResponse(input, {})) });
    const result = await provider.execute(context);
    expect(result.status).toBe("SUCCEEDED");
    expect(result.data?.domain).toMatchObject({ state: "AVAILABLE", freshness: "UNKNOWN", whoisStatus: "UNAVAILABLE" });
  });

  it("classifies provider timeout and invalid response explicitly", async () => {
    const controller = new AbortController();
    controller.abort();
    const timeout = await new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch(() => vtResponse({})) }).execute({ ...context, signal: controller.signal });
    expect(timeout).toMatchObject({ status: "TIMED_OUT", errorCode: "VIRUSTOTAL_ABORTED" });

    const invalid = await new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch(() => new Response("{not-json", { status: 200, headers: { "content-type": "application/json" } })) }).execute(context);
    expect(invalid).toMatchObject({ status: "FAILED", errorCode: "VIRUSTOTAL_INVALID_RESPONSE" });
  });

  it("uses bounded cache and single-flight for concurrent identical lookups", async () => {
    let calls = 0;
    const fetchImpl = mockFetch(async (input) => {
      calls += 1;
      await Promise.resolve();
      return vtLookupResponse(input, cleanAttributes());
    });
    const provider = new VirusTotalProvider({ apiKey: "test-key", fetchImpl });
    const [first, second] = await Promise.all([provider.execute(context), provider.execute(context)]);
    expect(first.status).toBe("SUCCEEDED");
    expect(second.status).toBe("SUCCEEDED");
    expect(calls).toBe(2);

    const cached = await provider.execute(context);
    expect(calls).toBe(2);
    expect(cached.data?.domain.cache).toBe("HIT");
    expect(cached.data?.url.cache).toBe("HIT");
  });

  it("rejects credential failures and hostile response metadata", async () => {
    const rejected = await new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch(() => new Response("{}", { status: 401, headers: { "content-type": "application/json" } })) }).execute(context);
    expect(rejected.status).toBe("DISABLED_NO_CREDENTIALS");

    const wrongType = await new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch(() => new Response("ok", { status: 200, headers: { "content-type": "text/plain" } })) }).execute(context);
    expect(wrongType).toMatchObject({ status: "FAILED", errorCode: "VIRUSTOTAL_INVALID_CONTENT_TYPE" });
  });

  it("enforces a sliding four-request window rather than refilling within the minute", async () => {
    let now = Date.parse("2026-08-30T12:00:00Z");
    let calls = 0;
    const fetchImpl = mockFetch((input) => {
      calls += 1;
      if (input.includes("/urls/")) return vtResponse(cleanAttributes(), "synthetic-url-id", "url");
      const domain = decodeURIComponent(input.split("/").at(-1) ?? "");
      return vtResponse(cleanAttributes(), domain, "domain");
    });
    const provider = new VirusTotalProvider({ apiKey: "test-key", fetchImpl, now: () => now });
    await expect(provider.execute({ ...context, domain: "example.com", targetUrl: "https://example.com/" })).resolves.toMatchObject({ status: "SUCCEEDED" });
    await expect(provider.execute({ ...context, domain: "example.org", targetUrl: "https://example.org/" })).resolves.toMatchObject({ status: "SUCCEEDED" });
    now += 15_000;
    await expect(provider.execute({ ...context, domain: "example.net", targetUrl: "https://example.net/" })).resolves.toMatchObject({ status: "RATE_LIMITED" });
    expect(calls).toBe(4);
    now += 45_000;
    await expect(provider.execute({ ...context, domain: "example.net", targetUrl: "https://example.net/" })).resolves.toMatchObject({ status: "SUCCEEDED" });
    expect(calls).toBe(6);
  });

  it("rejects invalid stats and stops streaming oversized bodies", async () => {
    const invalidStats = await new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch((input) => vtLookupResponse(input, { last_analysis_stats: { malicious: -1 } })) }).execute(context);
    expect(invalidStats).toMatchObject({ status: "FAILED", errorCode: "VIRUSTOTAL_INVALID_RESPONSE" });

    const oversizedBody = JSON.stringify({ data: { id: "example.com", type: "domain", attributes: { padding: "x".repeat(1_048_576) } } });
    const oversized = await new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch(() => new Response(oversizedBody, { status: 200, headers: { "content-type": "application/json" } })) }).execute(context);
    expect(oversized).toMatchObject({ status: "FAILED", errorCode: "VIRUSTOTAL_RESPONSE_TOO_LARGE" });
  });

  it("keeps single-flight upstream lifecycle independent from each caller abort", async () => {
    let calls = 0;
    const fetchImpl = mockFetch(async (input) => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return vtLookupResponse(input, cleanAttributes());
    });
    const provider = new VirusTotalProvider({ apiKey: "test-key", fetchImpl });
    const controller = new AbortController();
    const first = provider.execute({ ...context, signal: controller.signal });
    const second = provider.execute(context);
    await Promise.resolve();
    controller.abort();
    await expect(first).resolves.toMatchObject({ status: "TIMED_OUT" });
    await expect(second).resolves.toMatchObject({ status: "SUCCEEDED" });
    expect(calls).toBe(2);
  });

  it("recomputes cached freshness with the injected clock", async () => {
    let now = Date.parse("2026-08-30T12:00:00Z");
    const attributes = { ...cleanAttributes(), last_analysis_date: Math.floor((now - (89 * 24 + 12) * 60 * 60_000) / 1000) };
    const provider = new VirusTotalProvider({ apiKey: "test-key", fetchImpl: mockFetch((input) => vtLookupResponse(input, attributes)), now: () => now });
    await expect(provider.execute(context)).resolves.toMatchObject({ status: "SUCCEEDED" });
    now += 13 * 60 * 60_000;
    const cached = await provider.execute(context);
    expect(cached).toMatchObject({ status: "PARTIAL", errorCode: "VIRUSTOTAL_STALE_REPORT" });
    expect(cached.data?.domain).toMatchObject({ cache: "HIT", freshness: "STALE" });
  });
});
