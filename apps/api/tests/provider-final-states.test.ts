import { describe, expect, it } from "vitest";
import { DnsProvider } from "../src/providers/dns.js";
import { RdapProvider } from "../src/providers/rdap.js";
import { TlsProvider } from "../src/providers/tls.js";
import type { GuardedFetcher, GuardedResponse } from "../src/security/guarded-fetch.js";

const context = { scanId: "scan", domain: "example.com", targetUrl: "https://example.com/" };

describe("provider terminal-state contract", () => {
  it("classifies guarded RDAP deadlines and bootstrap 429 responses explicitly", async () => {
    const deadlineFetcher = { fetch: () => Promise.reject(new Error("FETCH_DEADLINE_EXCEEDED")) } as unknown as GuardedFetcher;
    await expect(new RdapProvider(deadlineFetcher).execute(context)).resolves.toMatchObject({ status: "TIMED_OUT", errorCode: "FETCH_DEADLINE_EXCEEDED" });

    const limitedFetcher = { fetch: () => Promise.resolve({ statusCode: 429, body: Buffer.from(""), headers: {}, finalUrl: "https://data.iana.org/rdap/dns.json", redirectChain: [], remoteAddress: "192.0.2.1" } satisfies GuardedResponse) } as unknown as GuardedFetcher;
    await expect(new RdapProvider(limitedFetcher).execute(context)).resolves.toMatchObject({ status: "RATE_LIMITED", errorCode: "IANA_BOOTSTRAP_RATE_LIMITED" });
  });

  it("honors an already-aborted DNS scan without starting resolver work", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(new DnsProvider().execute({ ...context, signal: controller.signal })).resolves.toMatchObject({ status: "TIMED_OUT", errorCode: "DNS_ABORTED" });
  });

  it("cancels and settles DNS work when a scan aborts mid-flight", async () => {
    let cancelCalls = 0;
    const pending = new Promise<never>(() => undefined);
    const resolver = {
      resolve4: () => pending,
      resolve6: () => pending,
      resolveNs: () => pending,
      resolveMx: () => pending,
      resolveCaa: () => pending,
      resolve: () => pending,
      cancel: () => { cancelCalls += 1; },
    };
    const controller = new AbortController();
    const execution = new DnsProvider(() => resolver as never).execute({ ...context, signal: controller.signal });
    controller.abort();
    await expect(execution).resolves.toMatchObject({ status: "TIMED_OUT", errorCode: "DNS_ABORTED" });
    expect(cancelCalls).toBe(1);
  });

  it("keeps a failed DNSSEC query distinct from an observed unsigned domain", async () => {
    const resolver = {
      resolve4: () => Promise.resolve(["192.0.2.10"]),
      resolve6: () => Promise.reject(Object.assign(new Error("no data"), { code: "ENODATA" })),
      resolveNs: () => Promise.resolve(["ns1.example.com"]),
      resolveMx: () => Promise.resolve([]),
      resolveCaa: () => Promise.resolve([]),
      resolve: () => Promise.reject(Object.assign(new Error("service failure"), { code: "ESERVFAIL" })),
      cancel: () => undefined,
    };
    await expect(new DnsProvider(() => resolver as never, () => Promise.resolve([{ address: "192.0.2.10", family: 4 }])).execute(context)).resolves.toMatchObject({
      status: "PARTIAL",
      errorCode: "DNS_PARTIAL_QUERY_FAILURE",
      data: { dnssec: "UNKNOWN" },
    });
  });

  it("does not collapse a failed address-family query into DNS no-data", async () => {
    const resolver = {
      resolveNs: () => Promise.resolve([]),
      resolveMx: () => Promise.resolve([]),
      resolveCaa: () => Promise.resolve([]),
      resolve: () => Promise.resolve([]),
      cancel: () => undefined,
    };
    const failedLookup = () => Promise.reject(Object.assign(new Error("service failure"), { code: "ESERVFAIL" }));
    await expect(new DnsProvider(() => resolver as never, failedLookup).execute(context)).resolves.toMatchObject({
      status: "FAILED",
      errorCode: "DNS_ADDRESS_LOOKUP_FAILED",
    });
  });

  it("classifies an aborted TLS inspection as timed out", async () => {
    const guard = {
      validate: () => Promise.resolve({ requestUrl: new URL("https://example.com/"), origin: "https://example.com", domain: "example.com", persistedTarget: "https://example.com/", addresses: [{ address: "192.0.2.1", family: 4 }] }),
      assertConnectedAddress: () => undefined,
    };
    const controller = new AbortController();
    controller.abort();
    await expect(new TlsProvider(guard as never).execute({ ...context, signal: controller.signal })).resolves.toMatchObject({ status: "TIMED_OUT", errorCode: "TLS_ABORTED" });
  });
});
