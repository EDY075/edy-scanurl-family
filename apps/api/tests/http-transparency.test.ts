import { describe, expect, it } from "vitest";
import type { GuardedFetcher, GuardedFetchOptions, GuardedResponse } from "../src/security/guarded-fetch.js";
import { HttpTransparencyProvider } from "../src/providers/http-transparency.js";

describe("passive transparency crawler", () => {
  it("classifies the provider as timed out when the guarded fetch deadline expires", async () => {
    const fetcher = {
      fetch(): Promise<GuardedResponse> {
        return Promise.reject(new Error("FETCH_DEADLINE_EXCEEDED"));
      },
    } as unknown as GuardedFetcher;

    const provider = new HttpTransparencyProvider(fetcher);
    const result = await provider.execute({
      scanId: "scan-timeout",
      domain: "synthetic.example",
      targetUrl: "https://synthetic.example/",
    });

    expect(result.status).toBe("TIMED_OUT");
    expect(result.errorCode).toBe("FETCH_DEADLINE_EXCEEDED");
  });

  it("crawls only a bounded same-origin depth-one frontier and records every selected page", async () => {
    const calls: { url: string; options: GuardedFetchOptions }[] = [];
    const homeLinks = Array.from({ length: 14 }, (_, index) =>
      `<a href="/${index % 2 === 0 ? "contato" : "privacidade"}-${String(index)}">${index % 2 === 0 ? "Contato" : "Privacidade"}</a>`,
    ).join("");
    const fetcher = {
      fetch(url: string, options: GuardedFetchOptions): Promise<GuardedResponse> {
        calls.push({ url, options });
        const body = calls.length === 1
          ? `<html><body>${homeLinks}<a href="https://external.example/contact">Contato externo</a></body></html>`
          : `<html><body><h1>Contato</h1><p>${"Dados de contato e privacidade. ".repeat(40)}</p><p>contato@synthetic.example</p></body></html>`;
        return Promise.resolve({
          finalUrl: url, statusCode: 200, headers: { "content-type": "text/html" },
          body: Buffer.from(body), redirectChain: [], remoteAddress: "203.0.113.1",
        });
      },
    } as unknown as GuardedFetcher;
    const provider = new HttpTransparencyProvider(fetcher);
    const result = await provider.execute({ scanId: "scan", domain: "synthetic.example", targetUrl: "https://synthetic.example/" });
    expect(result.status).toBe("PARTIAL");
    expect(result.data?.pagesFetched).toBe(11);
    expect(result.data?.notSelectedByLimit).toBe(4);
    expect(result.data?.crawlManifest).toHaveLength(11);
    expect(result.data?.crawlManifest.every((item) => item.outcome === "FETCHED")).toBe(true);
    expect(calls.every((call) => call.options.allowedOrigin === "https://synthetic.example")).toBe(true);
    expect(calls.some((call) => call.url.includes("external.example"))).toBe(false);
  });

  it("does not extract policy evidence from a non-success page", async () => {
    let calls = 0;
    const fetcher = {
      fetch(url: string): Promise<GuardedResponse> {
        calls += 1;
        const body = calls === 1
          ? '<a href="/privacidade">Política de privacidade</a>'
          : `<h1>Privacidade</h1><p>${"Dados pessoais e cookies. ".repeat(50)}</p>`;
        return Promise.resolve({
          finalUrl: url,
          statusCode: calls === 1 ? 200 : 404,
          headers: { "content-type": "text/html" },
          body: Buffer.from(body),
          redirectChain: [],
          remoteAddress: "203.0.113.1",
        });
      },
    } as unknown as GuardedFetcher;
    const provider = new HttpTransparencyProvider(fetcher);
    const result = await provider.execute({ scanId: "scan-404", domain: "synthetic.example", targetUrl: "https://synthetic.example/" });
    expect(result.status).toBe("PARTIAL");
    expect(result.data?.signals.policies.privacy).toBe(false);
    expect(result.data?.pagesFetched).toBe(1);
    expect(result.data?.crawlManifest.at(-1)).toMatchObject({ outcome: "FAILED", reason: "HTTP_STATUS_404" });
  });

  it("rejects encoded, double-encoded and parameterized action paths", async () => {
    const calls: string[] = [];
    const fetcher = {
      fetch(url: string): Promise<GuardedResponse> {
        calls.push(url);
        const body = calls.length === 1
          ? [
              '<a href="/%63heckout">Checkout encoded</a>',
              '<a href="/%2563heckout">Checkout double encoded</a>',
              '<a href="/checkout;sid=1">Checkout parameter</a>',
              '<a href="/%5ccheckout">Checkout backslash encoded</a>',
              '<a href="/%255ccheckout">Checkout double backslash encoded</a>',
              '<a href="/contato">Contato</a>',
            ].join("")
          : `<h1>Contato</h1><p>${"Dados públicos de contato. ".repeat(40)}</p>`;
        return Promise.resolve({
          finalUrl: url, statusCode: 200, headers: { "content-type": "text/html" },
          body: Buffer.from(body), redirectChain: [], remoteAddress: "203.0.113.1",
        });
      },
    } as unknown as GuardedFetcher;
    const provider = new HttpTransparencyProvider(fetcher);
    const result = await provider.execute({ scanId: "scan-actions", domain: "synthetic.example", targetUrl: "https://synthetic.example/" });
    expect(result.data?.pagesFetched).toBe(2);
    expect(calls).toEqual(["https://synthetic.example/", "https://synthetic.example/contato"]);
  });
});
