import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { GuardedFetcher } from "../src/security/guarded-fetch.js";
import type { ResolvedTarget } from "../src/security/egress-guard.js";

const servers: http.Server[] = [];
afterEach(async () => Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve())))));

describe("GuardedFetcher crawl controls", () => {
  it("blocks a cross-origin redirect before following it", async () => {
    const server = http.createServer((_request, response) => {
      response.writeHead(302, { location: "http://other.example/path" });
      response.end();
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server unavailable");
    const guard = {
      validate(input: string): Promise<ResolvedTarget> {
        const url = new URL(input);
        return Promise.resolve({ requestUrl: url, origin: url.origin, domain: url.hostname, persistedTarget: `${url.origin}/`, addresses: [{ address: "127.0.0.1", family: 4 }] });
      },
      assertConnectedAddress(addressValue: string): void { void addressValue; },
    };
    const fetcher = new GuardedFetcher(guard as never);
    await expect(fetcher.fetch(`http://public.example:${String(address.port)}/`, {
      allowedOrigin: `http://public.example:${String(address.port)}`,
      maxRedirects: 2,
    })).rejects.toThrow("CROSS_ORIGIN_REDIRECT_BLOCKED");
  });

  it("enforces the response byte limit", async () => {
    const server = http.createServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/html" });
      response.end("x".repeat(2048));
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server unavailable");
    const guard = {
      validate(input: string): Promise<ResolvedTarget> {
        const url = new URL(input);
        return Promise.resolve({ requestUrl: url, origin: url.origin, domain: url.hostname, persistedTarget: `${url.origin}/`, addresses: [{ address: "127.0.0.1", family: 4 }] });
      },
      assertConnectedAddress(addressValue: string): void { void addressValue; },
    };
    const fetcher = new GuardedFetcher(guard as never);
    await expect(fetcher.fetch(`http://public.example:${String(address.port)}/`, {
      allowedOrigin: `http://public.example:${String(address.port)}`,
      maxBytes: 128,
    })).rejects.toThrow("RESPONSE_TOO_LARGE");
  });

  it("blocks an action-path redirect before requesting the destination", async () => {
    let requests = 0;
    const server = http.createServer((request, response) => {
      requests += 1;
      if (request.url === "/") {
        response.writeHead(302, { location: "/checkout.html" });
        response.end();
        return;
      }
      response.writeHead(200, { "content-type": "text/html" });
      response.end("checkout");
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server unavailable");
    const guard = {
      validate(input: string): Promise<ResolvedTarget> {
        const url = new URL(input);
        return Promise.resolve({ requestUrl: url, origin: url.origin, domain: url.hostname, persistedTarget: `${url.origin}/`, addresses: [{ address: "127.0.0.1", family: 4 }] });
      },
      assertConnectedAddress(addressValue: string): void { void addressValue; },
    };
    const fetcher = new GuardedFetcher(guard as never);
    await expect(fetcher.fetch(`http://public.example:${String(address.port)}/`, {
      allowedOrigin: `http://public.example:${String(address.port)}`,
      allowedUrl: (url) => !/checkout/i.test(url.pathname),
      requireContentType: true,
    })).rejects.toThrow("URL_POLICY_BLOCKED");
    expect(requests).toBe(1);
  });

  it("stops a same-origin redirect loop deterministically", async () => {
    const server = http.createServer((_request, response) => { response.writeHead(302, { location: "/loop" }); response.end(); });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server unavailable");
    const guard = {
      validate(input: string): Promise<ResolvedTarget> { const url = new URL(input); return Promise.resolve({ requestUrl: url, origin: url.origin, domain: url.hostname, persistedTarget: `${url.origin}/`, addresses: [{ address: "127.0.0.1", family: 4 }] }); },
      assertConnectedAddress(): void { return; },
    };
    const fetcher = new GuardedFetcher(guard as never);
    await expect(fetcher.fetch(`http://public.example:${String(address.port)}/loop`, { allowedOrigin: `http://public.example:${String(address.port)}`, maxRedirects: 4 })).rejects.toThrow("REDIRECT_LOOP");
  });

  it("rejects a non-HTML content type before buffering the body", async () => {
    const server = http.createServer((_request, response) => { response.writeHead(200, { "content-type": "application/octet-stream" }); response.end("binary"); });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server unavailable");
    const guard = {
      validate(input: string): Promise<ResolvedTarget> { const url = new URL(input); return Promise.resolve({ requestUrl: url, origin: url.origin, domain: url.hostname, persistedTarget: `${url.origin}/`, addresses: [{ address: "127.0.0.1", family: 4 }] }); },
      assertConnectedAddress(): void { return; },
    };
    const fetcher = new GuardedFetcher(guard as never);
    await expect(fetcher.fetch(`http://public.example:${String(address.port)}/`, { allowedOrigin: `http://public.example:${String(address.port)}`, allowedContentTypes: ["text/html"], requireContentType: true })).rejects.toThrow("CONTENT_TYPE_BLOCKED");
  });
});
