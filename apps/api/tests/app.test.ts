import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { createApp } from "../src/app.js";

let app: FastifyInstance | undefined;

afterEach(async () => {
  if (app) await app.close();
  app = undefined;
});

describe("Fastify application", () => {
  it("completes health responses with private no-store headers", async () => {
    app = createApp();
    const response = await app.inject({ method: "GET", url: "/health" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ status: "ok", persistence: "ephemeral" });
    expect(response.headers["cache-control"]).toBe("no-store, private");
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("returns SCAN_REJECTED for a private target without creating a verdict", async () => {
    app = createApp();
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      payload: { url: "http://127.0.0.1/private" },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ code: "SCAN_REJECTED", reason: "IP_LITERAL" });
  });

  it("rejects unapproved browser origins", async () => {
    app = createApp();
    const response = await app.inject({
      method: "GET",
      url: "/health",
      headers: { origin: "https://unapproved.example" },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ code: "ORIGIN_NOT_ALLOWED" });
  });

  it("classifies malformed JSON and oversized payloads without exposing internals", async () => {
    app = createApp();
    const malformed = await app.inject({ method: "POST", url: "/api/v1/scans", headers: { "content-type": "application/json" }, payload: "{" });
    expect(malformed.statusCode).toBe(400);
    expect(malformed.json()).toMatchObject({ code: "INVALID_REQUEST" });
    expect(malformed.body).not.toMatch(/stack|SyntaxError/i);
    const oversized = await app.inject({ method: "POST", url: "/api/v1/scans", payload: { url: `https://${"a".repeat(17_000)}.example` } });
    expect(oversized.statusCode).toBe(413);
    expect(oversized.json()).toMatchObject({ code: "PAYLOAD_TOO_LARGE" });
  });
});
