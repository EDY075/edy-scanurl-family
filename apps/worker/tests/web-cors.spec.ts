import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/types";
const origin = "https://family.example.com";
const bindings = () => ({
  ...(env as unknown as Env),
  WEB_ALLOWED_ORIGINS: origin,
});
describe("Exact production Web CORS — local source only", () => {
  it("allows configured HTTPS origin on health and exposes Retry-After", async () => {
    const response = await worker.fetch(
      new Request("https://api.example.com/health", {
        headers: { Origin: origin },
      }),
      bindings(),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(origin);
    expect(response.headers.get("Access-Control-Expose-Headers")).toBe(
      "Retry-After",
    );
    expect(response.headers.get("Cache-Control")).toContain("no-store");
  });
  it("permits signed request headers on preflight", async () => {
    const response = await worker.fetch(
      new Request("https://api.example.com/family/v1/scans", {
        method: "OPTIONS",
        headers: { Origin: origin },
      }),
      bindings(),
    );
    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Headers")).toContain(
      "X-Family-Signature",
    );
    expect(response.headers.get("Access-Control-Allow-Credentials")).toBeNull();
  });
  it.each([
    "https://evil.example.com",
    "https://family.example.com.evil.com",
    "https://sub.family.example.com",
    "null",
    "http://family.example.com",
  ])("rejects unapproved origin %s", async (value) => {
    const response = await worker.fetch(
      new Request("https://api.example.com/health", {
        headers: { Origin: value },
      }),
      bindings(),
    );
    expect(response.status).toBe(403);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
  it.each([
    "*",
    "https://family.example.com/",
    "http://family.example.com",
    "https://user:pass@family.example.com",
    "https://family.example.com:8443",
  ])("does not interpret malformed configuration %s", async (value) => {
    const response = await worker.fetch(
      new Request("https://api.example.com/health", {
        headers: { Origin: origin },
      }),
      { ...bindings(), WEB_ALLOWED_ORIGINS: value },
    );
    expect(response.status).toBe(403);
  });
  it("keeps new web origins disabled by default", async () => {
    const response = await worker.fetch(
      new Request("https://api.example.com/health", {
        headers: { Origin: origin },
      }),
      { ...bindings(), WEB_ALLOWED_ORIGINS: "" },
    );
    expect(response.status).toBe(403);
  });
  it("returns readable disabled-service errors only to approved origins", async () => {
    const response = await worker.fetch(
      new Request("https://api.example.com/family/v1/scans", {
        method: "POST",
        headers: { Origin: origin },
      }),
      { ...bindings(), SERVICE_ENABLED: "false" },
    );
    expect(response.status).toBe(503);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(origin);
  });
  it("preserves native origin without additional configuration", async () => {
    const response = await worker.fetch(
      new Request("https://api.example.com/health", {
        headers: { Origin: "https://localhost" },
      }),
      { ...bindings(), WEB_ALLOWED_ORIGINS: "" },
    );
    expect(response.status).toBe(200);
  });
});
