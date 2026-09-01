import { afterEach, describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import {
  ApiError,
  checkHealth,
  friendlyError,
  requestJson,
  scanStore,
  validateChallenge,
} from "./api";
import { validateReport } from './report-validation';
import { API_ORIGIN } from "./config";
import { signatureToDer } from "./identity";
import type { ScanReport } from "../../types";

vi.mock("./identity", async (importOriginal) => {
  const original = await importOriginal<typeof import("./identity")>();
  return {
    ...original,
    getBrowserIdentity: async () => {
      const key = await webcrypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"],
      );
      const publicKey = await webcrypto.subtle.exportKey("spki", key.publicKey);
      return {
        privateKey: key.privateKey,
        publicKeySpki: Buffer.from(publicKey).toString("base64"),
        deviceId: Buffer.from(
          await webcrypto.subtle.digest("SHA-256", publicKey),
        ).toString("hex"),
      };
    },
  };
});
export function fixtureReport(): ScanReport {
  return {
    id: "12345678-1234-4234-8234-123456789abc",
    mode: "real",
    inputUrl: "https://example.com/",
    normalizedUrl: "https://example.com/",
    domain: "example.com",
    scannedAt: new Date().toISOString(),
    verdict: "BUY",
    score: 90,
    confidence: "HIGH",
    coverage: 94,
    summary: "Test-only evidence",
    recommendation: "Test-only recommendation",
    checks: [
      {
        id: "domain.age",
        category: "domain",
        title: "Idade do domínio",
        description: "Test fixture only",
        impact: "positive",
        status: "PASS",
        points: 10,
        sourceId: "rdap",
      },
    ],
    sources: [
      {
        id: "rdap",
        name: "RDAP",
        category: "domain",
        status: "available",
        tier: 1,
      },
    ],
    scoreAreas: [],
    technical: {
      domainAge: "10 anos",
      registrar: "Example",
      dns: [],
      tls: "HTTPS",
      tlsIssuer: "Example",
      redirects: [],
      headers: [],
      threatStatus: "Consultado",
      salesVolume: "Não confirmado",
      paymentSignals: [],
    },
  };
}
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});
describe("Web API boundary", () => {
  it("health success does not enroll a device", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValue(
        Response.json({ status: "ok", authentication: "DEVICE_SIGNATURE" }),
      );
    vi.stubGlobal("fetch", fetcher);
    expect(await checkHealth()).toBe("online");
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(String(fetcher.mock.calls[0]?.[0])).toContain("/health");
  });
  it("marks malformed health as degraded", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(Response.json({ status: "ok" })),
    );
    expect(await checkHealth()).toBe("degraded");
  });
  it("translates an unavailable API without raw errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("Failed to fetch")),
    );
    await expect(requestJson("/health")).rejects.toMatchObject({
      code: "unavailable",
    });
    expect(friendlyError(new TypeError("Failed to fetch"))).not.toContain(
      "fetch",
    );
  });
  it("handles offline state distinctly", async () => {
    vi.spyOn(navigator, "onLine", "get").mockReturnValue(false);
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error()));
    expect(await checkHealth()).toBe("offline");
    await expect(requestJson("/health")).rejects.toMatchObject({
      code: "offline",
    });
  });
  it("aborts at the timeout", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url: string, init: RequestInit) =>
          new Promise((_resolve, reject) => {
            init.signal?.addEventListener("abort", () => {
              reject(new DOMException("Aborted", "AbortError"));
            });
          }),
      ),
    );
    const pending = expect(
      requestJson("/health", {}, 10),
    ).rejects.toMatchObject({ code: "timeout" });
    await vi.advanceTimersByTimeAsync(11);
    await pending;
  });
  it.each([
    [429, "rate_limited"],
    [403, "authentication"],
    [400, "scan_rejected"],
    [404, "expired"],
    [500, "unavailable"],
    [503, "unavailable"],
  ])("normalizes HTTP %s", async (status, code) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("private diagnostic", {
            status,
            headers: { "Retry-After": "42" },
          }),
        ),
    );
    await expect(requestJson("/family/v1/scans")).rejects.toMatchObject({
      code,
      retryAfter: 42,
    });
  });
  it("does not follow redirects or send cookies", async () => {
    const fetcher = vi.fn().mockResolvedValue(Response.json({ status: "ok" }));
    vi.stubGlobal("fetch", fetcher);
    await requestJson("/health");
    expect(fetcher).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
      }),
    );
  });
  it("rejects a response exceeding the streaming byte limit", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(new Uint8Array(2 * 1024 * 1024 + 1), {
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );
    await expect(requestJson("/health")).rejects.toMatchObject({
      code: "response",
    });
  });
  it("rejects HTML instead of JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("<html/>", { headers: { "Content-Type": "text/html" } }),
        ),
    );
    await expect(requestJson("/health")).rejects.toMatchObject({
      code: "response",
    });
  });
  it("accepts a valid actual report schema", () => {
    expect(validateReport(fixtureReport()).domain).toBe("example.com");
  });
  it.each([
    "mode",
    "confidence",
    "verdict",
    "coverage",
    "checks",
    "sources",
    "technical",
    "domain",
    "score",
    "scannedAt",
  ])("rejects malformed report field %s", (field) => {
    expect(() =>
      validateReport({ ...fixtureReport(), [field]: { unexpected: true } }),
    ).toThrow();
  });
  it("does not accept a demo report", () => {
    expect(() =>
      validateReport({ ...fixtureReport(), mode: "demo" }),
    ).toThrow();
  });
  it("rejects malformed check values consumed by explanations", () => {
    const report = fixtureReport();
    report.checks[0] = { ...report.checks[0], value: 123 as unknown as string };
    expect(() => validateReport(report)).toThrow();
  });
  it("rejects invalid threat counters", () => {
    const report = fixtureReport();
    expect(() =>
      validateReport({
        ...report,
        technical: {
          ...report.technical,
          virusTotal: {
            state: "AVAILABLE",
            domain: { state: "AVAILABLE", stats: { malicious: -1 } },
          },
        },
      }),
    ).toThrow();
  });
  it("completes signed flow and never polls a consumed result twice", async () => {
    vi.stubGlobal("crypto", webcrypto);
    let device = "";
    const paths: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: string, init: RequestInit) => {
        const path = new URL(input, API_ORIGIN).pathname;
        paths.push(path);
        const body = JSON.parse(
          typeof init.body === "string" && init.body ? init.body : "{}",
        ) as Record<string, string>;
        if (path.endsWith("/enroll"))
          return webcrypto.subtle
            .digest("SHA-256", Buffer.from(body.publicKeySpki, "base64"))
            .then((hash) => {
              device = Buffer.from(hash).toString("hex");
              return Response.json({ deviceId: device, status: "ACTIVE" });
            });
        if (path.endsWith("/challenge"))
          return Promise.resolve(
            Response.json({
              challengeId: fixtureReport().id,
              message: [
                "EDY-FAMILY-V1",
                API_ORIGIN,
                device,
                fixtureReport().id,
                "a".repeat(64),
                body.method,
                body.path,
                body.bodyHash,
              ].join("\n"),
              expiresAt: new Date(Date.now() + 90_000).toISOString(),
            }),
          );
        expect(new Headers(init.headers).get("X-Family-Signature")).toMatch(
          /^M/,
        );
        if (init.method === "POST") {
          expect(body).toEqual({ url: "https://example.com/" });
          return Promise.resolve(
            Response.json({ scanId: fixtureReport().id, status: "QUEUED" }),
          );
        }
        return Promise.resolve(
          Response.json({
            scanId: fixtureReport().id,
            status: "SUCCEEDED",
            report: fixtureReport(),
          }),
        );
      }),
    );
    const phases: string[] = [];
    const result = await scanStore(
      "https://example.com/private?code=personal",
      (phase) => phases.push(phase),
    );
    expect(result.verdict).toBe("BUY");
    expect(
      paths.filter((path) => path === `/family/v1/scans/${result.id}`),
    ).toHaveLength(1);
    expect(paths).toHaveLength(5);
    expect(phases).toEqual([
      "validating",
      "authenticating",
      "collecting",
      "preparing",
    ]);
  });
});

describe("Web challenge binding", () => {
  const expected = {
    deviceId: "a".repeat(64),
    method: "POST",
    path: "/family/v1/scans",
    bodyHash: "b".repeat(64),
  };
  const now = Date.now();
  const id = "12345678-1234-4234-8234-123456789abc";
  const valid = () => ({
    challengeId: id,
    message: [
      "EDY-FAMILY-V1",
      API_ORIGIN,
      expected.deviceId,
      id,
      "c".repeat(64),
      expected.method,
      expected.path,
      expected.bodyHash,
    ].join("\n"),
    expiresAt: new Date(now + 90_000).toISOString(),
  });
  it("accepts the exact eight-line protocol", () => {
    expect(validateChallenge(valid(), expected, now).challengeId).toBe(id);
  });
  it.each([0, 1, 2, 3, 4, 5, 6, 7])(
    "rejects modified challenge line %s",
    (index) => {
      const data = valid();
      const lines = data.message.split("\n");
      lines[index] = "tampered";
      data.message = lines.join("\n");
      expect(() => validateChallenge(data, expected, now)).toThrow(ApiError);
    },
  );
  it.each([-1, 0, 120001, Infinity])(
    "rejects invalid expiry offset %s",
    (offset) => {
      const data = valid();
      data.expiresAt = Number.isFinite(offset)
        ? new Date(now + offset).toISOString()
        : "invalid";
      expect(() => validateChallenge(data, expected, now)).toThrow();
    },
  );
  it("rejects a trailing newline", () => {
    const data = valid();
    data.message += "\n";
    expect(() => validateChallenge(data, expected, now)).toThrow();
  });
  it("encodes ECDSA integers without sign corruption", () => {
    const raw = new Uint8Array(64);
    raw[0] = 128;
    raw[63] = 1;
    expect([...signatureToDer(raw.buffer)].slice(0, 5)).toEqual([
      48, 38, 2, 33, 0,
    ]);
  });
  it("rejects non-P256 signature length", () => {
    expect(() => signatureToDer(new ArrayBuffer(65))).toThrow();
  });
});
