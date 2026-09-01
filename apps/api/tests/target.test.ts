import { describe, expect, it } from "vitest";
import { normalizeTarget, redactUrl, TargetRejectedError } from "../src/security/target.js";

describe("target normalization", () => {
  it("defaults to HTTPS and persists only the origin", () => {
    const result = normalizeTarget("Loja.Example/path?q=secret#fragment");
    expect(result.requestUrl.toString()).toBe("https://loja.example/path");
    expect(result.persistedTarget).toBe("https://loja.example/");
    expect(result.domain).toBe("loja.example");
  });

  it.each([
    ["file:///etc/passwd", "UNSUPPORTED_PROTOCOL"],
    ["gopher://example.com", "UNSUPPORTED_PROTOCOL"],
    ["https://user:pass@example.com", "CREDENTIAL_URL"],
    ["https://example.com:8080", "UNSUPPORTED_PORT"],
    ["http://127.0.0.1", "IP_LITERAL"],
    ["http://[::1]", "IP_LITERAL"],
    ["http://localhost", "INTERNAL_HOSTNAME"],
    ["http://service.local", "INTERNAL_HOSTNAME"],
    ["http://2130706433", "IP_LITERAL"],
    ["http://0177.0.0.1", "IP_LITERAL"],
    ["http://0x7f000001", "IP_LITERAL"],
    ["http://127.1", "IP_LITERAL"],
    ["http://[::ffff:127.0.0.1]", "IP_LITERAL"],
    ["http://localhost。", "INTERNAL_HOSTNAME"],
    ["https://example.com%00.evil", "MALFORMED_URL"],
    ["not-a-public-host", "INVALID_PUBLIC_DOMAIN"],
  ])("rejects hostile target %s", (input, reason) => {
    expect(() => normalizeTarget(input)).toThrowError(TargetRejectedError);
    try {
      normalizeTarget(input);
    } catch (error) {
      expect((error as TargetRejectedError).reason).toBe(reason);
    }
  });

  it("redacts path, query and fragment for logs", () => {
    expect(redactUrl("https://example.com/private?token=abc#x")).toBe("https://example.com/[redacted]");
  });
});
