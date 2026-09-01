import { describe, expect, it } from "vitest";
import { normalizeStoreUrl, validStoreUrl } from "./url";
describe("Public store URL normalization", () => {
  it.each([
    ["example.com", "https://example.com/"],
    [
      "  https://EXAMPLE.com/product?private=abc#cart  ",
      "https://example.com/",
    ],
    ["Olha esta loja:\nhttps://example.com/produto.", "https://example.com/"],
    ["http://example.com:80/test", "http://example.com/"],
    ["https://example.com:443/", "https://example.com/"],
    ["https://ação.com.br", "https://xn--ao-siap.com.br/"],
  ])("normalizes %s", (input, expected) => {
    expect(normalizeStoreUrl(input)).toBe(expected);
  });
  it.each([
    "",
    "localhost",
    "https://localhost",
    "https://127.0.0.1",
    "https://127.1",
    "http://2130706433",
    "http://0x7f000001",
    "http://[::1]",
    "https://192.168.1.1",
    "https://10.0.0.1",
    "http://169.254.169.254/latest/meta-data",
    "https://metadata.google.internal",
    "https://store.internal",
    "https://store.local",
    "https://127.0.0.1.nip.io",
    "file:///etc/passwd",
    "data:text/html,hi",
    "javascript:alert(1)",
    "ftp://example.com",
    "https://user:password@example.com",
    "https://example.com:8080",
    "https://example.com\\@evil.com",
    "example.com evil.com",
    "https://example.com https://other.com",
    "https://example.com\u0000",
    "x".repeat(8193),
  ])("rejects %s", (input) => {
    expect(validStoreUrl(input)).toBeNull();
  });
});
