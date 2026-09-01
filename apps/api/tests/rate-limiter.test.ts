import { describe, expect, it } from "vitest";
import { InMemoryTokenBucket } from "../src/services/rate-limiter.js";

describe("InMemoryTokenBucket", () => {
  it("limits repeated guest/domain requests and reports retry time", () => {
    const limiter = new InMemoryTokenBucket(2, 1);
    expect(limiter.consume("guest:domain", 0).allowed).toBe(true);
    expect(limiter.consume("guest:domain", 0).allowed).toBe(true);
    const limited = limiter.consume("guest:domain", 0);
    expect(limited.allowed).toBe(false);
    expect(limited.retryAfterSeconds).toBe(60);
  });

  it("refills independently", () => {
    const limiter = new InMemoryTokenBucket(1, 1);
    limiter.consume("a", 0);
    expect(limiter.consume("a", 60_000).allowed).toBe(true);
    expect(limiter.consume("b", 0).allowed).toBe(true);
  });
});
