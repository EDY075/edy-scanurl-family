import { describe, expect, it } from "vitest";
import { classifyAddress } from "../src/security/ip-policy.js";

describe("Family cloud metadata egress", () => {
  it.each(["168.63.129.16", "169.254.169.254", "100.100.100.200", "fd00:ec2::254", "::ffff:168.63.129.16", "127.0.0.1", "10.1.2.3"])("blocks infrastructure %s", (address) => {
    expect(classifyAddress(address).allowed).toBe(false);
  });
  it("does not block ordinary public addresses by default", () => {
    expect(classifyAddress("1.1.1.1").allowed).toBe(true);
  });
});
