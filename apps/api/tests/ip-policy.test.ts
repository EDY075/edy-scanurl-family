import { describe, expect, it } from "vitest";
import { assertPublicAddresses, classifyAddress } from "../src/security/ip-policy.js";

describe("egress IP policy", () => {
  it.each([
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "0.0.0.0",
    "224.0.0.1",
    "::1",
    "fe80::1",
    "fc00::1",
    "::ffff:127.0.0.1",
  ])("blocks non-public address %s", (address) => {
    expect(classifyAddress(address).allowed).toBe(false);
  });

  it.each(["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])("allows public address %s", (address) => {
    expect(classifyAddress(address).allowed).toBe(true);
  });

  it("fails closed if any DNS answer is private", () => {
    expect(() => assertPublicAddresses(["1.1.1.1", "127.0.0.1"])).toThrow(/EGRESS_BLOCKED/);
  });
});
