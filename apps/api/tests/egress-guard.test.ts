import { describe, expect, it } from "vitest";
import { EgressGuard } from "../src/security/egress-guard.js";

describe("EgressGuard", () => {
  it("returns only prevalidated public addresses", async () => {
    const guard = new EgressGuard(() => Promise.resolve([
      { address: "1.1.1.1", family: 4 },
      { address: "1.1.1.1", family: 4 },
    ]));
    const result = await guard.validate("https://example.com/path");
    expect(result.addresses).toEqual([{ address: "1.1.1.1", family: 4 }]);
  });

  it("blocks DNS rebinding answers before connection", async () => {
    const guard = new EgressGuard(() => Promise.resolve([{ address: "169.254.169.254", family: 4 }]));
    await expect(guard.validate("http://example.com")).rejects.toThrow(/EGRESS_BLOCKED/);
  });

  it("blocks a connected address not present in the validated set", () => {
    const guard = new EgressGuard(() => Promise.resolve([]));
    expect(() => guard.assertConnectedAddress("8.8.8.8", ["1.1.1.1"])).toThrow("DNS_REBINDING_BLOCKED");
  });
});
