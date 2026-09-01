import { describe, expect, it } from "vitest";
import { assertComplianceRegistry, providerComplianceRegistry } from "../src/providers/compliance.js";

describe("provider compliance registry", () => {
  it("is fail-closed", () => {
    expect(() => assertComplianceRegistry()).not.toThrow();
    expect(providerComplianceRegistry.find((record) => record.provider === "virus-total-public")?.enabled).toBe(false);
    expect(providerComplianceRegistry.find((record) => record.provider === "google-web-risk")?.enabled).toBe(false);
  });

  it("rejects an unknown enabled provider", () => {
    const baseline = providerComplianceRegistry[0];
    expect(baseline).toBeDefined();
    if (!baseline) throw new Error("Missing compliance fixture");
    expect(() => assertComplianceRegistry([{ ...baseline, provider: "unknown", enabled: true, commercialStatus: "UNKNOWN" }])).toThrow(/without confirmed commercial permission/);
  });
});
