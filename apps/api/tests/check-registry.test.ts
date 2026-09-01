import { describe, expect, it } from "vitest";
import { evaluateCheckRegistry, SCAN_CHECK_REGISTRY, type RegistryFacts } from "../src/services/check-registry.js";

function facts(): RegistryFacts {
  return {
    providers: {
      rdap: { status: "SUCCEEDED", durationMs: 20 },
      "dns-direct": { status: "SUCCEEDED", durationMs: 12 },
      "tls-direct": { status: "SUCCEEDED", durationMs: 18 },
      "transparency-passive": { status: "PARTIAL", durationMs: 320 },
    },
    rdap: { registrationDate: "2020-01-01T00:00:00Z", updatedDate: "2026-01-01T00:00:00Z", registrar: "Example Registrar", statuses: ["active"] },
    dns: { addresses: 2, nameservers: 2, mailExchangers: 1, caa: 1, dnssec: "NOT_OBSERVED" },
    tls: { available: true, authorized: true, daysRemaining: 90 },
    virusTotal: { available: false, fresh: false, malicious: 0, suspicious: 0, engines: 0 },
    http: {
      redirects: 1, headerCount: 4,
      securityHeaders: { hsts: true, csp: true, frameProtection: true, referrerPolicy: true, permissionsPolicy: false, noSniff: false },
      finalHostname: true, pagesFetched: 6, pagesDiscovered: 14, partial: true,
      companyNames: 1, cnpjClaims: 1, distinctCnpj: 1, structuredOrganizations: 1,
      contacts: 1, addresses: 1, emails: 1, phones: 1, about: true, privacy: true,
      terms: true, returns: true, refund: false, shipping: true, legal: true,
      socialLinks: 2, catalog: true, paymentMethods: 3, platforms: 1, checkoutDomains: 1,
    },
  };
}

describe("deterministic scan check registry", () => {
  it("finalizes every registry check with 100% completion while evidence coverage remains independent", () => {
    const result = evaluateCheckRegistry(facts());
    expect(SCAN_CHECK_REGISTRY).toHaveLength(53);
    expect(result.trace).toHaveLength(53);
    expect(result.scanCompletion).toBe(100);
    expect(result.evidenceCoverage).toBeLessThan(100);
    expect(result.silentSkips).toBe(0);
    expect(result.trace.every((item) => item.attempted)).toBe(true);
  });

  it("keeps unavailable providers and non-applicable commerce explicit", () => {
    const input = facts();
    input.http.catalog = false;
    const result = evaluateCheckRegistry(input);
    expect(result.trace.find((item) => item.check === "THREAT_PHISHTANK")?.finalState).toBe("UNAVAILABLE");
    expect(result.trace.find((item) => item.check === "BUSINESS_OFFICIAL_VALIDATION")?.finalState).toBe("NOT_CHECKED");
    expect(result.trace.find((item) => item.check === "CONSUMER_RECLAME_AQUI")?.finalState).toBe("NOT_CHECKED");
    expect(result.trace.find((item) => item.check === "COMMERCE_PAYMENT_METHODS")?.finalState).toBe("NOT_APPLICABLE");
  });

  it("keeps self-declared site claims neutral even when they are observed", () => {
    const result = evaluateCheckRegistry(facts());
    const neutralChecks = [
      "BUSINESS_SITE_IDENTITY", "BUSINESS_CNPJ_SITE", "BUSINESS_STRUCTURED_DATA",
      "TRANSPARENCY_CONTACT", "TRANSPARENCY_ADDRESS", "TRANSPARENCY_EMAIL",
      "TRANSPARENCY_PHONE", "PUBLIC_SOCIAL_PRESENCE", "COMMERCE_PAYMENT_METHODS",
      "COMMERCE_CHECKOUT_DOMAIN", "EVIDENCE_CONSISTENCY",
    ];
    for (const check of neutralChecks) {
      const trace = result.trace.find((item) => item.check === check);
      expect(trace?.finalState).toBe("UNKNOWN");
      expect(trace?.evidenceCount).toBeGreaterThan(0);
      expect(trace?.reason).toContain("NOT_INDEPENDENTLY_VERIFIED");
    }
  });

  it("treats VirusTotal as one aggregate provider and never makes zero detections a safety pass", () => {
    const input = facts();
    input.providers["virus-total-public"] = { status: "SUCCEEDED", durationMs: 42 };
    input.virusTotal = { available: true, fresh: true, malicious: 0, suspicious: 0, engines: 72 };
    let trace = evaluateCheckRegistry(input).trace.find((item) => item.check === "THREAT_VIRUSTOTAL");
    expect(trace).toMatchObject({ finalState: "UNKNOWN", evidenceCount: 1, reason: "VIRUSTOTAL_NO_MALICIOUS_DETECTION_NOT_SAFETY_PROOF" });

    input.virusTotal.malicious = 4;
    trace = evaluateCheckRegistry(input).trace.find((item) => item.check === "THREAT_VIRUSTOTAL");
    expect(trace).toMatchObject({ finalState: "CRITICAL", evidenceCount: 1 });

    input.virusTotal.fresh = false;
    trace = evaluateCheckRegistry(input).trace.find((item) => item.check === "THREAT_VIRUSTOTAL");
    expect(trace).toMatchObject({ finalState: "UNKNOWN", reason: "VIRUSTOTAL_REPORT_STALE" });
  });
});
