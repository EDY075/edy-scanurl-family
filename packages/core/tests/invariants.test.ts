import { describe, expect, it } from "vitest";
import {
  DomainInvariantError,
  EvidenceSchema,
  TRUST_RULESET_V1,
  decideProviderCompliance,
  evaluateDecision,
  goldenScenarios,
  providerFailureStatusToCheckStatus,
  scanJobStatuses,
  scanProgressPhases
} from "../src/index.js";
import type { DecisionEvaluationInput, ProviderComplianceRecord } from "../src/index.js";

function getScenario(id: string): DecisionEvaluationInput {
  const scenario = goldenScenarios.find((item) => item.id === id);
  if (!scenario) throw new Error(`Missing scenario ${id}`);
  return scenario.input;
}

describe("decision kernel invariants", () => {
  it("a confirmed blocker can never produce BUY and caps the effective score", () => {
    for (const id of ["confirmed-phishing", "confirmed-malware", "business-mismatch", "redirect-threat"]) {
      const result = evaluateDecision(getScenario(id));
      expect(result.verdict.verdict).toBe("DO_NOT_BUY");
      expect(result.blockers.confirmed.length).toBeGreaterThan(0);
      expect(result.score.effectiveValue).toBeLessThanOrEqual(20);
    }
  });

  it("UNKNOWN never increases score and always lowers coverage", () => {
    const trusted = getScenario("trusted-store");
    const baseline = evaluateDecision(trusted);
    const targetFinding = must(
      trusted.findings.find((finding) => finding.controlId === "public.presence")
    );
    const modified: DecisionEvaluationInput = {
      ...trusted,
      findings: trusted.findings.map((finding) =>
        finding.id === targetFinding.id ? { ...finding, status: "UNKNOWN", evidenceIds: [] } : finding
      ),
      evidence: trusted.evidence.filter((evidence) => !targetFinding.evidenceIds.includes(evidence.id))
    };
    const result = evaluateDecision(modified);
    expect(result.score.baseValue).toBeLessThanOrEqual(must(baseline.score.baseValue));
    expect(result.coverage.value).toBeLessThan(baseline.coverage.value);
    expect(result.detectionSummary.approved).toBe(baseline.detectionSummary.approved - 1);
    expect(result.detectionSummary.unknown).toBe(1);
  });

  it("provider timeout and missing provider never become negative evidence", () => {
    expect(providerFailureStatusToCheckStatus("TIMED_OUT")).toBe("UNKNOWN");
    expect(providerFailureStatusToCheckStatus("RATE_LIMITED")).toBe("UNKNOWN");
    expect(providerFailureStatusToCheckStatus("FAILED")).toBe("UNKNOWN");
    expect(providerFailureStatusToCheckStatus("DISABLED_BY_POLICY")).toBe("NOT_CHECKED");
    expect(evaluateDecision(getScenario("provider-failure")).verdict.verdict).not.toBe("DO_NOT_BUY");
  });

  it("insufficient coverage never produces a green verdict", () => {
    const result = evaluateDecision(getScenario("insufficient-data"));
    expect(result.coverage.value).toBeLessThan(70);
    expect(result.verdict.verdict).toBe("INSUFFICIENT_DATA");
  });

  it("rejects DEMO evidence in a REAL scan", () => {
    const trusted = getScenario("trusted-store");
    expect(() => evaluateDecision({ ...trusted, provenance: "REAL" })).toThrow(DomainInvariantError);
  });

  it("rejects evidence from another ruleset version", () => {
    const trusted = getScenario("trusted-store");
    const first = must(trusted.evidence[0]);
    const input: DecisionEvaluationInput = {
      ...trusted,
      evidence: trusted.evidence.map((evidence) =>
        evidence.id === first.id ? { ...evidence, rulesetVersion: "unrelated-v2" } : evidence
      )
    };
    expect(() => evaluateDecision(input)).toThrow(/ruleset version/);
  });

  it("does not confirm a blocker from a source absent from blocking policy", () => {
    const phishing = getScenario("confirmed-phishing");
    const result = evaluateDecision({
      ...phishing,
      authorizedBlockingSourceIds: []
    });
    expect(result.blockers.confirmed).toHaveLength(0);
    expect(result.blockers.rejected[0]?.reasons).toContain("PROVIDER_NOT_AUTHORIZED_FOR_BLOCKING");
    expect(result.verdict.verdict).not.toBe("BUY");
  });

  it("treats technical security and store transparency as essential", () => {
    const essentials = TRUST_RULESET_V1.categories
      .filter((category) => category.essential)
      .map((category) => category.category);
    expect(essentials).toContain("TECHNICAL_SECURITY");
    expect(essentials).toContain("STORE_TRANSPARENCY");

    const trusted = getScenario("trusted-store");
    const transparency = must(
      trusted.findings.find((finding) => finding.controlId === "transparency.policies")
    );
    const result = evaluateDecision({
      ...trusted,
      findings: trusted.findings.map((finding) =>
        finding.id === transparency.id
          ? { ...finding, status: "UNKNOWN", evidenceIds: [] }
          : finding
      ),
      evidence: trusted.evidence.filter(
        (evidence) => !transparency.evidenceIds.includes(evidence.id)
      )
    });
    expect(result.coverage.essentialCategoriesComplete).toBe(false);
    expect(result.verdict.verdict).toBe("INSUFFICIENT_DATA");
  });

  it("keeps partial results as progress and not as a durable job status", () => {
    expect(scanJobStatuses).not.toContain("PARTIAL");
    expect(scanProgressPhases).toContain("PARTIAL_RESULTS_AVAILABLE");
  });

  it("allows only HTTP(S) evidence source links", () => {
    const evidence = must(getScenario("trusted-store").evidence[0]);
    expect(() =>
      EvidenceSchema.parse({ ...evidence, sourceUrlAllowed: "file:///etc/passwd" })
    ).toThrow(/HTTP\(S\)/);
    expect(() =>
      EvidenceSchema.parse({ ...evidence, sourceUrlAllowed: "https://source.example.test/item" })
    ).not.toThrow();
  });

  it("requires authoritative evidence for every assessed essential control", () => {
    const trusted = getScenario("trusted-store");
    const threat = must(trusted.findings.find((finding) => finding.controlId === "threat.phishing"));
    const input: DecisionEvaluationInput = {
      ...trusted,
      evidence: trusted.evidence.map((evidence) =>
        threat.evidenceIds.includes(evidence.id) ? { ...evidence, sourceTier: 5 } : evidence
      )
    };
    expect(() => evaluateDecision(input)).toThrow(/requires Tier 1 or Tier 2 evidence/);
  });

  it("requires confirmed Tier 1-3 evidence for a strong negative finding", () => {
    const trusted = getScenario("trusted-store");
    const publicFinding = must(
      trusted.findings.find((finding) => finding.controlId === "public.presence")
    );
    const input: DecisionEvaluationInput = {
      ...trusted,
      findings: trusted.findings.map((finding) =>
        finding.id === publicFinding.id
          ? { ...finding, status: "FAIL", strongNegative: true, material: true }
          : finding
      ),
      evidence: trusted.evidence.map((evidence) =>
        publicFinding.evidenceIds.includes(evidence.id)
          ? { ...evidence, sourceTier: 5, findingCertainty: "UNVERIFIED" }
          : evidence
      )
    };
    expect(() => evaluateDecision(input)).toThrow(/confirmed Tier 1-3 evidence/);
  });

  it("can issue DO_NOT_BUY without a blocker only for a low score with strong evidence", () => {
    const trusted = getScenario("trusted-store");
    const failedControls = new Set([
      "business.identity",
      "domain.registration",
      "consumer.reputation",
      "transparency.policies",
      "public.presence"
    ]);
    const input: DecisionEvaluationInput = {
      ...trusted,
      findings: trusted.findings.map((finding) =>
        failedControls.has(finding.controlId)
          ? {
              ...finding,
              status: "FAIL",
              material: true,
              strongNegative: finding.controlId === "business.identity"
            }
          : finding
      )
    };
    const result = evaluateDecision(input);
    expect(result.score.effectiveValue).toBeLessThan(50);
    expect(result.blockers.confirmed).toHaveLength(0);
    expect(result.verdict.verdict).toBe("DO_NOT_BUY");
  });

  it("does not allow stale evidence to retain HIGH confidence", () => {
    const trusted = getScenario("trusted-store");
    const result = evaluateDecision({
      ...trusted,
      evidence: trusted.evidence.map((evidence) => ({
        ...evidence,
        validUntil: "2026-08-29T00:00:00.000Z"
      }))
    });
    expect(result.confidence.level).toBe("MEDIUM");
    expect(result.verdict.verdict).not.toBe("BUY");
  });

  it("derives blocker freshness from evidence, not only the candidate flag", () => {
    const phishing = getScenario("confirmed-phishing");
    const result = evaluateDecision({
      ...phishing,
      evidence: phishing.evidence.map((evidence) => ({
        ...evidence,
        validUntil: "2026-08-29T00:00:00.000Z"
      }))
    });
    expect(result.blockers.confirmed).toHaveLength(0);
    expect(result.blockers.rejected[0]?.reasons).toContain("EVIDENCE_FRESHNESS_UNPROVEN");
  });
});

function must<T>(value: T | null | undefined): T {
  if (value === null || value === undefined) throw new Error("Expected fixture value");
  return value;
}

describe("provider compliance is fail closed", () => {
  const allowed: ProviderComplianceRecord = {
    providerId: "synthetic-free-provider",
    termsUrl: "https://provider.example.test/terms",
    licenseStatus: "CONFIRMED",
    commercialStatus: "ALLOWED",
    authentication: "NONE",
    cost: "FREE",
    quota: "documented fair use",
    dataSent: ["hostname"],
    retention: "normalized evidence only",
    caching: "allowed with TTL",
    redistribution: "normalized result allowed",
    attribution: "required",
    lastReviewedAt: "2026-08-30T00:00:00.000Z",
    credentialsAvailable: true,
    enabled: true,
    killSwitch: false
  };

  it("enables only a confirmed, permitted and free provider", () => {
    expect(decideProviderCompliance(allowed, { zeroCostOnly: true })).toBe("ENABLED");
  });

  it("disables unknown terms", () => {
    expect(
      decideProviderCompliance({ ...allowed, licenseStatus: "UNCONFIRMED" }, { zeroCostOnly: true })
    ).toBe("DISABLED_BY_POLICY");
  });

  it("disables paid providers in zero-cost mode", () => {
    expect(decideProviderCompliance({ ...allowed, cost: "PAID" }, { zeroCostOnly: true })).toBe(
      "DISABLED_ZERO_COST_POLICY"
    );
  });

  it("honors the kill switch before every other condition", () => {
    expect(decideProviderCompliance({ ...allowed, killSwitch: true }, { zeroCostOnly: false })).toBe(
      "DISABLED_KILL_SWITCH"
    );
  });
});
