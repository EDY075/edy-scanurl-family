import type { Evidence, Finding } from "./domain.js";
import type { CoverageResult } from "./coverage.js";

export type AnalysisConfidence = "LOW" | "MEDIUM" | "HIGH" | "VERY_HIGH";

export interface ConfidenceResult {
  level: AnalysisConfidence;
  reasons: readonly string[];
}

export function calculateConfidence(input: {
  coverage: CoverageResult;
  findings: readonly Finding[];
  evidence: readonly Evidence[];
  evaluatedAt: string;
}): ConfidenceResult {
  const evaluatedAt = Date.parse(input.evaluatedAt);
  const expired = input.evidence.filter(
    (evidence) => evidence.validUntil !== undefined && Date.parse(evidence.validUntil) < evaluatedAt
  );
  const authoritative = input.evidence.filter((evidence) => evidence.sourceTier <= 2);
  const materialConflict = input.findings.some(
    (finding) =>
      finding.controlId === "evidence.consistency" &&
      finding.material &&
      (finding.status === "FAIL" || finding.status === "CRITICAL")
  );
  const reasons: string[] = [`COVERAGE_${String(Math.round(input.coverage.value))}`];

  if (!input.coverage.essentialCategoriesComplete) reasons.push("ESSENTIAL_CATEGORY_INCOMPLETE");
  if (expired.length > 0) reasons.push("STALE_EVIDENCE_PRESENT");
  if (authoritative.length === 0) reasons.push("NO_TIER_1_OR_2_EVIDENCE");
  if (materialConflict) reasons.push("MATERIAL_CONFLICT");

  if (
    input.coverage.value >= 90 &&
    input.coverage.essentialCategoriesComplete &&
    authoritative.length >= Math.max(1, Math.ceil(input.evidence.length / 2)) &&
    expired.length === 0 &&
    !materialConflict
  ) {
    return { level: "VERY_HIGH", reasons };
  }

  if (
    input.coverage.value >= 80 &&
    input.coverage.essentialCategoriesComplete &&
    authoritative.length > 0 &&
    expired.length === 0 &&
    !materialConflict
  ) {
    return { level: "HIGH", reasons };
  }

  if (input.coverage.value >= 70 && input.coverage.essentialCategoriesComplete) {
    return { level: "MEDIUM", reasons };
  }

  return { level: "LOW", reasons };
}
