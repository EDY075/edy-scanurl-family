import type { Finding } from "./domain.js";
import type { CoverageResult } from "./coverage.js";
import type { AnalysisConfidence } from "./confidence.js";
import type { ScoreResult } from "./score.js";
import type { TrustRuleset } from "./ruleset.js";

export type Verdict = "BUY" | "CAUTION" | "DO_NOT_BUY" | "INSUFFICIENT_DATA";

export interface VerdictResult {
  verdict: Verdict;
  reasonCodes: readonly string[];
}

export function decideVerdict(input: {
  findings: readonly Finding[];
  coverage: CoverageResult;
  confidence: AnalysisConfidence;
  score: ScoreResult;
  confirmedHardBlockers: number;
  ruleset: TrustRuleset;
}): VerdictResult {
  if (input.confirmedHardBlockers > 0) {
    return { verdict: "DO_NOT_BUY", reasonCodes: ["CONFIRMED_HARD_BLOCKER"] };
  }

  if (input.coverage.value < input.ruleset.coverageThreshold) {
    return { verdict: "INSUFFICIENT_DATA", reasonCodes: ["COVERAGE_BELOW_THRESHOLD"] };
  }
  if (!input.coverage.essentialCategoriesComplete) {
    return { verdict: "INSUFFICIENT_DATA", reasonCodes: ["ESSENTIAL_CATEGORY_INCOMPLETE"] };
  }
  if (input.confidence === "LOW" || input.score.effectiveValue === null) {
    return { verdict: "INSUFFICIENT_DATA", reasonCodes: ["ANALYSIS_CONFIDENCE_LOW"] };
  }

  const materialAlerts = input.findings.filter(
    (finding) =>
      finding.material &&
      (finding.status === "WARNING" || finding.status === "FAIL" || finding.status === "CRITICAL")
  );
  const strongNegative = input.findings.some(
    (finding) =>
      finding.strongNegative && (finding.status === "FAIL" || finding.status === "CRITICAL")
  );

  if (
    input.score.effectiveValue >= input.ruleset.buyScoreThreshold &&
    input.coverage.value >= input.ruleset.buyCoverageThreshold &&
    (input.confidence === "HIGH" || input.confidence === "VERY_HIGH") &&
    materialAlerts.length === 0
  ) {
    return { verdict: "BUY", reasonCodes: ["BUY_GATES_SATISFIED"] };
  }

  if (input.score.effectiveValue < input.ruleset.doNotBuyScoreThreshold && strongNegative) {
    return { verdict: "DO_NOT_BUY", reasonCodes: ["LOW_SCORE_WITH_STRONG_NEGATIVE_EVIDENCE"] };
  }

  return {
    verdict: "CAUTION",
    reasonCodes: materialAlerts.length > 0 ? ["MATERIAL_WARNING_PRESENT"] : ["BUY_GATES_NOT_SATISFIED"]
  };
}
