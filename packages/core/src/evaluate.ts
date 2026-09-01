import { EvidenceSchema, summarizeDetections } from "./domain.js";
import type { Evidence, Finding, Provenance } from "./domain.js";
import { DomainInvariantError } from "./errors.js";
import { calculateCoverage } from "./coverage.js";
import { evaluateHardBlockers } from "./blockers.js";
import type { HardBlockerCandidate } from "./blockers.js";
import { calculateTrustScore } from "./score.js";
import { calculateConfidence } from "./confidence.js";
import { decideVerdict } from "./verdict.js";
import { TRUST_RULESET_V1, assertRuleset } from "./ruleset.js";
import type { TrustRuleset } from "./ruleset.js";

export interface DecisionEvaluationInput {
  scanId: string;
  targetSubjectKey: string;
  authorizedBlockingSourceIds: readonly string[];
  provenance: Provenance;
  findings: readonly Finding[];
  evidence: readonly Evidence[];
  hardBlockerCandidates: readonly HardBlockerCandidate[];
  evaluatedAt: string;
  ruleset?: TrustRuleset;
}

export type DecisionEvaluation = ReturnType<typeof evaluateDecision>;

export function evaluateDecision(input: DecisionEvaluationInput) {
  const ruleset = input.ruleset ?? TRUST_RULESET_V1;
  assertRuleset(ruleset);
  validateInput(input, ruleset);

  const blockers = evaluateHardBlockers(
    input.hardBlockerCandidates,
    input.evidence,
    input.evaluatedAt,
    {
      targetSubjectKey: input.targetSubjectKey,
      authorizedBlockingSourceIds: input.authorizedBlockingSourceIds
    }
  );
  const coverage = calculateCoverage(input.findings, ruleset);
  const score = calculateTrustScore(input.findings, ruleset, blockers.confirmed.length > 0);
  const confidence = calculateConfidence({
    coverage,
    findings: input.findings,
    evidence: input.evidence,
    evaluatedAt: input.evaluatedAt
  });
  const verdict = decideVerdict({
    findings: input.findings,
    coverage,
    confidence: confidence.level,
    score,
    confirmedHardBlockers: blockers.confirmed.length,
    ruleset
  });

  return {
    scanId: input.scanId,
    provenance: input.provenance,
    rulesetVersion: ruleset.version,
    coverage,
    score,
    confidence,
    verdict,
    blockers,
    detectionSummary: summarizeDetections(input.findings),
    evaluatedAt: input.evaluatedAt
  } as const;
}

function validateInput(input: DecisionEvaluationInput, ruleset: TrustRuleset): void {
  if (!Number.isFinite(Date.parse(input.evaluatedAt))) {
    throw new DomainInvariantError("evaluatedAt must be an ISO timestamp");
  }

  const evidenceById = new Map<string, Evidence>();
  for (const rawEvidence of input.evidence) {
    const evidence = EvidenceSchema.parse(rawEvidence);
    if (evidenceById.has(evidence.id)) throw new DomainInvariantError(`Duplicate evidence: ${evidence.id}`);
    if (evidence.scanId !== input.scanId) throw new DomainInvariantError("Evidence belongs to another scan");
    if (evidence.provenance !== input.provenance) {
      throw new DomainInvariantError("DEMO and REAL evidence cannot be mixed");
    }
    if (evidence.rulesetVersion !== ruleset.version) {
      throw new DomainInvariantError("Evidence ruleset version does not match evaluation ruleset");
    }
    evidenceById.set(evidence.id, evidence);
  }

  for (const finding of input.findings) {
    if (finding.provenance !== input.provenance) {
      throw new DomainInvariantError("DEMO and REAL findings cannot be mixed");
    }
    const assessed = ["PASS", "WARNING", "FAIL", "CRITICAL"].includes(finding.status);
    if (assessed && finding.evidenceIds.length === 0) {
      throw new DomainInvariantError(`Assessed finding ${finding.id} must reference evidence`);
    }
    for (const evidenceId of finding.evidenceIds) {
      if (!evidenceById.has(evidenceId)) {
        throw new DomainInvariantError(`Finding ${finding.id} references missing evidence ${evidenceId}`);
      }
    }
  }

  const findingIds = new Set(input.findings.map((finding) => finding.id));
  const authoritativeEssentialCategories = new Set([
    "BUSINESS_IDENTITY",
    "DOMAIN_HISTORY",
    "THREAT_IMPERSONATION"
  ]);
  const acceptedCertainty = new Set(["CONFIRMED", "CORROBORATED"]);
  for (const finding of input.findings) {
    const supportingEvidence = finding.evidenceIds
      .map((evidenceId) => evidenceById.get(evidenceId))
      .filter((evidence): evidence is Evidence => evidence !== undefined);
    const assessed = ["PASS", "WARNING", "FAIL", "CRITICAL"].includes(finding.status);
    if (
      assessed &&
      authoritativeEssentialCategories.has(finding.category) &&
      !supportingEvidence.some((evidence) => evidence.sourceTier <= 2)
    ) {
      throw new DomainInvariantError(
        `Essential control ${finding.controlId} requires Tier 1 or Tier 2 evidence`
      );
    }
    if (
      finding.strongNegative &&
      !supportingEvidence.some(
        (evidence) =>
          evidence.sourceTier <= 3 && acceptedCertainty.has(evidence.findingCertainty)
      )
    ) {
      throw new DomainInvariantError(
        `Strong negative finding ${finding.id} requires confirmed Tier 1-3 evidence`
      );
    }
  }

  for (const blocker of input.hardBlockerCandidates) {
    if (blocker.provenance !== input.provenance) {
      throw new DomainInvariantError("DEMO and REAL blockers cannot be mixed");
    }
    if (!findingIds.has(blocker.findingId)) {
      throw new DomainInvariantError(`Blocker ${blocker.id} references missing finding`);
    }
    for (const evidenceId of blocker.evidenceIds) {
      if (!evidenceById.has(evidenceId)) {
        throw new DomainInvariantError(`Blocker ${blocker.id} references missing evidence ${evidenceId}`);
      }
    }
  }
}
