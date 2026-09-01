import type { Evidence, FindingCertainty, Provenance } from "./domain.js";

export const hardBlockerKinds = [
  "CONFIRMED_PHISHING",
  "CONFIRMED_MALWARE",
  "MALICIOUS_CHECKOUT",
  "MALICIOUS_REDIRECT",
  "PROVEN_BUSINESS_FALSIFICATION",
  "CONFIRMED_CNPJ_MISMATCH",
  "STRONG_BRAND_IMPERSONATION",
  "AUTHORIZED_CRITICAL_THREAT"
] as const;

export type HardBlockerKind = (typeof hardBlockerKinds)[number];

export interface HardBlockerCandidate {
  id: string;
  kind: HardBlockerKind;
  findingId: string;
  evidenceIds: readonly string[];
  provenance: Provenance;
  reason: string;
}

export interface HardBlockerEvaluationPolicy {
  targetSubjectKey: string;
  authorizedBlockingSourceIds: readonly string[];
}

export interface RejectedBlockerCandidate {
  candidate: HardBlockerCandidate;
  reasons: readonly string[];
}

export interface HardBlockerResult {
  confirmed: readonly HardBlockerCandidate[];
  rejected: readonly RejectedBlockerCandidate[];
}

export function evaluateHardBlockers(
  candidates: readonly HardBlockerCandidate[],
  evidence: readonly Evidence[],
  evaluatedAt: string,
  policy: HardBlockerEvaluationPolicy
): HardBlockerResult {
  const confirmed: HardBlockerCandidate[] = [];
  const rejected: RejectedBlockerCandidate[] = [];
  const evidenceById = new Map(evidence.map((item) => [item.id, item]));
  const evaluatedAtMs = Date.parse(evaluatedAt);
  const acceptedCertainty = new Set<FindingCertainty>(["CONFIRMED", "CORROBORATED"]);
  const authorizedSources = new Set(policy.authorizedBlockingSourceIds);

  for (const candidate of candidates) {
    const reasons: string[] = [];
    const supportingEvidence = candidate.evidenceIds
      .map((evidenceId) => evidenceById.get(evidenceId))
      .filter((item): item is Evidence => item !== undefined);
    const targetMatched = supportingEvidence.some(
      (item) => item.subjectKey === policy.targetSubjectKey
    );
    const freshnessProven = supportingEvidence.some(
      (item) => item.validUntil !== undefined && Date.parse(item.validUntil) >= evaluatedAtMs
    );
    const authorityProven = supportingEvidence.some((item) => item.sourceTier <= 2);
    const providerAuthorized = supportingEvidence.some((item) =>
      authorizedSources.has(item.sourceId)
    );
    const certaintyProven = supportingEvidence.some((item) =>
      acceptedCertainty.has(item.findingCertainty)
    );
    const qualifyingEvidence = supportingEvidence.some(
      (item) =>
        item.subjectKey === policy.targetSubjectKey &&
        item.validUntil !== undefined &&
        Date.parse(item.validUntil) >= evaluatedAtMs &&
        item.sourceTier <= 2 &&
        authorizedSources.has(item.sourceId) &&
        acceptedCertainty.has(item.findingCertainty)
    );

    if (!targetMatched) reasons.push("TARGET_MATCH_NOT_EXACT");
    if (!freshnessProven) reasons.push("EVIDENCE_FRESHNESS_UNPROVEN");
    if (!authorityProven) reasons.push("SOURCE_TIER_TOO_WEAK");
    if (!providerAuthorized) reasons.push("PROVIDER_NOT_AUTHORIZED_FOR_BLOCKING");
    if (!certaintyProven) reasons.push("CERTAINTY_TOO_LOW");
    if (supportingEvidence.length > 0 && !qualifyingEvidence) {
      reasons.push("NO_SINGLE_QUALIFYING_EVIDENCE");
    }
    if (candidate.evidenceIds.length === 0 || supportingEvidence.length !== candidate.evidenceIds.length) {
      reasons.push("MISSING_EVIDENCE");
    }

    if (reasons.length === 0) confirmed.push(candidate);
    else rejected.push({ candidate, reasons });
  }

  return { confirmed, rejected };
}
