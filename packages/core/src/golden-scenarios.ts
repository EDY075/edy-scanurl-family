import type { HardBlockerCandidate, HardBlockerKind } from "./blockers.js";
import type { CheckStatus, Evidence, Finding, SourceTier } from "./domain.js";
import type { DecisionEvaluationInput } from "./evaluate.js";
import { RULESET_VERSION, TRUST_RULESET_V1 } from "./ruleset.js";
import type { Verdict } from "./verdict.js";

const COLLECTED_AT = "2026-08-30T03:00:00.000Z";
const VALID_UNTIL = "2026-09-30T03:00:00.000Z";

export interface GoldenScenario {
  id: string;
  title: string;
  input: DecisionEvaluationInput;
  expectedVerdict: Verdict;
}

interface ScenarioOverrides {
  statuses?: Readonly<Record<string, CheckStatus>>;
  material?: readonly string[];
  strongNegative?: readonly string[];
  blocker?: { controlId: string; kind: HardBlockerKind };
}

const DEFAULT_STATUSES: Readonly<Record<string, CheckStatus>> = Object.fromEntries(
  TRUST_RULESET_V1.controls.map((control) => [control.id, "PASS" as const])
);

export const goldenScenarios: readonly GoldenScenario[] = [
  scenario("trusted-store", "Trusted Store", "BUY"),
  scenario("new-store", "New Store", "CAUTION", {
    statuses: {
      "domain.registration": "WARNING",
      "consumer.reputation": "UNKNOWN",
      "commerce.payment": "WARNING",
      "public.presence": "WARNING"
    },
    material: ["domain.registration"]
  }),
  scenario("insufficient-data", "Insufficient Data", "INSUFFICIENT_DATA", {
    statuses: Object.fromEntries(
      TRUST_RULESET_V1.controls.map((control) => [
        control.id,
        ["business.identity", "domain.registration", "technical.https", "threat.phishing"].includes(
          control.id
        )
          ? "PASS"
          : "UNKNOWN"
      ])
    )
  }),
  scenario("confirmed-phishing", "Confirmed Phishing", "DO_NOT_BUY", {
    statuses: { "threat.phishing": "CRITICAL" },
    material: ["threat.phishing"],
    strongNegative: ["threat.phishing"],
    blocker: { controlId: "threat.phishing", kind: "CONFIRMED_PHISHING" }
  }),
  scenario("confirmed-malware", "Confirmed Malware", "DO_NOT_BUY", {
    statuses: { "threat.malware": "CRITICAL" },
    material: ["threat.malware"],
    strongNegative: ["threat.malware"],
    blocker: { controlId: "threat.malware", kind: "CONFIRMED_MALWARE" }
  }),
  scenario("business-mismatch", "Business Mismatch", "DO_NOT_BUY", {
    statuses: { "business.identity": "CRITICAL" },
    material: ["business.identity"],
    strongNegative: ["business.identity"],
    blocker: { controlId: "business.identity", kind: "CONFIRMED_CNPJ_MISMATCH" }
  }),
  scenario("provider-failure", "Provider Failure", "BUY", {
    statuses: { "consumer.reputation": "NOT_CHECKED" }
  }),
  scenario("only-pix-warning", "Only PIX Warning", "CAUTION", {
    statuses: { "commerce.payment": "WARNING" },
    material: ["commerce.payment"]
  }),
  scenario("missing-headers", "Missing Headers", "BUY", {
    statuses: { "technical.headers": "WARNING" }
  }),
  scenario("recent-domain", "Recent Domain", "CAUTION", {
    statuses: { "domain.registration": "WARNING" },
    material: ["domain.registration"]
  }),
  scenario("consumer-warning", "Consumer Reputation Warning", "CAUTION", {
    statuses: { "consumer.reputation": "WARNING" },
    material: ["consumer.reputation"]
  }),
  scenario("redirect-threat", "Redirect Threat", "DO_NOT_BUY", {
    statuses: { "threat.redirect": "CRITICAL" },
    material: ["threat.redirect"],
    strongNegative: ["threat.redirect"],
    blocker: { controlId: "threat.redirect", kind: "MALICIOUS_REDIRECT" }
  })
];

function scenario(
  id: string,
  title: string,
  expectedVerdict: Verdict,
  overrides: ScenarioOverrides = {}
): GoldenScenario {
  const scanId = `demo-${id}`;
  const statuses = { ...DEFAULT_STATUSES, ...overrides.statuses };
  const evidence: Evidence[] = [];
  const findings: Finding[] = [];

  for (const control of TRUST_RULESET_V1.controls) {
    const status = statuses[control.id] ?? "NOT_CHECKED";
    const isAssessed = ["PASS", "WARNING", "FAIL", "CRITICAL"].includes(status);
    const evidenceId = `${scanId}:evidence:${control.id}`;
    if (isAssessed) {
      evidence.push({
        id: evidenceId,
        scanId,
        providerRunId: `${scanId}:provider:${control.id}`,
        subjectType: "DOMAIN",
        subjectKey: `${id}.example.test`,
        category: control.category,
        claimType: control.id,
        value: status,
        normalizedValue: status,
        sourceId: `synthetic-${control.id}`,
        sourceTier: sourceTierFor(control.id),
        collectionMethod: "SYNTHETIC_GOLDEN_SCENARIO",
        collectedAt: COLLECTED_AT,
        validUntil: VALID_UNTIL,
        impact:
          status === "PASS"
            ? "POSITIVE"
            : status === "WARNING"
              ? "WARNING"
              : status === "CRITICAL"
                ? "CRITICAL"
                : "NEGATIVE",
        severity:
          status === "CRITICAL" ? "CRITICAL" : status === "FAIL" ? "HIGH" : status === "WARNING" ? "LOW" : "INFO",
        findingCertainty: status === "PASS" ? "CORROBORATED" : "CONFIRMED",
        provenance: "DEMO",
        rulesetVersion: RULESET_VERSION
      });
    }
    findings.push({
      id: `${scanId}:finding:${control.id}`,
      ruleId: `golden.${control.id}`,
      controlId: control.id,
      category: control.category,
      status,
      title: `${title}: ${control.id}`,
      reason: `Synthetic ${status} result for ${control.id}`,
      evidenceIds: isAssessed ? [evidenceId] : [],
      material: overrides.material?.includes(control.id) ?? false,
      strongNegative: overrides.strongNegative?.includes(control.id) ?? false,
      provenance: "DEMO"
    });
  }

  const blockerFinding = overrides.blocker
    ? findings.find((finding) => finding.controlId === overrides.blocker?.controlId)
    : undefined;
  const hardBlockerCandidates: HardBlockerCandidate[] = [];
  if (overrides.blocker && blockerFinding) {
    hardBlockerCandidates.push({
      id: `${scanId}:blocker:${overrides.blocker.kind}`,
      kind: overrides.blocker.kind,
      findingId: blockerFinding.id,
      evidenceIds: blockerFinding.evidenceIds,
      provenance: "DEMO",
      reason: `Synthetic confirmed blocker: ${overrides.blocker.kind}`
    });
  }

  return {
    id,
    title,
    expectedVerdict,
    input: {
      scanId,
      targetSubjectKey: `${id}.example.test`,
      authorizedBlockingSourceIds: overrides.blocker
        ? [`synthetic-${overrides.blocker.controlId}`]
        : [],
      provenance: "DEMO",
      findings,
      evidence,
      hardBlockerCandidates,
      evaluatedAt: COLLECTED_AT,
      ruleset: TRUST_RULESET_V1
    }
  };
}

function sourceTierFor(controlId: string): SourceTier {
  if (controlId.startsWith("business.") || controlId.startsWith("domain.")) return 1;
  if (
    controlId.startsWith("technical.") ||
    controlId.startsWith("threat.") ||
    controlId === "evidence.consistency"
  ) {
    return 2;
  }
  if (controlId.startsWith("consumer.")) return 3;
  return 4;
}
