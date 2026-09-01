import type { EvidenceCategory } from "./domain.js";

export const RULESET_VERSION = "edy-scanurl-trust-v1.0.0";

export interface CategoryRule {
  category: EvidenceCategory;
  weight: number;
  essential: boolean;
}

export interface ControlRule {
  id: string;
  category: EvidenceCategory;
  relativeWeight: number;
}

export interface TrustRuleset {
  version: string;
  coverageThreshold: number;
  buyCoverageThreshold: number;
  buyScoreThreshold: number;
  doNotBuyScoreThreshold: number;
  blockerScoreCeiling: number;
  categories: readonly CategoryRule[];
  controls: readonly ControlRule[];
}

export const TRUST_RULESET_V1: TrustRuleset = {
  version: RULESET_VERSION,
  coverageThreshold: 70,
  buyCoverageThreshold: 80,
  buyScoreThreshold: 80,
  doNotBuyScoreThreshold: 50,
  blockerScoreCeiling: 20,
  categories: [
    { category: "BUSINESS_IDENTITY", weight: 20, essential: true },
    { category: "DOMAIN_HISTORY", weight: 10, essential: true },
    { category: "TECHNICAL_SECURITY", weight: 10, essential: true },
    { category: "THREAT_IMPERSONATION", weight: 20, essential: true },
    { category: "CONSUMER_REPUTATION", weight: 15, essential: false },
    { category: "STORE_TRANSPARENCY", weight: 10, essential: true },
    { category: "COMMERCE_PAYMENT", weight: 5, essential: false },
    { category: "PUBLIC_PRESENCE", weight: 5, essential: false },
    { category: "EVIDENCE_CONSISTENCY", weight: 5, essential: false }
  ],
  controls: [
    { id: "business.identity", category: "BUSINESS_IDENTITY", relativeWeight: 1 },
    { id: "domain.registration", category: "DOMAIN_HISTORY", relativeWeight: 1 },
    { id: "technical.https", category: "TECHNICAL_SECURITY", relativeWeight: 0.6 },
    { id: "technical.headers", category: "TECHNICAL_SECURITY", relativeWeight: 0.4 },
    { id: "threat.phishing", category: "THREAT_IMPERSONATION", relativeWeight: 0.4 },
    { id: "threat.malware", category: "THREAT_IMPERSONATION", relativeWeight: 0.35 },
    { id: "threat.redirect", category: "THREAT_IMPERSONATION", relativeWeight: 0.25 },
    { id: "consumer.reputation", category: "CONSUMER_REPUTATION", relativeWeight: 1 },
    { id: "transparency.policies", category: "STORE_TRANSPARENCY", relativeWeight: 1 },
    { id: "commerce.payment", category: "COMMERCE_PAYMENT", relativeWeight: 1 },
    { id: "public.presence", category: "PUBLIC_PRESENCE", relativeWeight: 1 },
    { id: "evidence.consistency", category: "EVIDENCE_CONSISTENCY", relativeWeight: 1 }
  ]
};

export function assertRuleset(ruleset: TrustRuleset): void {
  const total = ruleset.categories.reduce((sum, category) => sum + category.weight, 0);
  if (total !== 100) {
    throw new Error(`Ruleset category weights must total 100; received ${String(total)}`);
  }

  for (const category of ruleset.categories) {
    const controls = ruleset.controls.filter((control) => control.category === category.category);
    const controlTotal = controls.reduce((sum, control) => sum + control.relativeWeight, 0);
    if (controls.length === 0 || Math.abs(controlTotal - 1) > Number.EPSILON * 10) {
      throw new Error(`Control weights for ${category.category} must total 1`);
    }
  }
}
