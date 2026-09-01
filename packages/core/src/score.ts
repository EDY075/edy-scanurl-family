import type { CheckStatus, EvidenceCategory, Finding } from "./domain.js";
import { mapFindingsByControl } from "./coverage.js";
import type { TrustRuleset } from "./ruleset.js";

const EARNED_FRACTION: Partial<Record<CheckStatus, number>> = {
  PASS: 1,
  WARNING: 0.6,
  FAIL: 0,
  CRITICAL: 0
};

export interface CategoryScore {
  category: EvidenceCategory;
  assessedWeight: number;
  earnedPoints: number;
  normalizedScore: number | null;
}

export interface ScoreResult {
  baseValue: number | null;
  effectiveValue: number | null;
  overriddenByHardBlocker: boolean;
  categories: readonly CategoryScore[];
}

export function calculateTrustScore(
  findings: readonly Finding[],
  ruleset: TrustRuleset,
  hasHardBlocker: boolean
): ScoreResult {
  const findingMap = mapFindingsByControl(findings, ruleset);
  const categories: CategoryScore[] = [];
  let assessedWeight = 0;
  let earnedPoints = 0;

  for (const categoryRule of ruleset.categories) {
    let categoryAssessed = 0;
    let categoryEarned = 0;
    for (const control of ruleset.controls.filter((item) => item.category === categoryRule.category)) {
      const finding = findingMap.get(control.id);
      const fraction = finding ? EARNED_FRACTION[finding.status] : undefined;
      if (fraction === undefined) continue;
      const weightedControl = categoryRule.weight * control.relativeWeight;
      categoryAssessed += weightedControl;
      categoryEarned += weightedControl * fraction;
    }

    assessedWeight += categoryAssessed;
    earnedPoints += categoryEarned;
    categories.push({
      category: categoryRule.category,
      assessedWeight: round(categoryAssessed),
      earnedPoints: round(categoryEarned),
      normalizedScore:
        categoryAssessed === 0 ? null : round((categoryEarned / categoryAssessed) * 100)
    });
  }

  const baseValue = assessedWeight === 0 ? null : round((earnedPoints / assessedWeight) * 100);
  const effectiveValue =
    baseValue === null
      ? null
      : hasHardBlocker
        ? Math.min(baseValue, ruleset.blockerScoreCeiling)
        : baseValue;

  return {
    baseValue,
    effectiveValue,
    overriddenByHardBlocker: hasHardBlocker && baseValue !== null,
    categories
  };
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}
