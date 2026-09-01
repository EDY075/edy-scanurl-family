import type { CheckStatus, EvidenceCategory, Finding } from "./domain.js";
import { DomainInvariantError } from "./errors.js";
import type { TrustRuleset } from "./ruleset.js";

const ASSESSED_STATUSES = new Set<CheckStatus>(["PASS", "WARNING", "FAIL", "CRITICAL"]);

export interface CategoryCoverage {
  category: EvidenceCategory;
  applicableWeight: number;
  assessedWeight: number;
  coverage: number;
  complete: boolean;
}

export interface CoverageResult {
  value: number;
  essentialCategoriesComplete: boolean;
  categories: readonly CategoryCoverage[];
}

export function mapFindingsByControl(
  findings: readonly Finding[],
  ruleset: TrustRuleset
): ReadonlyMap<string, Finding> {
  const knownControls = new Map(ruleset.controls.map((control) => [control.id, control]));
  const mapped = new Map<string, Finding>();

  for (const finding of findings) {
    const control = knownControls.get(finding.controlId);
    if (!control) throw new DomainInvariantError(`Unknown control: ${finding.controlId}`);
    if (control.category !== finding.category) {
      throw new DomainInvariantError(`Control ${finding.controlId} does not belong to ${finding.category}`);
    }
    if (mapped.has(finding.controlId)) {
      throw new DomainInvariantError(`Duplicate finding for control: ${finding.controlId}`);
    }
    mapped.set(finding.controlId, finding);
  }

  return mapped;
}

export function calculateCoverage(
  findings: readonly Finding[],
  ruleset: TrustRuleset
): CoverageResult {
  const findingMap = mapFindingsByControl(findings, ruleset);
  const categories: CategoryCoverage[] = [];
  let totalApplicableWeight = 0;
  let totalAssessedWeight = 0;

  for (const categoryRule of ruleset.categories) {
    let applicableWeight = 0;
    let assessedWeight = 0;
    const controls = ruleset.controls.filter((control) => control.category === categoryRule.category);

    for (const control of controls) {
      const finding = findingMap.get(control.id);
      if (finding?.status === "NOT_APPLICABLE") continue;
      const weightedControl = categoryRule.weight * control.relativeWeight;
      applicableWeight += weightedControl;
      if (finding && ASSESSED_STATUSES.has(finding.status)) assessedWeight += weightedControl;
    }

    totalApplicableWeight += applicableWeight;
    totalAssessedWeight += assessedWeight;
    const coverage = applicableWeight === 0 ? 0 : (assessedWeight / applicableWeight) * 100;
    categories.push({
      category: categoryRule.category,
      applicableWeight,
      assessedWeight,
      coverage: round(coverage),
      complete: applicableWeight > 0 && Math.abs(applicableWeight - assessedWeight) < 0.000_001
    });
  }

  const essentialCategoriesComplete = ruleset.categories
    .filter((category) => category.essential)
    .every((essential) => categories.find((item) => item.category === essential.category)?.complete === true);

  return {
    value: totalApplicableWeight === 0 ? 0 : round((totalAssessedWeight / totalApplicableWeight) * 100),
    essentialCategoriesComplete,
    categories
  };
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}
