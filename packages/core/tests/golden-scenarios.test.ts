import { describe, expect, it } from "vitest";
import { evaluateDecision, goldenScenarios } from "../src/index.js";

describe("golden scenarios", () => {
  it.each(goldenScenarios)("$title produces $expectedVerdict", (scenario) => {
    const result = evaluateDecision(scenario.input);
    expect(result.verdict.verdict).toBe(scenario.expectedVerdict);
  });

  it("evaluates deterministically", () => {
    const scenario = must(goldenScenarios[0]);
    const first = evaluateDecision(scenario.input);
    const second = evaluateDecision(scenario.input);
    expect(second).toEqual(first);
  });

  it("counts only checks that were actually assessed", () => {
    const insufficient = must(goldenScenarios.find((scenario) => scenario.id === "insufficient-data"));
    const result = evaluateDecision(insufficient.input);
    expect(result.detectionSummary.approved).toBe(4);
    expect(result.detectionSummary.unknown).toBeGreaterThan(0);
    expect(result.detectionSummary.approved + result.detectionSummary.unknown).toBe(
      insufficient.input.findings.length
    );
  });
});

function must<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("Expected fixture value");
  return value;
}
