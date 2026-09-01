import { describe, expect, it } from 'vitest';
import { createDemoReport, demoScenarios } from './fixtures';

describe('strictly synthetic demo reports', () => {
  it.each(demoScenarios)('creates the $id scenario with explicit demo provenance', ({ id, verdict, domain }) => {
    const report = createDemoReport(`https://${domain}`, id);
    expect(report.mode).toBe('demo');
    expect(report.demoScenarioId).toBe(id);
    expect(report.verdict).toBe(verdict);
    expect(report.domain).toBe(domain);
    expect(report.sources.length).toBeGreaterThanOrEqual(4);
  });

  it('withholds score when coverage is insufficient', () => {
    const report = createDemoReport('https://nova-vitrine.example', 'insufficient');
    expect(report.score).toBeNull();
    expect(report.confidence).toBe('LOW');
    expect(report.coverage).toBeLessThan(70);
  });

  it('keeps a confirmed threat above positive technical hygiene', () => {
    const report = createDemoReport('https://mundo-promos.example', 'confirmed-phishing');
    expect(report.checks.some((check) => check.impact === 'critical')).toBe(true);
    expect(report.score).toBeLessThanOrEqual(20);
  });

  it('keeps high-risk and business-mismatch as distinct simulations', () => {
    const highRisk = createDemoReport('https://loja-alerta.example', 'high-risk');
    const mismatch = createDemoReport('https://marca-clonada.example', 'business-mismatch');
    expect(highRisk.demoScenarioId).not.toBe(mismatch.demoScenarioId);
    expect(highRisk.checks.some((check) => check.title.includes('inapto'))).toBe(true);
    expect(mismatch.company?.match).toBe('MISMATCH');
  });
});
