import { expect, it } from 'vitest';
import { env } from 'cloudflare:workers';
import { collectScanEvidence } from '../src/providers';
import { buildScanReport } from '../src/report';
import { humanSignals, riskLevel, analysisCoverage } from '../../web/src/web-pwa/features/decision';
import type { Env } from '../src/types';

// Explicit opt-in QA targets requested by the owner; never a runtime whitelist.
// Public receipts only, no raw HTML, keys, identity, CNPJ values or query strings.
for (const domain of ['www.amazon.com.br', 'atelierdrahaiter.com.br']) {
  it.runIf((env as unknown as { EDY_SEMANTIC_LIVE?: string }).EDY_SEMANTIC_LIVE === 'true')(`real risk/coverage separation: ${domain}`, async () => {
    const collected = await collectScanEvidence(`https://${domain}/`, { VIRUSTOTAL_ENABLED: 'false' } as Env);
    const report = buildScanReport(crypto.randomUUID(), collected);
    const unchanged = JSON.stringify(report);
    const before = { score: report.score, coverage: report.coverage, decisionCoverage: report.technical.decisionCoverage, verdict: report.verdict, confidence: report.confidence };
    const signals = humanSignals(report);
    const observedRisk = riskLevel(report);
    const coverage = analysisCoverage(report);
    expect(report.mode).toBe('real');
    expect(report.domain).toBe(domain);
    expect(collected.subrequests).toBeLessThanOrEqual(32);
    expect(report.technical.virusTotal?.state).toBe('DISABLED_NO_CREDENTIALS');
    expect(signals.attention.every(item => item.state === 'WARNING')).toBe(true);
    expect(signals.risks.every(item => item.state === 'FAIL')).toBe(true);
    expect(signals.missing.every(item => ['INFO', 'UNAVAILABLE', 'NOT_CHECKED'].includes(item.state))).toBe(true);
    if (report.verdict === 'INSUFFICIENT_DATA' && !signals.attention.length && !signals.risks.length) expect(observedRisk).toBe('UNDETERMINED');
    expect(JSON.stringify(report)).toBe(unchanged);
    await expect(JSON.stringify({
      kind: 'REAL_LOCAL_RISK_COVERAGE', at: report.scannedAt, domain, subrequests: collected.subrequests, pagesFetched: collected.http.pagesFetched,
      before, after: { ...before }, observedRisk, analysisCoverage: coverage,
      counts: { positive: signals.positive.length, attention: signals.attention.length, risks: signals.risks.length, missing: signals.missing.length },
      evidence: [...signals.positive, ...signals.attention, ...signals.risks, ...signals.missing].map(item => ({ id: item.id, checkId: item.checkId, state: item.state, title: item.title })),
      backendChecks: report.checks.map(check => ({ id: check.id, status: check.status, impact: check.impact, points: check.points, source: report.sources.find(source => source.id === check.sourceId)?.status })),
      vt: report.technical.virusTotal?.state,
      comparison: 'Identical real report before/after presentation; weights/providers/report are unchanged. Different collection times may produce different coverage.',
    }, null, 2)).toMatchFileSnapshot(`../../../docs/web-pwa/evidence-review/semantic-${domain}.json`);
  }, 30_000);
}
