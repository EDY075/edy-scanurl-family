import { expect, it } from 'vitest';
import { env } from 'cloudflare:workers';
import { collectScanEvidence } from '../src/providers';
import { buildScanReport } from '../src/report';
import { analysisCoverage, humanSignals, riskLevel } from '../../web/src/web-pwa/features/decision';
import type { Env } from '../src/types';

const bindings = env as unknown as { EDY_COVERAGE_LIVE?: string; EDY_COVERAGE_PHASE?: string };
const phase = bindings.EDY_COVERAGE_PHASE === 'after' ? 'after' : 'before';

// Explicit opt-in QA cases requested by the owner. They are evidence samples,
// never runtime allowlists and never alter a result for these domains.
for (const domain of ['www.ingresso.com', 'www.amazon.com.br', 'atelierdrahaiter.com.br', 'www.gov.br', 'example.com']) {
  it.runIf(bindings.EDY_COVERAGE_LIVE === 'true')(`real coverage evidence (${phase}): ${domain}`, async () => {
    const collected = await collectScanEvidence(`https://${domain}/`, { VIRUSTOTAL_ENABLED: 'false' } as Env);
    const report = buildScanReport(crypto.randomUUID(), collected);
    const signals = humanSignals(report);
    expect(report.mode).toBe('real');
    expect(report.domain).toBe(domain);
    expect(collected.subrequests).toBeLessThanOrEqual(32);
    expect(signals.attention.every((item) => item.state === 'WARNING')).toBe(true);
    expect(signals.risks.every((item) => item.state === 'FAIL')).toBe(true);
    expect(signals.missing.every((item) => ['INFO', 'UNAVAILABLE', 'NOT_CHECKED'].includes(item.state))).toBe(true);
    await expect(JSON.stringify({
      kind: 'REAL_LOCAL_COVERAGE_REVIEW',
      phase,
      at: report.scannedAt,
      domain,
      subrequests: collected.subrequests,
      durationsMs: { dns: collected.dns.durationMs, rdap: collected.rdap.durationMs, http: collected.http.durationMs },
      crawl: { fetched: collected.http.pagesFetched, discovered: collected.http.pagesDiscovered, skipped: collected.http.pagesSkipped, status: collected.http.status },
      result: { score: report.score, reportCoverage: report.coverage, decisionCoverage: report.technical.decisionCoverage, verdict: report.verdict, confidence: report.confidence, observedRisk: riskLevel(report), analysisCoverage: analysisCoverage(report) },
      counts: { positive: signals.positive.length, attention: signals.attention.length, risks: signals.risks.length, missing: signals.missing.length },
      missing: signals.missing.map((item) => ({ id: item.id, checkId: item.checkId, state: item.state, title: item.title, explanation: item.explanation })),
      checks: report.checks.map((check) => ({ id: check.id, status: check.status, impact: check.impact, points: check.points, source: report.sources.find((source) => source.id === check.sourceId)?.status })),
      providerStates: { dns: collected.dns.status, rdap: collected.rdap.status, http: collected.http.status, virusTotal: collected.virusTotal.state },
    }, null, 2)).toMatchFileSnapshot(`../../../docs/web-pwa/evidence-review/coverage-${phase}-${domain}.json`);
  }, 45_000);
}
