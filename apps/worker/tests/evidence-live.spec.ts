import { expect, it } from 'vitest';
import { env } from 'cloudflare:workers';
import { collectScanEvidence } from '../src/providers';
import { buildScanReport } from '../src/report';
import { resultEvidence } from '../../web/src/web-pwa/features/evidence';
import type { Env } from '../src/types';

// Explicit single-domain local workerd probe. No secrets, fixtures, deploy or
// direct government scraping. VT stays NOT_CHECKED here, not manufactured clean.
it.runIf((env as unknown as { EDY_EVIDENCE_LIVE?: string }).EDY_EVIDENCE_LIVE === 'true')('collects real public evidence in local Workers and maps unique web items', async () => {
  const evidence = await collectScanEvidence('https://atelierdrahaiter.com.br/', { VIRUSTOTAL_ENABLED: 'false' } as Env);
  const report = buildScanReport(crypto.randomUUID(), evidence);
  const items = resultEvidence(report);
  expect(report.mode).toBe('real');
  expect(new Set(items.map((item) => item.id)).size).toBe(items.length);
  expect(report.storeEvidence?.registration).toBe('NOT_CHECKED');
  expect(report.technical.virusTotal?.state).toBe('DISABLED_NO_CREDENTIALS');
  expect(evidence.subrequests).toBeLessThanOrEqual(32);
  expect(evidence.http.pagesFetched).toBeGreaterThan(0);
  // Explicit -u refreshes a real public-only QA receipt, never runtime input.
  await expect(JSON.stringify({ kind: 'REAL_LOCAL_WORKER_EVIDENCE', at: report.scannedAt, domain: report.domain, subrequests: evidence.subrequests, pagesFetched: evidence.http.pagesFetched, collection: evidence.http.status, cnpjs: report.storeEvidence?.cnpjs, policies: report.storeEvidence?.policies, registration: report.storeEvidence?.registration, vt: report.technical.virusTotal?.state, rdap: evidence.rdap.status, age: report.technical.domainAge, verdict: report.verdict, score: report.score, coverage: report.coverage, decisionCoverage: report.technical.decisionCoverage, ids: items.map((item) => item.id), crawl: evidence.http.crawlManifest }, null, 2)).toMatchFileSnapshot('../../../docs/web-pwa/evidence-review/live-local.json');
}, 30_000);
