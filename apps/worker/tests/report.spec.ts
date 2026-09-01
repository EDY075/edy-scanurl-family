import { describe, expect, it } from 'vitest';
import { buildScanReport } from '../src/report';
import type { ScanEvidence, VirusTotalObjectReport } from '../src/types';

function sample(overrides: Partial<ScanEvidence> = {}): ScanEvidence {
  return {
    target: { origin: 'https://example.com', domain: 'example.com' },
    dns: { a: ['93.184.216.34'], aaaa: [], ns: ['a.iana-servers.net'], mx: [], caa: [], dnssec: 'SIGNED' },
    rdap: { status: 'available', registrationDate: '1995-08-14T00:00:00.000Z', registrar: 'IANA', nameservers: ['a.iana-servers.net'], statuses: ['active'], sourceUrl: 'https://rdap.example/domain/example.com' },
    http: { status: 'available', httpsValidated: true, finalOrigin: 'https://example.com', redirects: 0, headers: ['hsts', 'csp', 'noSniff'], securityHeaders: { hsts: true, csp: true, frameProtection: false, referrerPolicy: false, permissionsPolicy: false, noSniff: true }, pagesFetched: 1, pagesDiscovered: 1, cnpjClaims: [], companyNames: [], emails: [], phones: [], socialLinks: [], paymentMethods: [], policies: { about: true, privacy: true, terms: true, returns: false, refund: false, shipping: false, legal: false, contact: false } },
    virusTotal: { status: 'unavailable', state: 'DISABLED_NO_CREDENTIALS', reason: 'VIRUSTOTAL_SECRET_NOT_CONFIGURED' },
    subrequests: 11,
    ...overrides,
  };
}

describe('Worker decision report', () => {
  it('missing evidence != negative evidence: invalid declared digits affect only consistency', () => {
    const input = sample();
    const missing = buildScanReport(crypto.randomUUID(), input);
    input.http.cnpjObservations = [{ value: '11222333000182', checksum: 'INVALID', provenance: [{ url: 'https://example.com/', location: 'FOOTER' }] }];
    const invalid = buildScanReport(crypto.randomUUID(), input);
    expect(missing.scoreAreas.find((area) => area.id === 'EVIDENCE_CONSISTENCY')?.max).toBe(0);
    expect(invalid.scoreAreas.find((area) => area.id === 'EVIDENCE_CONSISTENCY')).toMatchObject({ max: 5, score: 0 });
    expect(invalid.checks.find((check) => check.id === 'BUSINESS_CNPJ_CHECKSUM')?.status).toBe('FAIL');
    expect(invalid.checks.find((check) => check.id === 'BUSINESS_OFFICIAL_VALIDATION')?.status).toBe('NOT_CHECKED');
    expect(invalid.verdict).not.toBe('DO_NOT_BUY');
  });
  it('keeps valid checksum and policy provenance separate from official identity', () => {
    const input = sample();
    input.http.cnpjClaims = ['11222333000181'];
    input.http.cnpjObservations = [{ value: '11222333000181', checksum: 'VALID', provenance: [{ url: 'https://example.com/', location: 'FOOTER' }] }];
    input.http.policyEvidence = [{ id: 'privacy', sourceUrls: ['https://example.com/privacy'] }];
    const report = buildScanReport(crypto.randomUUID(), input);
    expect(report.storeEvidence).toMatchObject({ registration: 'NOT_CHECKED', match: 'UNKNOWN', cnpjs: input.http.cnpjObservations, policies: input.http.policyEvidence });
    expect(report.scoreAreas.find((area) => area.id === 'BUSINESS_IDENTITY')?.max).toBe(0);
  });
  it('does not turn stale detections into fresh risk when the other report is fresh', () => {
    const stats = { harmless: 20, undetected: 40, suspicious: 0, malicious: 0, timeout: 0, other: 0, total: 60 };
    const domain: VirusTotalObjectReport = { state: 'AVAILABLE', cache: 'MISS', freshness: 'FRESH', stats };
    const url: VirusTotalObjectReport = { state: 'AVAILABLE', cache: 'MISS', freshness: 'STALE', stats: { ...stats, malicious: 6, total: 66 } };
    const report = buildScanReport(crypto.randomUUID(), sample({ virusTotal: { status: 'available', state: 'AVAILABLE', reason: 'AVAILABLE', domain, url } }));
    expect(report.checks.find((check) => check.id === 'THREAT_VIRUSTOTAL')?.status).toBe('UNKNOWN');
    expect(report.verdict).not.toBe('DO_NOT_BUY');
  });
  it('does not punish a missing CNPJ or an unavailable threat source', () => {
    const report = buildScanReport(crypto.randomUUID(), sample(), '2026-08-30T12:00:00.000Z');
    expect(report.checks.find((check) => check.id === 'BUSINESS_CNPJ_SITE')?.status).toBe('UNKNOWN');
    expect(report.checks.find((check) => check.id === 'BUSINESS_OFFICIAL_VALIDATION')?.status).toBe('NOT_CHECKED');
    expect(report.checks.find((check) => check.id === 'THREAT_VIRUSTOTAL')?.status).toBe('UNKNOWN');
    expect(report.verdict).not.toBe('DO_NOT_BUY');
  });

  it('raises a hard blocker only for multiple fresh malicious detections', () => {
    const vt: VirusTotalObjectReport = { state: 'AVAILABLE', cache: 'MISS', freshness: 'FRESH', stats: { harmless: 20, undetected: 40, suspicious: 0, malicious: 6, timeout: 0, other: 0, total: 66 } };
    const report = buildScanReport(crypto.randomUUID(), sample({ virusTotal: { status: 'available', state: 'AVAILABLE', reason: 'VIRUSTOTAL_READ_ONLY_REPORTS_AVAILABLE', domain: vt, url: vt, sourceUrl: 'https://www.virustotal.com/gui/domain/example.com' } }), '2026-08-30T12:00:00.000Z');
    expect(report.checks.find((check) => check.id === 'THREAT_VIRUSTOTAL')?.status).toBe('CRITICAL');
    expect(report.verdict).toBe('DO_NOT_BUY');
    expect(report.technical.confirmedCriticalThreat).toBe(true);
    expect(report.score).toBeNull();
  });

  it('keeps a temporary source failure distinct from data not found', () => {
    const evidence = sample({ rdap: { status: 'unavailable', nameservers: [], statuses: [], reason: 'RDAP_UNAVAILABLE' } });
    const report = buildScanReport(crypto.randomUUID(), evidence, '2026-08-30T12:00:00.000Z');
    expect(report.sources.find((source) => source.id === 'rdap')?.status).toBe('unavailable');
    expect(report.checks.find((check) => check.id === 'DOMAIN_AGE')?.description).toMatch(/fonte|data/i);
  });

  it('does not claim disabled sources were attempted and exposes crawl failures/skips', () => {
    const evidence = sample();
    evidence.http.crawlManifest = [
      { page: 0, attempted: true, outcome: 'FETCHED', reason: 'HOMEPAGE_FETCHED', durationMs: 20 },
      { page: 1, attempted: true, outcome: 'FAILED', reason: 'HTTP_STATUS_503', durationMs: 10 },
      { page: 2, attempted: false, outcome: 'SKIPPED', reason: 'CRAWL_PAGE_LIMIT', durationMs: 0 },
    ];
    evidence.http.status = 'limited'; evidence.http.policies = {}; evidence.http.durationMs = 30;
    evidence.virusTotal.attempted = false;
    const report = buildScanReport(crypto.randomUUID(), evidence);
    const trace = report.technical.checkTrace ?? [];
    for (const id of ['BUSINESS_OFFICIAL_VALIDATION', 'CONSUMER_REPUTATION', 'THREAT_VIRUSTOTAL']) expect(trace.find((item) => item.check === id)?.attempted).toBe(false);
    expect(trace.find((item) => item.check === 'CRAWL_PAGE_1')).toMatchObject({ attempted: true, finalState: 'FAILED', reason: 'HTTP_STATUS_503', durationMs: 10 });
    expect(trace.find((item) => item.check === 'CRAWL_PAGE_2')).toMatchObject({ attempted: false, finalState: 'SKIPPED', reason: 'CRAWL_PAGE_LIMIT' });
    expect(report.checks.find((check) => check.id === 'TRANSPARENCY_POLICIES')?.status).toBe('UNKNOWN');
  });

  it('keeps explicit RDAP and VT no-data distinct from unavailable', () => {
    const report = buildScanReport(crypto.randomUUID(), sample({ rdap: { status: 'limited', nameservers: [], statuses: [], reason: 'RDAP_NO_DATA' }, virusTotal: { status: 'limited', state: 'NO_DATA', reason: 'VIRUSTOTAL_NO_DATA', attempted: true } }));
    expect(report.checks.find((check) => check.id === 'DOMAIN_RDAP')?.description).toMatch(/respondeu sem registro/);
    expect(report.checks.find((check) => check.id === 'THREAT_VIRUSTOTAL')?.description).toMatch(/sem relatório/);
    expect(report.checks.find((check) => check.id === 'THREAT_VIRUSTOTAL')?.status).toBe('UNKNOWN');
  });

  it('does not certify zero silent skips for legacy fixtures without a crawl manifest', () => {
    const report = buildScanReport(crypto.randomUUID(), sample());
    expect(report.technical.silentSkips).toBeUndefined();
  });
});
