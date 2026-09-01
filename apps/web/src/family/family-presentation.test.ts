import { describe, expect, it } from 'vitest';
import type { Check, ScanReport } from '../types';
import { describeFamilyVirusTotal, explainFamilyCheck, extractFamilyUrl, familyErrorMessage, safeFamilySourceUrl, sanitizeFamilyHistory, summarizeFamilyReport } from './family-presentation';

// Synthetic data used ONLY in unit tests. Never loaded by the Family runtime.
export function testFamilyReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    id: 'test-only-report', mode: 'real', inputUrl: 'https://loja.example/pedido?segredo=1', normalizedUrl: 'https://loja.example/', domain: 'loja.example', scannedAt: new Date().toISOString(),
    verdict: 'BUY', score: 90, confidence: 'HIGH', coverage: 90, summary: 'TEST ONLY', recommendation: 'TEST ONLY',
    checks: [{ id: 'business.identity', category: 'Empresa', title: 'Cadastro empresarial', description: 'TEST ONLY', impact: 'positive', status: 'PASS', points: 10, sourceId: 'official' }],
    scoreAreas: [], sources: [{ id: 'official', name: 'Fonte de teste', tier: 1, category: 'Empresa', status: 'available', url: 'https://fonte.example/' }],
    technical: { domainAge: '', registrar: '', dns: [], tls: '', tlsIssuer: '', redirects: [], headers: [], threatStatus: '', salesVolume: '', paymentSignals: [] },
    ...overrides,
  };
}

describe('Family presentation — test-only fixtures', () => {
  it.each([
    ['https://loja.example/produto?id=1#trecho', 'https://loja.example/produto?id=1'],
    ['Oi mãe, olha isso: https://loja.example/oferta. Vale a pena?', 'https://loja.example/oferta'],
    ['loja.example', 'https://loja.example/'],
    ['Pode ver (www.loja.example/oferta)?', 'https://www.loja.example/oferta'],
  ])('extracts exactly one address from %s', (text, url) => expect(extractFamilyUrl(text)).toBe(url));

  it.each(['https://um.example https://dois.example', 'um.example ou dois.example', 'https://um.example e www.dois.example'])('rejects multiple links: %s', (text) => {
    expect(() => extractFamilyUrl(text)).toThrow('multiple_urls');
  });
  it.each(['', 'nenhum endereço aqui', 'javascript:alert(1)', 'https://usuario:senha@loja.example/', 'nome@loja.example', 'ftp://loja.example'])('rejects invalid addresses: %s', (text) => expect(() => extractFamilyUrl(text)).toThrow());

  it('only calls a BUY report reliable when evidence gates are met', () => {
    const report = testFamilyReport();
    expect(summarizeFamilyReport(report).verdict).toBe('Confiável');
    expect(summarizeFamilyReport({ ...report, coverage: 30 }).verdict).toBe('Atenção');
    expect(summarizeFamilyReport({ ...report, technical: { ...report.technical, decisionCoverage: 30 } }).verdict).toBe('Atenção');
    expect(summarizeFamilyReport({ ...report, confidence: 'LOW' }).verdict).toBe('Atenção');
    expect(summarizeFamilyReport({ ...report, score: null }).verdict).toBe('Atenção');
    expect(summarizeFamilyReport({ ...report, checks: [] }).verdict).toBe('Atenção');
    expect(summarizeFamilyReport({ ...report, sources: [] }).verdict).toBe('Atenção');
    expect(summarizeFamilyReport({ ...report, checks: [{ ...report.checks[0], status: 'CRITICAL', impact: 'critical' }] }).verdict).toBe('Atenção');
    expect(report.score).toBe(90);
    expect(report.verdict).toBe('BUY');
  });
  it('vetoes reliable presentation for the real Family similar-domain heuristic', () => {
    const report = testFamilyReport();
    const check: Check = { ...report.checks[0], id: 'FAMILY_DOMAIN_LOOKALIKE', title: 'Endereço parecido', status: 'WARNING', impact: 'warning', sourceId: 'family-domain-heuristic', value: 'oficial.example' };
    expect(summarizeFamilyReport({ ...report, checks: [...report.checks, check] }).verdict).toBe('Atenção');
    expect(explainFamilyCheck(check).explanation).toContain('oficial.example');
    expect(explainFamilyCheck(check).explanation).toContain('não prova de golpe');
  });
  it('keeps connection, extra protections, redirection and other check explanations specific', () => {
    const base = testFamilyReport().checks[0];
    expect(explainFamilyCheck({ ...base, id: 'TLS', category: 'Segurança', title: 'HTTPS' }).title).toBe('Conexão protegida verificada');
    expect(explainFamilyCheck({ ...base, id: 'HTTP_HEADERS', category: 'Segurança', title: 'Cabeçalhos' }).title).toBe('Proteções extras verificadas');
    expect(explainFamilyCheck({ ...base, id: 'HTTP_REDIRECT', category: 'Segurança', title: 'Redirecionamento' }).title).toBe('Destino do link verificado');
    expect(explainFamilyCheck({ ...base, id: 'RETURNS', category: 'Loja', title: 'Política de devolução' }).title).toBe('Política de devolução');
  });
  it('does not turn unavailable data or a technical error into a fraud verdict', () => {
    const result = summarizeFamilyReport(testFamilyReport({ verdict: 'INSUFFICIENT_DATA', score: null }));
    expect(result.verdict).toBe('Atenção');
    expect(result.summary).toContain('Não há informações suficientes');
    expect(summarizeFamilyReport(testFamilyReport({ verdict: 'DO_NOT_BUY' })).verdict).toBe('Alto risco');
    expect(() => summarizeFamilyReport(testFamilyReport({ mode: 'demo' }))).toThrow('scan_failed');
    expect(familyErrorMessage(new Error('offline'))).not.toMatch(/Confiável|Alto risco/);
    expect(familyErrorMessage(new Error('secret:internal:8787'))).not.toContain('secret');
  });
  it('explains missing CNPJ and reputation without claiming nonexistence or safety', () => {
    const check = testFamilyReport().checks[0];
    expect(explainFamilyCheck({ ...check, status: 'NOT_CHECKED' }).explanation).toContain('fonte necessária não estava disponível');
    expect(explainFamilyCheck({ ...check, status: 'UNKNOWN' }, 'limited').explanation).toContain('não encontramos um CNPJ nas páginas');
    expect(explainFamilyCheck({ ...check, status: 'UNKNOWN' }, 'limited').explanation).toContain('não é tratado como um sinal negativo');
    expect(explainFamilyCheck({ ...check, id: 'consumer.reputation', title: 'Reputação', status: 'UNKNOWN' }, 'limited').explanation).toContain('não é prova de confiança');
    expect(explainFamilyCheck({ ...check, id: 'domain.lookalike', title: 'Domínio parecido', status: 'WARNING' }).explanation).toContain('não prova de golpe');
  });
  it('distinguishes a source outage from a source that returned no usable domain age', () => {
    const check = { ...testFamilyReport().checks[0], id: 'DOMAIN_AGE', category: 'Domínio', title: 'Idade do domínio', status: 'UNKNOWN' as const, impact: 'neutral' as const };
    expect(explainFamilyCheck({ ...check, status: 'NOT_CHECKED' }, 'unavailable').explanation).toContain('não estava disponível');
    expect(explainFamilyCheck(check, 'available').explanation).toContain('respondeu, mas não trouxe');
    expect(explainFamilyCheck(check, 'available').explanation).toContain('não é tratado como um sinal negativo');
  });
  it('puts real critical findings ahead of favorable observations', () => {
    const report = testFamilyReport();
    const critical: Check = { ...report.checks[0], id: 'threat.phishing', title: 'Phishing', category: 'Ameaças', status: 'CRITICAL', impact: 'critical' };
    const result = summarizeFamilyReport({ ...report, checks: [...report.checks, critical] });
    expect(result.reasons[0].id).toBe(critical.id);
  });
  it('puts missing CNPJ, reputation and domain age before MX, DNSSEC and header warnings', () => {
    const base = testFamilyReport().checks[0];
    const checks: Check[] = [
      { ...base, id: 'HTTP_HEADERS', category: 'Segurança', title: 'Cabeçalhos de segurança', status: 'WARNING', impact: 'warning' },
      { ...base, id: 'DNS_MX', category: 'DNS', title: 'Servidores de e-mail', status: 'UNKNOWN', impact: 'neutral' },
      { ...base, id: 'DNSSEC', category: 'DNS', title: 'DNSSEC', status: 'UNKNOWN', impact: 'neutral' },
      { ...base, id: 'DOMAIN_AGE', category: 'Domínio', title: 'Idade do domínio', status: 'UNKNOWN', impact: 'neutral' },
      { ...base, id: 'BUSINESS_CNPJ_SITE', category: 'Empresa', title: 'CNPJ declarado no site', status: 'NOT_CHECKED', impact: 'neutral' },
      { ...base, id: 'consumer.reputation', category: 'Reputação', title: 'Reputação do consumidor', status: 'NOT_CHECKED', impact: 'neutral' },
      { ...base, id: 'business.identity', category: 'Empresa', title: 'Cadastro empresarial', status: 'UNKNOWN', impact: 'neutral' },
    ];
    const report = testFamilyReport({ verdict: 'INSUFFICIENT_DATA', coverage: 30, score: null, checks });
    const result = summarizeFamilyReport(report);
    expect(result.reasons.map((reason) => reason.id)).toEqual(['BUSINESS_CNPJ_SITE', 'consumer.reputation', 'DOMAIN_AGE', 'HTTP_HEADERS']);
    expect(result.reasons.map((reason) => reason.title)).toEqual(['CNPJ não confirmado', 'Poucas informações de compradores', 'Tempo de existência não confirmado', 'Faltam algumas proteções extras']);
    expect(result.reasons).toHaveLength(4);
    expect(result.verdict).toBe('Atenção');
    expect(report.checks).toEqual(checks);
    expect(report.checks[0].id).toBe('HTTP_HEADERS');
  });
  it('keeps critical/fail, real lookalike and threat warnings ahead of secondary information', () => {
    const base = testFamilyReport().checks[0];
    const checks: Check[] = [
      { ...base, id: 'DNS_MX', category: 'DNS', title: 'Servidores de e-mail', status: 'UNKNOWN', impact: 'neutral' },
      { ...base, id: 'DOMAIN_AGE', category: 'Domínio', title: 'Domínio recente', status: 'WARNING', impact: 'warning' },
      { ...base, id: 'FAMILY_DOMAIN_LOOKALIKE', category: 'Domínio', title: 'Nome parecido', status: 'WARNING', impact: 'warning' },
      { ...base, id: 'threat.suspicious', category: 'Ameaça', title: 'Ameaça suspeita', status: 'WARNING', impact: 'warning' },
      { ...base, id: 'identity-fail', category: 'Empresa', title: 'Cadastro empresarial divergente', status: 'FAIL', impact: 'negative' },
      { ...base, id: 'payment-critical', category: 'Pagamento', title: 'Recebedor divergente', status: 'CRITICAL', impact: 'critical' },
    ];
    expect(summarizeFamilyReport(testFamilyReport({ checks })).reasons.map((reason) => reason.id)).toEqual(['payment-critical', 'identity-fail', 'FAMILY_DOMAIN_LOOKALIKE', 'threat.suspicious']);
  });
  it('shows a fresh technical-only VT alert among the four main reasons without adding a Check', () => {
    const report = testFamilyReport();
    const base = report.checks[0];
    report.checks = Array.from({ length: 5 }, (_, i) => ({ ...base, id: `test-critical-${String(i)}`, category: 'Pagamento', title: `Sinal importante ${String(i)}`, status: 'CRITICAL' as const, impact: 'critical' as const }));
    report.technical.virusTotal = { state: 'AVAILABLE', reason: 'TEST ONLY', url: { state: 'AVAILABLE', cache: 'MISS', freshness: 'FRESH', stats: { malicious: 1, suspicious: 2, harmless: 0, undetected: 0, timeout: 0, other: 0, total: 3 } } };
    const before = JSON.stringify(report);
    const result = summarizeFamilyReport(report);
    expect(result.reasons).toHaveLength(4);
    expect(result.reasons.slice(0, 3).map((reason) => reason.id)).toEqual(['test-critical-0', 'test-critical-1', 'test-critical-2']);
    const vtReason = result.reasons.find((reason) => reason.id === 'technical.virusTotal.fresh-alerts');
    expect(vtReason?.explanation).toContain('1 alerta(s) de conteúdo malicioso e 2 de conteúdo suspeito');
    expect(vtReason?.explanation).toContain('não prova isolada de golpe');
    expect(vtReason?.sourceId).toBeUndefined();
    expect(result.verdict).toBe('Atenção');
    expect(JSON.stringify(report)).toBe(before);
  });
  it('does not promote unavailable, stale or zero-detection VT data to a main alert', () => {
    const report = testFamilyReport({ verdict: 'INSUFFICIENT_DATA', coverage: 30, score: null });
    const vt: NonNullable<ScanReport['technical']['virusTotal']> = { state: 'AVAILABLE', reason: 'TEST ONLY', domain: { state: 'AVAILABLE', cache: 'MISS', freshness: 'FRESH', stats: { malicious: 0, suspicious: 0, harmless: 3, undetected: 0, timeout: 0, other: 0, total: 3 } } };
    report.technical.virusTotal = vt;
    const hasAlert = () => summarizeFamilyReport(report).reasons.some((reason) => reason.id === 'technical.virusTotal.fresh-alerts');
    expect(hasAlert()).toBe(false);
    if (!vt.domain?.stats) throw new Error('missing test-only data');
    vt.domain.stats.malicious = 1; vt.domain.freshness = 'STALE';
    expect(hasAlert()).toBe(false);
    vt.domain.freshness = 'FRESH'; vt.state = 'DISABLED_BY_POLICY';
    expect(hasAlert()).toBe(false);
    expect(summarizeFamilyReport(report).verdict).toBe('Atenção');
  });
  it('distinguishes fresh detection, fresh zero detection and unavailable/old VirusTotal data', () => {
    const report = testFamilyReport();
    expect(describeFamilyVirusTotal(report)[0]).toContain('não estava disponível');
    const vt: NonNullable<ScanReport['technical']['virusTotal']> = { state: 'AVAILABLE', reason: 'TEST ONLY', domain: { state: 'AVAILABLE', cache: 'MISS', freshness: 'FRESH', stats: { malicious: 1, suspicious: 2, harmless: 0, undetected: 0, timeout: 0, other: 0, total: 3 } } };
    report.technical.virusTotal = vt;
    expect(describeFamilyVirusTotal(report)[0]).toContain('1 alerta(s)');
    expect(summarizeFamilyReport(report).verdict).toBe('Atenção');
    if (!vt.domain?.stats) throw new Error('missing test-only data');
    vt.domain.stats.malicious = 0; vt.domain.stats.suspicious = 0;
    expect(describeFamilyVirusTotal(report)[0]).toContain('não encontrou alertas');
    expect(describeFamilyVirusTotal(report)[0]).toContain('não garante');
    vt.domain.freshness = 'STALE';
    expect(describeFamilyVirusTotal(report)[0]).toContain('antiga');
  });
  it('whitelists the minimal history schema, expires after 30 days and caps at 20', () => {
    const now = Date.parse('2026-08-30T12:00:00Z');
    const records = Array.from({ length: 25 }, (_, i) => ({ domain: `loja${String(i)}.example`, verdict: 'Atenção', time: new Date(now - i * 1000).toISOString(), url: 'https://secret.example/pedido', query: 'private', score: 99, report: testFamilyReport() }));
    const safe = sanitizeFamilyHistory(records, now);
    expect(safe).toHaveLength(20);
    expect(Object.keys(safe[0]).sort()).toEqual(['domain', 'time', 'verdict']);
    expect(JSON.stringify(safe)).not.toMatch(/private|secret|report|score|pedido/);
    expect(sanitizeFamilyHistory([{ ...records[0], domain: 'loja.example/path?private=1' }, { ...records[0], time: '2020-01-01' }, { ...records[0], time: '2099-01-01' }], now)).toEqual([]);
    expect(sanitizeFamilyHistory({ bad: 'object' }, now)).toEqual([]);
  });
  it('does not expose unsafe source links', () => {
    expect(safeFamilySourceUrl('javascript:alert(1)')).toBeUndefined();
    expect(safeFamilySourceUrl('https://user:password@fonte.example')).toBeUndefined();
    expect(safeFamilySourceUrl('https://fonte.example')).toBe('https://fonte.example/');
  });
});
