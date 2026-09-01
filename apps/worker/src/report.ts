import { RULESET_VERSION, evaluateDecision, type CheckStatus, type Evidence, type EvidenceCategory, type Finding, type HardBlockerCandidate } from '@edy-scanurl/core';
import { getDomain, getDomainWithoutSuffix } from 'tldts';
import type { Check, ScanReport, ScanEvidence, Source, VirusTotalObjectReport } from './types';

interface FindingInput {
  controlId: string;
  category: EvidenceCategory;
  status: CheckStatus;
  title: string;
  reason: string;
  sourceId: string;
  sourceTier?: 1 | 2 | 3 | 4 | 5;
  value?: unknown;
  sourceUrl?: string;
  certainty?: 'CONFIRMED' | 'CORROBORATED' | 'PROBABLE' | 'UNVERIFIED';
}

export function buildScanReport(scanId: string, collected: ScanEvidence, now = new Date().toISOString()): ScanReport {
  const evidence: Evidence[] = [];
  const findings: Finding[] = [];
  const evidenceByControl = new Map<string, string>();
  const add = (input: FindingInput) => addFinding(scanId, collected.target.domain, now, findings, evidence, evidenceByControl, input);
  const policyCount = Object.values(collected.http.policies).filter(Boolean).length;
  const headerCount = Object.values(collected.http.securityHeaders).filter(Boolean).length;
  const ageDays = collected.rdap.registrationDate ? Math.max(0, (Date.parse(now) - Date.parse(collected.rdap.registrationDate)) / 86_400_000) : undefined;
  const vt = aggregateVirusTotal(collected.virusTotal.domain, collected.virusTotal.url);
  const vtFresh = vt.fresh;
  const invalidCnpj = collected.http.status !== 'unavailable' && (collected.http.cnpjObservations ?? []).some((item) => item.checksum === 'INVALID');
  const vtStatus: CheckStatus = !vt.available || !vtFresh ? 'UNKNOWN' : vt.malicious >= 5 ? 'CRITICAL' : vt.malicious > 0 ? 'FAIL' : vt.suspicious > 0 ? 'WARNING' : 'UNKNOWN';

  add({ controlId: 'business.identity', category: 'BUSINESS_IDENTITY', status: 'NOT_CHECKED', title: 'Cadastro empresarial', reason: 'A base oficial de CNPJ não é consultada pelo Worker gratuito; uma alegação publicada pela própria loja não é confirmação independente.', sourceId: 'business-cnpj-bulk' });
  add({ controlId: 'domain.registration', category: 'DOMAIN_HISTORY', status: collected.rdap.status === 'available' ? 'PASS' : 'UNKNOWN', title: 'Registro do domínio', reason: collected.rdap.status === 'available' ? 'O serviço RDAP indicado pela IANA respondeu à consulta.' : 'A fonte RDAP não pôde ser consultada; essa indisponibilidade não é um sinal negativo.', sourceId: 'rdap', sourceTier: 1, value: collected.rdap, ...(collected.rdap.sourceUrl ? { sourceUrl: collected.rdap.sourceUrl } : {}), certainty: 'CONFIRMED' });
  add({ controlId: 'technical.https', category: 'TECHNICAL_SECURITY', status: collected.http.status === 'unavailable' ? 'UNKNOWN' : collected.http.httpsValidated ? 'PASS' : 'WARNING', title: 'HTTPS e certificado', reason: collected.http.httpsValidated ? 'A conexão HTTPS foi validada pela plataforma Cloudflare.' : 'Não foi possível confirmar uma conexão HTTPS válida.', sourceId: 'tls-worker', sourceTier: 2, value: { httpsValidated: collected.http.httpsValidated }, certainty: 'CONFIRMED' });
  add({ controlId: 'technical.headers', category: 'TECHNICAL_SECURITY', status: collected.http.status === 'unavailable' ? 'UNKNOWN' : headerCount >= 3 ? 'PASS' : 'WARNING', title: 'Proteções adicionais do navegador', reason: collected.http.status === 'unavailable' ? 'A página não estava disponível para essa consulta.' : `${String(headerCount)} proteção(ões) adicional(is) foram observadas; ausência isolada não indica fraude.`, sourceId: 'transparency-worker', sourceTier: 4, value: collected.http.securityHeaders });
  add({ controlId: 'threat.phishing', category: 'THREAT_IMPERSONATION', status: vtStatus, title: 'Sinais de phishing no VirusTotal', reason: virusTotalFindingReason(vtStatus, vt.malicious, vt.suspicious, collected.virusTotal.reason), sourceId: 'virus-total-public', sourceTier: 2, value: vt, ...(collected.virusTotal.sourceUrl ? { sourceUrl: collected.virusTotal.sourceUrl } : {}), certainty: vt.malicious >= 5 ? 'CORROBORATED' : 'UNVERIFIED' });
  add({ controlId: 'threat.malware', category: 'THREAT_IMPERSONATION', status: vtStatus === 'CRITICAL' ? 'FAIL' : vtStatus, title: 'Sinais de malware no VirusTotal', reason: virusTotalFindingReason(vtStatus, vt.malicious, vt.suspicious, collected.virusTotal.reason), sourceId: 'virus-total-public', sourceTier: 2, value: vt, ...(collected.virusTotal.sourceUrl ? { sourceUrl: collected.virusTotal.sourceUrl } : {}), certainty: vt.malicious >= 5 ? 'CORROBORATED' : 'UNVERIFIED' });
  add({ controlId: 'threat.redirect', category: 'THREAT_IMPERSONATION', status: collected.http.status === 'unavailable' ? 'UNKNOWN' : 'PASS', title: 'Destino e redirecionamentos', reason: collected.http.status === 'unavailable' ? 'O destino final não pôde ser confirmado.' : 'Todos os redirecionamentos observados permaneceram no mesmo domínio registrável e foram revalidados.', sourceId: 'redirect-guard', sourceTier: 2, value: { redirects: collected.http.redirects, finalOrigin: collected.http.finalOrigin }, certainty: 'CONFIRMED' });
  add({ controlId: 'consumer.reputation', category: 'CONSUMER_REPUTATION', status: 'NOT_CHECKED', title: 'Reputação de compradores', reason: 'Não existe uma fonte nacional automática gratuita e autorizada provisionada para esta consulta.', sourceId: 'consumer-gov-open-data' });
  add({ controlId: 'transparency.policies', category: 'STORE_TRANSPARENCY', status: collected.http.status !== 'unavailable' && policyCount >= 3 ? 'PASS' : 'UNKNOWN', title: 'Informações e políticas da loja', reason: collected.http.status === 'unavailable' ? 'A fonte estava indisponível; isso não é um sinal negativo.' : `${String(policyCount)} categoria(s) com conteúdo relevante foram observadas; a cobertura limitada não prova ausência de políticas.`, sourceId: 'transparency-worker', sourceTier: 4, value: collected.http.policies, ...(collected.http.finalOrigin ? { sourceUrl: `${collected.http.finalOrigin}/` } : {}) });
  add({ controlId: 'commerce.payment', category: 'COMMERCE_PAYMENT', status: 'UNKNOWN', title: 'Métodos de pagamento declarados', reason: collected.http.paymentMethods.length ? 'O próprio site declarou métodos de pagamento; isso não confirma o recebedor nem a possibilidade de contestação.' : 'Não foi possível confirmar métodos de pagamento publicamente.', sourceId: 'transparency-worker', sourceTier: 4, value: collected.http.paymentMethods });
  add({ controlId: 'public.presence', category: 'PUBLIC_PRESENCE', status: 'UNKNOWN', title: 'Presença pública declarada', reason: collected.http.socialLinks.length ? 'Links sociais foram publicados no próprio site, sem confirmação independente de titularidade.' : 'Nenhuma presença social utilizável foi observada.', sourceId: 'transparency-worker', sourceTier: 4, value: collected.http.socialLinks });
  add({ controlId: 'evidence.consistency', category: 'EVIDENCE_CONSISTENCY', status: invalidCnpj ? 'FAIL' : collected.http.cnpjClaims.length > 1 ? 'WARNING' : 'UNKNOWN', title: 'Consistência das informações', reason: invalidCnpj ? 'Um número declarado como CNPJ não passou na validação matemática dos dígitos; pode haver erro de digitação. Confirme antes de pagar.' : collected.http.cnpjClaims.length > 1 ? 'O site publicou mais de um CNPJ distinto; confirme os dados antes de pagar.' : 'A cobertura atual não permite correlação empresarial independente suficiente.', sourceId: 'edy-correlation', sourceTier: 4, value: { invalidCnpj, cnpjClaims: collected.http.cnpjClaims.length, companyNames: collected.http.companyNames.length } });

  const blockerEvidence = evidenceByControl.get('threat.phishing');
  const blockers: HardBlockerCandidate[] = vtStatus === 'CRITICAL' && blockerEvidence ? [{
    id: crypto.randomUUID(), kind: 'AUTHORIZED_CRITICAL_THREAT', findingId: findings.find((item) => item.controlId === 'threat.phishing')?.id ?? '',
    evidenceIds: [blockerEvidence], provenance: 'REAL', reason: 'Múltiplas detecções maliciosas recentes foram agregadas pelo VirusTotal.',
  }] : [];
  const decision = evaluateDecision({ scanId, targetSubjectKey: collected.target.domain, authorizedBlockingSourceIds: ['virus-total-public'], provenance: 'REAL', findings, evidence, hardBlockerCandidates: blockers, evaluatedAt: now });
  const checks = buildChecks(collected, vtStatus, vt, ageDays);
  const availableChecks = checks.filter((item) => !['UNKNOWN', 'NOT_CHECKED', 'NOT_APPLICABLE'].includes(item.status ?? '')).length;
  const applicableChecks = checks.filter((item) => item.status !== 'NOT_APPLICABLE').length;
  const evidenceCoverage = applicableChecks ? Math.round(availableChecks / applicableChecks * 10_000) / 100 : 0;
  const scoreVisible = decision.coverage.value >= 70 ? decision.score.effectiveValue : null;
  const verdict = decision.verdict.verdict;
  const sources = buildSources(collected, now);

  return {
    id: scanId, mode: 'real', inputUrl: `${collected.target.origin}/`, normalizedUrl: `${collected.target.origin}/`, domain: collected.target.domain,
    scannedAt: now, verdict, score: scoreVisible, confidence: decision.confidence.level, coverage: evidenceCoverage, scanCompletion: 100,
    summary: summaryFor(verdict), recommendation: recommendationFor(verdict), checks,
    scoreAreas: decision.score.categories.map((category) => ({ id: category.category, label: category.category, score: category.earnedPoints, max: category.assessedWeight, coverage: decision.coverage.categories.find((item) => item.category === category.category)?.coverage ?? 0 })),
    sources,
    storeEvidence: { version: 1, collection: collected.http.status, cnpjs: collected.http.cnpjObservations ?? [], cnpjTruncated: collected.http.cnpjTruncated ?? false, registration: 'NOT_CHECKED', match: 'UNKNOWN', policies: collected.http.policyEvidence ?? [] },
    technical: {
      confirmedCriticalThreat: decision.blockers.confirmed.length > 0,
      domainAge: ageDays === undefined ? 'Não confirmado' : `${(ageDays / 365.2425).toFixed(1)} ano(s)`,
      domainUpdatedAt: collected.rdap.updatedDate ?? 'Não confirmado', registrar: collected.rdap.registrar ?? 'Não confirmado',
      nameservers: collected.rdap.nameservers.length ? collected.rdap.nameservers : collected.dns.ns,
      dns: [
        ...collected.dns.a.map((value) => `A · ${value}`), ...collected.dns.aaaa.map((value) => `AAAA · ${value}`),
        ...collected.dns.ns.map((value) => `NS · ${value}`), ...collected.dns.mx.map((value) => `MX ${String(value.priority)} · ${value.exchange}`),
        ...collected.dns.caa.map((value) => `CAA · ${value}`), `DNSSEC · ${collected.dns.dnssec}`,
      ].slice(0, 24),
      tls: collected.http.httpsValidated ? 'HTTPS válido' : 'Não confirmado', tlsIssuer: 'Não exposto pelo runtime Workers',
      redirects: collected.http.status === 'unavailable' ? [] : [`${String(collected.http.redirects)} redirecionamento(s) validado(s)`],
      finalHostname: collected.http.finalOrigin ? new URL(collected.http.finalOrigin).hostname : 'Não confirmado', headers: collected.http.headers,
      threatStatus: vtStatus === 'CRITICAL' ? 'Múltiplas detecções maliciosas recentes' : vtStatus === 'FAIL' ? 'Detecção maliciosa requer confirmação' : vtStatus === 'WARNING' ? 'Detecção suspeita requer confirmação' : collected.virusTotal.status === 'unavailable' ? 'Fonte indisponível' : 'Nenhuma detecção não comprova segurança',
      salesVolume: 'Não verificável publicamente', paymentSignals: collected.http.paymentMethods,
      decisionCoverage: decision.coverage.value, pagesDiscovered: collected.http.pagesDiscovered, pagesFetched: collected.http.pagesFetched,
      ...(collected.http.crawlManifest ? { silentSkips: 0 } : {}),
      checkTrace: [
        ...checks.map((check) => ({ check: check.id, category: check.category, title: check.title, ...collectionTrace(check.sourceId, collected), finalState: check.status ?? 'UNKNOWN', provider: check.sourceId, evidenceCount: check.id === 'BUSINESS_CNPJ_SITE' ? collected.http.cnpjClaims.length : check.id === 'THREAT_VIRUSTOTAL' ? Number(vt.available) : check.status === 'PASS' ? 1 : 0, reason: check.description })),
        ...(collected.http.crawlManifest ?? []).map((page) => ({ check: `CRAWL_PAGE_${String(page.page)}`, category: 'HTTP', title: `Página pública ${String(page.page + 1)}`, attempted: page.attempted, finalState: page.outcome, provider: 'transparency-worker', durationMs: page.durationMs, evidenceCount: page.outcome === 'FETCHED' ? 1 : 0, reason: page.reason })),
        ...(collected.http.discoveryTruncated ? [{ check: 'CRAWL_DISCOVERY_LIMIT', category: 'HTTP', title: 'Limite de descoberta de páginas', attempted: false, finalState: 'SKIPPED', provider: 'transparency-worker', durationMs: 0, evidenceCount: 0, reason: 'CRAWL_DISCOVERY_LIMIT' }] : []),
        ...(collected.dns.failedQueries ?? []).map((query) => ({ check: `DNS_QUERY_${query}`, category: 'DNS', title: `Consulta DNS ${query}`, attempted: true, finalState: 'UNAVAILABLE', provider: 'dns-worker', durationMs: collected.dns.durationMs ?? 0, evidenceCount: 0, reason: 'DNS_SOURCE_UNAVAILABLE' })),
      ],
      virusTotal: { state: collected.virusTotal.state, reason: collected.virusTotal.reason, collectedAt: now, policyMode: 'PUBLIC_NONCOMMERCIAL_HOSTED_OPERATOR_AUTHORIZED', disclosure: 'REGISTRABLE_DOMAIN_AND_NORMALIZED_ORIGIN_ONLY', ...(collected.virusTotal.domain ? { domain: collected.virusTotal.domain } : {}), ...(collected.virusTotal.url ? { url: collected.virusTotal.url } : {}), registrationCorrelation: 'UNKNOWN' },
    },
  };
}

function addFinding(scanId: string, subject: string, now: string, findings: Finding[], evidence: Evidence[], evidenceByControl: Map<string, string>, input: FindingInput): void {
  const assessed = ['PASS', 'WARNING', 'FAIL', 'CRITICAL'].includes(input.status);
  const evidenceId = assessed ? crypto.randomUUID() : undefined;
  if (evidenceId) {
    const expires = new Date(Date.parse(now) + (input.sourceId === 'virus-total-public' ? 24 : 168) * 3_600_000).toISOString();
    evidence.push({
      id: evidenceId, scanId, providerRunId: `${input.sourceId}:${scanId}`, subjectType: 'DOMAIN', subjectKey: subject,
      category: input.category, claimType: input.controlId, value: input.value ?? input.reason, normalizedValue: input.value ?? input.reason,
      sourceId: input.sourceId, sourceTier: input.sourceTier ?? 4, collectionMethod: input.sourceId === 'edy-correlation' ? 'DERIVED' : 'PASSIVE',
      collectedAt: now, validUntil: expires, impact: input.status === 'PASS' ? 'POSITIVE' : input.status === 'WARNING' ? 'WARNING' : input.status === 'CRITICAL' ? 'CRITICAL' : 'NEGATIVE',
      severity: input.status === 'CRITICAL' ? 'CRITICAL' : input.status === 'FAIL' ? 'HIGH' : input.status === 'WARNING' ? 'LOW' : 'INFO',
      findingCertainty: input.certainty ?? (input.sourceTier === 1 ? 'CONFIRMED' : 'UNVERIFIED'), ...(input.sourceUrl ? { sourceUrlAllowed: input.sourceUrl } : {}),
      provenance: 'REAL', rulesetVersion: RULESET_VERSION,
    });
    evidenceByControl.set(input.controlId, evidenceId);
  }
  findings.push({ id: crypto.randomUUID(), ruleId: `RULE_${input.controlId}`, controlId: input.controlId, category: input.category, status: input.status, title: input.title, reason: input.reason, evidenceIds: evidenceId ? [evidenceId] : [], material: input.status === 'FAIL' || input.status === 'CRITICAL', strongNegative: input.status === 'CRITICAL', provenance: 'REAL' });
}

function buildChecks(collected: ScanEvidence, vtStatus: CheckStatus, vt: ReturnType<typeof aggregateVirusTotal>, ageDays?: number): Check[] {
  const statusImpact = (status: CheckStatus): Check['impact'] => status === 'PASS' ? 'positive' : status === 'WARNING' ? 'warning' : status === 'FAIL' ? 'negative' : status === 'CRITICAL' ? 'critical' : 'neutral';
  const make = (id: string, category: string, title: string, description: string, status: CheckStatus, sourceId: string, value?: string): Check => ({ id, category, title, description, status, impact: statusImpact(status), points: status === 'PASS' ? 1 : 0, sourceId, ...(value ? { value } : {}) });
  const checks: Check[] = [
    make('DOMAIN_RDAP', 'DOMAIN', 'Registro do domínio', collected.rdap.status === 'available' ? 'Fonte RDAP respondeu.' : collected.rdap.reason === 'RDAP_NO_DATA' ? 'A fonte RDAP respondeu sem registro para esta consulta; isso não é sinal negativo.' : 'Fonte RDAP indisponível; não é sinal negativo.', collected.rdap.status === 'available' ? 'PASS' : 'UNKNOWN', 'rdap'),
    make('DOMAIN_AGE', 'DOMAIN', 'Idade do domínio', ageDays === undefined ? 'A data não foi fornecida pela fonte ou a fonte ficou indisponível.' : ageDays < 30 ? 'O domínio tem menos de 30 dias; confirme cuidadosamente a identidade da loja.' : ageDays < 180 ? 'O domínio é recente; procure referências adicionais.' : 'O histórico de registro foi consultado.', ageDays === undefined ? 'UNKNOWN' : ageDays < 180 ? 'WARNING' : 'PASS', 'rdap'),
    make('DOMAIN_DNS', 'DOMAIN', 'Resolução DNS', 'Endereços públicos foram observados e endereços privados foram bloqueados.', 'PASS', 'dns-worker'),
    make('DOMAIN_NAMESERVERS', 'DOMAIN', 'Nameservers', collected.dns.ns.length ? 'Nameservers observados.' : 'Nenhum nameserver utilizável retornado.', collected.dns.ns.length ? 'PASS' : 'UNKNOWN', 'dns-worker'),
    make('DOMAIN_DNSSEC', 'DOMAIN', 'DNSSEC', collected.dns.dnssec === 'SIGNED' ? 'Registro DS observado.' : collected.dns.dnssec === 'UNKNOWN' ? 'A consulta DS ficou indisponível; não é tratada como ausência.' : 'Registro DS não observado; isso não prova risco.', collected.dns.dnssec === 'SIGNED' ? 'PASS' : 'UNKNOWN', 'dns-worker'),
    make('TLS_HTTPS', 'TLS', 'HTTPS disponível', collected.http.httpsValidated ? 'A plataforma validou a conexão HTTPS.' : 'A fonte ficou indisponível.', collected.http.httpsValidated ? 'PASS' : 'UNKNOWN', 'tls-worker'),
    make('HTTP_REDIRECTS', 'HTTP', 'Destino do link', collected.http.status === 'unavailable' ? 'O destino não pôde ser confirmado.' : 'Redirecionamentos limitados ao mesmo domínio registrável.', collected.http.status === 'unavailable' ? 'UNKNOWN' : 'PASS', 'transparency-worker'),
    make('HTTP_HEADERS', 'HTTP', 'Proteções extras', `${String(collected.http.headers.length)} proteção(ões) adicional(is) observada(s).`, collected.http.status === 'unavailable' ? 'UNKNOWN' : collected.http.headers.length >= 3 ? 'PASS' : 'WARNING', 'transparency-worker'),
    make('BUSINESS_CNPJ_SITE', 'BUSINESS', 'CNPJ declarado no site', collected.http.status === 'unavailable' ? 'A fonte estava indisponível; não é tratado como ausência.' : collected.http.cnpjClaims.length ? 'CNPJ declarado no próprio site; ainda não confirmado por fonte oficial.' : 'A fonte respondeu, mas não foi localizado CNPJ nas páginas lidas. Isso não significa que a empresa não exista.', 'UNKNOWN', 'transparency-worker', collected.http.cnpjClaims[0]),
    make('BUSINESS_OFFICIAL_VALIDATION', 'BUSINESS', 'Validação oficial do CNPJ', 'Fonte oficial automática não provisionada no plano gratuito.', 'NOT_CHECKED', 'business-cnpj-bulk'),
    make('TRANSPARENCY_POLICIES', 'TRANSPARENCY', 'Informações e políticas', `${String(Object.values(collected.http.policies).filter(Boolean).length)} categoria(s) com conteúdo relevante consultado; páginas não lidas não são tratadas como ausência.`, collected.http.status !== 'unavailable' && Object.values(collected.http.policies).filter(Boolean).length >= 3 ? 'PASS' : 'UNKNOWN', 'transparency-worker'),
    make('THREAT_VIRUSTOTAL', 'THREAT', 'VirusTotal', virusTotalFindingReason(vtStatus, vt.malicious, vt.suspicious, collected.virusTotal.reason), vtStatus, 'virus-total-public'),
    make('CONSUMER_REPUTATION', 'CONSUMER', 'Reputação de compradores', 'Fonte nacional automática não provisionada; a indisponibilidade não é penalizada.', 'NOT_CHECKED', 'consumer-gov-open-data'),
  ];
  const warning = inspectDomainName(collected.target.domain);
  if (collected.http.status !== 'unavailable' && collected.http.cnpjObservations?.some((item) => item.checksum === 'INVALID')) checks.push(make('BUSINESS_CNPJ_CHECKSUM', 'BUSINESS', 'Dígitos do CNPJ inválidos', 'Um CNPJ declarado não passou no cálculo dos dígitos. Isso pode ser erro de digitação; não prova fraude nem consulta cadastral.', 'FAIL', 'transparency-worker'));
  if (collected.http.cnpjClaims.length > 1) checks.push(make('BUSINESS_CNPJ_MULTIPLE', 'BUSINESS', 'Mais de um CNPJ declarado', 'Há CNPJs distintos nas páginas lidas. Podem pertencer a filiais ou terceiros; confirme quem recebe o pagamento.', 'WARNING', 'transparency-worker'));
  if (warning) checks.push(make('FAMILY_DOMAIN_LOOKALIKE', 'DOMAIN', 'Domínio parecido: confira o endereço', `O nome lembra ${warning}, mas não é esse domínio. Essa comparação é apenas uma pista.`, 'WARNING', 'family-domain-heuristic', warning));
  return checks;
}

function buildSources(collected: ScanEvidence, now: string): Source[] {
  return [
    { id: 'rdap', name: 'RDAP autoritativo', tier: 1, category: 'DOMAIN', collectedAt: now, ...(collected.rdap.sourceUrl ? { url: collected.rdap.sourceUrl } : {}), status: collected.rdap.status },
    { id: 'dns-worker', name: 'DNS over HTTPS — Cloudflare', tier: 2, category: 'DNS', collectedAt: now, url: 'https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/', status: collected.dns.status ?? 'available' },
    { id: 'tls-worker', name: 'Validação HTTPS do Cloudflare Workers', tier: 2, category: 'TLS', collectedAt: now, status: collected.http.httpsValidated ? 'available' : 'unavailable' },
    { id: 'transparency-worker', name: 'Site analisado passivamente', tier: 4, category: 'TRANSPARENCY', collectedAt: now, ...(collected.http.finalOrigin ? { url: `${collected.http.finalOrigin}/` } : {}), status: collected.http.status },
    { id: 'redirect-guard', name: 'Guarda de redirecionamentos do Worker', tier: 2, category: 'THREAT', collectedAt: now, status: collected.http.status === 'unavailable' ? 'unavailable' : 'available' },
    { id: 'virus-total-public', name: 'VirusTotal Public API', tier: 2, category: 'THREAT', collectedAt: now, ...(collected.virusTotal.sourceUrl ? { url: collected.virusTotal.sourceUrl } : {}), status: collected.virusTotal.status },
    { id: 'business-cnpj-bulk', name: 'Receita Federal — base CNPJ', tier: 1, category: 'BUSINESS', status: 'unavailable' },
    { id: 'consumer-gov-open-data', name: 'Consumidor.gov.br — dados abertos', tier: 1, category: 'CONSUMER', status: 'unavailable' },
  ];
}

function aggregateVirusTotal(...items: (VirusTotalObjectReport | undefined)[]): { available: boolean; fresh: boolean; malicious: number; suspicious: number; engines: number } {
  const available = items.filter((item): item is VirusTotalObjectReport => item?.state === 'AVAILABLE');
  const fresh = available.filter((item) => item.freshness === 'FRESH');
  return { available: available.length > 0, fresh: fresh.length > 0, malicious: Math.max(0, ...fresh.map((item) => item.stats?.malicious ?? 0)), suspicious: Math.max(0, ...fresh.map((item) => item.stats?.suspicious ?? 0)), engines: Math.max(0, ...available.map((item) => item.stats?.total ?? 0)) };
}
function virusTotalFindingReason(status: CheckStatus, malicious: number, suspicious: number, unavailable: string): string {
  if (status === 'CRITICAL') return `${String(malicious)} detecções maliciosas recentes foram agregadas; não informe dados nem faça pagamentos.`;
  if (status === 'FAIL') return `${String(malicious)} detecção(ões) maliciosa(s) foram observadas e precisam de confirmação independente.`;
  if (status === 'WARNING') return `${String(suspicious)} detecção(ões) suspeita(s) foram observadas e precisam de confirmação independente.`;
  if (/NO_DATA|NOT_FOUND/.test(unavailable)) return 'A fonte respondeu sem relatório para esta consulta; ausência de relatório não comprova segurança.';
  if (/DISABLED|RATE_LIMITED|FAILED|TIMED_OUT|UNAVAILABLE/.test(unavailable)) return 'A fonte de ameaças estava indisponível; isso não significa que o site seja seguro.';
  return 'Nenhuma detecção maliciosa foi retornada; isso não comprova segurança.';
}

function collectionTrace(sourceId: string, collected: ScanEvidence): { attempted: boolean; durationMs: number } {
  if (sourceId === 'rdap') return { attempted: collected.rdap.attempted ?? true, durationMs: collected.rdap.durationMs ?? 0 };
  if (sourceId === 'dns-worker') return { attempted: true, durationMs: collected.dns.durationMs ?? 0 };
  if (['transparency-worker', 'tls-worker', 'redirect-guard'].includes(sourceId)) return { attempted: collected.http.attempted ?? true, durationMs: collected.http.durationMs ?? 0 };
  if (sourceId === 'virus-total-public') return { attempted: collected.virusTotal.attempted ?? !collected.virusTotal.state.startsWith('DISABLED'), durationMs: collected.virusTotal.durationMs ?? 0 };
  if (sourceId === 'family-domain-heuristic') return { attempted: true, durationMs: 0 };
  return { attempted: false, durationMs: 0 };
}

function inspectDomainName(input: string): string | undefined {
  const references = ['mercadolivre.com.br', 'amazon.com.br', 'amazon.com', 'magazineluiza.com.br', 'shopee.com.br', 'shopee.com'];
  const registrable = getDomain(input, { allowPrivateDomains: false });
  if (!registrable || references.some((domain) => input === domain || input.endsWith(`.${domain}`))) return undefined;
  const label = getDomainWithoutSuffix(registrable) ?? '';
  for (const reference of references) {
    const brand = getDomainWithoutSuffix(reference) ?? '';
    if (brand.length >= 5 && (distanceAtMostOne(label, brand) || label.startsWith(`${brand}-`) || label.endsWith(`-${brand}`))) return reference;
  }
  return undefined;
}
function distanceAtMostOne(left: string, right: string): boolean {
  if (left === right || Math.abs(left.length - right.length) > 1) return left === right;
  let i = 0; let j = 0; let edits = 0;
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) { i += 1; j += 1; continue; }
    edits += 1; if (edits > 1) return false;
    if (left.length > right.length) i += 1; else if (right.length > left.length) j += 1; else { i += 1; j += 1; }
  }
  return edits + (left.length - i) + (right.length - j) <= 1;
}
function summaryFor(verdict: ScanReport['verdict']): string { return verdict === 'BUY' ? 'Bons sinais observados nas fontes disponíveis.' : verdict === 'CAUTION' ? 'Existem pontos que você deve verificar antes de comprar.' : verdict === 'DO_NOT_BUY' ? 'Foram observadas evidências fortes de risco elevado.' : 'Não foi possível obter evidências suficientes para recomendar esta compra.'; }
function recommendationFor(verdict: ScanReport['verdict']): string { return verdict === 'BUY' ? 'Ainda assim, confirme os dados da loja e prefira pagamento com proteção ao comprador.' : verdict === 'CAUTION' ? 'Confirme a identidade da empresa e evite pagamentos irreversíveis.' : verdict === 'DO_NOT_BUY' ? 'Não realize a compra nem forneça dados pessoais ou de pagamento.' : 'Espere antes de pagar e confirme a loja por outro canal.'; }
