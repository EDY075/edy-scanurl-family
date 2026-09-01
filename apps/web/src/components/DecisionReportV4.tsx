import { useMemo, useState, type ReactNode } from 'react';
import { ArrowLeft, Check, ChevronDown, ChevronRight, Copy as CopyIcon, ExternalLink, Info, RefreshCw, Share2 } from 'lucide-react';
import type { Copy } from '../lib/i18n';
import type { Check as CheckModel, CheckStatus, ScanReport } from '../types';

type ReportTab = 'overview' | 'checks' | 'company' | 'reputation' | 'security' | 'technical' | 'sources';
type GroupId = 'business' | 'domain' | 'security' | 'reputation' | 'transparency' | 'commerce';
type CheckFilter = 'all' | 'pass' | 'warning' | 'fail' | 'critical' | 'unconfirmed';
type TechnicalId = 'overview' | 'business' | 'domain' | 'dns' | 'security' | 'threat' | 'virustotal' | 'reputation' | 'transparency' | 'commerce' | 'correlation' | 'sources' | 'scoring' | 'trace' | 'raw';

const groups: { id: GroupId; pt: string; en: string; match: string[] }[] = [
  { id: 'business', pt: 'Empresa', en: 'Business', match: ['empresa', 'business', 'business_identity'] },
  { id: 'domain', pt: 'Domínio', en: 'Domain', match: ['domínio', 'domain_history', 'domain'] },
  { id: 'security', pt: 'Segurança', en: 'Security', match: ['segurança', 'security', 'ameaça', 'threat', 'tls', 'http', 'technical_security', 'threat_impersonation'] },
  { id: 'reputation', pt: 'Reputação', en: 'Reputation', match: ['reputação', 'consumer_reputation'] },
  { id: 'transparency', pt: 'Transparência', en: 'Transparency', match: ['transparência', 'transparency', 'store_transparency', 'cobertura', 'coverage', 'presence', 'consistency', 'public_presence', 'evidence_consistency'] },
  { id: 'commerce', pt: 'Comércio', en: 'Commerce', match: ['pagamento', 'payment', 'comércio', 'commerce', 'commerce_payment'] },
];

const statusPriority: Record<CheckStatus, number> = { CRITICAL: 0, FAIL: 1, WARNING: 2, UNKNOWN: 3, NOT_CHECKED: 4, NOT_APPLICABLE: 5, PASS: 6 };
const positivePriority: Record<CheckStatus, number> = { PASS: 0, WARNING: 1, UNKNOWN: 2, NOT_CHECKED: 3, NOT_APPLICABLE: 4, FAIL: 5, CRITICAL: 6 };
const normalize = (value: string) => value.toLocaleLowerCase('pt-BR');
const getStatus = (item: CheckModel): CheckStatus => item.status ?? 'UNKNOWN';
const groupFor = (item: CheckModel): GroupId => groups.find((group) => group.match.includes(normalize(item.category)))?.id ?? 'transparency';
const formatDate = (value: string, locale: string) => new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
const sourceDateLabel = (value: string | undefined, copy: Copy, locale: string) => value ? formatDate(value, locale) : copy.notCollected;
const sourceStatusLabel = (status: ScanReport['sources'][number]['status'], copy: Copy, locale: string) => status === 'available' ? (locale.startsWith('pt') ? 'Consultada' : 'Available') : status === 'limited' ? copy.limited : copy.unavailable;
const companyTone = (value: string) => /ativa|active/i.test(value) && !/inativa|inactive/i.test(value) ? 'pass' : /baixada|inapta|inactive/i.test(value) ? 'fail' : 'unknown';
const companyMatchLabel = (match: NonNullable<ScanReport['company']>['match'], locale: string) => ({ MATCH: locale.startsWith('pt') ? 'Compatível' : 'Match', PARTIAL_MATCH: locale.startsWith('pt') ? 'Parcialmente compatível' : 'Partial match', MISMATCH: locale.startsWith('pt') ? 'Incompatível' : 'Mismatch', UNKNOWN: locale.startsWith('pt') ? 'Desconhecida' : 'Unknown' })[match];
const virusTotalCategoryLabel = (category: string, locale: string) => {
  if (!locale.startsWith('pt')) return category;
  return ({ malicious: 'maliciosa', suspicious: 'suspeita', harmless: 'inofensiva', undetected: 'não detectada', timeout: 'tempo esgotado', failure: 'falha', other: 'outros', total: 'total' } as Record<string, string>)[category] ?? category;
};
const virusTotalFreshnessLabel = (freshness: string | undefined, locale: string) => {
  const value = freshness ?? 'UNKNOWN';
  if (!locale.startsWith('pt')) return value;
  return ({ FRESH: 'ATUAL', STALE: 'DESATUALIZADO', UNKNOWN: 'DESCONHECIDO' } as Record<string, string>)[value] ?? value;
};
const virusTotalObjectLabel = (value: string, locale: string) => locale.startsWith('pt') && value === 'Domain' ? 'Domínio' : value;
const virusTotalEnumLabel = (value: string, locale: string) => {
  if (!locale.startsWith('pt')) return value;
  return ({ UNKNOWN: 'DESCONHECIDO', MATCH: 'COMPATÍVEL', PARTIAL_MATCH: 'PARCIALMENTE COMPATÍVEL', MISMATCH: 'INCOMPATÍVEL', AVAILABLE_REDACTED: 'DISPONÍVEL · DADOS REDIGIDOS', UNAVAILABLE: 'INDISPONÍVEL' } as Record<string, string>)[value] ?? value;
};

function StatusMark({ status, copy }: { status: CheckStatus; copy: Copy }) {
  return <span className={`check-status status-${status.toLowerCase().replace('_', '-')}`}><i aria-hidden="true" />{copy.statusLabels[status]}</span>;
}

function countsFor(report: ScanReport) {
  const count = (statuses: CheckStatus[]) => report.checks.filter((item) => statuses.includes(getStatus(item))).length;
  return { all: report.checks.length, pass: count(['PASS']), warning: count(['WARNING']), fail: count(['FAIL']), critical: count(['CRITICAL']), unconfirmed: count(['UNKNOWN', 'NOT_CHECKED', 'NOT_APPLICABLE']) };
}

function filterMatches(item: CheckModel, filter: CheckFilter) {
  const status = getStatus(item);
  if (filter === 'all') return true;
  if (filter === 'unconfirmed') return ['UNKNOWN', 'NOT_CHECKED', 'NOT_APPLICABLE'].includes(status);
  return status === filter.toUpperCase();
}

function DetectionSummary({ report, copy, onSelect }: { report: ScanReport; copy: Copy; onSelect: (filter: CheckFilter) => void }) {
  const counts = countsFor(report);
  const items: { id: CheckFilter; label: string; tone: string }[] = [
    { id: 'pass', label: copy.approvedChecks, tone: 'pass' }, { id: 'warning', label: copy.warningChecks, tone: 'warning' },
    { id: 'fail', label: copy.problemChecks, tone: 'fail' }, { id: 'critical', label: copy.criticalChecks, tone: 'critical' },
    { id: 'unconfirmed', label: copy.unconfirmedChecks, tone: 'unknown' },
  ];
  return <section className="detection-summary" aria-labelledby="detection-title"><h2 id="detection-title">{copy.detectionSummary}</h2><div>{items.map((item) => <button type="button" key={item.id} className={`detection-${item.tone}`} onClick={() => onSelect(item.id)}><strong>{counts[item.id]}</strong><span>{item.label}</span></button>)}</div></section>;
}

function EvidenceRail({ report, copy, locale, onOpen }: { report: ScanReport; copy: Copy; locale: string; onOpen: () => void }) {
  return <section className="evidence-rail-wrap"><h2>{locale.startsWith('pt') ? 'Evidence Rail' : 'Evidence Rail'}</h2><ol className="evidence-rail" aria-label={locale.startsWith('pt') ? 'Linha de evidências' : 'Evidence rail'}>{groups.map((group) => {
    const statuses = report.checks.filter((item) => groupFor(item) === group.id).map(getStatus);
    const status = statuses.length ? statuses.sort((a, b) => statusPriority[a] - statusPriority[b])[0] : 'NOT_CHECKED';
    const label = locale.startsWith('pt') ? group.pt : group.en;
    return <li key={group.id} className={`rail-${status.toLowerCase().replace('_', '-')}`}><button type="button" onClick={onOpen} aria-label={`${label}: ${copy.statusLabels[status]}`}><i aria-hidden="true" /><span>{label}</span><small>{copy.statusLabels[status]}</small></button></li>;
  })}</ol></section>;
}

function DecisionMetrics({ report, copy, locale }: { report: ScanReport; copy: Copy; locale: string }) {
  const insufficient = report.verdict === 'INSUFFICIENT_DATA';
  return <aside className={`decision-metrics ${insufficient ? 'metrics-insufficient' : ''}`} aria-label={copy.trustScore}>
    {!insufficient && <div className="metric-score"><strong>{report.score ?? '—'}</strong>{report.score !== null && <span>/100</span>}<small>{report.score === null ? copy.scoreUnavailable : copy.trustScore}</small></div>}
    <dl><div title={copy.analysisHelp}><dt>{copy.analysis}</dt><dd>{report.scanCompletion ?? 100}% {copy.completed}</dd></div><div title={copy.coverageHelp}><dt>{copy.coverage}</dt><dd>{report.coverage}%</dd></div><div><dt>{copy.confidence}</dt><dd>{copy.confidences[report.confidence]}</dd></div><div className="metric-date"><dt>{copy.lastChecked}</dt><dd>{formatDate(report.scannedAt, locale)}</dd></div></dl>
  </aside>;
}

function StateHighlights({ report, copy, locale }: { report: ScanReport; copy: Copy; locale: string }) {
  const isPt = locale.startsWith('pt');
  if (report.verdict === 'INSUFFICIENT_DATA') {
    const verified = report.checks.filter((item) => getStatus(item) === 'PASS');
    const missing = report.checks.filter((item) => ['UNKNOWN', 'NOT_CHECKED', 'NOT_APPLICABLE'].includes(getStatus(item)));
    return <div className="insufficient-ledger"><div><h2>{copy.verifiedWhat}</h2>{verified.length ? verified.slice(0, 3).map((item) => <p key={item.id}>{item.title}</p>) : <p>{copy.noVerifiedSignals}</p>}</div><div><h2>{copy.unverifiedWhat}</h2>{missing.length ? missing.slice(0, 4).map((item) => <p key={item.id}>{item.title}</p>) : <p>{copy.notVerified}</p>}</div></div>;
  }
  if (report.verdict === 'BUY') return null;
  const sought = report.verdict === 'CAUTION' ? ['CRITICAL', 'FAIL', 'WARNING'] : ['CRITICAL', 'FAIL'];
  const items = [...report.checks].filter((item) => sought.includes(getStatus(item))).sort((a, b) => statusPriority[getStatus(a)] - statusPriority[getStatus(b)]).slice(0, 3);
  return <section className="state-highlights"><h2>{report.verdict === 'CAUTION' ? (isPt ? 'Principais pontos de atenção' : 'Main points of attention') : (isPt ? 'Motivos críticos' : 'Critical reasons')}</h2><ol>{items.map((item) => <li key={item.id}><StatusMark status={getStatus(item)} copy={copy} /><strong>{item.title}</strong><p>{item.description}</p></li>)}</ol></section>;
}

function PriorityReasons({ report, copy }: { report: ScanReport; copy: Copy }) {
  const positive = [...report.checks].filter((item) => getStatus(item) === 'PASS').sort((a, b) => positivePriority[getStatus(a)] - positivePriority[getStatus(b)]).slice(0, 3);
  const residual = [...report.checks].filter((item) => getStatus(item) !== 'PASS').sort((a, b) => statusPriority[getStatus(a)] - statusPriority[getStatus(b)]).slice(0, 3);
  const hasSevereResidual = residual.some((item) => ['CRITICAL', 'FAIL'].includes(getStatus(item)));
  const residualList = residual.length ? <div className={`residual-risk ${hasSevereResidual ? 'residual-severe' : ''}`}><h3>{hasSevereResidual ? copy.residualRisk : copy.residualAttention}</h3><ul>{residual.map((item) => <li key={item.id}><StatusMark status={getStatus(item)} copy={copy} /><div><h4>{item.title}</h4><p>{item.description}</p></div></li>)}</ul></div> : null;
  return <section className="priority-reasons" aria-labelledby="priority-title"><header><p className="section-kicker">{copy.positive}</p><h2 id="priority-title">{copy.reasonsTitle}</h2></header>{hasSevereResidual && residualList}<ol>{positive.map((item, index) => <li key={item.id}><span>{String(index + 1).padStart(2, '0')}</span><div><StatusMark status={getStatus(item)} copy={copy} /><h3>{item.title}</h3><p>{item.description}</p></div></li>)}</ol>{!hasSevereResidual && residualList}</section>;
}

function ChecksSection({ report, copy, locale, filter, onFilter }: { report: ScanReport; copy: Copy; locale: string; filter: CheckFilter; onFilter: (filter: CheckFilter) => void }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const counts = countsFor(report);
  const filters: { id: CheckFilter; label: string }[] = [{ id: 'all', label: copy.allChecks }, { id: 'pass', label: copy.approvedChecks }, { id: 'warning', label: copy.warningChecks }, { id: 'fail', label: copy.problemChecks }, { id: 'critical', label: copy.criticalChecks }, { id: 'unconfirmed', label: copy.unconfirmedChecks }];
  const visible = report.checks.filter((item) => filterMatches(item, filter));
  return <div className="checks-sheet" id="checks-content">
    <div className="checks-filter" aria-label={copy.filterChecks}>{filters.map((item) => <button type="button" key={item.id} className={filter === item.id ? 'active' : ''} aria-pressed={filter === item.id} onClick={() => onFilter(item.id)}>{item.label} <span>{counts[item.id]}</span></button>)}</div>
    <label className="checks-filter-select"><span>{copy.filterChecks}</span><select value={filter} onChange={(event) => onFilter(event.target.value as CheckFilter)}>{filters.map((item) => <option key={item.id} value={item.id}>{item.label} ({counts[item.id]})</option>)}</select></label>
    {visible.length === 0 && <p className="empty-copy">{locale.startsWith('pt') ? 'Nenhuma verificação neste filtro.' : 'No checks in this filter.'}</p>}
    {groups.map((group) => {
      const items = visible.filter((item) => groupFor(item) === group.id); if (!items.length) return null;
      const label = locale.startsWith('pt') ? group.pt : group.en;
      return <section key={group.id} className="check-group" aria-labelledby={`group-${group.id}`}><h2 id={`group-${group.id}`}>{label}</h2><div className="checks-table"><div className="checks-head" aria-hidden="true"><span>{copy.checkColumns.status}</span><span>{copy.checkColumns.check}</span><span>{copy.checkColumns.result}</span><span>{copy.checkColumns.source}</span><span>{copy.checkColumns.details}</span></div>{items.map((item) => {
        const source = report.sources.find((entry) => entry.id === item.sourceId); const isOpen = expanded === item.id;
        return <div className={`check-record status-border-${getStatus(item).toLowerCase().replace('_', '-')}`} key={item.id}><button type="button" className="check-row" aria-expanded={isOpen} aria-controls={`detail-${item.id}`} onClick={() => setExpanded(isOpen ? null : item.id)}><span><StatusMark status={getStatus(item)} copy={copy} /></span><strong>{item.title}</strong><span>{item.value ?? item.description}</span><span className="source-signature">{source ? `${source.name} · ${copy.tier} ${String(source.tier)}` : copy.notVerified}</span><span className="check-disclosure" aria-hidden="true"><ChevronDown /></span></button>{isOpen && <div id={`detail-${item.id}`} className="check-detail"><dl><div><dt>{locale.startsWith('pt') ? 'O que foi verificado' : 'What was checked'}</dt><dd>{item.title}</dd></div><div><dt>{copy.checkColumns.result}</dt><dd>{item.value ?? copy.statusLabels[getStatus(item)]}</dd></div><div><dt>{locale.startsWith('pt') ? 'Evidência' : 'Evidence'}</dt><dd>{item.description}</dd></div><div><dt>{copy.confidence}</dt><dd>{copy.confidences[report.confidence]}</dd></div><div><dt>{copy.sources}</dt><dd>{source ? `${source.name} · ${sourceStatusLabel(source.status, copy, locale)} · ${sourceDateLabel(source.collectedAt, copy, locale)}` : copy.notVerified}</dd></div></dl></div>}</div>;
      })}</div></section>;
    })}
  </div>;
}

function ScoreBreakdown({ report, copy }: { report: ScanReport; copy: Copy }) {
  return <><section className="score-sheet" aria-labelledby="score-title"><header><p className="section-kicker">{copy.explainableScore}</p><h2 id="score-title">{copy.scoreComposition}</h2></header><div className="score-table" role="table">{report.scoreAreas.map((area) => <div role="row" key={area.id}><span role="cell">{area.label}</span><strong role="cell">{report.score === null || area.max === 0 ? '—' : `${String(area.score)} / ${String(area.max)}`}</strong><small role="cell">{area.coverage}% {copy.coverageSuffix}</small></div>)}</div></section><VirusTotalStatusLine report={report} copy={copy} /></>;
}

function virusTotalStateLabel(state: NonNullable<ScanReport['technical']['virusTotal']>['state'] | 'MISSING', copy: Copy) {
  if (state === 'AVAILABLE') return copy.virusTotal.available;
  if (state === 'DISABLED_BY_POLICY') return copy.virusTotal.disabled;
  if (state === 'RATE_LIMITED') return copy.virusTotal.rateLimited;
  if (state === 'NO_DATA') return copy.virusTotal.noData;
  if (state === 'PARTIAL') return copy.virusTotal.partial;
  if (state === 'FAILED' || state === 'TIMED_OUT' || state === 'DISABLED_NO_CREDENTIALS') return copy.virusTotal.failed;
  return copy.virusTotal.unavailable;
}

function VirusTotalStatusLine({ report, copy }: { report: ScanReport; copy: Copy }) {
  const vt = report.technical.virusTotal;
  return <section className="provider-disclosure" aria-label={copy.virusTotal.title}><strong>{copy.virusTotal.title}</strong><span>{virusTotalStateLabel(vt?.state ?? 'MISSING', copy)}</span><p>{vt?.reason ?? copy.virusTotal.unavailable}</p></section>;
}

function VirusTotalTechnicalSection({ report, copy, locale }: { report: ScanReport; copy: Copy; locale: string }) {
  const vt = report.technical.virusTotal;
  const objects = vt ? [['Domain', vt.domain], ['URL', vt.url]] as const : [];
  const engines = objects.flatMap(([, item]) => item?.engines ?? []).filter((item, index, list) => list.findIndex((candidate) => candidate.engine === item.engine && candidate.category === item.category) === index).sort((a, b) => {
    const rank = (value: string) => value === 'malicious' ? 0 : value === 'suspicious' ? 1 : value.includes('timeout') ? 2 : 3;
    return rank(a.category) - rank(b.category) || a.engine.localeCompare(b.engine);
  });
  const metadata: { key: string; label: string; value: string }[] = [];
  for (const [label, item] of objects) {
    if (!item) continue;
    const objectLabel = virusTotalObjectLabel(label, locale);
    if (item.creationAt) metadata.push({ key: `${label}-creation`, label: `${objectLabel} · ${copy.virusTotal.creation}`, value: formatDate(item.creationAt, locale) });
    if (item.registrar) metadata.push({ key: `${label}-registrar`, label: `${objectLabel} · ${copy.virusTotal.registrar}`, value: item.registrar });
    if (item.whoisStatus) metadata.push({ key: `${label}-whois`, label: `${objectLabel} · ${copy.virusTotal.whois}`, value: virusTotalEnumLabel(item.whoisStatus, locale) });
    if (item.firstSubmissionAt) metadata.push({ key: `${label}-submission`, label: `${objectLabel} · ${copy.virusTotal.firstSubmission}`, value: formatDate(item.firstSubmissionAt, locale) });
    if (item.finalOrigin) metadata.push({ key: `${label}-origin`, label: `${objectLabel} · ${copy.virusTotal.finalOrigin}`, value: item.finalOrigin });
    if (item.lastHttpResponseCode !== undefined) metadata.push({ key: `${label}-http`, label: `${objectLabel} · ${copy.virusTotal.httpCode}`, value: String(item.lastHttpResponseCode) });
    if (item.reputation !== undefined || item.communityVotes) metadata.push({ key: `${label}-community`, label: `${objectLabel} · ${copy.virusTotal.community}`, value: `${String(item.reputation ?? '—')} · ${virusTotalCategoryLabel('harmless', locale)} ${String(item.communityVotes?.harmless ?? 0)} · ${virusTotalCategoryLabel('malicious', locale)} ${String(item.communityVotes?.malicious ?? 0)}` });
    if (item.categories?.length) metadata.push({ key: `${label}-categories`, label: `${objectLabel} · ${copy.virusTotal.categories}`, value: item.categories.map((entry) => `${entry.source}: ${entry.label}`).join(' · ') });
    if (item.tags?.length) metadata.push({ key: `${label}-tags`, label: `${objectLabel} · ${copy.virusTotal.tags}`, value: item.tags.join(' · ') });
    if (item.dnsSnapshot?.length) metadata.push({ key: `${label}-dns`, label: `${objectLabel} · ${copy.virusTotal.dnsSnapshot}`, value: item.dnsSnapshot.map((entry) => `${entry.type} ${entry.value}`).join(' · ') });
    if (item.certificateSnapshot) metadata.push({ key: `${label}-certificate`, label: `${objectLabel} · ${copy.virusTotal.certificate}`, value: [item.certificateSnapshot.subject, item.certificateSnapshot.issuer, item.certificateSnapshot.validUntil].filter(Boolean).join(' · ') });
  }
  return <section className="technical-section vt-technical"><h2>{copy.virusTotal.title}</h2><div className="vt-technical-body"><dl>
    <div><dt>{copy.virusTotal.providerState}</dt><dd>{virusTotalStateLabel(vt?.state ?? 'MISSING', copy)}</dd></div>
    <div><dt>{locale.startsWith('pt') ? 'Motivo' : 'Reason'}</dt><dd>{vt?.reason ?? copy.virusTotal.unavailable}</dd></div>
    {vt?.collectedAt && <div><dt>{copy.lastChecked}</dt><dd>{formatDate(vt.collectedAt, locale)}</dd></div>}
    {vt?.registrationCorrelation && <div><dt>{copy.virusTotal.registrationCorrelation}</dt><dd>{virusTotalEnumLabel(vt.registrationCorrelation, locale)}</dd></div>}
    {objects.flatMap(([label, item]) => item?.stats ? [<div key={`${label}-stats`}><dt>{virusTotalObjectLabel(label, locale)}</dt><dd>{Object.entries(item.stats).map(([category, value]) => `${String(value)} ${virusTotalCategoryLabel(category, locale)}`).join(' · ')}</dd></div>] : [])}
    {objects.flatMap(([label, item]) => item?.lastAnalysisAt ? [<div key={`${label}-date`}><dt>{virusTotalObjectLabel(label, locale)} · {copy.virusTotal.lastAnalysis}</dt><dd>{formatDate(item.lastAnalysisAt, locale)} · {virusTotalFreshnessLabel(item.freshness, locale)}</dd></div>] : [])}
    {metadata.map((item) => <div key={item.key}><dt>{item.label}</dt><dd>{item.value}</dd></div>)}
  </dl>{engines.length > 0 && <details className="vt-engines"><summary>{copy.virusTotal.showEngines} ({engines.length})</summary><div className="vt-engine-list"><div className="vt-engine-head" aria-hidden="true"><span>{copy.virusTotal.engine}</span><span>{copy.virusTotal.category}</span><span>{copy.virusTotal.result}</span></div>{engines.map((engine) => <div className={`vt-engine-row vt-engine-${engine.category}`} key={`${engine.engine}-${engine.category}`}><strong data-label={copy.virusTotal.engine}>{engine.engine}</strong><span data-label={copy.virusTotal.category}>{virusTotalCategoryLabel(engine.category, locale)}</span><span data-label={copy.virusTotal.result}>{engine.result ?? '—'}</span></div>)}</div></details>}<p className="context-note">{copy.virusTotal.noSafetyProof}</p></div></section>;
}

function TechnicalSection({ title, items }: { title: string; items: string[][] }) {
  return <section className="technical-section"><h2>{title}</h2><dl>{items.length ? items.map(([label, value], index) => <div key={`${label}-${String(index)}`}><dt>{label}</dt><dd>{value || '—'}</dd></div>) : <div><dt>—</dt><dd>Não verificado</dd></div>}</dl></section>;
}

function TechnicalReport({ report, copy, locale }: { report: ScanReport; copy: Copy; locale: string }) {
  const [active, setActive] = useState<TechnicalId>('overview'); const isPt = locale.startsWith('pt');
  const labels = copy.technicalSections;
  const checksText = (group: GroupId) => report.checks.filter((item) => groupFor(item) === group).map((item) => [item.title, item.value ?? item.description]);
  const raw = JSON.stringify({ id: report.id, mode: report.mode, domain: report.domain, scannedAt: report.scannedAt, verdict: report.verdict, score: report.score, confidence: report.confidence, scanCompletion: report.scanCompletion ?? 100, evidenceCoverage: report.coverage, decisionCoverage: report.technical.decisionCoverage, virusTotal: report.technical.virusTotal, checks: report.checks.map((item) => ({ id: item.id, status: getStatus(item), sourceId: item.sourceId })), checkTrace: report.technical.checkTrace, sources: report.sources.map((source) => ({ id: source.id, status: source.status, collectedAt: source.collectedAt })) }, null, 2);
  const sections: { id: TechnicalId; label: string; content: ReactNode }[] = [
    { id: 'overview', label: labels.overview, content: <TechnicalSection title={labels.overview} items={[[copy.analysis, `${String(report.scanCompletion ?? 100)}% ${copy.completed}`], [copy.coverage, `${String(report.coverage)}%`], [copy.confidence, copy.confidences[report.confidence]], [copy.trustScore, report.score === null ? copy.scoreUnavailable : `${String(report.score)}/100`], [isPt ? 'Páginas descobertas' : 'Pages discovered', String(report.technical.pagesDiscovered ?? 0)], [isPt ? 'Páginas analisadas' : 'Pages fetched', String(report.technical.pagesFetched ?? 0)], [copy.lastChecked, formatDate(report.scannedAt, locale)]]} /> },
    { id: 'business', label: labels.business, content: <TechnicalSection title={labels.business} items={report.company ? [[copy.fields.legalName, report.company.legalName], [copy.fields.registration, report.company.registration], [copy.fields.status, report.company.status]] : []} /> },
    { id: 'domain', label: labels.domain, content: <TechnicalSection title={labels.domain} items={[[copy.technicalLabels.observedAge, report.technical.domainAge], [copy.technicalLabels.updatedAt, report.technical.domainUpdatedAt ?? copy.notVerified], [copy.technicalLabels.registrar, report.technical.registrar], [copy.technicalLabels.nameservers, report.technical.nameservers?.join(' · ') ?? copy.notVerified]]} /> },
    { id: 'dns', label: labels.dns, content: <TechnicalSection title={labels.dns} items={report.technical.dns.map((item) => [copy.technicalLabels.record, item])} /> },
    { id: 'security', label: labels.security, content: <TechnicalSection title={labels.security} items={[[copy.technicalLabels.connection, report.technical.tls], [copy.technicalLabels.issuer, report.technical.tlsIssuer], [copy.technicalLabels.finalHostname, report.technical.finalHostname ?? copy.notVerified], [copy.fields.headers, report.technical.headers.join(' · ')]]} /> },
    { id: 'threat', label: labels.threat, content: <TechnicalSection title={labels.threat} items={[[copy.threatStatus, report.technical.threatStatus]]} /> },
    { id: 'virustotal', label: labels.virustotal, content: <VirusTotalTechnicalSection report={report} copy={copy} locale={locale} /> },
    { id: 'reputation', label: labels.reputation, content: <TechnicalSection title={labels.reputation} items={checksText('reputation')} /> },
    { id: 'transparency', label: labels.transparency, content: <TechnicalSection title={labels.transparency} items={checksText('transparency')} /> },
    { id: 'commerce', label: labels.commerce, content: <TechnicalSection title={labels.commerce} items={[[copy.technicalLabels.salesVolume, report.technical.salesVolume], ...report.technical.paymentSignals.map((item) => [copy.technicalLabels.payment, item])]} /> },
    { id: 'correlation', label: labels.correlation, content: <TechnicalSection title={labels.correlation} items={[[copy.matchTitle, report.company ? companyMatchLabel(report.company.match, locale) : copy.notVerified]]} /> },
    { id: 'sources', label: labels.sources, content: <TechnicalSection title={labels.sources} items={report.sources.map((source) => [source.name, `${source.category} · ${sourceStatusLabel(source.status, copy, locale)}`])} /> },
    { id: 'scoring', label: labels.scoring, content: <TechnicalSection title={labels.scoring} items={report.scoreAreas.map((area) => [area.label, `${String(area.score)}/${String(area.max)} · ${String(area.coverage)}%`])} /> },
    { id: 'trace', label: labels.trace, content: <TechnicalSection title={labels.trace} items={(report.technical.checkTrace ?? []).map((item) => [item.check, `${item.finalState} · ${item.provider} · ${String(item.durationMs)} ms · ${String(item.evidenceCount)} evidência(s) · ${item.reason}`])} /> },
    { id: 'raw', label: labels.raw, content: <section className="technical-section raw-data"><h2>{copy.advancedData}</h2><details><summary>{isPt ? 'Exibir dados redigidos' : 'Show redacted data'}</summary><pre>{raw}</pre></details></section> },
  ];
  return <section className="technical-report"><header><p className="section-kicker">{copy.technical}</p><h2>{isPt ? 'Evidências técnicas' : 'Technical evidence'}</h2></header><label className="technical-picker"><span>{copy.technicalIndex}</span><select value={active} onChange={(event) => setActive(event.target.value as TechnicalId)}>{sections.map((section) => <option key={section.id} value={section.id}>{section.label}</option>)}</select></label><div className="technical-layout"><nav aria-label={copy.technicalIndex}>{sections.map((section) => <button type="button" key={section.id} className={active === section.id ? 'active' : ''} aria-current={active === section.id ? 'page' : undefined} onClick={() => setActive(section.id)}>{section.label}</button>)}</nav><div>{sections.find((section) => section.id === active)?.content}</div></div></section>;
}

function SourcesLedger({ report, copy, locale }: { report: ScanReport; copy: Copy; locale: string }) {
  const labels = locale.startsWith('pt') ? ['Fonte', 'Tipo', 'Autoridade', 'Consultada em', 'Estado', 'Link'] : ['Source', 'Type', 'Authority', 'Checked at', 'Status', 'Link'];
  return <section className="sources-sheet"><header><p className="section-kicker">{copy.provenance}</p><h2>{copy.sources}</h2><p className="context-note">{locale.startsWith('pt') ? 'Disponibilidade indica a resposta da fonte, não a aprovação da loja.' : 'Availability indicates the provider response, not store approval.'}</p></header><div className="sources-ledger"><div className="sources-head" aria-hidden="true">{labels.map((label) => <span key={label}>{label}</span>)}</div>{report.sources.map((source) => <article key={source.id}><div><h3>{source.name}</h3>{source.sourceUpdatedAt && <small>{copy.sourceUpdated}: {formatDate(source.sourceUpdatedAt, locale)}</small>}</div><span>{source.category}</span><span>{copy.tier} {String(source.tier)}</span><time dateTime={source.collectedAt}>{sourceDateLabel(source.collectedAt, copy, locale)}</time><span className={`provider-state provider-${source.status}`}>{sourceStatusLabel(source.status, copy, locale)}</span>{source.url ? <a href={source.url} target="_blank" rel="noreferrer">{source.id === 'reclame-aqui-manual' ? (locale.startsWith('pt') ? 'Abrir no Reclame AQUI' : 'Open Reclame AQUI') : copy.viewSource}<ExternalLink /></a> : <span className="source-internal">{copy.directObservation}</span>}</article>)}</div></section>;
}

export function DecisionReportV4({ report, copy, locale, onBack, onRescan }: { report: ScanReport; copy: Copy; locale: string; onBack: () => void; onRescan: () => void }) {
  const [tab, setTab] = useState<ReportTab>('overview'); const [filter, setFilter] = useState<CheckFilter>('all'); const [copied, setCopied] = useState(false);
  const tabs: { id: ReportTab; label: string }[] = [{ id: 'overview', label: copy.overview }, { id: 'checks', label: copy.checks }, { id: 'company', label: copy.company }, { id: 'reputation', label: copy.reputation }, { id: 'security', label: copy.security }, { id: 'technical', label: copy.technical }, { id: 'sources', label: copy.sources }];
  const modeLabel = report.mode === 'demo' ? copy.demoBadge : copy.realLabel; const summaryText = `${modeLabel} · ${report.domain} · ${copy.verdicts[report.verdict]}${report.score !== null ? ` · ${String(report.score)}/100` : ''} · ${copy.coverage}: ${String(report.coverage)}% · ${copy.confidence}: ${copy.confidences[report.confidence]}. ${report.summary} ${copy.disclaimer}`;
  const handleCopy = async () => { await navigator.clipboard.writeText(summaryText); setCopied(true); window.setTimeout(() => setCopied(false), 1800); };
  const handleShare = async () => {
    const shareMethod: unknown = Reflect.get(navigator, 'share');
    if (typeof shareMethod !== 'function') { await handleCopy(); return; }
    try {
      await (shareMethod as (data: ShareData) => Promise<void>).call(navigator, { title: `EDY ScanURL · ${report.domain}`, text: summaryText });
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) await handleCopy();
    }
  };
  const openChecks = (nextFilter: CheckFilter = 'all') => { setFilter(nextFilter); setTab('checks'); window.setTimeout(() => document.getElementById('report-content')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0); };
  const reputationChecks = useMemo(() => report.checks.filter((item) => groupFor(item) === 'reputation'), [report]); const securityChecks = useMemo(() => report.checks.filter((item) => groupFor(item) === 'security'), [report]);
  const insufficient = report.verdict === 'INSUFFICIENT_DATA';
  return <main id="main-content" className={`report-page verdict-surface-${report.verdict.toLowerCase()}`}>
    <div className={`mode-banner mode-${report.mode}`}><strong>{modeLabel}</strong><span>{report.mode === 'demo' ? copy.demoBody : `${copy.analyzedAt} ${formatDate(report.scannedAt, locale)}`}</span></div>
    <div className="report-topbar"><button className="quiet-button" type="button" onClick={onBack}><ArrowLeft /> {copy.newScan}</button><div className="report-actions"><button type="button" aria-label={copied ? copy.copied : copy.copyLink} onClick={() => { void handleCopy(); }}>{copied ? <Check /> : <CopyIcon />}<span>{copied ? copy.copied : copy.copyLink}</span></button><button type="button" aria-label={copy.share} onClick={() => { void handleShare(); }}><Share2 /><span>{copy.share}</span></button></div></div>
    <section className={`decision-sheet ${insufficient ? 'decision-sheet-insufficient' : ''}`} aria-labelledby="result-verdict"><div className="decision-verdict"><div className="report-identity"><strong>{report.domain}</strong><span>{formatDate(report.scannedAt, locale)}</span></div><p className="verdict-label">{copy.report}</p><h1 id="result-verdict">{copy.verdicts[report.verdict]}</h1><p className="decision-action">{copy.decisionActions[report.verdict]}</p><p className="decision-summary">{report.summary}</p>{!insufficient && <StateHighlights report={report} copy={copy} locale={locale} />}{!insufficient && <div className="recommendation-line"><span>{copy.recommendation}</span><p>{report.recommendation}</p></div>}</div><DecisionMetrics report={report} copy={copy} locale={locale} />{insufficient && <div className="insufficient-state"><StateHighlights report={report} copy={copy} locale={locale} /></div>}{insufficient && <div className="recommendation-line insufficient-recommendation"><span>{copy.recommendation}</span><p>{report.recommendation}</p></div>}{report.verdict === 'BUY' && <div className="decision-reasons"><PriorityReasons report={report} copy={copy} /></div>}<div className="decision-detection"><DetectionSummary report={report} copy={copy} onSelect={openChecks} /></div><div className="decision-evidence"><EvidenceRail report={report} copy={copy} locale={locale} onOpen={() => openChecks('all')} /></div><p className="decision-disclaimer"><Info />{copy.disclaimer}</p></section>
    <nav className="report-tabs" aria-label={copy.reportSections}><span className={`sticky-mode-badge sticky-mode-${report.mode}`}>{report.mode === 'demo' ? 'DEMO' : 'REAL'}</span>{tabs.map((item) => <button key={item.id} type="button" className={tab === item.id ? 'active' : ''} aria-current={tab === item.id ? 'page' : undefined} onClick={() => setTab(item.id)}>{item.label}</button>)}</nav>
    <label className={`report-section-picker picker-${report.mode}`}><span>{report.mode === 'demo' ? 'DEMO' : 'REAL'} · {copy.reportSections}</span><select value={tab} onChange={(event) => setTab(event.target.value as ReportTab)}>{tabs.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
    <div className="report-content" id="report-content">{tab === 'overview' && <ScoreBreakdown report={report} copy={copy} />}{tab === 'checks' && <ChecksSection report={report} copy={copy} locale={locale} filter={filter} onFilter={setFilter} />}{tab === 'company' && <section className="company-sheet"><header><p className="section-kicker">{copy.businessIdentityEyebrow}</p><h2>{copy.businessIdentity}</h2></header>{report.company ? <><dl className="detail-list"><div><dt>{copy.fields.legalName}</dt><dd>{report.company.legalName}</dd></div><div><dt>{copy.fields.tradeName}</dt><dd>{report.company.tradeName}</dd></div><div><dt>{copy.fields.registration}</dt><dd>{report.company.registration}</dd></div><div><dt>{copy.fields.status}</dt><dd><span className={`company-status company-${companyTone(report.company.status)}`}>{report.company.status}</span></dd></div><div><dt>{copy.fields.openedAt}</dt><dd>{report.company.openedAt}</dd></div><div><dt>{copy.fields.activity}</dt><dd>{report.company.activity}</dd></div><div><dt>{copy.fields.location}</dt><dd>{report.company.location}</dd></div></dl><div className="correlation-row"><span>{copy.matchTitle}</span><strong>{companyMatchLabel(report.company.match, locale)}</strong><p>{copy.matchBody}</p></div></> : <div className="empty-state"><h3>{copy.companyMissing}</h3><p>{copy.companyMissingBody}</p></div>}</section>}{tab === 'reputation' && <section className="flat-sheet"><header><p className="section-kicker">{copy.consumerReputation}</p><h2>{copy.reputationEvidence}</h2><p>{copy.reputationNote}</p></header>{reputationChecks.length ? <ChecksSection report={{ ...report, checks: reputationChecks }} copy={copy} locale={locale} filter="all" onFilter={() => undefined} /> : <p className="empty-copy">{copy.noReputation}</p>}</section>}{tab === 'security' && <section className="flat-sheet"><header><p className="section-kicker">{copy.threatReputation}</p><h2>{copy.threatStatus}</h2><p><strong>{report.technical.threatStatus}</strong></p><p className="context-note">{copy.httpsNote}</p></header><ChecksSection report={{ ...report, checks: securityChecks }} copy={copy} locale={locale} filter="all" onFilter={() => undefined} /></section>}{tab === 'technical' && <TechnicalReport report={report} copy={copy} locale={locale} />}{tab === 'sources' && <SourcesLedger report={report} copy={copy} locale={locale} />}</div>
    <div className="report-footer-actions"><button className="secondary-button" type="button" onClick={onRescan}><RefreshCw /> {copy.rescan}</button><button className="primary-button" type="button" onClick={onBack}>{copy.newScan} <ChevronRight /></button></div>
  </main>;
}
