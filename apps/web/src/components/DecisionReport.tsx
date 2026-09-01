import { useMemo, useState } from 'react';
import { ArrowLeft, Check, ChevronDown, ChevronRight, Copy as CopyIcon, ExternalLink, Info, RefreshCw, Share2 } from 'lucide-react';
import type { Copy } from '../lib/i18n';
import type { Check as CheckModel, CheckStatus, ScanReport } from '../types';

type ReportTab = 'overview' | 'checks' | 'company' | 'reputation' | 'security' | 'technical' | 'sources';
type GroupId = 'business' | 'domain' | 'security' | 'reputation' | 'transparency' | 'commerce';

const groups: { id: GroupId; pt: string; en: string; match: string[] }[] = [
  { id: 'business', pt: 'Empresa', en: 'Business', match: ['empresa', 'business', 'business_identity'] },
  { id: 'domain', pt: 'Domínio', en: 'Domain', match: ['domínio', 'domain_history', 'domain'] },
  { id: 'security', pt: 'Segurança', en: 'Security', match: ['segurança', 'security', 'ameaça', 'threat', 'technical_security', 'threat_impersonation'] },
  { id: 'reputation', pt: 'Reputação', en: 'Reputation', match: ['reputação', 'consumer_reputation'] },
  { id: 'transparency', pt: 'Transparência', en: 'Transparency', match: ['transparência', 'transparency', 'store_transparency', 'cobertura', 'coverage', 'public_presence', 'evidence_consistency'] },
  { id: 'commerce', pt: 'Comércio', en: 'Commerce', match: ['pagamento', 'payment', 'comércio', 'commerce', 'commerce_payment'] },
];

const statusPriority: Record<CheckStatus, number> = { CRITICAL: 0, FAIL: 1, WARNING: 2, UNKNOWN: 3, NOT_CHECKED: 4, NOT_APPLICABLE: 5, PASS: 6 };
const buyPriority: Record<CheckStatus, number> = { CRITICAL: 0, FAIL: 1, WARNING: 2, UNKNOWN: 3, NOT_CHECKED: 4, NOT_APPLICABLE: 5, PASS: 6 };

const formatDate = (value: string | undefined, locale: string) => value ? new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : (locale.startsWith('pt') ? 'Não consultada' : 'Not queried');
const getStatus = (item: CheckModel): CheckStatus => item.status ?? 'UNKNOWN';
const normalize = (value: string) => value.toLocaleLowerCase('pt-BR');
const groupFor = (item: CheckModel): GroupId => groups.find((group) => group.match.includes(normalize(item.category)))?.id ?? 'transparency';
const companyTone = (value: string) => /ativa|active/i.test(value) && !/inativa|inactive/i.test(value) ? 'pass' : /baixada|inapta|inactive/i.test(value) ? 'fail' : 'unknown';
const sourceStatusLabel = (status: ScanReport['sources'][number]['status'], copy: Copy, locale: string) => status === 'available' ? (locale.startsWith('pt') ? 'Consultada' : 'Available') : status === 'limited' ? copy.limited : copy.unavailable;
const companyMatchLabel = (match: NonNullable<ScanReport['company']>['match'], locale: string) => ({
  MATCH: locale.startsWith('pt') ? 'Compatível' : 'Match',
  PARTIAL_MATCH: locale.startsWith('pt') ? 'Parcialmente compatível' : 'Partial match',
  MISMATCH: locale.startsWith('pt') ? 'Incompatível' : 'Mismatch',
  UNKNOWN: locale.startsWith('pt') ? 'Desconhecida' : 'Unknown',
})[match];

function StatusMark({ status, copy }: { status: CheckStatus; copy: Copy }) {
  return <span className={`check-status status-${status.toLowerCase().replace('_', '-')}`}><i aria-hidden="true" />{copy.statusLabels[status]}</span>;
}

function EvidenceRail({ report, copy, locale }: { report: ScanReport; copy: Copy; locale: string }) {
  return (
    <ol className="evidence-rail" aria-label={locale.startsWith('pt') ? 'Linha de evidências' : 'Evidence rail'}>
      {groups.map((group) => {
        const statuses = report.checks.filter((item) => groupFor(item) === group.id).map(getStatus);
        const status = statuses.length ? statuses.sort((a, b) => statusPriority[a] - statusPriority[b])[0] : 'NOT_CHECKED';
        const label = locale.startsWith('pt') ? group.pt : group.en;
        return <li key={group.id} className={`rail-${status.toLowerCase().replace('_', '-')}`} aria-label={`${label}: ${copy.statusLabels[status]}`}><i aria-hidden="true" /><span>{label}</span><small>{copy.statusLabels[status]}</small></li>;
      })}
    </ol>
  );
}

function DecisionMetrics({ report, copy, locale }: { report: ScanReport; copy: Copy; locale: string }) {
  return (
    <aside className="decision-metrics" aria-label={copy.trustScore}>
      <div className="metric-score"><strong>{report.score ?? '—'}</strong>{report.score !== null && <span>/100</span>}<small>{report.score === null ? copy.scoreUnavailable : copy.trustScore}</small></div>
      <dl>
        <div><dt>{copy.confidence}</dt><dd>{copy.confidences[report.confidence]}</dd></div>
        <div><dt>{copy.coverage}</dt><dd>{report.coverage}%</dd></div>
        <div className="metric-date"><dt>{copy.lastChecked}</dt><dd>{formatDate(report.scannedAt, locale)}</dd></div>
      </dl>
    </aside>
  );
}

function PriorityReasons({ report, copy }: { report: ScanReport; copy: Copy }) {
  const priority = report.verdict === 'BUY' ? buyPriority : statusPriority;
  const ordered = [...report.checks].sort((a, b) => priority[getStatus(a)] - priority[getStatus(b)]).slice(0, 6);
  return (
    <section className="priority-reasons" aria-labelledby="priority-title">
      <header><p className="section-kicker">{copy.why}</p><h2 id="priority-title">{copy.reasonsTitle}</h2></header>
      <ol>
        {ordered.map((item, index) => <li key={item.id}><span>{String(index + 1).padStart(2, '0')}</span><div><StatusMark status={getStatus(item)} copy={copy} /><h3>{item.title}</h3><p>{item.description}</p></div></li>)}
      </ol>
    </section>
  );
}

function CriticalLead({ report, copy }: { report: ScanReport; copy: Copy }) {
  if (report.verdict !== 'DO_NOT_BUY') return null;
  const critical = report.checks.filter((item) => ['CRITICAL', 'FAIL'].includes(getStatus(item))).slice(0, 2);
  if (!critical.length) return null;
  return (
    <div className="critical-lead" aria-label={copy.attention}>
      {critical.map((item) => <div key={item.id}><StatusMark status={getStatus(item)} copy={copy} /><strong>{item.title}</strong><p>{item.description}</p></div>)}
    </div>
  );
}

function ChecksSection({ report, copy, locale }: { report: ScanReport; copy: Copy; locale: string }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  return (
    <div className="checks-sheet">
      {groups.map((group) => {
        const items = report.checks.filter((item) => groupFor(item) === group.id);
        if (!items.length) return null;
        const label = locale.startsWith('pt') ? group.pt : group.en;
        return (
          <section key={group.id} className="check-group" aria-labelledby={`group-${group.id}`}>
            <h2 id={`group-${group.id}`}>{label}</h2>
            <div className="checks-table">
              <div className="checks-head" aria-hidden="true"><span>{copy.checkColumns.status}</span><span>{copy.checkColumns.check}</span><span>{copy.checkColumns.result}</span><span>{copy.checkColumns.source}</span></div>
              {items.map((item) => {
                const source = report.sources.find((entry) => entry.id === item.sourceId);
                const isOpen = expanded === item.id;
                return (
                  <div className={`check-record status-border-${getStatus(item).toLowerCase().replace('_', '-')}`} key={item.id}>
                    <button type="button" className="check-row" aria-expanded={isOpen} aria-controls={`detail-${item.id}`} onClick={() => setExpanded(isOpen ? null : item.id)}>
                      <span><StatusMark status={getStatus(item)} copy={copy} /></span>
                      <strong>{item.title}</strong>
                      <span>{item.value ?? item.description}</span>
                      <span className="source-signature">{source ? `${source.name} · ${copy.tier} ${String(source.tier)}` : '—'}<ChevronDown /></span>
                    </button>
                    {isOpen && <div id={`detail-${item.id}`} className="check-detail"><p>{item.description}</p>{source && <small>{formatDate(source.collectedAt, locale)} · {sourceStatusLabel(source.status, copy, locale)}</small>}</div>}
                  </div>
                );
              })}
            </div>
          </section>
        );
      })}
    </div>
  );
}

function ScoreBreakdown({ report, copy }: { report: ScanReport; copy: Copy }) {
  return (
    <section className="score-sheet" aria-labelledby="score-title">
      <header><p className="section-kicker">{copy.explainableScore}</p><h2 id="score-title">{copy.scoreComposition}</h2></header>
      <div className="score-table" role="table">
        {report.scoreAreas.map((area) => <div role="row" key={area.id}><span role="cell">{area.label}</span><strong role="cell">{report.score === null || area.max === 0 ? '—' : `${String(area.score)} / ${String(area.max)}`}</strong><small role="cell">{area.coverage}% {copy.coverageSuffix}</small></div>)}
      </div>
    </section>
  );
}

function TechnicalSection({ title, items }: { title: string; items: string[][] }) {
  return <section className="technical-section"><h2>{title}</h2><dl>{items.map(([label, value], index) => <div key={`${label}-${String(index)}`}><dt>{label}</dt><dd>{value || '—'}</dd></div>)}</dl></section>;
}

export function DecisionReport({ report, copy, locale, onBack, onRescan }: { report: ScanReport; copy: Copy; locale: string; onBack: () => void; onRescan: () => void }) {
  const [tab, setTab] = useState<ReportTab>('overview');
  const [copied, setCopied] = useState(false);
  const tabs: { id: ReportTab; label: string }[] = [
    { id: 'overview', label: copy.overview }, { id: 'checks', label: copy.checks }, { id: 'company', label: copy.company }, { id: 'reputation', label: copy.reputation }, { id: 'security', label: copy.security }, { id: 'technical', label: copy.technical }, { id: 'sources', label: copy.sources },
  ];
  const modeLabel = report.mode === 'demo' ? copy.demoBadge : copy.realLabel;
  const summaryText = `${modeLabel} · ${report.domain} · ${copy.verdicts[report.verdict]}${report.score !== null ? ` · ${String(report.score)}/100` : ''}. ${copy.disclaimer}`;
  const handleCopy = async () => { await navigator.clipboard.writeText(summaryText); setCopied(true); window.setTimeout(() => setCopied(false), 1800); };
  const handleShare = async () => {
    const shareMethod: unknown = Reflect.get(navigator, 'share');
    if (typeof shareMethod === 'function') await (shareMethod as (data: ShareData) => Promise<void>).call(navigator, { title: `EDY ScanURL · ${report.domain}`, text: summaryText });
    else await handleCopy();
  };
  const reputationChecks = useMemo(() => report.checks.filter((item) => groupFor(item) === 'reputation'), [report]);
  const securityChecks = useMemo(() => report.checks.filter((item) => groupFor(item) === 'security'), [report]);

  return (
    <main id="main-content" className={`report-page verdict-surface-${report.verdict.toLowerCase()}`}>
      <div className={`mode-banner mode-${report.mode}`}><strong>{modeLabel}</strong><span>{report.mode === 'demo' ? copy.demoBody : `${copy.analyzedAt} ${formatDate(report.scannedAt, locale)}`}</span></div>
      <div className="report-topbar">
        <button className="quiet-button" type="button" onClick={onBack}><ArrowLeft /> {copy.newScan}</button>
        <div className="report-actions"><button type="button" onClick={() => { void handleCopy(); }}>{copied ? <Check /> : <CopyIcon />}<span>{copied ? copy.copied : copy.copyLink}</span></button><button type="button" onClick={() => { void handleShare(); }}><Share2 /><span>{copy.share}</span></button></div>
      </div>

      <section className="decision-sheet" aria-labelledby="result-verdict">
        <div className="decision-verdict">
          <div className="report-identity"><strong>{report.domain}</strong><span>{formatDate(report.scannedAt, locale)}</span></div>
          <p className="verdict-label">{copy.report}</p>
          <h1 id="result-verdict">{copy.verdicts[report.verdict]}</h1>
          <p className="decision-action">{copy.decisionActions[report.verdict]}</p>
          <p className="decision-summary">{report.summary}</p>
          <CriticalLead report={report} copy={copy} />
        </div>
        <DecisionMetrics report={report} copy={copy} locale={locale} />
        <div className="decision-reasons"><PriorityReasons report={report} copy={copy} /></div>
        <div className="decision-recommendation recommendation-line"><span>{copy.recommendation}</span><p>{report.recommendation}</p></div>
        <div className="decision-evidence"><EvidenceRail report={report} copy={copy} locale={locale} /></div>
        <p className="decision-disclaimer"><Info />{copy.disclaimer}</p>
      </section>

      <nav className="report-tabs" aria-label={copy.reportSections}><span className={`sticky-mode-badge sticky-mode-${report.mode}`}>{report.mode === 'demo' ? 'DEMO' : 'REAL'}</span>{tabs.map((item) => <button key={item.id} type="button" className={tab === item.id ? 'active' : ''} aria-current={tab === item.id ? 'page' : undefined} onClick={() => setTab(item.id)}>{item.label}</button>)}</nav>
      <label className={`report-section-picker picker-${report.mode}`}>
        <span>{report.mode === 'demo' ? 'DEMO' : 'REAL'} · {copy.reportSections}</span>
        <select value={tab} onChange={(event) => setTab(event.target.value as ReportTab)}>{tabs.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select>
      </label>

      <div className="report-content">
        {tab === 'overview' && <ScoreBreakdown report={report} copy={copy} />}
        {tab === 'checks' && <ChecksSection report={report} copy={copy} locale={locale} />}
        {tab === 'company' && <section className="company-sheet"><header><p className="section-kicker">{copy.businessIdentityEyebrow}</p><h2>{copy.businessIdentity}</h2></header>{report.company ? <><dl className="detail-list"><div><dt>{copy.fields.legalName}</dt><dd>{report.company.legalName}</dd></div><div><dt>{copy.fields.tradeName}</dt><dd>{report.company.tradeName}</dd></div><div><dt>{copy.fields.registration}</dt><dd>{report.company.registration}</dd></div><div><dt>{copy.fields.status}</dt><dd><span className={`company-status company-${companyTone(report.company.status)}`}>{report.company.status}</span></dd></div><div><dt>{copy.fields.openedAt}</dt><dd>{report.company.openedAt}</dd></div><div><dt>{copy.fields.activity}</dt><dd>{report.company.activity}</dd></div><div><dt>{copy.fields.location}</dt><dd>{report.company.location}</dd></div></dl><div className="correlation-row"><span>{copy.matchTitle}</span><strong>{companyMatchLabel(report.company.match, locale)}</strong><p>{copy.matchBody}</p></div></> : <div className="empty-state"><h3>{copy.companyMissing}</h3><p>{copy.companyMissingBody}</p></div>}</section>}
        {tab === 'reputation' && <section className="flat-sheet"><header><p className="section-kicker">{copy.consumerReputation}</p><h2>{copy.reputationEvidence}</h2><p>{copy.reputationNote}</p></header>{reputationChecks.length ? <ChecksSection report={{ ...report, checks: reputationChecks }} copy={copy} locale={locale} /> : <p className="empty-copy">{copy.noReputation}</p>}</section>}
        {tab === 'security' && <section className="flat-sheet"><header><p className="section-kicker">{copy.threatReputation}</p><h2>{copy.threatStatus}</h2><p><strong>{report.technical.threatStatus}</strong></p><p className="context-note">{copy.httpsNote}</p></header><ChecksSection report={{ ...report, checks: securityChecks }} copy={copy} locale={locale} /><TechnicalSection title={copy.connectionProtection} items={[["TLS", report.technical.tls], [copy.fields.issuer, report.technical.tlsIssuer], [copy.fields.headers, report.technical.headers.join(' · ') || copy.fields.none]]} /></section>}
        {tab === 'technical' && (
          <section className="technical-sheet">
            <header>
              <p className="section-kicker">{copy.technical}</p>
              <h2>{locale.startsWith('pt') ? 'Evidências técnicas' : 'Technical evidence'}</h2>
            </header>
            <TechnicalSection title={copy.technicalLabels.domainIntelligence} items={[[copy.technicalLabels.observedAge, report.technical.domainAge], [copy.technicalLabels.record, report.technical.registrar]]} />
            <TechnicalSection title="DNS" items={report.technical.dns.map((item) => [copy.technicalLabels.record, item])} />
            <TechnicalSection title="TLS / HTTPS" items={[[copy.technicalLabels.connection, report.technical.tls], [copy.technicalLabels.issuer, report.technical.tlsIssuer], [copy.fields.headers, report.technical.headers.join(' · ') || copy.fields.none]]} />
            <TechnicalSection title={copy.technicalLabels.redirectChain} items={report.technical.redirects.map((item, index) => [`${copy.technicalLabels.step} ${String(index + 1)}`, item])} />
            <TechnicalSection title={copy.technicalLabels.commerceSignals} items={[[copy.technicalLabels.salesVolume, report.technical.salesVolume], ...report.technical.paymentSignals.map((item) => [copy.technicalLabels.payment, item])]} />
          </section>
        )}
        {tab === 'sources' && <section className="sources-sheet"><header><p className="section-kicker">{copy.provenance}</p><h2>{copy.sources}</h2></header><div className="sources-ledger">{report.sources.map((source) => <article key={source.id}><div><h3>{source.name}</h3><p>{source.category} · {copy.tier} {source.tier}</p></div><span className={`provider-state provider-${source.status}`}>{sourceStatusLabel(source.status, copy, locale)}</span><time>{formatDate(source.collectedAt, locale)}</time>{source.url ? <a href={source.url} target="_blank" rel="noreferrer">{copy.viewSource}<ExternalLink /></a> : <span className="source-internal">{copy.directObservation}</span>}</article>)}</div></section>}
      </div>

      <div className="report-footer-actions"><button className="secondary-button" type="button" onClick={onRescan}><RefreshCw /> {copy.rescan}</button><button className="primary-button" type="button" onClick={onBack}>{copy.newScan} <ChevronRight /></button></div>
    </main>
  );
}
