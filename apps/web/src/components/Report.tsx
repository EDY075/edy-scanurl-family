import { useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import { ArrowLeft, Building2, Check, ChevronRight, Clipboard, Clock3, Copy as CopyIcon, ExternalLink, FileSearch, Globe2, Info, Link2, MapPin, RefreshCw, Share2, ShieldCheck, TriangleAlert } from 'lucide-react';
import type { Copy } from '../lib/i18n';
import type { Check as CheckModel, ScanReport } from '../types';
import { VerdictIcon } from './VerdictIcon';

type ReportTab = 'overview' | 'company' | 'reputation' | 'security' | 'technical' | 'sources';

const formatDate = (value: string | undefined, locale: string) => value ? new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : (locale.startsWith('pt') ? 'Não consultada' : 'Not queried');

function CheckCard({ item, report }: { item: CheckModel; report: ScanReport }) {
  const source = report.sources.find((entry) => entry.id === item.sourceId);
  return (
    <article className={`check-card impact-${item.impact}`}>
      <span className="check-icon">{item.impact === 'positive' ? <Check /> : item.impact === 'neutral' ? <Info /> : <TriangleAlert />}</span>
      <div><p className="check-category">{item.category}</p><h3>{item.title}</h3><p>{item.description}</p>{source && <small>{source.name}</small>}</div>
      {item.points !== 0 && <strong className="point-pill">{item.points > 0 ? '+' : ''}{item.points}</strong>}
    </article>
  );
}

function ScoreVisual({ report }: { report: ScanReport }) {
  const value = report.score ?? 0;
  return (
    <div className={`score-ring verdict-${report.verdict.toLowerCase()}`} style={{ '--score': value } as CSSProperties}>
      <div><span>{report.score ?? '—'}</span>{report.score !== null && <small>/100</small>}</div>
    </div>
  );
}

export function Report({ report, copy, locale, onBack, onRescan }: { report: ScanReport; copy: Copy; locale: string; onBack: () => void; onRescan: () => void }) {
  const [tab, setTab] = useState<ReportTab>('overview');
  const [copied, setCopied] = useState(false);
  const positives = useMemo(() => report.checks.filter((item) => item.impact === 'positive'), [report]);
  const warnings = useMemo(() => report.checks.filter((item) => ['warning', 'negative', 'critical'].includes(item.impact)), [report]);
  const tabs: { id: ReportTab; label: string }[] = [
    { id: 'overview', label: copy.overview }, { id: 'company', label: copy.company }, { id: 'reputation', label: copy.reputation }, { id: 'security', label: copy.security }, { id: 'technical', label: copy.technical }, { id: 'sources', label: copy.sources },
  ];
  const summaryText = `${report.domain} · ${copy.verdicts[report.verdict]}${report.score !== null ? ` · ${String(report.score)}/100` : ''}. ${copy.disclaimer}`;
  const handleCopy = async () => { await navigator.clipboard.writeText(summaryText); setCopied(true); window.setTimeout(() => setCopied(false), 1800); };
  const handleShare = async () => {
    const shareMethod: unknown = Reflect.get(navigator, 'share');
    if (typeof shareMethod === 'function') await (shareMethod as (data: ShareData) => Promise<void>).call(navigator, { title: `EDY ScanURL · ${report.domain}`, text: summaryText });
    else await handleCopy();
  };

  return (
    <main id="main-content" className={`report-page verdict-surface-${report.verdict.toLowerCase()}`}>
      {report.mode === 'demo' && <div className="demo-ribbon"><span>{copy.demoBadge}</span><small>{copy.demoBody}</small></div>}
      <div className="report-topbar">
        <button className="quiet-button" type="button" onClick={onBack}><ArrowLeft /> {copy.newScan}</button>
        <div className="report-actions"><button type="button" onClick={() => { void handleCopy(); }}>{copied ? <Check /> : <CopyIcon />}<span>{copied ? copy.copied : copy.copyLink}</span></button><button type="button" onClick={() => { void handleShare(); }}><Share2 /><span>{copy.share}</span></button></div>
      </div>

      <section className="verdict-hero" aria-labelledby="result-verdict">
        <div className="domain-line"><Globe2 /> <span>{report.domain}</span><small><Clock3 /> {formatDate(report.scannedAt, locale)}</small></div>
        <div className="verdict-grid">
          <ScoreVisual report={report} />
          <div className="verdict-copy">
            <p className="eyebrow">{report.score === null ? copy.coverage : copy.trustScore}</p>
            <h1 id="result-verdict"><span className="verdict-symbol"><VerdictIcon verdict={report.verdict} /></span>{copy.verdicts[report.verdict]}</h1>
            <p>{report.summary}</p>
            <div className="confidence-row"><span><strong>{copy.confidence}</strong>{copy.confidences[report.confidence]}</span><span><strong>{copy.coverage}</strong>{report.coverage}%</span></div>
          </div>
        </div>
        <div className="report-disclaimer"><Info /><p>{copy.disclaimer}</p></div>
      </section>

      <nav className="report-tabs" aria-label={copy.reportSections}>
        {tabs.map((item) => <button key={item.id} type="button" className={tab === item.id ? 'active' : ''} aria-current={tab === item.id ? 'page' : undefined} onClick={() => setTab(item.id)}>{item.label}</button>)}
      </nav>

      {tab === 'overview' && (
        <div className="report-content overview-grid">
          <section className="content-card recommendation-card"><span><ShieldCheck /></span><div><p className="eyebrow">{copy.recommendation}</p><h2>{report.recommendation}</h2></div></section>
          <section className="content-card"><div className="card-heading"><div><p className="eyebrow">{copy.why}</p><h2>{copy.reasonsTitle}</h2></div><FileSearch /></div><div className="checks-list">{report.checks.slice(0, 6).map((item) => <CheckCard key={item.id} item={item} report={report} />)}</div></section>
          <section className="content-card"><div className="card-heading"><div><p className="eyebrow">{copy.explainableScore}</p><h2>{copy.scoreComposition}</h2></div><span className="coverage-pill">{report.coverage}% {copy.coverage.toLowerCase()}</span></div><div className="score-breakdown">{report.scoreAreas.map((area) => <div key={area.id}><p><span>{area.label}</span><strong>{report.score === null || area.max === 0 ? '—' : `${String(area.score)}/${String(area.max)}`}</strong></p><div className="meter"><i style={{ width: `${String(report.score !== null && area.max > 0 ? (area.score / area.max) * 100 : area.max > 0 ? area.coverage : 0)}%` }} /></div><small>{area.coverage}% {copy.coverageSuffix}</small></div>)}</div></section>
        </div>
      )}

      {tab === 'company' && (
        <div className="report-content two-column">
          <section className="content-card"><div className="card-heading"><div><p className="eyebrow">{copy.businessIdentityEyebrow}</p><h2>{copy.businessIdentity}</h2></div><Building2 /></div>{report.company ? <dl className="detail-list"><div><dt>{copy.fields.legalName}</dt><dd>{report.company.legalName}</dd></div><div><dt>{copy.fields.tradeName}</dt><dd>{report.company.tradeName}</dd></div><div><dt>{copy.fields.registration}</dt><dd>{report.company.registration}</dd></div><div><dt>{copy.fields.status}</dt><dd><span className="status-chip">{report.company.status}</span></dd></div><div><dt>{copy.fields.openedAt}</dt><dd>{report.company.openedAt}</dd></div><div><dt>{copy.fields.activity}</dt><dd>{report.company.activity}</dd></div><div><dt>{copy.fields.location}</dt><dd><MapPin />{report.company.location}</dd></div></dl> : <div className="empty-state"><CircleHelpIcon /><h3>{copy.companyMissing}</h3><p>{copy.companyMissingBody}</p></div>}</section>
          <section className="content-card identity-match"><p className="eyebrow">{copy.evidenceCorrelation}</p><h2>{copy.matchTitle}</h2><div className={`match-seal match-${report.company?.match.toLowerCase().replace('_', '-') ?? 'unknown'}`}><Link2 /><strong>{report.company?.match.replace('_', ' ') ?? 'UNKNOWN'}</strong></div><p>{copy.matchBody}</p></section>
        </div>
      )}

      {tab === 'reputation' && <div className="report-content"><section className="content-card"><div className="card-heading"><div><p className="eyebrow">{copy.consumerReputation}</p><h2>{copy.reputationEvidence}</h2></div><Globe2 /></div><div className="checks-list">{[...positives, ...warnings].filter((item) => ['Reputação', 'CONSUMER_REPUTATION'].includes(item.category)).map((item) => <CheckCard key={item.id} item={item} report={report} />)}{!report.checks.some((item) => ['Reputação', 'CONSUMER_REPUTATION'].includes(item.category)) && <p className="empty-copy">{copy.noReputation}</p>}</div><div className="data-caution"><Info /><p>{copy.reputationNote}</p></div></section></div>}

      {tab === 'security' && <div className="report-content two-column"><section className="content-card"><p className="eyebrow">{copy.threatReputation}</p><h2>{copy.threatStatus}</h2><div className="technical-highlight"><ShieldCheck /><div><strong>{report.technical.threatStatus}</strong><p>{copy.observedSources}</p></div></div>{report.checks.filter((item) => ['Segurança', 'Ameaça', 'TECHNICAL_SECURITY', 'THREAT_IMPERSONATION'].includes(item.category)).map((item) => <CheckCard key={item.id} item={item} report={report} />)}</section><section className="content-card"><p className="eyebrow">{copy.webSecurity}</p><h2>{copy.connectionProtection}</h2><dl className="detail-list"><div><dt>TLS</dt><dd>{report.technical.tls}</dd></div><div><dt>{copy.fields.issuer}</dt><dd>{report.technical.tlsIssuer}</dd></div><div><dt>{copy.fields.headers}</dt><dd>{report.technical.headers.join(' · ') || copy.fields.none}</dd></div></dl><div className="data-caution"><Info /><p>{copy.httpsNote}</p></div></section></div>}

      {tab === 'technical' && <div className="report-content technical-grid"><TechnicalCard title={copy.technicalLabels.domainIntelligence} icon={<Globe2 />} items={[[copy.technicalLabels.observedAge, report.technical.domainAge], [copy.technicalLabels.record, report.technical.registrar]]} /><TechnicalCard title="DNS" icon={<Link2 />} items={report.technical.dns.map((item) => [copy.technicalLabels.record, item])} /><TechnicalCard title="TLS" icon={<ShieldCheck />} items={[[copy.technicalLabels.connection, report.technical.tls], [copy.technicalLabels.issuer, report.technical.tlsIssuer]]} /><TechnicalCard title={copy.technicalLabels.redirectChain} icon={<RefreshCw />} items={report.technical.redirects.map((item, index) => [`${copy.technicalLabels.step} ${String(index + 1)}`, item])} /><TechnicalCard title={copy.technicalLabels.commerceSignals} icon={<Clipboard />} items={[[copy.technicalLabels.salesVolume, report.technical.salesVolume], ...report.technical.paymentSignals.map((item) => [copy.technicalLabels.payment, item])]} /></div>}

      {tab === 'sources' && <div className="report-content"><section className="content-card"><div className="card-heading"><div><p className="eyebrow">{copy.provenance}</p><h2>{copy.sources}</h2></div><span className="coverage-pill">{String(report.sources.length)} {copy.sources.toLowerCase()}</span></div><div className="source-list">{report.sources.map((source) => <article key={source.id}><span className={`source-status ${source.status}`} role="img" aria-label={source.status} /><div><h3>{source.name}</h3><p>{source.category} · {copy.tier} {source.tier}</p><small>{copy.collected}: {formatDate(source.collectedAt, locale)}</small></div>{source.url ? <a href={source.url} target="_blank" rel="noreferrer">{copy.viewSource}<ExternalLink /></a> : <span className="source-internal">{copy.directObservation}</span>}</article>)}</div></section></div>}

      <div className="report-footer-actions"><button className="secondary-button" type="button" onClick={onRescan}><RefreshCw /> {copy.rescan}</button><button className="primary-button" type="button" onClick={onBack}>{copy.newScan} <ChevronRight /></button></div>
    </main>
  );
}

function CircleHelpIcon() { return <span className="empty-icon"><Info /></span>; }

function TechnicalCard({ title, icon, items }: { title: string; icon: ReactNode; items: string[][] }) {
  return <section className="content-card technical-card"><div className="card-heading"><h2>{title}</h2>{icon}</div><dl>{items.map(([label, value], index) => <div key={`${label}-${String(index)}`}><dt>{label}</dt><dd>{value}</dd></div>)}</dl></section>;
}
