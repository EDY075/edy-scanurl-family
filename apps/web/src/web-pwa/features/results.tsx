import { useEffect, useRef, useState } from "react";
import { ArrowRight, Check, TriangleAlert, OctagonAlert, Copy, Share2, ChevronDown, ExternalLink, Info } from "lucide-react";
import type { ScanReport } from "../../types";
import { formatDate, resultSnapshot, savedRisk, type SavedResult } from "./history";
import { validStoreUrl } from "../utils/url";
import { EvidenceSection } from "./evidence-section";
import { resultEvidence, sourceConsultation, evidenceLabels, type EvidenceItem } from "./evidence";
import { decisionCopy, decisionLabel, humanSignals, purchaseChecklist, riskLevel, analysisCoverage, observedRiskLabels } from "./decision";

export function shareText(item: SavedResult): string {
  const risk = savedRisk(item);
  const copy = decisionCopy[risk];
  const observation = risk === 'UNDETERMINED' ? 'Sem conclusão de risco; confirme os dados que faltam.' : observedRiskLabels[risk];
  return `EDY ScanURL Family\n\nSite:\n${item.domain}\n\nResultado:\n${copy.title}\n${decisionLabel(risk, item.analysisCoverage ?? 'PARTIAL')}\n\nRisco observado:\n${observation}\n\nCobertura da análise:\n${item.analysisCoverage === 'SUFFICIENT' ? 'Suficiente' : 'Parcial — nem todas as verificações puderam ser concluídas.'}\n\nVerificado em:\n${formatDate(item.time)}\n\nEste resultado é informativo e não representa garantia absoluta sobre a segurança de uma compra.`;
}
export async function shareResult(item: SavedResult): Promise<"shared" | "copied" | "cancelled"> {
  const text = shareText(item);
  if (typeof navigator.share === "function") {
    try { await navigator.share({ title: "EDY ScanURL Family", text }); return "shared"; }
    catch (error) { if (error instanceof DOMException && error.name === "AbortError") return "cancelled"; }
  }
  await navigator.clipboard.writeText(text);
  return "copied";
}
const conclusionStrength = { LOW: "Baixa", MEDIUM: "Moderada", HIGH: "Alta", VERY_HIGH: "Alta" };
function Signals({ title, items, reasonPrefix = false }: { title: string; items: EvidenceItem[]; reasonPrefix?: boolean }) {
  if (!items.length) return null;
  const rows = items.map(item => {
      const Icon = item.state === 'FAIL' ? OctagonAlert : item.state === 'WARNING' ? TriangleAlert : item.state === 'PASS' ? Check : Info;
      return <li key={item.id} data-human-id={item.id} className={`state-${item.state.toLowerCase()}`}>
        <Icon size={18} aria-hidden="true" /><div><strong>{item.title}</strong>
        <small>{evidenceLabels[item.state]}</small><p>{reasonPrefix && <strong>Motivo: </strong>}{item.explanation}</p></div>
      </li>;
    });
  const compact = title === 'O que passou' && rows.length > 4;
  return <section className="human-signals" aria-label={title}>
    <h3>{title}</h3><ul>{compact ? rows.slice(0,4) : rows}</ul>
    {compact && <details className="more-signals"><summary>Ver mais {rows.length-4} sinais confirmados <ChevronDown size={16} /></summary><ul>{rows.slice(4)}</ul></details>}
  </section>;
}
export function Results({ report, saved, reset }: { report: ScanReport | null; saved: SavedResult | null; reset: () => void }) {
  const heading = useRef<HTMLHeadingElement>(null);
  const [notice, setNotice] = useState("");
  useEffect(() => { heading.current?.focus(); }, [report, saved]);
  const item = report ? resultSnapshot(report) : saved;
  if (!item) return null;
  const risk = report ? riskLevel(report) : savedRisk(item);
  const copy = decisionCopy[risk];
  const coverage = report ? analysisCoverage(report) : item.analysisCoverage ?? 'PARTIAL';
  const signals = report ? humanSignals(report) : null;
  const Icon = risk === 'LOW' ? Check : risk === 'UNDETERMINED' ? Info : risk === 'MODERATE' ? TriangleAlert : OctagonAlert;
  const evidence = report ? resultEvidence(report) : [];
  const threat = evidence.find(entry => entry.id === 'fraud_intelligence');
  const company = evidence.find(entry => entry.id === 'company_identity');
  const detailList = (values: string[] | undefined) => Array.isArray(values) && values.length ? values.join(' · ') : 'Não disponível';
  return <section className={`results ${copy.tone}`} aria-labelledby="result-title">
    <div className="decision-card">
      <p className="eyebrow">{saved ? 'RESUMO DO HISTÓRICO' : 'SUA VERIFICAÇÃO'}</p>
      <h1 id="result-title" ref={heading} tabIndex={-1} aria-live="polite">{copy.title}</h1>
      <p className="risk-label"><Icon size={20} aria-hidden="true" />{decisionLabel(risk, coverage)}</p>
      <h2 className="result-domain">{item.domain}</h2>
      <p className="result-summary">{saved ? 'Resumo da análise anterior. Consulte a recomendação abaixo e faça uma nova verificação para obter informações atuais.' : copy.summary}</p>
      {coverage === 'PARTIAL' && <p className="uncertainty-note">Nem todas as verificações puderam ser concluídas. Falta de informação não é prova de fraude nem garantia de segurança.</p>}
      <dl className="risk-coverage" aria-label="Risco e cobertura da análise">
        <div><dt>Risco observado</dt><dd>{saved && risk === 'UNDETERMINED' ? 'Sem conclusão no resumo salvo' : observedRiskLabels[risk]}</dd></div>
        <div><dt>Cobertura da análise</dt><dd>{coverage === 'PARTIAL' ? 'Parcial' : 'Suficiente'}</dd></div>
      </dl>
      {signals && <ul className="signal-counts" aria-label="Resumo das evidências">
        {signals.positive.length > 0 && <li><strong>{signals.positive.length}</strong> {signals.positive.length === 1 ? 'sinal positivo' : 'sinais positivos'}</li>}
        {signals.attention.length > 0 && <li className="attention-count"><strong>{signals.attention.length}</strong> {signals.attention.length === 1 ? 'ponto de atenção real' : 'pontos de atenção reais'}</li>}
        {signals.risks.length > 0 && <li className="risk-count"><strong>{signals.risks.length}</strong> {signals.risks.length === 1 ? 'risco encontrado' : 'riscos encontrados'}</li>}
        {signals.missing.length > 0 && <li className="missing-count"><strong>{signals.missing.length}</strong> {signals.missing.length === 1 ? 'verificação sem dados suficientes' : 'verificações sem dados suficientes'}</li>}
      </ul>}
      <time dateTime={item.time}>Verificado em {formatDate(item.time)}</time>
    </div>
    {saved && <p className="saved-notice">Este é um resumo salvo, não uma consulta atual. As informações podem ter mudado. Os detalhes completos não são guardados no histórico.</p>}
    <section className="recommendation"><h2>Nossa recomendação</h2><p>{copy.recommendation}</p>
      {risk === 'MODERATE' && <p>Confira a identificação da empresa, a reputação da loja e as condições de pagamento antes de continuar.</p>}
    </section>
    <button className="primary-button another-scan" onClick={reset}>Verificar outro site <ArrowRight size={20} /></button>
    {signals && <section className="quick-summary" aria-labelledby="quick-summary-title">
      <h2 id="quick-summary-title">Resumo rápido</h2><p>Veja os principais sinais encontrados antes de decidir se deseja continuar com a compra.</p>
      <Signals title="Riscos encontrados" items={signals.risks} />
      <div className="human-columns">
        {signals.positive.length ? <Signals title="O que passou" items={signals.positive} /> : <section className="human-signals"><h3>O que passou</h3><p>Nenhum sinal positivo pôde ser confirmado nesta análise.</p></section>}
        <Signals title="Pontos de atenção reais" items={signals.attention} />
      </div>
      {signals.missing.length > 0 && <details className="report-details missing-checks"><summary>Ver quais ficaram sem dados ({signals.missing.length}) <ChevronDown size={18} aria-hidden="true" /></summary>
        <p>Veja o motivo de cada item. Esses limites não são alertas contra a loja.</p><Signals title="O que não foi possível confirmar" items={signals.missing} reasonPrefix />
      </details>}
    </section>}
    <details className="report-details purchase-checklist"><summary>Antes de finalizar a compra <ChevronDown size={18} /></summary><ul>{purchaseChecklist.map(tip => <li key={tip}>{tip}</li>)}</ul></details>
    <p className="result-disclaimer">Esta análise usa sinais técnicos e informações públicas disponíveis no momento da consulta.</p>
    <div className="result-tools">
      <button className="text-button" onClick={() => { void navigator.clipboard.writeText(shareText(item)).then(() => { setNotice("Resumo copiado."); }).catch(() => { setNotice("Não foi possível copiar. Seu navegador pode bloquear a área de transferência."); }); }}><Copy size={17} />Copiar resumo</button>
      <button className="text-button" onClick={() => { void shareResult(item).then(outcome => { setNotice(outcome === 'copied' ? 'Resumo copiado para compartilhar.' : outcome === 'shared' ? 'Resumo compartilhado.' : ''); }).catch(() => { setNotice('Não foi possível compartilhar neste navegador.'); }); }}><Share2 size={17} />Compartilhar</button>
    </div><p className="fineprint" role="status">{notice}</p>
    {report && <details className="report-details technical-details"><summary>Ver detalhes técnicos <ChevronDown size={18} /></summary>
      <h2>Detalhes técnicos da análise</h2><p>Informações adicionais para quem deseja entender como a verificação foi realizada.</p>
      <dl className="technical-list">
        <div><dt>Força da conclusão</dt><dd>{conclusionStrength[item.confidence]}</dd>
          {item.confidence === 'LOW' && <dd className="technical-list-note">Ainda faltam verificações importantes para uma conclusão mais forte.</dd>}
        </div>
        <div><dt>Verificações com informação</dt><dd>{item.coverage}%</dd></div>
        {report.technical.decisionCoverage !== undefined && <div><dt>Cobertura ponderada da decisão</dt><dd>{report.technical.decisionCoverage}%</dd>
          <dd className="technical-list-note">Considera a importância das verificações disponíveis para a decisão final.</dd>
        </div>}
        <div><dt>Pontuação dos sinais</dt><dd>{item.score === null ? 'Não publicada: cobertura insuficiente' : `${String(item.score)}/100`}</dd></div>
      </dl>
      <p className="coverage-meaning-note">Esses percentuais medem apenas a disponibilidade das verificações. Não representam porcentagem de segurança, chance de fraude nem confiabilidade da empresa.</p>
      <section><h3>Identidade da empresa</h3>
        <p>{company?.title ?? 'Identificação não verificada'}</p>
        <dl className="technical-list"><div><dt>Situação cadastral</dt><dd>Não consultada</dd></div><div><dt>Relação com o site</dt><dd>Não determinada</dd></div></dl>
        <p>Um número com dígitos válidos não confirma empresa ativa nem vínculo com a loja.</p>
      </section>
      <section><h3>Reputação pública</h3><p>{evidence.find(entry => entry.id === 'public_reputation')?.label ?? 'Não avaliada'}</p><p>{evidence.find(entry => entry.id === 'public_reputation')?.explanation ?? 'Esta análise não consultou uma fonte apropriada de reputação pública.'}</p></section>
      <section><h3>Sinais de fraude e ameaças</h3><p>{threat?.state === 'FAIL' || threat?.state === 'WARNING' ? 'Indicadores de risco encontrados' : threat?.label === 'Sem alertas nas consultas recentes' ? 'Nenhuma ameaça conhecida encontrada' : 'Verificação inconclusiva'}</p><p>{threat?.explanation ?? 'Não tivemos informações suficientes para concluir esta etapa.'}</p></section>
      <EvidenceSection report={report} />
      <section><h3>Dados do domínio</h3><dl className="technical-list">
        <div><dt>Idade informada pela fonte</dt><dd>{report.technical.domainAge || 'Não confirmada'}</dd></div>
        <div><dt>Registro</dt><dd>{report.technical.registrar || 'Não confirmado'}</dd></div>
        <div><dt>Conexão</dt><dd>{report.technical.tls || 'Não confirmada'}</dd></div>
        <div><dt>Servidores do domínio</dt><dd>{detailList(report.technical.nameservers)}</dd></div>
        <div><dt>DNS</dt><dd>{detailList(report.technical.dns)}</dd></div>
        <div><dt>Endereço final</dt><dd>{report.technical.finalHostname ?? 'Não informado'}</dd></div>
        <div><dt>Redirecionamentos</dt><dd>{detailList(report.technical.redirects)}</dd></div>
        <div><dt>Cabeçalhos do servidor</dt><dd>{detailList(report.technical.headers)}</dd></div>
      </dl></section>
      <section><h3>Fontes e disponibilidade</h3><ul className="sources-list">{report.sources.map(source => {
        const href = source.url && validStoreUrl(source.url) ? source.url : undefined;
        return <li key={source.id}><div><strong>{source.name}</strong><span>{sourceConsultation(report, source)}</span></div>{href && <a href={href} target="_blank" rel="noopener noreferrer" aria-label={`Abrir ${source.name}`}><ExternalLink size={17} /></a>}</li>;
      })}</ul></section>
    </details>}
  </section>;
}
