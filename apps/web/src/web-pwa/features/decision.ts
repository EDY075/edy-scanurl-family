import type { ScanReport } from '../../types';
import { resultEvidence, type EvidenceItem } from './evidence';

// UNDETERMINED is a web-only absence of a risk conclusion, not a fifth backend verdict.
export type RiskLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' | 'UNDETERMINED';
export type AnalysisCoverage = 'PARTIAL' | 'SUFFICIENT';
export const decisionCopy = {
  LOW: { label: 'RISCO BAIXO', title: 'Pode comprar com cautela', tone: 'good', summary: 'Não encontramos sinais graves nas verificações realizadas. Mesmo assim, confirme os dados da loja e use uma forma de pagamento que ofereça proteção ao comprador.', recommendation: 'Os sinais analisados são favoráveis, mas nenhuma verificação online garante uma compra sem riscos.' },
  MODERATE: { label: 'RISCO MODERADO', title: 'Vale confirmar mais antes de pagar', tone: 'caution', summary: 'Encontramos pontos de atenção nas verificações realizadas. Confira os motivos antes de decidir sobre a compra.', recommendation: 'Esclareça os pontos de atenção antes de pagar e prefira uma forma de pagamento com proteção ao comprador.' },
  HIGH: { label: 'RISCO ALTO', title: 'Melhor evitar agora', tone: 'risk', summary: 'Encontramos sinais que reduzem a confiança nesta compra. Recomendamos não realizar o pagamento antes de verificar melhor a loja.', recommendation: 'Recomendamos não realizar o pagamento enquanto os sinais encontrados não forem esclarecidos.' },
  CRITICAL: { label: 'RISCO CRÍTICO', title: 'Não recomendamos continuar', tone: 'risk', summary: 'Foram encontrados indicadores importantes de risco nas verificações realizadas.', recommendation: 'Não recomendamos fornecer dados ou realizar pagamentos neste endereço.' },
  UNDETERMINED: { label: 'ANÁLISE PARCIAL', title: 'Vale confirmar alguns dados', tone: 'partial', summary: 'Nenhuma evidência negativa relevante foi encontrada nas verificações concluídas.', recommendation: 'Confirme os dados que faltam por outros canais antes de pagar. Prefira uma forma de pagamento com proteção ao comprador.' },
} as const;

/** Presentation never changes backend weights or reconstructs a hard blocker. */
export function riskLevel(report: ScanReport): RiskLevel {
  const items = resultEvidence(report);
  const negative = items.some(item => item.state === 'FAIL');
  if (report.verdict === 'DO_NOT_BUY' && report.technical.confirmedCriticalThreat === true && negative) return 'CRITICAL';
  if (report.verdict === 'DO_NOT_BUY' || negative) return 'HIGH';
  if (items.some(item => item.state === 'WARNING')) return 'MODERATE';
  if (report.verdict === 'BUY' && report.score !== null && report.score >= 80 && (report.technical.decisionCoverage ?? report.coverage) >= 80 && ['HIGH', 'VERY_HIGH'].includes(report.confidence) && !items.some(item => item.state === 'WARNING') && items.some(item => item.state === 'PASS' && report.sources.some(source => source.id === item.sourceId && source.status === 'available'))) return 'LOW';
  return 'UNDETERMINED';
}

/** Coverage is independent of whether concrete warnings or failures were found. */
export function analysisCoverage(report: ScanReport): AnalysisCoverage {
  return report.verdict === 'INSUFFICIENT_DATA' || (report.technical.decisionCoverage ?? report.coverage) < 80 ||
    humanSignals(report).missing.length > 0 ? 'PARTIAL' : 'SUFFICIENT';
}
export function decisionLabel(risk: RiskLevel, coverage: AnalysisCoverage): string {
  return risk === 'UNDETERMINED' && coverage === 'SUFFICIENT' ? 'ANÁLISE INCONCLUSIVA' : decisionCopy[risk].label;
}
export const observedRiskLabels: Record<RiskLevel, string> = {
  LOW: 'Baixo nos sinais avaliados', MODERATE: 'Pontos de atenção encontrados', HIGH: 'Alto', CRITICAL: 'Crítico',
  UNDETERMINED: 'Nenhum indício negativo encontrado',
};

const humanTitles: Record<string, string> = {
  domain_registration: 'Registro do domínio consultado', domain_history: 'Tempo de existência do endereço',
  dns_resolution: 'Domínio respondeu corretamente', nameservers: 'Servidores do domínio encontrados',
  https: 'Conexão protegida por HTTPS', redirect_destination: 'Endereço final do site verificado',
  policy_contact: 'Informações de contato encontradas', policy_privacy: 'Política de privacidade encontrada',
  policy_returns: 'Política de troca encontrada', policy_shipping: 'Informações de entrega encontradas',
};
export function humanSignals(report: ScanReport) {
  const evidence = resultEvidence(report);
  const positive: EvidenceItem[] = [], attention: EvidenceItem[] = [], risks: EvidenceItem[] = [], missing: EvidenceItem[] = [];
  for (const original of evidence) {
    const item = { ...original };
    if (item.state === 'PASS' && !report.sources.some(source => source.id === item.sourceId && source.status !== 'unavailable')) {
      item.state = 'UNAVAILABLE'; item.explanation = 'A fonte desta confirmação não está disponível. Confirme por outro canal.';
    }
    if (item.id === 'site_policies' && evidence.some(entry => entry.id.startsWith('policy_')) && !['FAIL', 'WARNING'].includes(item.state)) continue;
    if (item.state === 'FAIL') { risks.push(item); continue; }
    if (item.state === 'WARNING') { attention.push(item); continue; }
    const observedCnpj = item.id === 'company_identity' && item.details.some(detail => detail.includes('verificadores: válidos'));
    const freshClean = item.id === 'fraud_intelligence' && item.label === 'Sem alertas nas consultas recentes';
    if (item.state === 'PASS' || (item.state === 'INFO' && (observedCnpj || freshClean))) {
      item.title = freshClean ? 'Nenhuma ameaça conhecida encontrada nas consultas recentes' : humanTitles[item.id] ?? item.title;
      positive.push(item);
    } else {
      if (item.id === 'company_identity' && item.state === 'INFO') {
        item.title = 'Não localizamos um CNPJ nas páginas analisadas.';
        item.explanation = 'Isso não significa necessariamente que a empresa não possua CNPJ. Vale confirmar essa informação antes de realizar o pagamento.';
      }
      if (item.id === 'company_registration' && item.state === 'NOT_CHECKED') {
        item.title = 'A situação cadastral do CNPJ não foi consultada.';
        item.explanation = 'Encontrar um número válido no site não confirma, por si só, que a empresa esteja ativa.';
      }
      if (item.id === 'public_reputation' && item.state === 'NOT_CHECKED') {
        item.title = 'Não conseguimos avaliar a reputação pública desta loja.';
        item.explanation = 'Essa ausência não foi tratada como má reputação.';
      }
      if (item.state === 'UNAVAILABLE') item.explanation = 'Uma das fontes de verificação não respondeu. Essa ausência não foi considerada como evidência negativa.';
      missing.push(item);
    }
  }
  const priority = ['fraud_intelligence','company_identity','https','policy_contact','policy_privacy','domain_history','domain_registration','redirect_destination','dns_resolution'];
  positive.sort((a,b) => (priority.includes(a.id) ? priority.indexOf(a.id) : 99) - (priority.includes(b.id) ? priority.indexOf(b.id) : 99));
  return { positive, attention, risks, missing };
}

export const purchaseChecklist = [
  'Prefira cartão ou serviço com proteção ao comprador.', 'Tenha cuidado com PIX para pessoas desconhecidas.',
  'Compare o preço com outras lojas.', 'Confira CNPJ, contato e políticas da empresa.',
  'Pesquise a reputação da loja fora do próprio site.', 'Desconfie de pressão para pagar rapidamente.',
  'Confira se o endereço realmente corresponde à empresa procurada.',
];
