import type { Check, CheckStatus, DemoScenarioId, ScanReport, Verdict } from '../types';

const collectedAt = '2026-08-30T13:42:00.000Z';

const commonSources = [
  { id: 'receita', name: 'Receita Federal · CNPJ', tier: 1 as const, category: 'Identidade empresarial', collectedAt, url: 'https://dados.gov.br/dados/conjuntos-dados/cadastro-nacional-da-pessoa-juridica---cnpj', status: 'available' as const },
  { id: 'registro', name: 'Registro.br · RDAP', tier: 1 as const, category: 'Domínio', collectedAt, url: 'https://rdap.registro.br/', status: 'available' as const },
  { id: 'webrisk', name: 'Google Web Risk', tier: 2 as const, category: 'Ameaças', collectedAt, url: 'https://cloud.google.com/web-risk', status: 'available' as const },
  { id: 'tls', name: 'Observação técnica EDY', tier: 2 as const, category: 'TLS e cabeçalhos', collectedAt, status: 'available' as const },
  { id: 'consumer', name: 'Consumidor.gov.br', tier: 3 as const, category: 'Reputação', collectedAt, url: 'https://www.consumidor.gov.br/pages/dadosabertos/externo/', status: 'available' as const },
];

const profiles: Record<Verdict, Omit<ScanReport, 'id' | 'mode' | 'inputUrl' | 'normalizedUrl' | 'domain' | 'scannedAt'>> = {
  BUY: {
    verdict: 'BUY', score: 89, confidence: 'VERY_HIGH', coverage: 94,
    summary: 'As evidências disponíveis indicam baixo risco observado para compra.',
    recommendation: 'Para compras de maior valor, mantenha a proteção habitual: prefira cartão de crédito ou um método com possibilidade de contestação.',
    company: { legalName: 'Aurora Comércio Digital Ltda.', tradeName: 'Aurora Casa', registration: '12.345.678/0001-90', status: 'Ativa', openedAt: '18/04/2017', activity: 'Comércio varejista online', location: 'Curitiba · PR', match: 'MATCH' },
    checks: [
      { id: 'c1', category: 'Empresa', title: 'Empresa identificada e ativa', description: 'Nome, CNPJ e endereço exibidos no site são compatíveis com o cadastro público.', impact: 'positive', points: 24, sourceId: 'receita' },
      { id: 'c2', category: 'Domínio', title: 'Domínio com histórico consistente', description: 'O domínio possui mais de sete anos e dados técnicos estáveis.', impact: 'positive', points: 14, sourceId: 'registro' },
      { id: 'c3', category: 'Segurança', title: 'Nenhuma ameaça conhecida detectada', description: 'A URL não apresentou correspondência nas fontes técnicas consultadas.', impact: 'positive', points: 15, sourceId: 'webrisk' },
      { id: 'c4', category: 'Reputação', title: 'Boa resolução de reclamações', description: 'O histórico público disponível mostra respostas e resolução consistentes.', impact: 'positive', points: 17, sourceId: 'consumer' },
      { id: 'c5', category: 'Transparência', title: 'Políticas essenciais localizadas', description: 'Trocas, devoluções, privacidade, contato e prazos estão acessíveis.', impact: 'positive', points: 9, sourceId: 'tls' },
      { id: 'c6', category: 'Reputação', title: 'Reclamações recentes sobre atraso', description: 'Há relatos recentes de entrega fora do prazo, sem padrão crítico.', impact: 'warning', points: -3, sourceId: 'consumer' },
    ],
    scoreAreas: [
      { id: 'business', label: 'Identidade empresarial', score: 24, max: 25, coverage: 100 },
      { id: 'domain', label: 'Domínio e histórico', score: 14, max: 15, coverage: 100 },
      { id: 'security', label: 'Segurança técnica', score: 14, max: 15, coverage: 100 },
      { id: 'reputation', label: 'Reputação do consumidor', score: 17, max: 20, coverage: 95 },
      { id: 'transparency', label: 'Transparência da loja', score: 9, max: 10, coverage: 100 },
      { id: 'presence', label: 'Presença pública', score: 4, max: 5, coverage: 80 },
      { id: 'commerce', label: 'Sinais de pagamento', score: 4, max: 5, coverage: 70 },
      { id: 'consistency', label: 'Consistência das evidências', score: 3, max: 5, coverage: 100 },
    ],
    sources: commonSources,
    technical: { domainAge: '7 anos e 4 meses', registrar: 'Registro.br', dns: ['A · 203.0.113.24', 'AAAA · 2001:db8::24', 'MX · mail.example'], tls: 'TLS 1.3 · válido até 12/05/2027', tlsIssuer: 'Example Trust Services', redirects: ['http → https', 'www → domínio principal'], headers: ['HSTS', 'Content-Security-Policy', 'Referrer-Policy'], threatStatus: 'Nenhuma correspondência nas fontes consultadas', salesVolume: 'Não verificável publicamente', paymentSignals: ['Cartão de crédito', 'Pix', 'Boleto', 'Checkout no mesmo domínio'] },
  },
  CAUTION: {
    verdict: 'CAUTION', score: 58, confidence: 'HIGH', coverage: 83,
    summary: 'Há sinais legítimos, mas inconsistências relevantes pedem uma compra mais protegida.',
    recommendation: 'Evite Pix na primeira compra. Confirme o prazo por escrito e prefira cartão virtual com limite ajustado.',
    company: { legalName: 'Oferta Certa Utilidades Ltda.', tradeName: 'Oferta Certa', registration: '23.456.789/0001-01', status: 'Ativa', openedAt: '08/11/2024', activity: 'Comércio varejista', location: 'Goiânia · GO', match: 'PARTIAL_MATCH' },
    checks: [
      { id: 'c1', category: 'Empresa', title: 'CNPJ ativo', description: 'O cadastro existe, mas o telefone da loja não coincide com a fonte oficial.', impact: 'warning', points: 16, sourceId: 'receita' },
      { id: 'c2', category: 'Domínio', title: 'Domínio recente', description: 'O registro tem menos de um ano, reduzindo o histórico disponível.', impact: 'warning', points: 6, sourceId: 'registro' },
      { id: 'c3', category: 'Segurança', title: 'HTTPS válido', description: 'A conexão é criptografada e não houve ameaça técnica conhecida.', impact: 'positive', points: 13, sourceId: 'webrisk' },
      { id: 'c4', category: 'Reputação', title: 'Volume crescente de reclamações', description: 'Relatos recentes citam demora no suporte e atraso de entrega.', impact: 'negative', points: 7, sourceId: 'consumer' },
      { id: 'c5', category: 'Transparência', title: 'Política de devolução incompleta', description: 'O prazo de arrependimento não está apresentado com clareza.', impact: 'warning', points: 5, sourceId: 'tls' },
    ],
    scoreAreas: [
      { id: 'business', label: 'Identidade empresarial', score: 16, max: 25, coverage: 100 }, { id: 'domain', label: 'Domínio e histórico', score: 6, max: 15, coverage: 100 }, { id: 'security', label: 'Segurança técnica', score: 13, max: 15, coverage: 100 }, { id: 'reputation', label: 'Reputação do consumidor', score: 7, max: 20, coverage: 85 }, { id: 'transparency', label: 'Transparência da loja', score: 5, max: 10, coverage: 90 }, { id: 'presence', label: 'Presença pública', score: 3, max: 5, coverage: 70 }, { id: 'commerce', label: 'Sinais de pagamento', score: 4, max: 5, coverage: 50 }, { id: 'consistency', label: 'Consistência das evidências', score: 4, max: 5, coverage: 90 },
    ],
    sources: commonSources,
    technical: { domainAge: '9 meses', registrar: 'Registro.br', dns: ['A · 198.51.100.18', 'MX · mail.example'], tls: 'TLS 1.3 · válido até 03/02/2027', tlsIssuer: 'Example Trust Services', redirects: ['http → https'], headers: ['HSTS', 'Referrer-Policy'], threatStatus: 'Nenhuma correspondência nas fontes consultadas', salesVolume: 'Não verificável publicamente', paymentSignals: ['Cartão de crédito', 'Pix', 'Checkout no mesmo domínio'] },
  },
  DO_NOT_BUY: {
    verdict: 'DO_NOT_BUY', score: 18, confidence: 'VERY_HIGH', coverage: 91,
    summary: 'Uma fonte reconhecida confirmou phishing ativo. O risco elevado prevalece sobre os demais sinais.',
    recommendation: 'Não informe dados, não faça pagamentos e feche o site. Se já pagou, contate imediatamente sua instituição financeira.',
    company: { legalName: 'Mundo Promoções Serviços Ltda.', tradeName: 'Mundo Promoções', registration: '34.567.890/0001-12', status: 'Baixada', openedAt: '11/02/2025', activity: 'Serviços promocionais', location: 'São Paulo · SP', match: 'MISMATCH' },
    checks: [
      { id: 'c1', category: 'Ameaça', title: 'Phishing ativo confirmado', description: 'A URL aparece como ameaça ativa em fonte técnica reconhecida.', impact: 'critical', points: -45, sourceId: 'webrisk' },
      { id: 'c2', category: 'Empresa', title: 'CNPJ incompatível e baixado', description: 'O número exibido pertence a empresa sem atividade e nome diferente.', impact: 'critical', points: -22, sourceId: 'receita' },
      { id: 'c3', category: 'Domínio', title: 'Domínio criado há poucos dias', description: 'O registro recente é incompatível com a alegação de dez anos de mercado.', impact: 'negative', points: -8, sourceId: 'registro' },
      { id: 'c4', category: 'Pagamento', title: 'Pagamento irreversível como única opção', description: 'O checkout oferece apenas Pix e redireciona para outro domínio.', impact: 'negative', points: -7, sourceId: 'tls' },
    ],
    scoreAreas: [
      { id: 'business', label: 'Identidade empresarial', score: 1, max: 25, coverage: 100 }, { id: 'domain', label: 'Domínio e histórico', score: 2, max: 15, coverage: 100 }, { id: 'security', label: 'Segurança técnica', score: 0, max: 15, coverage: 100 }, { id: 'reputation', label: 'Reputação do consumidor', score: 4, max: 20, coverage: 80 }, { id: 'transparency', label: 'Transparência da loja', score: 3, max: 10, coverage: 100 }, { id: 'presence', label: 'Presença pública', score: 2, max: 5, coverage: 70 }, { id: 'commerce', label: 'Sinais de pagamento', score: 1, max: 5, coverage: 80 }, { id: 'consistency', label: 'Consistência das evidências', score: 5, max: 5, coverage: 100 },
    ],
    sources: commonSources,
    technical: { domainAge: '12 dias', registrar: 'Registro.br', dns: ['A · 192.0.2.62'], tls: 'TLS 1.2 · certificado válido', tlsIssuer: 'Example Trust Services', redirects: ['http → https', 'checkout → domínio externo'], headers: ['Referrer-Policy'], threatStatus: 'Phishing ativo confirmado', salesVolume: 'Não verificável publicamente', paymentSignals: ['Somente Pix', 'Recebedor não verificável', 'Checkout em domínio diferente'] },
  },
  INSUFFICIENT_DATA: {
    verdict: 'INSUFFICIENT_DATA', score: null, confidence: 'LOW', coverage: 32,
    summary: 'As fontes disponíveis não cobrem o suficiente para calcular uma nota responsável.',
    recommendation: 'Não decida com base nesta análise. Procure identificação empresarial verificável e um meio de pagamento com proteção.',
    checks: [
      { id: 'c1', category: 'Domínio', title: 'Domínio localizado', description: 'O domínio responde, mas há pouco histórico público disponível.', impact: 'neutral', points: 0, sourceId: 'registro' },
      { id: 'c2', category: 'Empresa', title: 'Empresa não identificada', description: 'Nenhum CNPJ foi encontrado no site para uma correspondência segura.', impact: 'warning', points: 0, sourceId: 'receita' },
      { id: 'c3', category: 'Cobertura', title: 'Fonte de reputação sem dados', description: 'A ausência de registros não significa reputação positiva ou negativa.', impact: 'neutral', points: 0, sourceId: 'consumer' },
    ],
    scoreAreas: [
      { id: 'business', label: 'Identidade empresarial', score: 0, max: 25, coverage: 10 }, { id: 'domain', label: 'Domínio e histórico', score: 0, max: 15, coverage: 65 }, { id: 'security', label: 'Segurança técnica', score: 0, max: 15, coverage: 60 }, { id: 'reputation', label: 'Reputação do consumidor', score: 0, max: 20, coverage: 5 }, { id: 'transparency', label: 'Transparência da loja', score: 0, max: 10, coverage: 45 }, { id: 'presence', label: 'Presença pública', score: 0, max: 5, coverage: 30 }, { id: 'commerce', label: 'Sinais de pagamento', score: 0, max: 5, coverage: 20 }, { id: 'consistency', label: 'Consistência das evidências', score: 0, max: 5, coverage: 20 },
    ],
    sources: commonSources.map((source, index) => index > 1 ? { ...source, status: 'limited' as const } : source),
    technical: { domainAge: 'Não disponível', registrar: 'Registro.br', dns: ['A · 192.0.2.90'], tls: 'TLS válido', tlsIssuer: 'Example Trust Services', redirects: ['http → https'], headers: ['Referrer-Policy'], threatStatus: 'Cobertura parcial', salesVolume: 'Não verificável publicamente', paymentSignals: ['Não verificável'] },
  },
};

export const demoScenarios: { id: DemoScenarioId; verdict: Verdict; domain: string }[] = [
  { id: 'trusted', verdict: 'BUY', domain: 'aurora-casa.example' },
  { id: 'caution', verdict: 'CAUTION', domain: 'oferta-certa.example' },
  { id: 'high-risk', verdict: 'DO_NOT_BUY', domain: 'loja-alerta.example' },
  { id: 'insufficient', verdict: 'INSUFFICIENT_DATA', domain: 'nova-vitrine.example' },
  { id: 'confirmed-phishing', verdict: 'DO_NOT_BUY', domain: 'mundo-promos.example' },
  { id: 'business-mismatch', verdict: 'DO_NOT_BUY', domain: 'marca-clonada.example' },
];

function demoStatus(check: Check, scenarioId?: DemoScenarioId): CheckStatus {
  if (check.impact === 'positive') return 'PASS';
  if (check.impact === 'warning') return 'WARNING';
  if (check.impact === 'negative') return 'FAIL';
  if (check.impact === 'critical') return 'CRITICAL';
  if (scenarioId === 'insufficient' && check.id === 'c3') return 'NOT_CHECKED';
  return 'UNKNOWN';
}

function withDemoStatuses(report: ScanReport): ScanReport {
  return { ...report, checks: report.checks.map((check) => ({ ...check, status: demoStatus(check, report.demoScenarioId) })) };
}

export function createDemoReport(rawUrl: string, scenarioId?: DemoScenarioId): ScanReport {
  const url = new URL(rawUrl);
  const selected = demoScenarios.find((item) => item.domain === url.hostname)
    ?? demoScenarios.find((item) => item.id === scenarioId)
    ?? demoScenarios[0];
  const chosen = selected.verdict;
  const base: ScanReport = {
    id: `demo-${selected.id}-${String(Date.now())}`,
    mode: 'demo', inputUrl: rawUrl, normalizedUrl: rawUrl, domain: url.hostname, scannedAt: new Date().toISOString(),
    demoScenarioId: selected.id,
    ...profiles[chosen],
  };
  if (selected.id === 'high-risk') {
    return withDemoStatuses({
      ...base, score: 34, confidence: 'HIGH', coverage: 87,
      summary: 'Vários sinais fortes indicam risco elevado, mesmo sem confirmação de phishing ou malware.',
      recommendation: 'Evite a compra neste momento. Confirme a empresa por um canal independente e não use pagamento irreversível.',
      company: { legalName: 'Loja Alerta Comércio Ltda.', tradeName: 'Loja Alerta', registration: '45.678.901/0001-23', status: 'Inapta', openedAt: '19/06/2026', activity: 'Comércio varejista', location: 'Rio de Janeiro · RJ', match: 'PARTIAL_MATCH' },
      checks: [
        { id: 'c1', category: 'Empresa', title: 'Cadastro empresarial inapto', description: 'A situação cadastral observada impede confirmar atividade regular.', impact: 'negative', points: -20, sourceId: 'receita' },
        { id: 'c2', category: 'Domínio', title: 'Domínio muito recente', description: 'O domínio tem poucas semanas e não possui histórico suficiente.', impact: 'negative', points: -10, sourceId: 'registro' },
        { id: 'c3', category: 'Reputação', title: 'Padrão severo de não entrega', description: 'Relatos recentes e consistentes apontam pedidos não recebidos.', impact: 'negative', points: -16, sourceId: 'consumer' },
        { id: 'c4', category: 'Pagamento', title: 'Somente pagamento irreversível', description: 'A loja oferece apenas Pix e não apresenta recebedor verificável.', impact: 'negative', points: -8, sourceId: 'tls' },
        { id: 'c5', category: 'Ameaça', title: 'Sem ameaça técnica confirmada', description: 'As fontes consultadas não confirmaram phishing ou malware ativo.', impact: 'neutral', points: 0, sourceId: 'webrisk' },
      ],
      technical: { ...base.technical, domainAge: '24 dias', threatStatus: 'Nenhuma ameaça técnica confirmada', paymentSignals: ['Somente Pix', 'Recebedor não verificável'] },
    });
  }
  if (selected.id === 'business-mismatch') {
    return withDemoStatuses({
      ...base, score: 20, confidence: 'VERY_HIGH', coverage: 92,
      summary: 'A identidade empresarial exibida não corresponde ao cadastro oficial localizado.',
      recommendation: 'Não compre enquanto a loja não esclarecer e corrigir sua identificação empresarial em canais verificáveis.',
      company: { legalName: 'Comercial Horizonte Ltda.', tradeName: 'Horizonte Atacado', registration: '56.789.012/0001-34', status: 'Ativa', openedAt: '03/09/2019', activity: 'Comércio atacadista', location: 'Recife · PE', match: 'MISMATCH' },
      checks: [
        { id: 'c1', category: 'Empresa', title: 'Identidade empresarial incompatível', description: 'CNPJ, razão social e atividade encontrados pertencem a outra operação comercial.', impact: 'critical', points: -42, sourceId: 'receita' },
        { id: 'c2', category: 'Domínio', title: 'Marca e domínio não correlacionados', description: 'O domínio não aparece entre os sinais públicos da empresa cadastrada.', impact: 'negative', points: -12, sourceId: 'registro' },
        { id: 'c3', category: 'Segurança', title: 'HTTPS válido', description: 'A conexão é criptografada, mas isso não corrige a divergência de identidade.', impact: 'positive', points: 8, sourceId: 'tls' },
        { id: 'c4', category: 'Ameaça', title: 'Sem malware confirmado', description: 'Nenhuma ameaça técnica ativa foi confirmada nas fontes consultadas.', impact: 'neutral', points: 0, sourceId: 'webrisk' },
      ],
      technical: { ...base.technical, domainAge: '4 meses', threatStatus: 'Nenhuma ameaça técnica confirmada', paymentSignals: ['Cartão de crédito', 'Pix', 'Recebedor divergente da empresa'] },
    });
  }
  return withDemoStatuses(base);
}
