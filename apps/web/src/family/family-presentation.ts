import type { Check, ScanReport, Source } from '../types';

export type FamilyVerdict = 'Confiável' | 'Atenção' | 'Alto risco';
export type FamilyTheme = 'dark' | 'light' | 'system';
export interface FamilyHistoryItem { domain: string; verdict: FamilyVerdict; time: string; }
export interface FamilyReason { id: string; title: string; explanation: string; sourceId?: string; }
export interface FamilyResult { verdict: FamilyVerdict; tone: 'good' | 'caution' | 'risk'; summary: string; recommendation: string; reasons: FamilyReason[]; }

export const FAMILY_HISTORY_KEY = 'edy-family-history-v1';
export const FAMILY_HISTORY_ENABLED_KEY = 'edy-family-history-enabled';
export const FAMILY_THEME_KEY = 'edy-family-theme-v1';
const MAX_AGE = 30 * 24 * 60 * 60 * 1000;

export function parseFamilyTheme(value: string | null): FamilyTheme {
  return value === 'light' || value === 'system' ? value : 'dark';
}

/** Accept one address in a pasted message, never silently select among several. */
export function extractFamilyUrl(text: string): string {
  const value = text.trim();
  if (!value) throw new Error('empty_url');
  if (value.length > 8192 || /(?:javascript|data|file|ftp):/i.test(value)) throw new Error('invalid_url');
  const explicit = /https?:\/\/[^\s<>"“”]+/gi;
  const links = [...value.matchAll(explicit)].map((match) => match[0]);
  const remaining = value.replace(explicit, ' ');
  const bare = /(?:^|[\s([{<"“])((?:www\.)?(?:[a-z\d\u00a1-\uffff](?:[a-z\d\u00a1-\uffff-]*[a-z\d\u00a1-\uffff])?\.)+[a-z\u00a1-\uffff]{2,}(?::\d+)?(?:[/?#][^\s<>"“”]*)?)/gi;
  links.push(...[...remaining.matchAll(bare)].map((match) => match[1]));
  if (links.length > 1) throw new Error('multiple_urls');
  if (links.length !== 1) throw new Error('invalid_url');
  const candidate = links[0].replace(/[.,;!?)\]}]+$/g, '');
  try {
    const url = new URL(/^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || !url.hostname.includes('.')) throw new Error('invalid_url');
    url.hash = '';
    return url.toString();
  } catch { throw new Error('invalid_url'); }
}

export function familyErrorMessage(error: unknown): string {
  const code = error instanceof Error ? error.message : '';
  const messages: Record<string, string> = {
    empty_url: 'Cole ou digite o endereço da loja para começar.',
    invalid_url: 'Não encontramos um endereço válido. Copie o link completo da loja e tente novamente.',
    multiple_urls: 'Há mais de um link nessa mensagem. Cole apenas o link da loja que você quer verificar.',
    not_activated: 'Ainda estamos preparando o acesso da família. O serviço ainda não foi ativado. Fale com a pessoa responsável pelo aplicativo.',
    device_pending: 'Seu acesso está aguardando a liberação da pessoa responsável pela família.',
    device_revoked: 'O acesso deste aparelho foi desativado. Fale com a pessoa responsável pela família.',
    offline: 'Não foi possível conectar agora. Confira sua internet; o serviço da família também pode estar temporariamente indisponível. Tente novamente em instantes.',
    rate_limited: 'Já fizemos várias verificações. Aguarde um pouco e tente novamente.',
    scan_rejected: 'Não conseguimos verificar esse endereço. Confira o link da loja e tente novamente.',
    scan_failed: 'Não conseguimos concluir a verificação. Tente novamente em instantes.',
    scan_timeout: 'A verificação demorou mais que o esperado. Tente novamente em instantes.',
    clipboard: 'Não conseguimos acessar o link copiado. Toque no campo e cole o endereço manualmente.',
  };
  return messages[code] ?? messages.scan_failed;
}

const incomplete = (check: Check) => !check.status || ['UNKNOWN', 'NOT_CHECKED', 'NOT_APPLICABLE'].includes(check.status);
const concerning = (check: Check) => ['WARNING', 'FAIL', 'CRITICAL'].includes(check.status ?? '') || ['critical', 'negative', 'warning'].includes(check.impact);

/** Rephrase existing findings only. No new check, score or accusation is generated. */
export function explainFamilyCheck(check: Check, sourceStatus?: Source['status']): FamilyReason {
  const text = `${check.id} ${check.title} ${check.category}`.toLocaleLowerCase('pt-BR');
  const absent = incomplete(check);
  const alert = concerning(check);
  const sourceUnavailable = sourceStatus === 'unavailable' || check.status === 'NOT_CHECKED' || (sourceStatus === undefined && check.status === 'UNKNOWN');
  const result = (title: string, explanation: string): FamilyReason => ({ id: check.id, title, explanation, sourceId: check.sourceId });
  if (/lookalike|confus|homog|parecid|semelhan|typosquat/.test(text)) {
    const comparedDomain = check.value ? safeFamilyDomain(check.value.trim()) : null;
    return absent ? result('Nome do endereço não confirmado', 'Não há informações suficientes para comparar este endereço com o de outras lojas.')
      : alert ? result('Confira o nome do endereço', `O endereço tem sinais de semelhança com ${comparedDomain ?? 'outro nome'}. Isso é uma pista, não prova de golpe. Compare com um canal oficial da loja.`)
        : result('Nome do endereço verificado', 'Essa verificação não encontrou o sinal de semelhança procurado. Isso não garante que a loja seja legítima.');
  }
  if (/cnpj|cadastro|business.identity|identidade empresarial/.test(text)) {
    if (sourceUnavailable) return result('CNPJ não confirmado', 'A fonte necessária não estava disponível ou não pôde ser consultada. Isso não significa que a empresa não exista e não é tratado como um sinal negativo. Confirme o cadastro por outro canal.');
    if (absent || /não encontr|não identific/.test(text)) return result('CNPJ não confirmado', 'A fonte consultada respondeu, mas não encontramos um CNPJ nas páginas que conseguimos ler. Isso não significa que a empresa não exista e não é tratado como um sinal negativo. Confirme o cadastro por outro canal.');
    return alert ? result('Confira os dados da empresa', 'A verificação encontrou um ponto de atenção nos dados da empresa. Confirme quem está vendendo antes de pagar.')
      : result('Dados da empresa verificados', 'Foram encontradas informações da empresa na fonte consultada. Isso, sozinho, não garante a entrega.');
  }
  if (/domain.age|domain_age|idade|recente|criado há/.test(text)) {
    if (sourceUnavailable) return result('Tempo de existência não confirmado', 'A fonte de registro do domínio não estava disponível. A falha temporária da fonte não é tratada como um sinal negativo.');
    if (absent) return result('Tempo de existência não confirmado', 'A fonte respondeu, mas não trouxe uma data de registro utilizável. Isso não é tratado como um sinal negativo.');
    return alert ? result('Endereço recente', 'O endereço tem pouco tempo de existência ou um histórico que pede cuidado. Uma loja nova não é necessariamente falsa; procure mais referências.')
      : result('Histórico do endereço verificado', 'Foi possível consultar o tempo de existência do endereço.');
  }
  if (/reputa|consumer|reclama|entrega/.test(text)) {
    if (sourceUnavailable) return result('Poucas informações de compradores', 'A fonte de reputação não estava disponível ou exige consulta manual. Isso não é tratado como um sinal negativo, e a falta de reclamações não é prova de confiança.');
    if (absent || /sem dados|insuficiente/.test(text)) return result('Poucas informações de compradores', 'A fonte consultada não trouxe informações suficientes sobre outros compradores. Isso não é tratado como um sinal negativo, e a falta de reclamações não é prova de confiança.');
    return alert ? result('Atenção à experiência de compradores', 'As informações consultadas sobre compradores pedem cuidado. Procure relatos recentes em mais de uma fonte.')
      : result('Informações de compradores verificadas', 'A fonte consultada trouxe informações favoráveis. Considere também relatos recentes antes de comprar.');
  }
  if (/phish|malware|ameaça|threat/.test(text)) {
    if (absent) return result('Proteção contra golpes não confirmada', 'Não conseguimos concluir essa consulta de ameaças. Isso não é um sinal de segurança.');
    return alert ? result('Alerta de segurança', 'Uma verificação identificou um sinal de risco. Não informe senhas, documentos ou dados de pagamento enquanto houver dúvida.')
      : result('Consulta de ameaças realizada', 'A consulta não encontrou a ameaça procurada naquele momento. Novos golpes podem ainda não ser conhecidos.');
  }
  if (/redirect|redirecion|destino/.test(text)) {
    if (absent) return result('Destino do link não confirmado', 'Não conseguimos confirmar para onde o link leva.');
    return alert ? result('O destino do link pede cuidado', 'A verificação do caminho até a loja encontrou um ponto de atenção. Confira o endereço final antes de informar dados.')
      : result('Destino do link verificado', 'Foi possível verificar o destino do link. Isso, sozinho, não garante a confiança da loja.');
  }
  if (/https|\btls\b|\bssl\b|certificado/.test(text)) {
    if (absent) return result('Conexão protegida não confirmada', 'Não conseguimos confirmar a proteção da conexão com a loja.');
    return alert ? result('Atenção à conexão com a loja', 'A verificação da conexão ou do certificado encontrou um ponto de atenção. Não envie dados pessoais enquanto houver dúvida.')
      : result('Conexão protegida verificada', 'A conexão protege os dados durante o envio. Sites falsos também podem ter essa proteção; ela não garante uma compra segura.');
  }
  if (/header|cabeçalho|hsts|content.security|referrer/.test(text)) {
    if (absent) return result('Proteções extras não confirmadas', 'Não conseguimos consultar algumas proteções adicionais do site.');
    return alert ? result('Faltam algumas proteções extras', 'O site pode deixar de usar proteções adicionais do navegador. Isso pede cuidado, mas não prova que a loja seja falsa.')
      : result('Proteções extras verificadas', 'Foram encontradas proteções adicionais do site. Elas não garantem a entrega da compra.');
  }
  const title = check.title.trim().replace(/_/g, ' ').slice(0, 140) || 'Informação da loja';
  if (absent) return result(title, 'Essa parte da verificação ficou sem informações suficientes. Não conte com ela como prova de segurança.');
  if (alert) return result(title, 'Essa verificação encontrou um ponto de atenção. Confirme a loja por outro canal antes de pagar.');
  return result(title, 'Foi possível verificar essa informação na fonte consultada. Ela não garante, sozinha, que a compra seja segura.');
}

export function describeFamilyVirusTotal(report: ScanReport): string[] {
  const vt = report.technical.virusTotal;
  if (!vt || !['AVAILABLE', 'PARTIAL'].includes(vt.state)) return ['A consulta de ameaças do VirusTotal não estava disponível. Isso não significa que o site seja seguro.'];
  const descriptions: string[] = [];
  for (const [label, item] of [['endereço da loja', vt.domain], ['link enviado', vt.url]] as const) {
    if (!item) continue;
    if (item.state !== 'AVAILABLE' || !item.stats || item.stats.total <= 0) {
      descriptions.push(`Não há resultados utilizáveis do VirusTotal para o ${label}.`);
    } else if (item.freshness !== 'FRESH') {
      descriptions.push(`A consulta do VirusTotal para o ${label} está antiga ou sem atualização confirmada. Ela não confirma a segurança atual.`);
    } else if (item.stats.malicious + item.stats.suspicious > 0) {
      descriptions.push(`A consulta recente do VirusTotal para o ${label} trouxe ${String(item.stats.malicious)} alerta(s) de conteúdo malicioso e ${String(item.stats.suspicious)} de conteúdo suspeito. São sinais para investigar, não prova isolada de golpe.`);
    } else {
      descriptions.push(`A consulta recente do VirusTotal para o ${label} não encontrou alertas maliciosos ou suspeitos. Isso não garante uma compra segura.`);
    }
  }
  return descriptions.length ? descriptions : ['A consulta de ameaças não trouxe informações suficientes.'];
}

function familyReasonPriority(check: Check): number {
  if (check.status === 'CRITICAL' || check.impact === 'critical') return 0;
  if (check.status === 'FAIL') return 10;
  const text = `${check.id} ${check.title} ${check.category}`.toLocaleLowerCase('pt-BR');
  const identity = /cnpj|cadastro|business.identity|identidade empresarial/.test(text);
  const reputation = /reputa|consumer|reclama|entrega/.test(text);
  const age = /domain.age|domain_age|idade do dom|idade do end|recente|criado há/.test(text);
  const familyTopic = identity ? 0 : reputation ? 1 : age ? 2 : null;
  const threatOrLookalike = /lookalike|confus|homog|parecid|semelhan|typosquat|phish|malware|ameaça|threat|virustotal|virus.total/.test(text);
  // Confirmed risk first. Missing identity/reputation/history then precedes
  // secondary browser/DNS warnings: these are the most useful family decisions.
  if (!incomplete(check) && concerning(check) && threatOrLookalike) return 20;
  if (!incomplete(check) && concerning(check) && familyTopic !== null) return 30 + familyTopic;
  if (incomplete(check) && familyTopic !== null) return 40 + familyTopic;
  if (concerning(check)) return 60;
  if (incomplete(check)) return 70;
  return familyTopic !== null ? 80 + familyTopic : 90;
}

/** A view of existing technical evidence, not an invented Check or score input. */
function freshVirusTotalReason(report: ScanReport): FamilyReason | undefined {
  const vt = report.technical.virusTotal;
  if (!vt || !['AVAILABLE', 'PARTIAL'].includes(vt.state)) return undefined;
  const evidence: string[] = [];
  for (const [label, item] of [['endereço da loja', vt.domain], ['link enviado', vt.url]] as const) {
    const stats = item?.stats;
    if (item?.state !== 'AVAILABLE' || item.freshness !== 'FRESH' || !stats || stats.total <= 0) continue;
    if (![stats.malicious, stats.suspicious].every((count) => Number.isInteger(count) && count >= 0) || stats.malicious + stats.suspicious === 0) continue;
    evidence.push(`Para o ${label}: ${String(stats.malicious)} alerta(s) de conteúdo malicioso e ${String(stats.suspicious)} de conteúdo suspeito.`);
  }
  if (!evidence.length) return undefined;
  return {
    id: 'technical.virusTotal.fresh-alerts',
    title: 'Alertas recentes na consulta de ameaças',
    explanation: `A consulta recente do VirusTotal trouxe alertas. ${evidence.join(' ')} São sinais para investigar, não prova isolada de golpe. Não informe dados de pagamento enquanto houver dúvida.`,
    sourceId: report.sources.find((source) => /virus.?total/i.test(`${source.id} ${source.name}`))?.id,
  };
}

export function summarizeFamilyReport(report: ScanReport): FamilyResult {
  if (report.mode !== 'real') throw new Error('scan_failed');
  const critical = report.checks.some((check) => check.status === 'CRITICAL' || check.impact === 'critical');
  const severe = critical || report.checks.some((check) => check.status === 'FAIL');
  const similarDomain = report.checks.some((check) => check.id === 'FAMILY_DOMAIN_LOOKALIKE' && concerning(check));
  const vtAlert = [report.technical.virusTotal?.domain, report.technical.virusTotal?.url].some((item) => item?.state === 'AVAILABLE' && item.freshness === 'FRESH' && item.stats && item.stats.malicious + item.stats.suspicious > 0);
  // A presentation safety guard, never a replacement for the server's decision.
  const adequate = (report.technical.decisionCoverage ?? report.coverage) >= 80 && report.score !== null && report.score >= 80 && ['HIGH', 'VERY_HIGH'].includes(report.confidence) && report.checks.some((check) => check.status === 'PASS') && report.sources.some((source) => source.status === 'available');
  const verdict: FamilyVerdict = report.verdict === 'DO_NOT_BUY' ? 'Alto risco' : report.verdict === 'BUY' && adequate && !severe && !vtAlert && !similarDomain ? 'Confiável' : 'Atenção';
  const insufficient = report.verdict === 'INSUFFICIENT_DATA' || (report.verdict === 'BUY' && !adequate);
  const technicalThreat = freshVirusTotalReason(report);
  const candidates = report.checks.map((check) => ({
    priority: familyReasonPriority(check),
    reason: explainFamilyCheck(check, report.sources.find((source) => source.id === check.sourceId)?.status),
  }));
  if (technicalThreat) candidates.push({ priority: 20, reason: technicalThreat });
  const allReasons = candidates.sort((a, b) => a.priority - b.priority).map((item) => item.reason);
  const reasons = allReasons.filter((reason, index) => allReasons.findIndex((entry) => entry.title === reason.title) === index).slice(0, 4);
  // Reserve visibility for a fresh technical-only alert even in a dense report.
  // The other three positions still contain the highest-priority real findings.
  if (technicalThreat && !reasons.some((reason) => reason.id === technicalThreat.id)) reasons[3] = technicalThreat;
  return {
    verdict, tone: verdict === 'Confiável' ? 'good' : verdict === 'Alto risco' ? 'risk' : 'caution',
    summary: verdict === 'Confiável' ? 'As informações disponíveis trazem bons sinais para esta loja.' : verdict === 'Alto risco' ? 'Foram encontrados sinais importantes de risco.' : insufficient ? 'Não há informações suficientes para confiar nesta compra.' : 'Há pontos que precisam de cuidado antes de comprar.',
    recommendation: verdict === 'Confiável' ? 'Mesmo assim, confirme os dados da loja e prefira um pagamento com proteção ao comprador.' : verdict === 'Alto risco' ? 'Não pague nem informe senhas, documentos ou dados do cartão. Se já pagou, procure sua instituição financeira.' : 'Espere antes de pagar. Confirme a loja por outro canal e peça ajuda a alguém da família se tiver dúvida.',
    reasons,
  };
}

export function safeFamilyDomain(value: string): string | null {
  if (!/^[a-z\d.-]+$/i.test(value) || value.length > 253) return null;
  try { const url = new URL(`https://${value}`); return url.hostname.includes('.') && url.hostname === value.toLowerCase() ? url.hostname : null; } catch { return null; }
}

/** Whitelist fields, drop malformed/expired items, and never keep a detailed report. */
export function sanitizeFamilyHistory(raw: unknown, now = Date.now()): FamilyHistoryItem[] {
  if (!Array.isArray(raw)) return [];
  const records: FamilyHistoryItem[] = [];
  for (const item of raw as unknown[]) {
    if (!item || typeof item !== 'object') continue;
    const record = item as Record<string, unknown>;
    const domain = typeof record.domain === 'string' ? safeFamilyDomain(record.domain) : null;
    const timestamp = typeof record.time === 'string' ? Date.parse(record.time) : NaN;
    if (!domain || !['Confiável', 'Atenção', 'Alto risco'].includes(String(record.verdict)) || !Number.isFinite(timestamp) || timestamp > now || timestamp < now - MAX_AGE) continue;
    records.push({ domain, verdict: record.verdict as FamilyVerdict, time: new Date(timestamp).toISOString() });
  }
  return records.sort((a, b) => Date.parse(b.time) - Date.parse(a.time)).slice(0, 20);
}

export function safeFamilySourceUrl(value?: string): string | undefined {
  if (!value) return undefined;
  try { const url = new URL(value); return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password ? url.toString() : undefined; } catch { return undefined; }
}
