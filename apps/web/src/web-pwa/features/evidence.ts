import type { Check, ScanReport, Source } from "../../types";
import { formatCnpj, normalizeCnpj, validCnpj } from "../../evidence/cnpj";

export type EvidenceState =
  "PASS" | "INFO" | "WARNING" | "FAIL" | "UNAVAILABLE" | "NOT_CHECKED";
export interface EvidenceItem {
  id: string;
  group: string;
  title: string;
  state: EvidenceState;
  label: string;
  explanation: string;
  details: string[];
  sourceId: string;
  urls: string[];
  checkId?: string;
}
export const evidenceLabels: Record<EvidenceState, string> = {
  PASS: "Verificado",
  INFO: "Informação",
  WARNING: "Atenção",
  FAIL: "Risco encontrado",
  UNAVAILABLE: "Não disponível",
  NOT_CHECKED: "Não verificado",
};
const missing =
  "A falta dessa informação não é prova de fraude. Ela não foi considerada como evidência negativa.";
const unavailable =
  "Esta fonte não respondeu durante a análise. Ela não foi considerada como evidência negativa.";
const definitions: Record<string, [string, string, string]> = {
  DOMAIN_RDAP: [
    "domain_registration",
    "Domínio e conexão",
    "Registro do domínio",
  ],
  DOMAIN_AGE: [
    "domain_history",
    "Domínio e conexão",
    "Tempo de existência do endereço",
  ],
  DOMAIN_DNS: ["dns_resolution", "Domínio e conexão", "Resolução DNS"],
  DOMAIN_NAMESERVERS: [
    "nameservers",
    "Domínio e conexão",
    "Servidores do domínio",
  ],
  DOMAIN_DNSSEC: ["dnssec", "Domínio e conexão", "DNSSEC"],
  TLS_HTTPS: ["https", "Domínio e conexão", "Conexão HTTPS"],
  HTTP_REDIRECTS: [
    "redirect_destination",
    "Sinais de fraude e ameaças",
    "Destino do link",
  ],
  HTTP_HEADERS: [
    "extra_protections",
    "Domínio e conexão",
    "Proteções extras do navegador",
  ],
  FAMILY_DOMAIN_LOOKALIKE: [
    "domain_lookalike",
    "Sinais de fraude e ameaças",
    "Semelhança com outro endereço",
  ],
  BUSINESS_CNPJ_MULTIPLE: [
    "company_multiple",
    "Identidade da empresa",
    "Mais de um CNPJ declarado",
  ],
};
export function sourceConsultation(report: ScanReport, source: Source): string {
  const related = report.checks.filter((check) => check.sourceId === source.id);
  if (
    related.length &&
    related.every(
      (check) =>
        check.status === "NOT_CHECKED" || check.status === "NOT_APPLICABLE",
    )
  )
    return "Não consultada";
  if (
    source.id === "virus-total-public" &&
    report.technical.virusTotal?.state.startsWith("DISABLED")
  )
    return "Não consultada";
  return source.status === "available"
    ? "Consultada"
    : source.status === "limited"
      ? "Consulta limitada"
      : "Fonte indisponível";
}
function stateFor(check: Check, source?: Source): EvidenceState {
  if (check.impact === 'critical' || check.impact === 'negative') return 'FAIL';
  if (check.impact === 'warning' && check.status !== 'FAIL' && check.status !== 'CRITICAL') return 'WARNING';
  if (check.status === "NOT_CHECKED" || check.status === "NOT_APPLICABLE")
    return "NOT_CHECKED";
  if (check.status === "FAIL" || check.status === "CRITICAL") return "FAIL";
  if (check.status === "WARNING") return "WARNING";
  if (check.status === "PASS") return "PASS";
  if (check.id === 'DOMAIN_DNSSEC' && /consulta DS ficou indisponível/i.test(check.description)) return 'UNAVAILABLE';
  return source?.status === "unavailable" ? "UNAVAILABLE" : "INFO";
}
const policyNames: Record<string, string> = {
  contact: "Contato",
  privacy: "Política de privacidade",
  terms: "Termos de uso",
  returns: "Trocas e devoluções",
  refund: "Reembolso",
  shipping: "Entrega",
  legal: "Identificação empresarial declarada",
  about: "Sobre a loja",
};
const severity = (state: EvidenceState) => state === 'FAIL' ? 2 : state === 'WARNING' ? 1 : 0;

/** Canonical view model; evidence stays distinct from scored backend checks. */
export function resultEvidence(report: ScanReport): EvidenceItem[] {
  const items: EvidenceItem[] = [];
  // Collapse repeated identifiers deterministically without suppressing a
  // conflict: it is explicitly marked and both observations remain readable.
  const byCheck = new Map<string, Check>();
  const conflicts = new Map<string, Check[]>();
  for (const check of report.checks) {
    const previous = byCheck.get(check.id);
    if (!previous) byCheck.set(check.id, check);
    else if (JSON.stringify(previous) !== JSON.stringify(check)) {
      conflicts.set(check.id, [
        ...(conflicts.get(check.id) ?? [previous]),
        check,
      ]);
      if (severity(stateFor(check)) > severity(stateFor(previous)))
        byCheck.set(check.id, check);
    }
  }
  for (const check of byCheck.values()) {
    if (
      check.id === "BUSINESS_CNPJ_CHECKSUM" &&
      report.storeEvidence?.cnpjs.some((claim) => claim.checksum === 'INVALID') && byCheck.has('BUSINESS_CNPJ_SITE')
    )
      continue;
    const source = report.sources.find(
      (candidate) => candidate.id === check.sourceId,
    );
    const [id, group, title] = definitions[check.id] ?? [
      `check_${check.id}`,
      "Outras evidências",
      check.title,
    ];
    const state = stateFor(check, source);
    const item: EvidenceItem = {
      id,
      group,
      title,
      state,
      label: evidenceLabels[state],
      explanation: check.description,
      details: [],
      sourceId: check.sourceId,
      urls: [],
      checkId: check.id,
    };
    if (state === "INFO") item.explanation += ` ${missing}`;
    if (state === "UNAVAILABLE") item.explanation = unavailable;
    if (
      check.id === "DOMAIN_AGE" &&
      report.technical.domainAge !== "Não confirmado"
    )
      item.details.push(`Idade informada: ${report.technical.domainAge}.`);
    if (check.id === "TLS_HTTPS")
      item.details.push(
        "HTTPS protege a conexão. Sites falsos também podem usar HTTPS; isso não garante a entrega.",
      );
    if (check.id === "DOMAIN_DNSSEC")
      item.details.push(
        "Um registro DS foi procurado. Isso não é uma auditoria completa da cadeia DNSSEC nem da loja.",
      );
    if (check.id === "BUSINESS_CNPJ_SITE") {
      item.id = "company_identity";
      item.group = "Identidade da empresa";
      const observed =
        report.storeEvidence?.cnpjs ??
        (check.value && /^\d{14}$/.test(normalizeCnpj(check.value))
          ? [
              {
                value: normalizeCnpj(check.value),
                checksum: validCnpj(check.value)
                  ? ("VALID" as const)
                  : ("INVALID" as const),
                provenance: [],
              },
            ]
          : []);
      item.title = observed.length
        ? "CNPJ encontrado no site"
        : state === "UNAVAILABLE"
          ? "Leitura do CNPJ indisponível"
          : "CNPJ não encontrado nas páginas lidas";
      item.state = observed.length
        ? "INFO"
        : state === "UNAVAILABLE"
          ? state
          : "INFO";
      item.label = observed.length
        ? `${String(observed.length)} encontrado${observed.length > 1 ? "s" : ""}`
        : state === "UNAVAILABLE"
          ? evidenceLabels[state]
          : "Não localizado";
      item.explanation = observed.length
        ? "A loja publicou este número. Validar os dígitos não confirma cadastro ativo nem que a loja pertence à empresa."
        : state === "UNAVAILABLE"
          ? unavailable
          : "Não localizamos um CNPJ nas páginas que conseguimos analisar. Isso não significa necessariamente que a empresa não possua um.";
      for (const claim of observed) {
        item.details.push(formatCnpj(claim.value));
        item.details.push(
          claim.checksum === "VALID"
            ? "Formato numérico e dígitos verificadores: válidos."
            : "Dígitos verificadores: inválidos. Pode haver erro de digitação; confirme com a loja.",
        );
        if (claim.checksum === "INVALID") {
          item.state = "FAIL";
          item.label = "Dígitos inválidos";
        }
        if (!claim.provenance.length)
          item.details.push(
            "Página exata não informada por esta versão do serviço.",
          );
        for (const origin of claim.provenance) {
          item.details.push(
            `Origem: ${origin.location === "FOOTER" ? "rodapé" : origin.location === "STRUCTURED_DATA" ? "dados estruturados" : "conteúdo da página"} — ${origin.url}`,
          );
          if (!item.urls.includes(origin.url)) item.urls.push(origin.url);
        }
      }
      item.details.push("Correspondência empresa e site: não determinada.");
      if (report.storeEvidence?.cnpjTruncated) item.details.push('A lista atingiu o limite de 8 CNPJs distintos. Outros números podem existir; a relação não é completa.');
    }
    if (check.id === "BUSINESS_OFFICIAL_VALIDATION") {
      item.id = "company_registration";
      item.group = "Identidade da empresa";
      item.title = "CNPJ cadastral";
      if (check.status === "NOT_CHECKED") {
        item.title = "CNPJ cadastral não consultado";
        item.label = "Não consultado";
        item.explanation =
          "Não consultamos um cadastro oficial nesta análise. Não podemos afirmar situação ativa, razão social ou nome fantasia. Peça os dados à loja e confira por outro canal.";
      }
    }
    if (check.id === "CONSUMER_REPUTATION") {
      item.id = "public_reputation";
      item.group = "Reputação pública";
      item.title = "Experiência de compradores";
      item.label =
        state === "NOT_CHECKED"
          ? "Não avaliada"
          : state === "UNAVAILABLE"
            ? "Fonte indisponível"
            : state === "INFO"
              ? "Evidência limitada"
              : state === "PASS"
                ? "Evidência suficiente"
                : evidenceLabels[state];
      item.explanation =
        state === "NOT_CHECKED"
          ? "Esta análise não consultou uma fonte apropriada de reputação pública. Textos publicados pela loja não comprovam a experiência dos compradores."
          : state === "UNAVAILABLE"
            ? unavailable
            : check.description;
    }
    if (check.id === "TRANSPARENCY_POLICIES") {
      item.id = "site_policies";
      item.group = "Informações da loja";
      item.title = "Conteúdo público da loja";
      // Legacy aggregate PASS cannot support invented per-policy confirmations.
      item.state = state === "UNAVAILABLE" ? state : "INFO";
      item.label =
        state === "UNAVAILABLE" ? evidenceLabels[state] : "Leitura limitada";
      item.explanation =
        "Procuramos conteúdo de contato e políticas nas páginas acessíveis. Links de menu isolados não confirmam o conteúdo nem o cumprimento da política.";
      if (report.storeEvidence?.policies.length) {
        item.label = `${String(report.storeEvidence.policies.length)} categorias encontradas`;
        for (const policy of report.storeEvidence.policies)
          items.push({
            id: `policy_${policy.id}`,
            group: item.group,
            title: policyNames[policy.id] ?? policy.id,
            state: "PASS",
            label: "Conteúdo encontrado",
            explanation:
              "Encontramos texto compatível com esta categoria. Não foi feita uma auditoria jurídica nem confirmamos o cumprimento da política.",
            details: [],
            sourceId: check.sourceId,
            urls: policy.sourceUrls,
          });
      } else if (!report.storeEvidence)
        item.details.push(
          "Esta versão do serviço informa apenas um resultado agregado, sem identificar quais políticas foram encontradas.",
        );
      else
        item.details.push(
          state === "UNAVAILABLE"
            ? unavailable
            : "Não encontramos conteúdo suficiente para detalhar políticas nas páginas lidas. Isso não prova que não existam.",
        );
    }
    if (check.id === "THREAT_VIRUSTOTAL") {
      item.id = "fraud_intelligence";
      item.group = "Sinais de fraude e ameaças";
      item.title = "Consulta de ameaças — VirusTotal";
      const vt = report.technical.virusTotal;
      const fresh = [vt?.domain, vt?.url].filter(
        (entry) =>
          entry?.state === "AVAILABLE" &&
          entry.freshness === "FRESH" &&
          entry.stats &&
          entry.stats.total > 0,
      );
      const malicious = fresh.some(
        (entry) => (entry?.stats?.malicious ?? 0) > 0,
      );
      const suspicious = fresh.some(
        (entry) => (entry?.stats?.suspicious ?? 0) > 0,
      );
      const disabled = vt?.state.startsWith("DISABLED");
      if (malicious || suspicious) {
        item.state = malicious ? "FAIL" : "WARNING";
        item.label = "Indicadores de risco";
        item.explanation =
          "Relatórios recentes trouxeram alertas. São sinais para investigar; não informe dados de pagamento enquanto houver dúvida.";
      } else if (state === "FAIL" || state === "WARNING") {
        /* Preserve an explicit backend alert. */
      } else if (fresh.length) {
        item.state = "INFO";
        item.label = "Sem alertas nas consultas recentes";
        item.explanation =
          "Nenhuma ameaça conhecida encontrada nos relatórios recentes consultados. Isso não garante uma compra sem riscos. Consultas ausentes ou antigas continuam inconclusivas.";
      } else {
        item.state = disabled
          ? "NOT_CHECKED"
          : state === "UNAVAILABLE"
            ? "UNAVAILABLE"
            : "INFO";
        item.label = disabled
          ? "Não consultada"
          : state === "UNAVAILABLE"
            ? "Fonte indisponível"
            : "Dados inconclusivos";
        item.explanation = disabled
          ? "A consulta de ameaças não foi executada. Isso não é sinal de segurança."
          : state === "UNAVAILABLE"
            ? unavailable
            : "A fonte não trouxe relatórios recentes suficientes para concluir esta consulta. Ausência de alertas não é garantia de segurança.";
      }
      for (const [name, entry] of [
        ["Domínio", vt?.domain],
        ["Link", vt?.url],
      ] as const) {
        item.details.push(
          `${name}: ${entry?.state === "AVAILABLE" && entry.stats ? `${String(entry.stats.malicious)} malicioso(s), ${String(entry.stats.suspicious)} suspeito(s), de ${String(entry.stats.total)} resultados; ${entry.freshness === "FRESH" ? "relatório recente" : "atualidade não confirmada"}.` : entry?.state === "NO_DATA" ? "sem relatório na fonte." : entry?.state === "FAILED" || entry?.state === "TIMED_OUT" || entry?.state === "RATE_LIMITED" ? "fonte indisponível." : "não consultado."}`,
        );
      }
    }
    // Specific explanatory views must never downgrade an explicit backend
    // alert, including legacy reports with impact but no status.
    if (severity(state) > severity(item.state)) {
      item.state = state; item.label = evidenceLabels[state]; item.explanation = check.description;
      item.details.push('O serviço retornou um alerta para esta verificação. Confirme os dados antes de pagar.');
    }
    const conflict = conflicts.get(check.id);
    if (conflict) {
      item.details.push(
        "O serviço retornou observações conflitantes para esta verificação; confirme antes de concluir.",
        ...conflict.map(
          (entry) => `${entry.status ?? "UNKNOWN"} / ${entry.impact}: ${entry.description}`,
        ),
      );
      if (severity(item.state) === 0) {
        // Divergent missing data is uncertainty, not evidence against the store.
        // Do not claim a positive either when a duplicate contradicts it.
        if (item.state === 'PASS') item.state = 'INFO';
        item.label = "Dados divergentes — confirmar";
        item.explanation = 'As observações desta verificação divergem. Não foi possível confirmá-la; isso não é evidência de risco da loja.';
      }
    }
    items.push(item);
  }
  return [...new Map(items.map((item) => [item.id, item])).values()];
}
