import { randomUUID } from "node:crypto";
import {
  RULESET_VERSION,
  evaluateDecision,
  type CheckStatus,
  type Evidence,
  type EvidenceCategory,
  type Finding,
} from "@edy-scanurl/core";
import type { DnsData } from "../providers/dns.js";
import { providerComplianceRegistry } from "../providers/compliance.js";
import type { HttpTransparencyData } from "../providers/http-transparency.js";
import { ProviderRegistry } from "../providers/registry.js";
import { providerResult, type ProviderResult, type ScanProvider } from "../providers/contracts.js";
import type { RdapData } from "../providers/rdap.js";
import type { TlsData } from "../providers/tls.js";
import type { VirusTotalData, VirusTotalObjectReport } from "../providers/virus-total.js";
import { normalizeTarget, TargetRejectedError } from "../security/target.js";
import {
  evaluateCheckRegistry,
  type CheckExecutionTrace,
  type RegistryFacts,
} from "./check-registry.js";

export type ScanStatus = "QUEUED" | "RUNNING" | "SUCCEEDED" | "FAILED" | "SCAN_REJECTED";

export interface ScanJobSnapshot {
  scanId: string;
  status: ScanStatus;
  progress: { completed: number; total: number; current: string };
  report?: RealScanReport;
  coverageStatus?: "COMPLETE" | "LIMITED";
  rejection?: { code: string; message: string };
  error?: string;
}

export interface RealScanReport {
  id: string;
  mode: "real";
  inputUrl: string;
  normalizedUrl: string;
  domain: string;
  scannedAt: string;
  verdict: "BUY" | "CAUTION" | "DO_NOT_BUY" | "INSUFFICIENT_DATA";
  score: number | null;
  confidence: "LOW" | "MEDIUM" | "HIGH" | "VERY_HIGH";
  coverage: number;
  scanCompletion: number;
  summary: string;
  recommendation: string;
  checks: { id: string; category: string; title: string; description: string; status: CheckStatus; impact: "positive" | "neutral" | "warning" | "negative" | "critical"; points: number; sourceId: string; value?: string }[];
  scoreAreas: { id: string; label: string; score: number; max: number; coverage: number }[];
  sources: { id: string; name: string; tier: 1 | 2 | 3 | 4; category: string; collectedAt?: string; sourceUpdatedAt?: string; url?: string; status: "available" | "limited" | "unavailable" }[];
  technical: {
    domainAge: string;
    domainUpdatedAt: string;
    registrar: string;
    nameservers: string[];
    dns: string[];
    tls: string;
    tlsIssuer: string;
    redirects: string[];
    finalHostname: string;
    headers: string[];
    threatStatus: string;
    salesVolume: string;
    paymentSignals: string[];
    decisionCoverage: number;
    pagesDiscovered: number;
    pagesFetched: number;
    silentSkips: number;
    checkTrace: CheckExecutionTrace[];
    virusTotal: {
      state: "AVAILABLE" | "DISABLED_BY_POLICY" | "DISABLED_NO_CREDENTIALS" | "DISABLED_NOT_PROVISIONED" | "RATE_LIMITED" | "NO_DATA" | "TIMED_OUT" | "FAILED" | "PARTIAL";
      reason: string;
      collectedAt?: string;
      policyMode?: string;
      disclosure?: string;
      domain?: VirusTotalObjectReport;
      url?: VirusTotalObjectReport;
      registrationCorrelation?: "MATCH" | "MINOR_DIFFERENCE" | "CONFLICT" | "UNKNOWN";
    };
  };
}

interface MutableJob extends ScanJobSnapshot {
  createdAt: number;
}

export class ScanOrchestrator {
  private readonly jobs = new Map<string, MutableJob>();
  private readonly runWaiters: (() => void)[] = [];
  private activeRuns = 0;
  private readonly maximumConcurrentRuns = 6;

  constructor(private readonly registry: { enabled(): readonly ScanProvider[] } = new ProviderRegistry()) {}

  create(input: string): ScanJobSnapshot {
    this.prune();
    this.ensureCapacity();
    const scanId = randomUUID();
    const total = this.registry.enabled().length;
    const job: MutableJob = {
      scanId,
      status: "QUEUED",
      progress: { completed: 0, total, current: "QUEUED" },
      createdAt: Date.now(),
    };
    this.jobs.set(scanId, job);
    void this.schedule(job, input);
    return snapshot(job);
  }

  get(scanId: string): ScanJobSnapshot | undefined {
    this.prune();
    const job = this.jobs.get(scanId);
    return job ? snapshot(job) : undefined;
  }

  private async schedule(job: MutableJob, input: string): Promise<void> {
    await this.acquireRunSlot();
    try {
      await this.run(job, input);
    } finally {
      this.releaseRunSlot();
    }
  }

  private acquireRunSlot(): Promise<void> {
    if (this.activeRuns < this.maximumConcurrentRuns) {
      this.activeRuns += 1;
      return Promise.resolve();
    }
    return new Promise((resolve) => this.runWaiters.push(resolve));
  }

  private releaseRunSlot(): void {
    const next = this.runWaiters.shift();
    if (next) next();
    else this.activeRuns -= 1;
  }

  private async run(job: MutableJob, input: string): Promise<void> {
    let target;
    try {
      target = normalizeTarget(input);
    } catch (error) {
      if (error instanceof TargetRejectedError) {
        job.status = "SCAN_REJECTED";
        job.rejection = { code: error.reason, message: error.message };
        job.progress.current = "REJECTED";
        return;
      }
      job.status = "FAILED";
      job.error = "TARGET_NORMALIZATION_FAILED";
      return;
    }

    job.status = "RUNNING";
    job.progress.current = "PROVIDERS";
    const providers = this.registry.enabled();
    const results = await Promise.all(
      providers.map(async (provider) => {
        const result = await executeProviderSafely(provider, {
          scanId: job.scanId,
          domain: target.domain,
          targetUrl: target.requestUrl.toString(),
        });
        job.progress.completed += 1;
        job.progress.current = provider.id;
        return result;
      }),
    );

    try {
      job.report = buildReport(job.scanId, target.persistedTarget, target.domain, results);
      job.status = "SUCCEEDED";
      job.coverageStatus = results.some((result) => result.status !== "SUCCEEDED") || job.report.coverage < 100
        ? "LIMITED"
        : "COMPLETE";
      job.progress.current = "COMPLETE";
    } catch {
      job.status = "FAILED";
      job.error = "DECISION_ENGINE_FAILED";
      job.progress.current = "FAILED";
    }
  }

  private prune(now = Date.now()): void {
    for (const [id, job] of this.jobs) {
      if (job.status !== "RUNNING" && job.status !== "QUEUED" && now - job.createdAt > 15 * 60_000) this.jobs.delete(id);
    }
  }

  private ensureCapacity(): void {
    const maximumJobs = 2_000;
    if (this.jobs.size < maximumJobs) return;
    const oldestTerminal = [...this.jobs.values()]
      .filter((job) => job.status !== "RUNNING" && job.status !== "QUEUED")
      .sort((a, b) => a.createdAt - b.createdAt)[0];
    if (!oldestTerminal) throw new Error("SCAN_CAPACITY_REACHED");
    this.jobs.delete(oldestTerminal.scanId);
  }
}

async function executeProviderSafely(
  provider: ScanProvider,
  context: { scanId: string; domain: string; targetUrl: string },
): Promise<ProviderResult> {
  const startedAt = new Date().toISOString();
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      provider.execute({ ...context, signal: controller.signal }),
      new Promise<ProviderResult>((resolve) => {
        timer = setTimeout(
          () => {
            controller.abort();
            resolve(providerResult(provider, startedAt, "TIMED_OUT", { errorCode: "PROVIDER_DEADLINE_EXCEEDED" }));
          },
          9_000,
        );
      }),
    ]);
  } catch (error) {
    return providerResult(provider, startedAt, "FAILED", {
      errorCode: error instanceof Error ? error.message.slice(0, 100) : "PROVIDER_UNEXPECTED_FAILURE",
    });
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function buildReport(scanId: string, persistedTarget: string, domain: string, results: ProviderResult[]): RealScanReport {
  const now = new Date().toISOString();
  const evidence: Evidence[] = [];
  const findings: Finding[] = [];
  const byId = new Map(results.map((result) => [result.providerId, result]));
  const rdap = byId.get("rdap") as ProviderResult<RdapData> | undefined;
  const dns = byId.get("dns-direct") as ProviderResult<DnsData> | undefined;
  const tls = byId.get("tls-direct") as ProviderResult<TlsData> | undefined;
  const http = byId.get("transparency-passive") as ProviderResult<HttpTransparencyData> | undefined;
  const virusTotal = byId.get("virus-total-public") as ProviderResult<VirusTotalData> | undefined;
  const httpAvailable = http?.status === "SUCCEEDED" || http?.status === "PARTIAL";

  addFinding(findings, evidence, {
    scanId, controlId: "business.identity", category: "BUSINESS_IDENTITY", status: "NOT_CHECKED",
    title: "Cadastro empresarial", reason: "A base CNPJ gratuita não foi provisionada neste MVP local.", sourceId: "business-cnpj-bulk", now,
  });
  addFinding(findings, evidence, {
    scanId, controlId: "domain.registration", category: "DOMAIN_HISTORY", status: rdap?.status === "SUCCEEDED" ? "PASS" : "UNKNOWN",
    title: "Registro do domínio", reason: rdap?.status === "SUCCEEDED" ? "O registro RDAP autoritativo respondeu à consulta." : "O registro RDAP não pôde ser confirmado.", sourceId: "rdap", sourceTier: 1, value: rdap?.data, sourceUrl: rdap?.sourceUrl, now,
  });
  const tlsStatus: CheckStatus = tls?.status !== "SUCCEEDED" ? "UNKNOWN" : tls.data?.authorized ? "PASS" : "WARNING";
  addFinding(findings, evidence, {
    scanId, controlId: "technical.https", category: "TECHNICAL_SECURITY", status: tlsStatus,
    title: "HTTPS e certificado", reason: tlsStatus === "PASS" ? "A conexão TLS observada possui certificado válido para o domínio." : tlsStatus === "WARNING" ? "HTTPS respondeu, mas o certificado não foi validado integralmente." : "A conexão TLS não foi confirmada.", sourceId: "tls-direct", sourceTier: 2, value: tls?.data, now,
  });
  const headerCount = http?.data ? Object.values(http.data.securityHeaders).filter(Boolean).length : 0;
  addFinding(findings, evidence, {
    scanId, controlId: "technical.headers", category: "TECHNICAL_SECURITY", status: !httpAvailable ? "UNKNOWN" : headerCount >= 3 ? "PASS" : "WARNING",
    title: "Postura de cabeçalhos", reason: !httpAvailable ? "Os cabeçalhos HTTP não foram confirmados." : `${String(headerCount)} controles de cabeçalho foram observados; ausência isolada não indica fraude.`, sourceId: "transparency-passive", sourceTier: 4, value: http?.data?.securityHeaders, sourceUrl: http?.sourceUrl, now,
  });
  for (const [controlId, title] of [["threat.phishing", "Phishing"], ["threat.malware", "Malware"], ["threat.redirect", "Redirecionamento malicioso"]] as const) {
    addFinding(findings, evidence, { scanId, controlId, category: "THREAT_IMPERSONATION", status: "NOT_CHECKED", title, reason: "Nenhum provider comercial de ameaças está habilitado no modo zero-cost.", sourceId: "threat-provider-disabled", now });
  }
  addFinding(findings, evidence, { scanId, controlId: "consumer.reputation", category: "CONSUMER_REPUTATION", status: "NOT_CHECKED", title: "Reputação do consumidor", reason: "Consumidor.gov e Procon não estão provisionados; o Reclame AQUI permanece apenas para consulta manual.", sourceId: "consumer-gov-open-data", now });
  const policies = http?.data?.signals.policies;
  const policyCount = policies ? Object.values(policies).filter(Boolean).length : 0;
  const policyStatus: CheckStatus = !httpAvailable || (http.status === "PARTIAL" && policyCount < 3)
    ? "UNKNOWN"
    : policyCount >= 3 ? "PASS" : "WARNING";
  addFinding(findings, evidence, {
    scanId, controlId: "transparency.policies", category: "STORE_TRANSPARENCY", status: policyStatus,
    title: "Transparência da loja", reason: !httpAvailable ? "A página não pôde ser analisada passivamente." : `${String(policyCount)} páginas de política com conteúdo relevante foram confirmadas.`, sourceId: "transparency-passive", sourceTier: 4, value: policies, sourceUrl: http?.sourceUrl, now,
  });
  const payments = http?.data?.signals.paymentMethods ?? [];
  addFinding(findings, evidence, {
    scanId, controlId: "commerce.payment", category: "COMMERCE_PAYMENT", status: "UNKNOWN",
    title: "Métodos de pagamento declarados", reason: payments.length === 0 ? "Não foi possível confirmar métodos de pagamento publicamente." : "Métodos foram declarados pelo próprio site; a observação não confirma checkout, recebedor ou contestabilidade.", sourceId: "transparency-passive", sourceTier: 4, value: payments, sourceUrl: http?.sourceUrl, now,
  });
  const socials = http?.data?.signals.socialLinks ?? [];
  addFinding(findings, evidence, {
    scanId, controlId: "public.presence", category: "PUBLIC_PRESENCE", status: "UNKNOWN",
    title: "Presença pública declarada", reason: socials.length > 0 ? "Links sociais foram publicados pelo próprio site; posse e legitimidade não foram confirmadas." : "Nenhum link público pôde ser confirmado.", sourceId: "transparency-passive", sourceTier: 4, value: socials, sourceUrl: http?.sourceUrl, now,
  });
  addFinding(findings, evidence, {
    scanId, controlId: "evidence.consistency", category: "EVIDENCE_CONSISTENCY", status: "UNKNOWN",
    title: "Consistência das evidências", reason: "A cobertura atual não permite correlação empresarial independente suficiente.", sourceId: "edy-correlation", sourceTier: 4, value: { evidenceCount: evidence.length }, now,
  });

  const decision = evaluateDecision({
    scanId,
    targetSubjectKey: "origin-redacted",
    authorizedBlockingSourceIds: [],
    provenance: "REAL",
    findings,
    evidence,
    hardBlockerCandidates: [],
    evaluatedAt: now,
  });
  const scoreVisible = decision.coverage.value >= 70 ? decision.score.effectiveValue : null;
  const verdict = decision.verdict.verdict;
  const registry = evaluateCheckRegistry(buildRegistryFacts(results, rdap, dns, tls, http, virusTotal));
  const checks = registry.trace.map((item) => {
    const status: CheckStatus = item.finalState === "UNAVAILABLE" ? "NOT_CHECKED" : item.finalState;
    return {
      id: item.check,
      category: item.category,
      title: item.title,
      description: humanTraceReason(item.reason),
      status,
      impact: statusImpact(status),
      points: status === "PASS" ? 1 : 0,
      sourceId: item.provider,
      value: `${String(item.evidenceCount)} evidência(s) · ${String(item.durationMs)} ms`,
    };
  });
  const sources = [...results.map((result) => ({
    id: result.providerId,
    name: providerName(result.providerId),
    tier: providerTier(result.providerId),
    category: result.category,
    collectedAt: result.completedAt,
    ...(result.sourceUrl ? { url: result.sourceUrl } : {}),
    status: result.status === "SUCCEEDED" ? "available" as const : result.status === "PARTIAL" || result.status === "NO_DATA" ? "limited" as const : "unavailable" as const,
    ...(result.providerId === "rdap" && rdap?.data?.updatedDate ? { sourceUpdatedAt: rdap.data.updatedDate } : {}),
  })), ...complianceUnavailableSources(new Set(results.map((result) => result.providerId)))];

  return {
    id: scanId,
    mode: "real",
    inputUrl: persistedTarget,
    normalizedUrl: persistedTarget,
    domain,
    scannedAt: now,
    verdict,
    score: scoreVisible,
    confidence: decision.confidence.level,
    coverage: registry.evidenceCoverage,
    scanCompletion: registry.scanCompletion,
    summary: summaryFor(verdict),
    recommendation: recommendationFor(verdict),
    checks,
    scoreAreas: decision.score.categories.map((category) => ({
      id: category.category,
      label: category.category,
      score: category.earnedPoints,
      max: category.assessedWeight,
      coverage: decision.coverage.categories.find((item) => item.category === category.category)?.coverage ?? 0,
    })),
    sources,
    technical: {
      domainAge: rdap?.data?.registrationDate ? ageLabel(rdap.data.registrationDate, now) : "Não confirmado",
      domainUpdatedAt: rdap?.data?.updatedDate ?? "Não confirmado",
      registrar: rdap?.data?.registrar ?? "Não confirmado",
      nameservers: rdap?.data?.nameservers ?? dns?.data?.ns ?? [],
      dns: [
        ...(dns?.data?.a ?? []).map((value) => `A · ${value}`),
        ...(dns?.data?.aaaa ?? []).map((value) => `AAAA · ${value}`),
        ...(dns?.data?.ns ?? []).map((value) => `NS · ${value}`),
        ...(dns?.data?.mx ?? []).map((value) => `MX ${String(value.priority)} · ${value.exchange}`),
        ...(dns?.data?.caa ?? []).map((value) => `CAA · ${formatTechnicalValue(value)}`),
        ...(dns?.data?.dnssec ? [`DNSSEC · ${dns.data.dnssec}`] : []),
      ].slice(0, 24),
      tls: tls?.data?.authorized ? `${tls.data.protocol ?? "TLS"} válido` : "Não confirmado",
      tlsIssuer: tls?.data?.issuer ?? "Não confirmado",
      redirects: http?.data ? [`${String(http.data.redirects)} redirecionamento(s) validado(s)`] : [],
      finalHostname: http?.data ? new URL(http.data.finalOrigin).hostname : "Não confirmado",
      headers: http?.data ? Object.entries(http.data.securityHeaders).filter(([, present]) => present).map(([name]) => name) : [],
      threatStatus: virusTotalThreatStatus(virusTotal),
      salesVolume: "Não verificável publicamente",
      paymentSignals: payments,
      decisionCoverage: decision.coverage.value,
      pagesDiscovered: http?.data?.pagesDiscovered ?? 0,
      pagesFetched: http?.data?.pagesFetched ?? 0,
      silentSkips: registry.silentSkips,
      checkTrace: registry.trace,
      virusTotal: virusTotalTechnicalReport(virusTotal, rdap?.data?.registrationDate),
    },
  };
}

interface AddFindingInput {
  scanId: string;
  controlId: string;
  category: EvidenceCategory;
  status: CheckStatus;
  title: string;
  reason: string;
  sourceId: string;
  sourceTier?: 1 | 2 | 3 | 4 | 5;
  value?: unknown;
  sourceUrl?: string | undefined;
  now: string;
}

function addFinding(findings: Finding[], evidence: Evidence[], input: AddFindingInput): void {
  const assessed = ["PASS", "WARNING", "FAIL", "CRITICAL"].includes(input.status);
  const evidenceId = assessed ? randomUUID() : undefined;
  if (evidenceId) {
    evidence.push({
      id: evidenceId, scanId: input.scanId, providerRunId: `${input.sourceId}:${input.scanId}`, subjectType: "DOMAIN",
      subjectKey: "origin-redacted", category: input.category, claimType: input.controlId, value: input.value ?? input.reason,
      normalizedValue: input.value ?? input.reason, sourceId: input.sourceId, sourceTier: input.sourceTier ?? 4,
      collectionMethod: input.sourceId === "edy-correlation" ? "DERIVED" : "PASSIVE", collectedAt: input.now,
      impact: input.status === "PASS" ? "POSITIVE" : input.status === "WARNING" ? "WARNING" : input.status === "CRITICAL" ? "CRITICAL" : "NEGATIVE",
      severity: input.status === "CRITICAL" ? "CRITICAL" : input.status === "FAIL" ? "HIGH" : input.status === "WARNING" ? "LOW" : "INFO",
      findingCertainty: input.sourceTier === 1 ? "CONFIRMED" : "UNVERIFIED",
      ...(input.sourceUrl ? { sourceUrlAllowed: input.sourceUrl } : {}),
      provenance: "REAL", rulesetVersion: RULESET_VERSION,
    });
  }
  findings.push({
    id: randomUUID(), ruleId: `RULE_${input.controlId}`, controlId: input.controlId, category: input.category,
    status: input.status, title: input.title, reason: input.reason, evidenceIds: evidenceId ? [evidenceId] : [],
    material: input.status === "FAIL" || input.status === "CRITICAL", strongNegative: input.status === "CRITICAL", provenance: "REAL",
  });
}

function buildRegistryFacts(
  results: ProviderResult[],
  rdap: ProviderResult<RdapData> | undefined,
  dns: ProviderResult<DnsData> | undefined,
  tls: ProviderResult<TlsData> | undefined,
  http: ProviderResult<HttpTransparencyData> | undefined,
  virusTotal: ProviderResult<VirusTotalData> | undefined,
): RegistryFacts {
  const signals = http?.data?.signals;
  const providerReceipts = Object.fromEntries(results.map((result) => [
    result.providerId,
    {
      status: result.status,
      durationMs: Math.max(0, Date.parse(result.completedAt) - Date.parse(result.startedAt)),
    },
  ]));
  const cnpjValues = new Set((signals?.cnpjClaims ?? []).map((item) => item.value.replace(/[^A-Z0-9]/gi, "").toUpperCase()));
  return {
    providers: providerReceipts,
    rdap: {
      ...(rdap?.data?.registrationDate ? { registrationDate: rdap.data.registrationDate } : {}),
      ...(rdap?.data?.updatedDate ? { updatedDate: rdap.data.updatedDate } : {}),
      ...(rdap?.data?.registrar ? { registrar: rdap.data.registrar } : {}),
      statuses: rdap?.data?.statuses ?? [],
    },
    dns: {
      addresses: (dns?.data?.a.length ?? 0) + (dns?.data?.aaaa.length ?? 0),
      nameservers: dns?.data?.ns.length ?? 0,
      mailExchangers: dns?.data?.mx.length ?? 0,
      caa: dns?.data?.caa.length ?? 0,
      ...(dns?.data?.dnssec ? { dnssec: dns.data.dnssec } : {}),
    },
    tls: {
      available: tls?.data?.available ?? false,
      authorized: tls?.data?.authorized ?? false,
      ...(tls?.data?.daysRemaining !== undefined ? { daysRemaining: tls.data.daysRemaining } : {}),
    },
    virusTotal: virusTotalRegistryFacts(virusTotal),
    http: {
      redirects: http?.data?.redirects ?? 0,
      headerCount: http?.data ? Object.values(http.data.securityHeaders).filter(Boolean).length : 0,
      securityHeaders: {
        hsts: http?.data?.securityHeaders.hsts ?? false,
        csp: http?.data?.securityHeaders.csp ?? false,
        frameProtection: http?.data?.securityHeaders.frameProtection ?? false,
        referrerPolicy: http?.data?.securityHeaders.referrerPolicy ?? false,
        permissionsPolicy: http?.data?.securityHeaders.permissionsPolicy ?? false,
        noSniff: http?.data?.securityHeaders.noSniff ?? false,
      },
      finalHostname: Boolean(http?.data?.finalOrigin),
      pagesFetched: http?.data?.pagesFetched ?? 0,
      pagesDiscovered: http?.data?.pagesDiscovered ?? 0,
      partial: http?.status === "PARTIAL",
      companyNames: signals?.companyNames.length ?? 0,
      cnpjClaims: signals?.cnpjClaims.length ?? 0,
      distinctCnpj: cnpjValues.size,
      structuredOrganizations: signals?.structuredOrganizations.length ?? 0,
      contacts: signals?.contactFound ? 1 : 0,
      addresses: signals?.addresses.length ?? 0,
      emails: signals?.corporateEmails.length ?? 0,
      phones: signals?.phones.length ?? 0,
      about: signals?.aboutFound ?? false,
      privacy: signals?.policies.privacy ?? false,
      terms: signals?.policies.terms ?? false,
      returns: signals?.policies.returns ?? false,
      refund: signals?.policies.refund ?? false,
      shipping: signals?.policies.shipping ?? false,
      legal: signals?.legalFound ?? false,
      socialLinks: signals?.socialLinks.length ?? 0,
      catalog: signals?.catalogFound ?? false,
      paymentMethods: signals?.paymentMethods.length ?? 0,
      platforms: signals?.platforms.length ?? 0,
      checkoutDomains: signals?.checkoutDomains.length ?? 0,
    },
  };
}

function complianceUnavailableSources(executed: Set<string>): RealScanReport["sources"] {
  return providerComplianceRegistry
    .filter((record) => !executed.has(record.provider))
    .map((record) => ({
      id: record.provider,
      name: providerName(record.provider),
      tier: providerTier(record.provider),
      category: providerCategory(record.provider),
      status: "unavailable" as const,
      url: record.termsUrl,
    }));
}

function humanTraceReason(reason: string): string {
  if (reason.includes("NOT_INDEPENDENTLY_VERIFIED")) {
    return "Observado no próprio site; não verificado por fonte independente.";
  }
  const labels: Record<string, string> = {
    OFFICIAL_PROVIDER_NOT_PROVISIONED: "A fonte oficial gratuita não está provisionada; a validação permanece não verificada.",
    OFFICIAL_IDENTITY_NOT_AVAILABLE: "A identidade oficial não está disponível para uma correlação independente.",
    ZERO_COST_COMMERCIAL_PROVIDER_UNAVAILABLE: "Não existe provider comercial de ameaças autorizado e sem billing habilitado.",
    AUTHORIZED_AUTOMATIC_SOURCE_UNAVAILABLE: "Não existe fonte automática autorizada para esta verificação.",
    OPEN_DATA_SNAPSHOT_NOT_PROVISIONED: "A fonte oficial publica dados abertos em lote, mas o snapshot local ainda não está provisionado.",
    MANUAL_REVIEW_ONLY: "A fonte não é consultada automaticamente; use o link para uma verificação manual.",
    NATIONAL_AUTOMATIC_SOURCE_NOT_PROVISIONED: "Não existe uma fonte nacional agregada do Procon provisionada para consulta automática por domínio.",
    NO_COMMERCE_CONTEXT_OBSERVED: "Nenhum contexto comercial foi observado; esta verificação não é aplicável.",
    NO_USABLE_EVIDENCE: "A verificação foi concluída, mas não retornou evidência utilizável.",
    CONFLICTING_SITE_CLAIMS: "O próprio site publicou declarações conflitantes; isso não equivale a divergência oficial.",
    DISABLED_BY_POLICY_COMMERCIAL_USE_PROHIBITED: "A API pública do VirusTotal não pode ser usada neste produto comercial; nenhuma consulta foi realizada.",
    VIRUSTOTAL_NO_REPORT: "Nenhum relatório existente foi encontrado; ausência de dados não significa segurança.",
    VIRUSTOTAL_REPORT_STALE: "O relatório existente está antigo e não foi usado como conclusão de segurança.",
    VIRUSTOTAL_MULTIPLE_MALICIOUS_DETECTIONS: "Múltiplas detecções maliciosas foram observadas em um único provider agregado.",
    VIRUSTOTAL_MALICIOUS_DETECTION: "Uma detecção maliciosa foi observada; requer confirmação independente.",
    VIRUSTOTAL_SUSPICIOUS_DETECTION: "Uma detecção suspeita foi observada; requer confirmação independente.",
    VIRUSTOTAL_NO_MALICIOUS_DETECTION_NOT_SAFETY_PROOF: "Nenhuma detecção maliciosa foi retornada; isso não comprova que o endereço seja seguro.",
  };
  return labels[reason] ?? reason.replaceAll("_", " ").toLowerCase();
}

function statusImpact(status: CheckStatus): "positive" | "neutral" | "warning" | "negative" | "critical" {
  if (status === "PASS") return "positive";
  if (status === "WARNING") return "warning";
  if (status === "FAIL") return "negative";
  if (status === "CRITICAL") return "critical";
  return "neutral";
}

function providerTier(id: string): 1 | 2 | 3 | 4 {
  if (["rdap", "google-web-risk", "business-cnpj-bulk", "consumer-gov-open-data", "procon-official-warnings"].includes(id)) return 1;
  if (["virus-total-public", "urlhaus-community", "phishtank"].includes(id)) return 2;
  if (id === "reclame-aqui-manual") return 3;
  if (id === "tls-direct" || id === "dns-direct") return 2;
  return 4;
}

function providerName(id: string): string {
  return ({
    rdap: "RDAP autoritativo",
    "dns-direct": "DNS direto",
    "tls-direct": "TLS direto",
    "transparency-passive": "Site analisado passivamente",
    "google-web-risk": "Google Web Risk",
    "virus-total-public": "VirusTotal Public API",
    "urlhaus-community": "URLhaus Community API",
    phishtank: "PhishTank",
    "business-cnpj-bulk": "Receita Federal — base CNPJ",
    "consumer-gov-open-data": "Consumidor.gov.br — dados abertos",
    "reclame-aqui-manual": "Reclame AQUI",
    "procon-official-warnings": "Procon — alertas oficiais",
  } as Record<string, string>)[id] ?? id;
}

function formatTechnicalValue(value: unknown): string {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  try { return JSON.stringify(value); } catch { return "registro observado"; }
}

function providerCategory(id: string): string {
  if (id === "rdap") return "DOMAIN";
  if (id === "dns-direct") return "DNS";
  if (id === "tls-direct") return "TLS";
  if (id === "transparency-passive") return "TRANSPARENCY";
  if (id.includes("cnpj")) return "BUSINESS";
  if (id.includes("consumer") || id === "reclame-aqui-manual" || id === "procon-official-warnings") return "CONSUMER";
  return "THREAT";
}

function virusTotalRegistryFacts(result: ProviderResult<VirusTotalData> | undefined): RegistryFacts["virusTotal"] {
  const reports = result?.data ? [result.data.domain, result.data.url].filter((report) => report.state === "AVAILABLE") : [];
  const stats = reports.flatMap((report) => report.stats ? [report.stats] : []);
  return {
    available: reports.length > 0,
    fresh: reports.length > 0 && reports.every((report) => report.freshness === "FRESH"),
    malicious: Math.max(0, ...stats.map((item) => item.malicious)),
    suspicious: Math.max(0, ...stats.map((item) => item.suspicious)),
    engines: Math.max(0, ...stats.map((item) => item.total)),
  };
}

function virusTotalThreatStatus(result: ProviderResult<VirusTotalData> | undefined): string {
  if (!result) return "Não verificado — VirusTotal desativado por política de uso";
  const facts = virusTotalRegistryFacts(result);
  if (!facts.available) {
    if (result.status === "RATE_LIMITED") return "Consulta VirusTotal limitada; nenhuma conclusão de segurança foi inferida";
    if (result.status === "NO_DATA") return "Sem relatório VirusTotal; ausência de dados não significa segurança";
    return "Consulta VirusTotal indisponível; a cobertura permanece limitada";
  }
  if (!facts.fresh) return "Relatório VirusTotal antigo; não usado como prova de segurança";
  return `${String(facts.malicious)} maliciosa(s), ${String(facts.suspicious)} suspeita(s), ${String(facts.engines)} resultado(s) de engine — uma única fonte agregada`;
}

function virusTotalTechnicalReport(result: ProviderResult<VirusTotalData> | undefined, rdapCreation?: string): RealScanReport["technical"]["virusTotal"] {
  if (!result) {
    return {
      state: "DISABLED_BY_POLICY",
      reason: "A API pública não é usada neste produto porque os termos proíbem produtos e serviços comerciais.",
    };
  }
  const state = result.status === "SUCCEEDED" ? "AVAILABLE" : result.status === "PARTIAL" ? "PARTIAL" : result.status;
  return {
    state,
    reason: virusTotalThreatStatus(result),
    collectedAt: result.completedAt,
    ...(result.data ? {
      policyMode: result.data.policyMode,
      disclosure: result.data.disclosure,
      domain: result.data.domain,
      url: result.data.url,
      registrationCorrelation: registrationCorrelation(result.data.domain.creationAt, rdapCreation),
    } : {}),
  };
}

function registrationCorrelation(virusTotalCreation?: string, rdapCreation?: string): "MATCH" | "MINOR_DIFFERENCE" | "CONFLICT" | "UNKNOWN" {
  if (!virusTotalCreation || !rdapCreation) return "UNKNOWN";
  const differenceDays = Math.abs(Date.parse(virusTotalCreation) - Date.parse(rdapCreation)) / 86_400_000;
  if (!Number.isFinite(differenceDays)) return "UNKNOWN";
  if (differenceDays <= 1) return "MATCH";
  if (differenceDays <= 30) return "MINOR_DIFFERENCE";
  return "CONFLICT";
}

function summaryFor(verdict: RealScanReport["verdict"]): string {
  if (verdict === "BUY") return "Bons sinais observados nas fontes disponíveis.";
  if (verdict === "CAUTION") return "Existem pontos que você deve verificar antes de comprar.";
  if (verdict === "DO_NOT_BUY") return "Foram observadas evidências fortes de risco elevado.";
  return "Não foi possível obter evidências suficientes para recomendar esta compra.";
}

function recommendationFor(verdict: RealScanReport["verdict"]): string {
  if (verdict === "BUY") return "Com base nas evidências atuais, não foram encontrados sinais relevantes que impeçam a compra. Prefira meios com contestação em compras de alto valor.";
  if (verdict === "CAUTION") return "Confirme a identidade da empresa e prefira um meio de pagamento com possibilidade de contestação.";
  if (verdict === "DO_NOT_BUY") return "Não realize a compra neste momento e não forneça dados de cartão ou documentos.";
  return "Evite pagamentos irreversíveis até confirmar a identidade da empresa por outras fontes.";
}

function ageLabel(from: string, to: string): string {
  const years = Math.max(0, (Date.parse(to) - Date.parse(from)) / 31_557_600_000);
  return Number.isFinite(years) ? `${years.toFixed(1)} ano(s)` : "Não confirmado";
}

function snapshot(job: MutableJob): ScanJobSnapshot {
  return JSON.parse(JSON.stringify(job)) as ScanJobSnapshot;
}
