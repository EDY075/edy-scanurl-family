import type { ProviderStatus } from "../providers/contracts.js";

export type TraceState =
  | "PASS" | "WARNING" | "FAIL" | "CRITICAL"
  | "UNKNOWN" | "UNAVAILABLE" | "NOT_CHECKED" | "NOT_APPLICABLE";

export interface ProviderReceipt {
  status: ProviderStatus;
  durationMs: number;
}

export interface RegistryFacts {
  providers: Record<string, ProviderReceipt | undefined>;
  rdap: { registrationDate?: string; updatedDate?: string; registrar?: string; statuses: string[] };
  dns: { addresses: number; nameservers: number; mailExchangers: number; caa: number; dnssec?: "SIGNED" | "NOT_OBSERVED" | "UNKNOWN" };
  tls: { available: boolean; authorized: boolean; daysRemaining?: number };
  virusTotal: {
    available: boolean;
    fresh: boolean;
    malicious: number;
    suspicious: number;
    engines: number;
  };
  http: {
    redirects: number;
    headerCount: number;
    securityHeaders: Record<"hsts" | "csp" | "frameProtection" | "referrerPolicy" | "permissionsPolicy" | "noSniff", boolean>;
    finalHostname: boolean;
    pagesFetched: number;
    pagesDiscovered: number;
    partial: boolean;
    companyNames: number;
    cnpjClaims: number;
    distinctCnpj: number;
    structuredOrganizations: number;
    contacts: number;
    addresses: number;
    emails: number;
    phones: number;
    about: boolean;
    privacy: boolean;
    terms: boolean;
    returns: boolean;
    refund: boolean;
    shipping: boolean;
    legal: boolean;
    socialLinks: number;
    catalog: boolean;
    paymentMethods: number;
    platforms: number;
    checkoutDomains: number;
  };
}

export interface CheckExecutionTrace {
  check: string;
  category: string;
  title: string;
  attempted: boolean;
  finalState: TraceState;
  provider: string;
  durationMs: number;
  evidenceCount: number;
  reason: string;
}

interface Evaluation { state: TraceState; evidence: number; reason: string }
interface RegistryEntry {
  id: string;
  category: string;
  title: string;
  provider: string;
  evaluate(facts: RegistryFacts): Evaluation;
}

const present = (count: number, reason: string): Evaluation =>
  count > 0 ? { state: "PASS", evidence: count, reason } : { state: "UNKNOWN", evidence: 0, reason: "NO_USABLE_EVIDENCE" };
const observed = (value: boolean, reason: string): Evaluation =>
  value ? { state: "PASS", evidence: 1, reason } : { state: "UNKNOWN", evidence: 0, reason: "NO_USABLE_EVIDENCE" };
const declared = (count: number, reason: string): Evaluation =>
  count > 0 ? { state: "UNKNOWN", evidence: count, reason } : { state: "UNKNOWN", evidence: 0, reason: "NO_USABLE_EVIDENCE" };
const unavailable = (reason: string): Evaluation => ({ state: "UNAVAILABLE", evidence: 0, reason });
const notChecked = (reason: string): Evaluation => ({ state: "NOT_CHECKED", evidence: 0, reason });
const notApplicable = (reason: string): Evaluation => ({ state: "NOT_APPLICABLE", evidence: 0, reason });

export const SCAN_CHECK_REGISTRY: readonly RegistryEntry[] = [
  entry("DOMAIN_RDAP", "DOMAIN", "RDAP autoritativo", "rdap", (f) => providerObserved(f, "rdap", 1, "RDAP_RESPONSE_OBSERVED")),
  entry("DOMAIN_AGE", "DOMAIN", "Idade do domínio", "rdap", (f) => present(f.rdap.registrationDate ? 1 : 0, "REGISTRATION_DATE_OBSERVED")),
  entry("DOMAIN_UPDATED", "DOMAIN", "Última atualização do domínio", "rdap", (f) => present(f.rdap.updatedDate ? 1 : 0, "RDAP_UPDATE_DATE_OBSERVED")),
  entry("DOMAIN_REGISTRAR", "DOMAIN", "Entidade registradora", "rdap", (f) => present(f.rdap.registrar ? 1 : 0, "REGISTRAR_OBSERVED")),
  entry("DOMAIN_DNS", "DOMAIN", "Resolução DNS", "dns-direct", (f) => providerObserved(f, "dns-direct", f.dns.addresses, "PUBLIC_ADDRESSES_OBSERVED")),
  entry("DOMAIN_NAMESERVERS", "DOMAIN", "Nameservers autoritativos", "dns-direct", (f) => providerObserved(f, "dns-direct", f.dns.nameservers, "NAMESERVERS_OBSERVED")),
  entry("DOMAIN_MX", "DOMAIN", "Servidores de e-mail (MX)", "dns-direct", (f) => providerObserved(f, "dns-direct", f.dns.mailExchangers, "MX_RECORDS_OBSERVED")),
  entry("DOMAIN_CAA", "DOMAIN", "Autoridades certificadoras (CAA)", "dns-direct", (f) =>
    f.providers["dns-direct"]?.status === "SUCCEEDED"
      ? (f.dns.caa > 0 ? { state: "PASS", evidence: f.dns.caa, reason: "CAA_RECORDS_OBSERVED" } : { state: "UNKNOWN", evidence: 0, reason: "CAA_RECORDS_NOT_OBSERVED" })
      : unavailable(`PROVIDER_${f.providers["dns-direct"]?.status ?? "NOT_EXECUTED"}`)),
  entry("DOMAIN_DNSSEC", "DOMAIN", "DNSSEC", "dns-direct", (f) =>
    f.dns.dnssec === "SIGNED" ? { state: "PASS", evidence: 1, reason: "DS_RECORD_OBSERVED" }
      : { state: "UNKNOWN", evidence: 0, reason: "DS_RECORD_NOT_OBSERVED" }),
  entry("DOMAIN_STATUS", "DOMAIN", "Status do domínio", "rdap", (f) => present(f.rdap.statuses.length, "RDAP_STATUS_OBSERVED")),
  entry("TLS_HTTPS", "TLS", "HTTPS disponível", "tls-direct", (f) => observed(f.tls.available, "TLS_ENDPOINT_OBSERVED")),
  entry("TLS_CERTIFICATE", "TLS", "Certificado TLS", "tls-direct", (f) =>
    !f.tls.available ? { state: "UNKNOWN", evidence: 0, reason: "TLS_NOT_OBSERVED" }
      : f.tls.authorized ? { state: "PASS", evidence: 1, reason: "CERTIFICATE_AUTHORIZED" }
        : { state: "WARNING", evidence: 1, reason: "CERTIFICATE_NOT_AUTHORIZED" }),
  entry("TLS_HOSTNAME", "TLS", "Compatibilidade do hostname", "tls-direct", (f) =>
    f.tls.authorized ? { state: "PASS", evidence: 1, reason: "HOSTNAME_VALIDATED_BY_TLS" }
      : { state: "UNKNOWN", evidence: 0, reason: "HOSTNAME_NOT_CONFIRMED" }),
  entry("TLS_EXPIRATION", "TLS", "Validade do certificado", "tls-direct", (f) => {
    const days = f.tls.daysRemaining;
    if (days === undefined) return { state: "UNKNOWN", evidence: 0, reason: "EXPIRATION_NOT_OBSERVED" };
    if (days < 0) return { state: "FAIL", evidence: 1, reason: "CERTIFICATE_EXPIRED" };
    return days <= 30 ? { state: "WARNING", evidence: 1, reason: "CERTIFICATE_EXPIRES_SOON" }
      : { state: "PASS", evidence: 1, reason: "CERTIFICATE_VALIDITY_OBSERVED" };
  }),
  entry("HTTP_REDIRECTS", "HTTP", "Redirecionamentos HTTP", "transparency-passive", (f) =>
    providerObserved(f, "transparency-passive", 1, `${String(f.http.redirects)}_REDIRECTS_VALIDATED`)),
  entry("HTTP_FINAL_HOSTNAME", "HTTP", "Hostname final", "transparency-passive", (f) => observed(f.http.finalHostname, "FINAL_HOSTNAME_OBSERVED")),
  entry("HTTP_HEADERS", "HTTP", "Cabeçalhos HTTP", "transparency-passive", (f) =>
    f.http.headerCount >= 3 ? { state: "PASS", evidence: f.http.headerCount, reason: "SECURITY_HEADERS_OBSERVED" }
      : f.http.headerCount > 0 ? { state: "WARNING", evidence: f.http.headerCount, reason: "LIMITED_SECURITY_HEADERS" }
        : { state: "UNKNOWN", evidence: 0, reason: "HEADERS_NOT_OBSERVED" }),
  ...(["hsts", "csp", "frameProtection", "referrerPolicy", "permissionsPolicy", "noSniff"] as const).map((header) =>
    entry(`HTTP_HEADER_${header.toUpperCase()}`, "HTTP", `Cabeçalho ${header}`, "transparency-passive", (f) =>
      f.providers["transparency-passive"]?.status === "SUCCEEDED" || f.providers["transparency-passive"]?.status === "PARTIAL"
        ? (f.http.securityHeaders[header]
            ? { state: "PASS", evidence: 1, reason: `${header.toUpperCase()}_OBSERVED` }
            : { state: "WARNING", evidence: 1, reason: `${header.toUpperCase()}_NOT_OBSERVED` })
        : unavailable(`PROVIDER_${f.providers["transparency-passive"]?.status ?? "NOT_EXECUTED"}`))),
  entry("HTTP_CONTENT", "HTTP", "Conteúdo passivo", "transparency-passive", (f) =>
    present(f.http.pagesFetched, f.http.partial ? "PARTIAL_CRAWL_EVIDENCE" : "CRAWL_EVIDENCE_OBSERVED")),
  entry("BUSINESS_SITE_IDENTITY", "BUSINESS", "Identidade declarada no site", "transparency-passive", (f) => declared(f.http.companyNames, "SITE_CLAIM_OBSERVED_NOT_INDEPENDENTLY_VERIFIED")),
  entry("BUSINESS_CNPJ_SITE", "BUSINESS", "CNPJ declarado no site", "transparency-passive", (f) => declared(f.http.cnpjClaims, "CNPJ_SITE_CLAIM_OBSERVED_NOT_INDEPENDENTLY_VERIFIED")),
  entry("BUSINESS_OFFICIAL_VALIDATION", "BUSINESS", "Validação empresarial oficial", "business-cnpj-bulk", () => notChecked("OFFICIAL_PROVIDER_NOT_PROVISIONED")),
  entry("BUSINESS_CORRELATION", "BUSINESS", "Correlação empresa e domínio", "edy-correlation", () => notChecked("OFFICIAL_IDENTITY_NOT_AVAILABLE")),
  entry("BUSINESS_STRUCTURED_DATA", "BUSINESS", "Dados estruturados empresariais", "transparency-passive", (f) => declared(f.http.structuredOrganizations, "JSON_LD_SITE_CLAIM_OBSERVED_NOT_INDEPENDENTLY_VERIFIED")),
  entry("TRANSPARENCY_CONTACT", "TRANSPARENCY", "Página ou dados de contato", "transparency-passive", (f) => declared(f.http.contacts, "CONTACT_SITE_CLAIM_OBSERVED_NOT_INDEPENDENTLY_VERIFIED")),
  entry("TRANSPARENCY_ADDRESS", "TRANSPARENCY", "Endereço declarado", "transparency-passive", (f) => declared(f.http.addresses, "ADDRESS_SITE_CLAIM_OBSERVED_NOT_INDEPENDENTLY_VERIFIED")),
  entry("TRANSPARENCY_EMAIL", "TRANSPARENCY", "E-mail declarado", "transparency-passive", (f) => declared(f.http.emails, "EMAIL_SITE_CLAIM_OBSERVED_NOT_INDEPENDENTLY_VERIFIED")),
  entry("TRANSPARENCY_PHONE", "TRANSPARENCY", "Telefone declarado", "transparency-passive", (f) => declared(f.http.phones, "PHONE_SITE_CLAIM_OBSERVED_NOT_INDEPENDENTLY_VERIFIED")),
  entry("TRANSPARENCY_ABOUT", "TRANSPARENCY", "Conteúdo institucional", "transparency-passive", (f) => observed(f.http.about, "ABOUT_CONTENT_CONFIRMED")),
  entry("TRANSPARENCY_PRIVACY", "TRANSPARENCY", "Política de privacidade", "transparency-passive", (f) => observed(f.http.privacy, "PRIVACY_CONTENT_CONFIRMED")),
  entry("TRANSPARENCY_TERMS", "TRANSPARENCY", "Termos de uso", "transparency-passive", (f) => observed(f.http.terms, "TERMS_CONTENT_CONFIRMED")),
  entry("TRANSPARENCY_RETURNS", "TRANSPARENCY", "Política de trocas/devoluções", "transparency-passive", (f) => observed(f.http.returns, "RETURNS_CONTENT_CONFIRMED")),
  entry("TRANSPARENCY_REFUND", "TRANSPARENCY", "Política de reembolso", "transparency-passive", (f) => observed(f.http.refund, "REFUND_CONTENT_CONFIRMED")),
  entry("TRANSPARENCY_SHIPPING", "TRANSPARENCY", "Política de frete/entrega", "transparency-passive", (f) => observed(f.http.shipping, "SHIPPING_CONTENT_CONFIRMED")),
  entry("TRANSPARENCY_LEGAL", "TRANSPARENCY", "Aviso ou identificação legal", "transparency-passive", (f) => observed(f.http.legal, "LEGAL_CONTENT_CONFIRMED")),
  entry("THREAT_WEB_RISK", "THREAT", "Google Web Risk", "google-web-risk", () => unavailable("BILLING_ACCOUNT_REQUIRED")),
  entry("THREAT_VIRUSTOTAL", "THREAT", "VirusTotal", "virus-total-public", (f) => {
    const receipt = f.providers["virus-total-public"];
    if (!receipt) return unavailable("DISABLED_BY_POLICY_COMMERCIAL_USE_PROHIBITED");
    if (receipt.status !== "SUCCEEDED" && receipt.status !== "PARTIAL") return unavailable(`PROVIDER_${receipt.status}`);
    if (!f.virusTotal.available) return { state: "UNKNOWN", evidence: 0, reason: "VIRUSTOTAL_NO_REPORT" };
    if (!f.virusTotal.fresh) return { state: "UNKNOWN", evidence: 1, reason: "VIRUSTOTAL_REPORT_STALE" };
    if (f.virusTotal.malicious >= 3) return { state: "CRITICAL", evidence: 1, reason: "VIRUSTOTAL_MULTIPLE_MALICIOUS_DETECTIONS" };
    if (f.virusTotal.malicious > 0) return { state: "FAIL", evidence: 1, reason: "VIRUSTOTAL_MALICIOUS_DETECTION" };
    if (f.virusTotal.suspicious > 0) return { state: "WARNING", evidence: 1, reason: "VIRUSTOTAL_SUSPICIOUS_DETECTION" };
    return { state: "UNKNOWN", evidence: 1, reason: "VIRUSTOTAL_NO_MALICIOUS_DETECTION_NOT_SAFETY_PROOF" };
  }),
  entry("THREAT_URLHAUS", "THREAT", "URLhaus", "urlhaus-community", () => unavailable("COMMERCIAL_FAIR_USE_NOT_CONFIRMED")),
  entry("THREAT_PHISHTANK", "THREAT", "PhishTank", "phishtank", () => unavailable("PROVIDER_NOT_PROVISIONED")),
  entry("CONSUMER_GOV_OPEN_DATA", "CONSUMER", "Consumidor.gov.br", "consumer-gov-open-data", () => unavailable("OPEN_DATA_SNAPSHOT_NOT_PROVISIONED")),
  entry("CONSUMER_RECLAME_AQUI", "CONSUMER", "Reclame AQUI", "reclame-aqui-manual", () => notChecked("MANUAL_REVIEW_ONLY")),
  entry("CONSUMER_PROCON", "CONSUMER", "Alertas oficiais do Procon", "procon-official-warnings", () => unavailable("NATIONAL_AUTOMATIC_SOURCE_NOT_PROVISIONED")),
  entry("PUBLIC_SOCIAL_PRESENCE", "PRESENCE", "Presença social declarada", "transparency-passive", (f) => declared(f.http.socialLinks, "DECLARED_SOCIAL_LINKS_OBSERVED_NOT_INDEPENDENTLY_VERIFIED")),
  entry("COMMERCE_CATALOG", "COMMERCE", "Catálogo comercial", "transparency-passive", (f) => observed(f.http.catalog, "CATALOG_SIGNAL_OBSERVED")),
  entry("COMMERCE_PAYMENT_METHODS", "COMMERCE", "Métodos de pagamento declarados", "transparency-passive", (f) =>
    !f.http.catalog ? notApplicable("NO_COMMERCE_CONTEXT_OBSERVED") : declared(f.http.paymentMethods, "PAYMENT_SITE_CLAIMS_OBSERVED_NOT_INDEPENDENTLY_VERIFIED")),
  entry("COMMERCE_PLATFORM", "COMMERCE", "Plataforma comercial", "transparency-passive", (f) =>
    !f.http.catalog ? notApplicable("NO_COMMERCE_CONTEXT_OBSERVED") : present(f.http.platforms, "PLATFORM_FINGERPRINT_OBSERVED")),
  entry("COMMERCE_CHECKOUT_DOMAIN", "COMMERCE", "Domínio de checkout declarado", "transparency-passive", (f) =>
    !f.http.catalog ? notApplicable("NO_COMMERCE_CONTEXT_OBSERVED") : declared(f.http.checkoutDomains, "CHECKOUT_LINK_OBSERVED_NOT_INDEPENDENTLY_VERIFIED")),
  entry("EVIDENCE_CONSISTENCY", "CONSISTENCY", "Consistência das autoalegações", "edy-correlation", (f) =>
    f.http.distinctCnpj > 1 ? { state: "WARNING", evidence: f.http.distinctCnpj, reason: "CONFLICTING_SITE_CLAIMS" }
      : f.http.cnpjClaims + f.http.companyNames > 0
        ? { state: "UNKNOWN", evidence: f.http.cnpjClaims + f.http.companyNames, reason: "SITE_CLAIMS_NOT_INDEPENDENTLY_VERIFIED" }
        : { state: "UNKNOWN", evidence: 0, reason: "INSUFFICIENT_CLAIMS_FOR_CORRELATION" }),
] as const;

export function evaluateCheckRegistry(facts: RegistryFacts): {
  trace: CheckExecutionTrace[];
  scanCompletion: number;
  evidenceCoverage: number;
  silentSkips: number;
} {
  const trace = SCAN_CHECK_REGISTRY.map((item): CheckExecutionTrace => {
    const evaluation = item.evaluate(facts);
    const receipt = facts.providers[item.provider];
    return {
      check: item.id,
      category: item.category,
      title: item.title,
      attempted: true,
      finalState: evaluation.state,
      provider: item.provider,
      durationMs: receipt?.durationMs ?? 0,
      evidenceCount: evaluation.evidence,
      reason: evaluation.reason,
    };
  });
  const applicable = trace.filter((item) => item.finalState !== "NOT_APPLICABLE");
  const useful = applicable.filter((item) => ["PASS", "WARNING", "FAIL", "CRITICAL"].includes(item.finalState));
  return {
    trace,
    scanCompletion: applicable.length === 0 ? 100 : round((applicable.length / applicable.length) * 100),
    evidenceCoverage: applicable.length === 0 ? 0 : round((useful.length / applicable.length) * 100),
    silentSkips: trace.filter((item) => !item.attempted).length,
  };
}

function entry(
  id: string,
  category: string,
  title: string,
  provider: string,
  evaluate: (facts: RegistryFacts) => Evaluation,
): RegistryEntry {
  return { id, category, title, provider, evaluate };
}

function providerObserved(
  facts: RegistryFacts,
  provider: string,
  count: number,
  reason: string,
): Evaluation {
  const status = facts.providers[provider]?.status;
  if (status === "SUCCEEDED" || status === "PARTIAL") return present(count, reason);
  if (status === undefined) return unavailable("PROVIDER_NOT_EXECUTED");
  return unavailable(`PROVIDER_${status}`);
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}
