import * as cheerio from "cheerio";

export type PolicyKind = "privacy" | "terms" | "returns" | "refund" | "shipping";
export type RelevantPageKind = "CONTACT" | "ABOUT" | "PRIVACY" | "TERMS" | "RETURNS" | "REFUND" | "SHIPPING" | "LEGAL" | "SUPPORT" | "OTHER";

export interface RelevantPageLink { url: string; kind: RelevantPageKind }
export interface CnpjClaim {
  value: string;
  provenance: "FOOTER" | "CONTACT" | "LEGAL" | "STRUCTURED_DATA" | "OTHER";
  sourceUrl: string;
}
export interface StructuredOrganizationClaim {
  type: string;
  name?: string | undefined;
  legalName?: string | undefined;
  email?: string | undefined;
  telephone?: string | undefined;
  address?: string | undefined;
  sameAs: string[];
}
export interface TransparencySignals {
  companyNames: string[];
  cnpjCandidates: string[];
  cnpjClaims: CnpjClaim[];
  corporateEmails: string[];
  phones: string[];
  addresses: string[];
  socialLinks: string[];
  policies: Record<PolicyKind, boolean>;
  declaredPolicies: Record<PolicyKind, boolean>;
  paymentMethods: string[];
  relevantLinks: RelevantPageLink[];
  structuredOrganizations: StructuredOrganizationClaim[];
  aboutFound: boolean;
  contactFound: boolean;
  legalFound: boolean;
  catalogFound: boolean;
  cartFound: boolean;
  checkoutDomains: string[];
  platforms: string[];
  pageTitle?: string | undefined;
}

const cnpjPattern = /\b(?:\d{2}[.\s]?\d{3}[.\s]?\d{3}[\s/]?[A-Z0-9]{4}[-\s]?[A-Z0-9]{2})\b/gi;
const phonePattern = /(?:\+?55\s*)?(?:\(?\d{2}\)?\s*)?(?:9\s*)?\d{4}[-\s]?\d{4}/g;
const emailPattern = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const socialHosts = ["instagram.com", "facebook.com", "linkedin.com", "youtube.com", "tiktok.com", "x.com", "twitter.com"];
const organizationTypes = new Set(["Organization", "LocalBusiness", "OnlineStore", "WebSite"]);
const pagePatterns: readonly [RelevantPageKind, RegExp][] = [
  ["CONTACT", /contato|fale[-\s]?conosco|atendimento|contact/i],
  ["ABOUT", /quem[-\s]?somos|sobre|institucional|about/i],
  ["PRIVACY", /privacidade|privacy/i],
  ["TERMS", /termos|conditions|terms/i],
  ["RETURNS", /troca|devolu|returns?/i],
  ["REFUND", /reembolso|refund/i],
  ["SHIPPING", /frete|entrega|envio|shipping|delivery/i],
  ["LEGAL", /aviso[-\s]?legal|legal/i],
  ["SUPPORT", /suporte|support|faq/i],
];

export function extractTransparencySignals(html: string, baseUrl: string, pageKind: RelevantPageKind = "OTHER"): TransparencySignals {
  const $ = cheerio.load(html.slice(0, 1_000_000), { xml: false });
  const structuredOrganizations = extractStructuredOrganizations($);
  $("script,style,noscript,iframe,object,embed,input,textarea,select,button").remove();
  const text = $("body").find("*").addBack().contents()
    .filter((_index, node) => (node as { type: string }).type === "text")
    .map((_index, node) => $(node).text()).get().join(" ").replace(/\s+/g, " ").slice(0, 500_000);
  const normalizedText = text.toLowerCase();
  const links = $("a[href]").map((_index, element) => ({
    href: $(element).attr("href") ?? "",
    label: $(element).text().trim(),
  })).get();
  const declaredPolicies = {
    privacy: linkMatches(links, /privacidade|privacy/),
    terms: linkMatches(links, /termos|terms|conditions/),
    returns: linkMatches(links, /troca|devolu|returns?/),
    refund: linkMatches(links, /reembolso|refund/),
    shipping: linkMatches(links, /frete|entrega|envio|shipping|delivery/),
  };
  const pageCnpjs = unique(text.match(cnpjPattern) ?? []).slice(0, 8);
  const structuredCnpjs = unique(structuredOrganizations.flatMap((item) =>
    [item.legalName ?? "", item.name ?? ""].flatMap((value) => value.match(cnpjPattern) ?? []),
  ));
  const cnpjClaims = unique([...pageCnpjs, ...structuredCnpjs]).map((value): CnpjClaim => ({
    value,
    provenance: structuredCnpjs.includes(value) ? "STRUCTURED_DATA" : cnpjProvenance($, pageKind),
    sourceUrl: stripUrl(baseUrl),
  }));
  const addresses = unique([
    ...$("[itemprop='address'], address").map((_index, element) => $(element).text().replace(/\s+/g, " ").trim().slice(0, 240)).get(),
    ...structuredOrganizations.flatMap((item) => item.address ? [item.address] : []),
  ]).slice(0, 10);
  const corporateEmails = unique([
    ...(text.match(emailPattern) ?? []),
    ...structuredOrganizations.flatMap((item) => item.email ? [item.email] : []),
  ]).slice(0, 12);
  const phones = unique([
    ...(text.match(phonePattern) ?? []),
    ...structuredOrganizations.flatMap((item) => item.telephone ? [item.telephone] : []),
  ]).slice(0, 12);
  const socialLinks = unique([
    ...links.flatMap((link) => normalizeSocialUrl(link.href, baseUrl)),
    ...structuredOrganizations.flatMap((item) => item.sameAs.flatMap((url) => normalizeSocialUrl(url, baseUrl))),
  ]).slice(0, 12);
  const paymentMethods = [
    ["PIX", /\bpix\b/i], ["CARD", /cart[aã]o|credit card|visa|mastercard/i],
    ["BOLETO", /\bboleto\b/i], ["PAYPAL", /\bpaypal\b/i], ["MERCADO_PAGO", /mercado\s*pago/i],
  ].filter(([, pattern]) => (pattern as RegExp).test(text)).map(([name]) => name as string);
  const checkoutDomains = unique(links.flatMap((link) => {
    if (!/checkout|carrinho|cart|finalizar|comprar/i.test(`${link.label} ${link.href}`)) return [];
    try {
      const url = new URL(link.href, baseUrl);
      return ["http:", "https:"].includes(url.protocol) ? [url.hostname.toLowerCase()] : [];
    } catch { return []; }
  })).slice(0, 8);
  const catalogFound = /["']@type["']\s*:\s*["']Product["']/i.test(html)
    || links.some((link) => /produto|product|cole[cç][aã]o|catalog/i.test(`${link.label} ${link.href}`));
  const cartFound = links.some((link) => /carrinho|cart|checkout|finalizar/i.test(`${link.label} ${link.href}`))
    || /add_to_cart|adicionar ao carrinho|comprar agora/i.test(html);

  return {
    companyNames: unique([
      ...$("[itemprop='name'], [itemtype*='Organization'] [itemprop='legalName']")
        .map((_index, element) => $(element).text().trim().slice(0, 160)).get(),
      ...structuredOrganizations.flatMap((item) => [item.legalName ?? "", item.name ?? ""]),
    ]).filter(Boolean).slice(0, 12),
    cnpjCandidates: cnpjClaims.map((item) => item.value),
    cnpjClaims,
    corporateEmails,
    phones,
    addresses,
    socialLinks,
    policies: confirmedPolicies(normalizedText),
    declaredPolicies,
    paymentMethods,
    relevantLinks: extractRelevantLinks(links, baseUrl),
    structuredOrganizations,
    aboutFound: pageKind === "ABOUT" || /quem somos|about us|nossa hist[oó]ria/i.test(normalizedText),
    contactFound: pageKind === "CONTACT" || corporateEmails.length > 0 || phones.length > 0 || addresses.length > 0,
    legalFound: pageKind === "LEGAL" || /aviso legal|legal notice|raz[aã]o social/i.test(normalizedText),
    catalogFound,
    cartFound,
    checkoutDomains,
    platforms: detectPlatforms(html),
    pageTitle: $("title").first().text().trim().slice(0, 160) || undefined,
  };
}

function confirmedPolicies(text: string): Record<PolicyKind, boolean> {
  const substantial = text.split(/\s+/).length >= 35;
  return {
    privacy: substantial && /dados pessoais|prote[cç][aã]o de dados|data protection|privacy policy|cookies|\blgpd\b/i.test(text),
    terms: substantial && /termos de uso|terms of (?:use|service)|condi[cç][oõ]es (?:de uso|gerais)/i.test(text),
    returns: substantial && /prazo.{0,40}(?:troca|devolu)|pol[ií]tica.{0,30}(?:troca|devolu)|return policy/i.test(text),
    refund: substantial && /reembolso|estorno|refund policy/i.test(text),
    shipping: substantial && /prazo.{0,40}(?:entrega|envio)|pol[ií]tica.{0,30}(?:frete|entrega|envio)|shipping policy|delivery time/i.test(text),
  };
}

function extractRelevantLinks(links: { href: string; label: string }[], baseUrl: string): RelevantPageLink[] {
  const base = new URL(baseUrl);
  const seen = new Set<string>();
  return links.flatMap((link) => {
    const match = pagePatterns.find(([, pattern]) => pattern.test(`${link.label} ${link.href}`));
    if (!match) return [];
    try {
      const url = new URL(link.href, base);
      url.hash = "";
      const normalized = url.toString();
      if (!["http:", "https:"].includes(url.protocol) || url.origin !== base.origin || seen.has(normalized)) return [];
      seen.add(normalized);
      return [{ url: normalized, kind: match[0] }];
    } catch { return []; }
  }).slice(0, 30);
}

function extractStructuredOrganizations($: cheerio.CheerioAPI): StructuredOrganizationClaim[] {
  const claims: StructuredOrganizationClaim[] = [];
  const budget = { remaining: 1_000 };
  $("script[type='application/ld+json']").slice(0, 20).each((_index, element) => {
    if (budget.remaining <= 0 || claims.length >= 20) return;
    try { visitStructuredValue(JSON.parse($(element).text().slice(0, 128_000)) as unknown, claims, budget); } catch { /* ignore hostile JSON */ }
  });
  return claims.slice(0, 20);
}

function visitStructuredValue(value: unknown, claims: StructuredOrganizationClaim[], budget: { remaining: number }, depth = 0): void {
  budget.remaining -= 1;
  if (budget.remaining < 0 || claims.length >= 20 || depth > 6 || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.slice(0, 50).forEach((item) => visitStructuredValue(item, claims, budget, depth + 1));
    return;
  }
  const record = value as Record<string, unknown>;
  if (Array.isArray(record["@graph"])) visitStructuredValue(record["@graph"], claims, budget, depth + 1);
  const rawType = record["@type"];
  const types = Array.isArray(rawType)
    ? rawType.flatMap((item) => typeof item === "string" ? [item] : [])
    : typeof rawType === "string" ? [rawType] : [];
  const type = types.find((item) => organizationTypes.has(item));
  if (!type) return;
  claims.push({
    type,
    name: boundedString(record.name),
    legalName: boundedString(record.legalName),
    email: boundedString(record.email),
    telephone: boundedString(record.telephone),
    address: structuredAddress(record.address),
    sameAs: Array.isArray(record.sameAs) ? record.sameAs.flatMap((item) => typeof item === "string" ? [item] : []).slice(0, 20) : [],
  });
}

function structuredAddress(value: unknown): string | undefined {
  if (typeof value === "string") return value.trim().slice(0, 240) || undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const parts = ["streetAddress", "addressLocality", "addressRegion", "postalCode", "addressCountry"]
    .flatMap((key) => typeof record[key] === "string" ? [record[key].trim()] : []);
  return parts.length ? parts.join(", ").slice(0, 240) : undefined;
}

function detectPlatforms(html: string): string[] {
  const patterns: readonly [string, RegExp][] = [
    ["Shopify", /cdn\.shopify\.com|shopify-section|myshopify\.com/i],
    ["WooCommerce", /woocommerce|wp-content\/plugins\/woocommerce/i],
    ["Nuvemshop", /nuvemshop|tiendanube/i],
    ["VTEX", /vtexassets|vtex\.com|__RUNTIME__/i],
    ["Magento", /mage\/|magento|static\/version\d+\/frontend/i],
  ];
  return patterns.filter(([, pattern]) => pattern.test(html)).map(([name]) => name);
}

function cnpjProvenance($: cheerio.CheerioAPI, pageKind: RelevantPageKind): CnpjClaim["provenance"] {
  if (pageKind === "CONTACT") return "CONTACT";
  if (["LEGAL", "PRIVACY", "TERMS"].includes(pageKind)) return "LEGAL";
  if ($("footer").text().match(cnpjPattern)) return "FOOTER";
  return "OTHER";
}
function normalizeSocialUrl(value: string, baseUrl: string): string[] {
  try {
    const url = new URL(value, baseUrl);
    const host = url.hostname.toLowerCase();
    const recognized = socialHosts.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
    return recognized && ["http:", "https:"].includes(url.protocol) ? [`${url.protocol}//${host}${url.pathname}`] : [];
  } catch { return []; }
}
function linkMatches(links: { href: string; label: string }[], pattern: RegExp): boolean {
  return links.some((link) => pattern.test(`${link.label} ${link.href}`));
}
function boundedString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim().slice(0, 240) : undefined;
}
function stripUrl(value: string): string {
  const url = new URL(value); url.search = ""; url.hash = ""; return url.toString();
}
function unique(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
