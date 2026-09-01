import { GuardedFetcher } from "../security/guarded-fetch.js";
import {
  extractTransparencySignals,
  type RelevantPageKind,
  type TransparencySignals,
} from "../security/html-signals.js";
import { providerResult, type ProviderContext, type ProviderResult, type ScanProvider } from "./contracts.js";

export interface CrawlPageReceipt {
  url: string;
  kind: RelevantPageKind | "HOME";
  selected: boolean;
  outcome: "FETCHED" | "SKIPPED" | "FAILED";
  reason: string;
  bytes: number;
  redirects: number;
  durationMs: number;
}

export interface HttpTransparencyData {
  statusCode: number;
  finalOrigin: string;
  redirects: number;
  securityHeaders: Record<string, boolean>;
  signals: TransparencySignals;
  pagesDiscovered: number;
  pagesFetched: number;
  notSelectedByLimit: number;
  discoveryTruncated: boolean;
  crawlManifest: CrawlPageReceipt[];
}

const MAX_CHILD_PAGES = 10;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024;
const CHILD_MAX_BYTES = 256 * 1024;
const ACTION_PATH = /(?:^|\/)(?:login|signin|sign-in|logout|logoff|cart|carrinho|checkout|order|orders|pedido|pedidos|delete|remove|api|download|downloads|search|busca|oauth|auth|admin|account|conta|unsubscribe)(?:[/.?;_-]|$)/i;

export class HttpTransparencyProvider implements ScanProvider<HttpTransparencyData> {
  readonly id = "transparency-passive";
  readonly version = "2.0.0";
  readonly category = "TRANSPARENCY" as const;

  constructor(private readonly fetcher = new GuardedFetcher()) {}

  async execute(context: ProviderContext): Promise<ProviderResult<HttpTransparencyData>> {
    const startedAt = new Date().toISOString();
    const crawlOrigin = new URL(context.targetUrl).origin;
    const deadlineAt = Date.now() + 8_000;
    const manifest: CrawlPageReceipt[] = [];
    try {
      const homeStarted = Date.now();
      const response = await this.fetcher.fetch(context.targetUrl, {
        timeoutMs: 4_300,
        maxBytes: 512 * 1024,
        maxRedirects: 2,
        allowedOrigin: crawlOrigin,
        allowedUrl: isPassivePageUrl,
        requireContentType: true,
        signal: context.signal,
      });
      if (!isSuccessful(response.statusCode)) throw new Error(`HTTP_STATUS_${String(response.statusCode)}`);
      const final = new URL(response.finalUrl);
      const homeSignals = extractTransparencySignals(response.body.toString("utf8"), response.finalUrl);
      manifest.push({
        url: redactPageUrl(response.finalUrl),
        kind: "HOME",
        selected: true,
        outcome: "FETCHED",
        reason: "HOMEPAGE_FETCHED",
        bytes: response.body.length,
        redirects: response.redirectChain.length,
        durationMs: Date.now() - homeStarted,
      });

      const safeLinks = homeSignals.relevantLinks
        .filter((item) => isPassivePageUrl(new URL(item.url)))
        .sort((a, b) => a.kind.localeCompare(b.kind) || a.url.localeCompare(b.url));
      const selected = safeLinks.slice(0, MAX_CHILD_PAGES);
      const notSelectedByLimit = Math.max(0, safeLinks.length - selected.length);
      let remainingBytes = Math.max(0, MAX_TOTAL_BYTES - response.body.length);
      const childSignals: TransparencySignals[] = [];

      await mapConcurrent(selected, 2, async (page) => {
        const reserve = Math.min(CHILD_MAX_BYTES, remainingBytes);
        remainingBytes -= reserve;
        const pageStarted = Date.now();
        if (reserve <= 0 || Date.now() >= deadlineAt - 250) {
          manifest.push({
            url: redactPageUrl(page.url), kind: page.kind, selected: true, outcome: "SKIPPED",
            reason: reserve <= 0 ? "CRAWL_BYTE_BUDGET_EXHAUSTED" : "CRAWL_DEADLINE_EXHAUSTED",
            bytes: 0, redirects: 0, durationMs: Date.now() - pageStarted,
          });
          return;
        }
        try {
          const child = await this.fetcher.fetch(page.url, {
            timeoutMs: Math.max(250, Math.min(3_200, deadlineAt - Date.now())),
            maxBytes: reserve,
            maxRedirects: 2,
            allowedOrigin: crawlOrigin,
            allowedUrl: isPassivePageUrl,
            requireContentType: true,
            signal: context.signal,
          });
          if (!isSuccessful(child.statusCode)) {
            manifest.push({
              url: redactPageUrl(child.finalUrl), kind: page.kind, selected: true, outcome: "FAILED",
              reason: `HTTP_STATUS_${String(child.statusCode)}`, bytes: child.body.length,
              redirects: child.redirectChain.length, durationMs: Date.now() - pageStarted,
            });
            return;
          }
          remainingBytes += Math.max(0, reserve - child.body.length);
          childSignals.push(extractTransparencySignals(child.body.toString("utf8"), child.finalUrl, page.kind));
          manifest.push({
            url: redactPageUrl(child.finalUrl), kind: page.kind, selected: true, outcome: "FETCHED",
            reason: "RELEVANT_PAGE_FETCHED", bytes: child.body.length,
            redirects: child.redirectChain.length, durationMs: Date.now() - pageStarted,
          });
        } catch (error) {
          manifest.push({
            url: redactPageUrl(page.url), kind: page.kind, selected: true, outcome: "FAILED",
            reason: safeErrorCode(error), bytes: 0, redirects: 0, durationMs: Date.now() - pageStarted,
          });
        }
      });

      const signals = mergeSignals([homeSignals, ...childSignals]);
      const partial = notSelectedByLimit > 0 || manifest.some((item) => item.outcome !== "FETCHED");
      return providerResult(this, startedAt, partial ? "PARTIAL" : "SUCCEEDED", {
        sourceUrl: final.origin,
        data: {
          statusCode: response.statusCode,
          finalOrigin: final.origin,
          redirects: response.redirectChain.length,
          securityHeaders: {
            hsts: hasHeader(response.headers, "strict-transport-security"),
            csp: hasHeader(response.headers, "content-security-policy"),
            frameProtection: hasHeader(response.headers, "x-frame-options")
              || String(response.headers["content-security-policy"] ?? "").includes("frame-ancestors"),
            referrerPolicy: hasHeader(response.headers, "referrer-policy"),
            permissionsPolicy: hasHeader(response.headers, "permissions-policy"),
            noSniff: String(response.headers["x-content-type-options"] ?? "").toLowerCase() === "nosniff",
          },
          signals,
          pagesDiscovered: safeLinks.length,
          pagesFetched: manifest.filter((item) => item.outcome === "FETCHED").length,
          notSelectedByLimit,
          discoveryTruncated: notSelectedByLimit > 0,
          crawlManifest: manifest,
        },
      });
    } catch (error) {
      const code = safeErrorCode(error);
      return providerResult(this, startedAt, isTimeoutCode(code) ? "TIMED_OUT" : "FAILED", { errorCode: code });
    }
  }
}

function mergeSignals(items: TransparencySignals[]): TransparencySignals {
  const policyKeys = ["privacy", "terms", "returns", "refund", "shipping"] as const;
  const merged = items[0];
  if (!merged) throw new Error("TRANSPARENCY_EMPTY");
  return {
    companyNames: unique(items.flatMap((item) => item.companyNames)),
    cnpjCandidates: unique(items.flatMap((item) => item.cnpjCandidates)),
    cnpjClaims: uniqueBy(items.flatMap((item) => item.cnpjClaims), (item) => `${item.value}:${item.sourceUrl}`),
    corporateEmails: unique(items.flatMap((item) => item.corporateEmails)),
    phones: unique(items.flatMap((item) => item.phones)),
    addresses: unique(items.flatMap((item) => item.addresses)),
    socialLinks: unique(items.flatMap((item) => item.socialLinks)),
    policies: Object.fromEntries(policyKeys.map((key) => [key, items.some((item) => item.policies[key])])) as TransparencySignals["policies"],
    declaredPolicies: Object.fromEntries(policyKeys.map((key) => [key, items.some((item) => item.declaredPolicies[key])])) as TransparencySignals["declaredPolicies"],
    paymentMethods: unique(items.flatMap((item) => item.paymentMethods)),
    relevantLinks: merged.relevantLinks,
    structuredOrganizations: uniqueBy(items.flatMap((item) => item.structuredOrganizations), (item) => JSON.stringify(item)),
    aboutFound: items.some((item) => item.aboutFound),
    contactFound: items.some((item) => item.contactFound),
    legalFound: items.some((item) => item.legalFound),
    catalogFound: items.some((item) => item.catalogFound),
    cartFound: items.some((item) => item.cartFound),
    checkoutDomains: unique(items.flatMap((item) => item.checkoutDomains)),
    platforms: unique(items.flatMap((item) => item.platforms)),
    pageTitle: merged.pageTitle,
  };
}

async function mapConcurrent<T>(items: T[], concurrency: number, operation: (item: T) => Promise<void>): Promise<void> {
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      const item = items[index];
      if (item !== undefined) await operation(item);
    }
  }));
}

function redactPageUrl(value: string): string {
  const url = new URL(value);
  url.search = "";
  url.hash = "";
  return url.toString().slice(0, 500);
}
function safeErrorCode(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 100) : "HTTP_FAILED";
}
function isTimeoutCode(code: string): boolean {
  return /TIMEOUT|DEADLINE|ABORTED/.test(code);
}
function isSuccessful(statusCode: number): boolean {
  return statusCode >= 200 && statusCode < 300;
}
function isPassivePageUrl(url: URL): boolean {
  const pathname = canonicalPathname(url.pathname);
  return pathname !== null && !ACTION_PATH.test(pathname);
}
function canonicalPathname(pathname: string): string | null {
  let value = pathname;
  for (let pass = 0; pass < 4; pass += 1) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(value);
    } catch {
      return null;
    }
    if (decoded === value) break;
    value = decoded;
  }
  if (/%[0-9a-f]{2}/i.test(value)) return null;
  if (value.includes("\\")) return null;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return null;
  }
  return value.replaceAll(";", "/");
}
function hasHeader(headers: Record<string, unknown>, key: string): boolean {
  const value = headers[key];
  return typeof value === "string" ? value.trim().length > 0 : Array.isArray(value) && value.length > 0;
}
function unique(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
function uniqueBy<T>(values: T[], key: (value: T) => string): T[] {
  const seen = new Set<string>();
  return values.filter((value) => {
    const id = key(value);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}
