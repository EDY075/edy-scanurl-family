import { createHmac } from "node:crypto";
import { Readable } from "node:stream";
import { getDomain } from "tldts";
import { z } from "zod";
import { providerResult, type ProviderContext, type ProviderResult, type ScanProvider } from "./contracts.js";

const VT_API_BASE = "https://www.virustotal.com/api/v3";
const MAX_RESPONSE_BYTES = 1_048_576;
const DEFAULT_CACHE_TTL_MS = 24 * 60 * 60_000;
const DEFAULT_CACHE_ENTRIES = 500;

const envelopeSchema = z.object({
  data: z.object({
    id: z.string().min(1),
    type: z.string().min(1),
    attributes: z.record(z.string(), z.unknown()),
  }),
});
const statsSchema = z.record(z.string(), z.number().int().nonnegative().max(100_000));
const engineResultsSchema = z.record(z.string(), z.looseObject({
  category: z.string().min(1).max(60),
  result: z.string().max(240).nullable().optional(),
  method: z.string().max(80).optional(),
  engine_version: z.string().max(80).optional(),
  engine_update: z.string().max(40).optional(),
}));

export type VirusTotalEndpointState = "AVAILABLE" | "NO_DATA" | "RATE_LIMITED" | "TIMED_OUT" | "FAILED";

export interface VirusTotalStats {
  harmless: number;
  undetected: number;
  suspicious: number;
  malicious: number;
  timeout: number;
  other: number;
  total: number;
}

export interface VirusTotalEngineResult {
  engine: string;
  category: string;
  result?: string;
  method?: string;
  engineVersion?: string;
  engineUpdate?: string;
}

export interface VirusTotalObjectReport {
  state: VirusTotalEndpointState;
  cache: "HIT" | "MISS";
  id?: string;
  objectType?: string;
  stats?: VirusTotalStats;
  engines?: VirusTotalEngineResult[];
  reputation?: number;
  communityVotes?: { harmless: number; malicious: number };
  categories?: { source: string; label: string }[];
  tags?: string[];
  firstSubmissionAt?: string;
  lastSubmissionAt?: string;
  lastAnalysisAt?: string;
  freshness?: "FRESH" | "STALE" | "UNKNOWN";
  creationAt?: string;
  lastModificationAt?: string;
  registrar?: string;
  whoisStatus?: "AVAILABLE_REDACTED" | "PRIVACY_REDACTED" | "UNAVAILABLE";
  whoisAt?: string;
  dnsSnapshot?: { type: string; value: string; ttl?: number }[];
  dnsSnapshotAt?: string;
  certificateSnapshot?: {
    issuer?: string;
    subject?: string;
    validFrom?: string;
    validUntil?: string;
    thumbprintSha256?: string;
  };
  certificateSnapshotAt?: string;
  finalOrigin?: string;
  lastHttpResponseCode?: number;
  errorCode?: string;
  retryAfterSeconds?: number;
}

export interface VirusTotalData {
  policyMode: "PUBLIC_NONCOMMERCIAL_LOCAL_ONLY" | "PUBLIC_NONCOMMERCIAL_HOSTED_OPERATOR_AUTHORIZED";
  disclosure: "REGISTRABLE_DOMAIN_AND_NORMALIZED_ORIGIN_ONLY";
  registrableDomain: string;
  normalizedOrigin: string;
  domain: VirusTotalObjectReport;
  url: VirusTotalObjectReport;
}

interface CacheEntry {
  expiresAt: number;
  report: VirusTotalObjectReport;
}

export interface VirusTotalProviderOptions {
  apiKey: string;
  fetchImpl?: VirusTotalFetch;
  now?: () => number;
  cacheTtlMs?: number;
  maximumCacheEntries?: number;
  reserveRequest?: () => boolean;
  policyMode?: VirusTotalData["policyMode"];
}

export type VirusTotalRuntimeReason =
  | "ENABLED_LOCAL_NONCOMMERCIAL"
  | "DISABLED"
  | "DISABLED_BY_USE_MODE"
  | "DISABLED_BY_DEPLOYMENT"
  | "DISABLED_BY_WRITE_CAPABILITY"
  | "DISABLED_NO_CREDENTIALS";

export interface VirusTotalRuntimeStatus {
  enabled: boolean;
  reason: VirusTotalRuntimeReason;
  backendOnly: true;
  submitNewUrls: false;
  reanalyze: false;
}

/**
 * Fail-closed policy gate for a personal Community API key. The secret is
 * deliberately absent from the returned diagnostic object so it cannot be
 * exposed by ordinary configuration logging.
 */
export function virusTotalRuntimeStatus(env: NodeJS.ProcessEnv = process.env): VirusTotalRuntimeStatus {
  const disabled = (reason: VirusTotalRuntimeReason): VirusTotalRuntimeStatus => ({
    enabled: false,
    reason,
    backendOnly: true,
    submitNewUrls: false,
    reanalyze: false,
  });
  if (env.VIRUSTOTAL_ENABLED !== "true") return disabled("DISABLED");
  if (env.PROJECT_USE_MODE !== "LOCAL_NONCOMMERCIAL") return disabled("DISABLED_BY_USE_MODE");
  if (env.NODE_ENV === "production" || !isLoopbackHost(effectiveLocalHost(env)) || !isLoopbackCors(env.CORS_ORIGIN)) {
    return disabled("DISABLED_BY_DEPLOYMENT");
  }
  if (env.VIRUSTOTAL_SUBMIT_NEW_URLS !== "false" || env.VIRUSTOTAL_REANALYZE !== "false") {
    return disabled("DISABLED_BY_WRITE_CAPABILITY");
  }
  if (!isPlausibleCommunityKey(env.VIRUSTOTAL_API_KEY)) return disabled("DISABLED_NO_CREDENTIALS");
  return {
    enabled: true,
    reason: "ENABLED_LOCAL_NONCOMMERCIAL",
    backendOnly: true,
    submitNewUrls: false,
    reanalyze: false,
  };
}

export function effectiveLocalHost(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.HOST?.trim();
  if (!configured) return "127.0.0.1";
  return configured;
}

export function createVirusTotalProviderFromEnvironment(env: NodeJS.ProcessEnv = process.env): VirusTotalProvider | undefined {
  const status = virusTotalRuntimeStatus(env);
  if (!status.enabled) {
    if (env.VIRUSTOTAL_ENABLED === "true") throw new Error(`VIRUSTOTAL_CONFIGURATION_REJECTED:${status.reason}`);
    return undefined;
  }
  const apiKey = env.VIRUSTOTAL_API_KEY;
  if (apiKey === undefined) throw new Error("VIRUSTOTAL_CONFIGURATION_REJECTED:DISABLED_NO_CREDENTIALS");
  return new VirusTotalProvider({ apiKey });
}

export type VirusTotalFetch = (input: string, init: RequestInit) => Promise<Response>;

export class VirusTotalProvider implements ScanProvider<VirusTotalData> {
  readonly id = "virus-total-public";
  readonly version = "v3-read-only-1.0.0";
  readonly category = "THREAT" as const;
  private readonly fetchImpl: VirusTotalFetch;
  private readonly now: () => number;
  private readonly cacheTtlMs: number;
  private readonly maximumCacheEntries: number;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inFlight = new Map<string, Promise<VirusTotalObjectReport>>();
  private requestTimestamps: number[] = [];
  private dailyWindow = "";
  private dailyRequests = 0;

  constructor(private readonly options: VirusTotalProviderOptions) {
    if (!options.apiKey.trim()) throw new Error("VIRUSTOTAL_API_KEY_REQUIRED");
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? Date.now;
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.maximumCacheEntries = options.maximumCacheEntries ?? DEFAULT_CACHE_ENTRIES;
  }

  async execute(context: ProviderContext): Promise<ProviderResult<VirusTotalData>> {
    const startedAt = new Date(this.now()).toISOString();
    if (context.signal?.aborted) {
      return providerResult(this, startedAt, "TIMED_OUT", { errorCode: "VIRUSTOTAL_ABORTED" });
    }

    const registrableDomain = getDomain(context.domain, { allowPrivateDomains: false });
    if (!registrableDomain) {
      return providerResult(this, startedAt, "FAILED", { errorCode: "VIRUSTOTAL_INVALID_REGISTRABLE_DOMAIN" });
    }
    const normalizedOrigin = normalizeOrigin(context.targetUrl);
    if (!normalizedOrigin) {
      return providerResult(this, startedAt, "FAILED", { errorCode: "VIRUSTOTAL_INVALID_ORIGIN" });
    }

    const domain = await this.lookup("domain", registrableDomain, context.signal);
    const urlId = Buffer.from(normalizedOrigin, "utf8").toString("base64url");
    const stopAfterDomain = domain.state === "RATE_LIMITED" || domain.state === "TIMED_OUT" || domain.errorCode === "VIRUSTOTAL_CREDENTIALS_REJECTED";
    const url = stopAfterDomain
      ? { state: domain.state, cache: "MISS", errorCode: "VIRUSTOTAL_SKIPPED_AFTER_DOMAIN_TERMINAL" } satisfies VirusTotalObjectReport
      : await this.lookup("url", urlId, context.signal);
    const data: VirusTotalData = {
      policyMode: this.options.policyMode ?? "PUBLIC_NONCOMMERCIAL_LOCAL_ONLY",
      disclosure: "REGISTRABLE_DOMAIN_AND_NORMALIZED_ORIGIN_ONLY",
      registrableDomain,
      normalizedOrigin,
      domain,
      url,
    };
    const states = [domain.state, url.state];
    const available = states.filter((state) => state === "AVAILABLE").length;
    const sourceUrl = `https://www.virustotal.com/gui/domain/${encodeURIComponent(registrableDomain)}`;
    const stale = [domain, url].some((report) => report.state === "AVAILABLE" && report.freshness === "STALE");
    const credentialFailure = [domain, url].some((report) => report.errorCode === "VIRUSTOTAL_CREDENTIALS_REJECTED");
    if (credentialFailure) return providerResult(this, startedAt, "DISABLED_NO_CREDENTIALS", { data, errorCode: "VIRUSTOTAL_CREDENTIALS_REJECTED" });
    if (available === 2 && !stale) return providerResult(this, startedAt, "SUCCEEDED", { data, sourceUrl });
    if (available === 2 && stale) return providerResult(this, startedAt, "PARTIAL", { data, sourceUrl, errorCode: "VIRUSTOTAL_STALE_REPORT" });
    if (available === 1) return providerResult(this, startedAt, "PARTIAL", { data, sourceUrl, errorCode: firstOperationalError(domain, url) });
    if (states.every((state) => state === "NO_DATA")) return providerResult(this, startedAt, "NO_DATA", { data, sourceUrl, errorCode: "VIRUSTOTAL_NO_REPORT" });
    if (states.includes("RATE_LIMITED")) return providerResult(this, startedAt, "RATE_LIMITED", { data, errorCode: "VIRUSTOTAL_RATE_LIMITED" });
    if (states.includes("TIMED_OUT")) return providerResult(this, startedAt, "TIMED_OUT", { data, errorCode: "VIRUSTOTAL_TIMED_OUT" });
    return providerResult(this, startedAt, "FAILED", { data, errorCode: firstOperationalError(domain, url) ?? "VIRUSTOTAL_LOOKUP_FAILED" });
  }

  private async lookup(kind: "domain" | "url", id: string, signal?: AbortSignal): Promise<VirusTotalObjectReport> {
    const cacheKey = createHmac("sha256", this.options.apiKey).update(`${kind}:${id}`).digest("hex");
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > this.now()) return refreshFreshness({ ...cached.report, cache: "HIT" }, this.now());
    if (cached) this.cache.delete(cacheKey);
    const pending = this.inFlight.get(cacheKey);
    if (pending) return waitForCaller(pending, signal);
    const request = this.lookupUncached(kind, id, cacheKey).finally(() => this.inFlight.delete(cacheKey));
    this.inFlight.set(cacheKey, request);
    return waitForCaller(request, signal);
  }

  private async lookupUncached(kind: "domain" | "url", id: string, cacheKey: string): Promise<VirusTotalObjectReport> {
    if (!this.takeToken() || (this.options.reserveRequest && !this.options.reserveRequest())) return { state: "RATE_LIMITED", cache: "MISS", errorCode: "VIRUSTOTAL_LOCAL_RATE_LIMIT" };

    const path = kind === "domain" ? `domains/${encodeURIComponent(id)}` : `urls/${encodeURIComponent(id)}`;
    let response: Response;
    try {
      response = await this.fetchImpl(`${VT_API_BASE}/${path}`, {
        method: "GET",
        headers: { accept: "application/json", "x-apikey": this.options.apiKey },
        redirect: "error",
        signal: AbortSignal.timeout(7_000),
      });
    } catch (error) {
      const aborted = error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError");
      return { state: aborted ? "TIMED_OUT" : "FAILED", cache: "MISS", errorCode: aborted ? "VIRUSTOTAL_ABORTED" : "VIRUSTOTAL_NETWORK_FAILURE" };
    }

    if (response.status === 404) return this.store(cacheKey, { state: "NO_DATA", cache: "MISS", errorCode: "VIRUSTOTAL_NOT_FOUND" });
    if (response.status === 429) {
      return {
        state: "RATE_LIMITED",
        cache: "MISS",
        errorCode: "VIRUSTOTAL_REMOTE_RATE_LIMIT",
        ...retryAfter(response.headers.get("retry-after")),
      };
    }
    if (response.status === 401 || response.status === 403) {
      return { state: "FAILED", cache: "MISS", errorCode: "VIRUSTOTAL_CREDENTIALS_REJECTED" };
    }
    if (!response.ok) {
      return { state: response.status === 408 || response.status === 504 ? "TIMED_OUT" : "FAILED", cache: "MISS", errorCode: `VIRUSTOTAL_HTTP_${String(response.status)}` };
    }

    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json")) {
      return { state: "FAILED", cache: "MISS", errorCode: "VIRUSTOTAL_INVALID_CONTENT_TYPE" };
    }
    const contentLength = Number(response.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
      return { state: "FAILED", cache: "MISS", errorCode: "VIRUSTOTAL_RESPONSE_TOO_LARGE" };
    }
    const bodyResult = await readBoundedBody(response);
    if (!bodyResult.body) return { state: "FAILED", cache: "MISS", errorCode: bodyResult.errorCode ?? "VIRUSTOTAL_BODY_READ_FAILED" };
    const body = bodyResult.body;
    let parsed: z.infer<typeof envelopeSchema>;
    try {
      parsed = envelopeSchema.parse(JSON.parse(body));
    } catch {
      return { state: "FAILED", cache: "MISS", errorCode: "VIRUSTOTAL_INVALID_RESPONSE" };
    }
    const expectedType = kind === "domain" ? "domain" : "url";
    if (parsed.data.type !== expectedType || (kind === "domain" && parsed.data.id.toLowerCase() !== id.toLowerCase()) || !validAnalysisAttributes(parsed.data.attributes)) {
      return { state: "FAILED", cache: "MISS", errorCode: "VIRUSTOTAL_INVALID_RESPONSE" };
    }
    return this.store(cacheKey, sanitizeReport(parsed.data.id, parsed.data.type, parsed.data.attributes, this.now()));
  }

  private takeToken(): boolean {
    const now = this.now();
    const dailyWindow = new Date(now).toISOString().slice(0, 10);
    if (dailyWindow !== this.dailyWindow) {
      this.dailyWindow = dailyWindow;
      this.dailyRequests = 0;
    }
    if (this.dailyRequests >= 500) return false;
    this.requestTimestamps = this.requestTimestamps.filter((timestamp) => now - timestamp < 60_000);
    if (this.requestTimestamps.length >= 4) return false;
    this.requestTimestamps.push(now);
    this.dailyRequests += 1;
    return true;
  }

  private store(key: string, report: VirusTotalObjectReport): VirusTotalObjectReport {
    if (this.cache.size >= this.maximumCacheEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) this.cache.delete(oldestKey);
    }
    this.cache.set(key, { expiresAt: this.now() + this.cacheTtlMs, report });
    return report;
  }
}

function normalizeOrigin(value: string): string | undefined {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    url.username = "";
    url.password = "";
    url.pathname = "/";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return undefined;
  }
}

function isLoopbackHost(value: string): boolean {
  return ["127.0.0.1", "localhost", "::1"].includes(value.toLowerCase());
}

function isLoopbackCors(value: string | undefined): boolean {
  if (value === undefined || value.trim() === "") return true;
  try {
    const hostname = new URL(value).hostname.toLowerCase();
    return ["127.0.0.1", "localhost", "::1", "[::1]"].includes(hostname);
  } catch {
    return false;
  }
}

function isPlausibleCommunityKey(value: string | undefined): boolean {
  return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value.trim());
}

function sanitizeReport(id: string, objectType: string, attributes: Record<string, unknown>, now: number): VirusTotalObjectReport {
  const stats = sanitizeStats(attributes.last_analysis_stats);
  const engines = sanitizeEngines(attributes.last_analysis_results);
  const categories = sanitizeCategories(attributes.categories);
  const rawWhois = stringValue(attributes.whois);
  const reputation = numberValue(attributes.reputation);
  const registrar = stringValue(attributes.registrar);
  const lastAnalysisAt = unixDate(attributes.last_analysis_date);
  const votes = sanitizeVotes(attributes.total_votes);
  const tags = Array.isArray(attributes.tags) ? attributes.tags.filter((item): item is string => typeof item === "string").map((item) => item.slice(0, 80)).slice(0, 50) : [];
  const rawFinalUrl = stringValue(attributes.last_final_url);
  const finalOrigin = rawFinalUrl ? normalizeOrigin(rawFinalUrl) : undefined;
  const lastHttpResponseCode = numberValue(attributes.last_http_response_code);
  const lastModificationValue = attributes.last_modification_date ?? attributes.last_update_date;
  return {
    state: "AVAILABLE",
    cache: "MISS",
    id,
    objectType,
    ...(stats ? { stats } : {}),
    ...(engines.length > 0 ? { engines } : {}),
    ...(reputation !== undefined ? { reputation } : {}),
    ...(votes ? { communityVotes: votes } : {}),
    ...(categories.length > 0 ? { categories } : {}),
    ...(tags.length > 0 ? { tags } : {}),
    ...dateField("firstSubmissionAt", attributes.first_submission_date),
    ...dateField("lastSubmissionAt", attributes.last_submission_date),
    ...(lastAnalysisAt ? { lastAnalysisAt, freshness: reportFreshness(lastAnalysisAt, now) } : { freshness: "UNKNOWN" as const }),
    ...dateField("creationAt", attributes.creation_date),
    ...dateField("lastModificationAt", lastModificationValue),
    ...(registrar ? { registrar } : {}),
    whoisStatus: rawWhois ? (/registrant|admin|tech|privacy|redacted/i.test(rawWhois) ? "PRIVACY_REDACTED" : "AVAILABLE_REDACTED") : "UNAVAILABLE",
    ...dateField("whoisAt", attributes.whois_date),
    ...sanitizeDns(attributes.last_dns_records),
    ...dateField("dnsSnapshotAt", attributes.last_dns_records_date),
    ...sanitizeCertificate(attributes.last_https_certificate),
    ...dateField("certificateSnapshotAt", attributes.last_https_certificate_date),
    ...(finalOrigin ? { finalOrigin } : {}),
    ...(lastHttpResponseCode !== undefined && Number.isInteger(lastHttpResponseCode) && lastHttpResponseCode >= 100 && lastHttpResponseCode <= 599 ? { lastHttpResponseCode } : {}),
  };
}

function sanitizeVotes(value: unknown): { harmless: number; malicious: number } | undefined {
  if (!recordValue(value)) return undefined;
  const harmless = numberValue(value.harmless);
  const malicious = numberValue(value.malicious);
  if (harmless === undefined || malicious === undefined || !Number.isInteger(harmless) || !Number.isInteger(malicious) || harmless < 0 || malicious < 0) return undefined;
  return { harmless, malicious };
}

function sanitizeStats(value: unknown): VirusTotalStats | undefined {
  if (!recordValue(value)) return undefined;
  const harmless = safeCount(value.harmless);
  const undetected = safeCount(value.undetected);
  const suspicious = safeCount(value.suspicious);
  const malicious = safeCount(value.malicious);
  const timeout = safeCount(value.timeout) + safeCount(value["confirmed-timeout"]);
  const known = new Set(["harmless", "undetected", "suspicious", "malicious", "timeout", "confirmed-timeout"]);
  const other = Object.entries(value).reduce((sum, [key, count]) => sum + (known.has(key) ? 0 : safeCount(count)), 0);
  return { harmless, undetected, suspicious, malicious, timeout, other, total: harmless + undetected + suspicious + malicious + timeout + other };
}

function sanitizeEngines(value: unknown): VirusTotalEngineResult[] {
  if (!recordValue(value)) return [];
  return Object.entries(value).slice(0, 150).flatMap(([engine, result]) => {
    if (!recordValue(result)) return [];
    const category = stringValue(result.category);
    const detectedResult = stringValue(result.result);
    const method = stringValue(result.method);
    const engineVersion = stringValue(result.engine_version);
    const engineUpdate = stringValue(result.engine_update);
    if (!category) return [];
    return [{
      engine: engine.slice(0, 120),
      category: category.slice(0, 60),
      ...(detectedResult ? { result: detectedResult.slice(0, 240) } : {}),
      ...(method ? { method: method.slice(0, 80) } : {}),
      ...(engineVersion ? { engineVersion: engineVersion.slice(0, 80) } : {}),
      ...(engineUpdate ? { engineUpdate: engineUpdate.slice(0, 40) } : {}),
    }];
  });
}

function sanitizeCategories(value: unknown): { source: string; label: string }[] {
  if (!recordValue(value)) return [];
  return Object.entries(value).flatMap(([source, label]) => typeof label === "string" ? [{ source: source.slice(0, 120), label: label.slice(0, 160) }] : []).slice(0, 50);
}

function sanitizeDns(value: unknown): Pick<VirusTotalObjectReport, "dnsSnapshot"> {
  if (!Array.isArray(value)) return {};
  const dnsSnapshot = value.flatMap((item) => {
    if (!recordValue(item)) return [];
    const type = stringValue(item.type);
    const record = stringValue(item.value);
    if (!type || !record) return [];
    const ttl = numberValue(item.ttl);
    return [{ type: type.slice(0, 20), value: record.slice(0, 300), ...(ttl !== undefined ? { ttl } : {}) }];
  }).slice(0, 50);
  return dnsSnapshot.length > 0 ? { dnsSnapshot } : {};
}

function sanitizeCertificate(value: unknown): Pick<VirusTotalObjectReport, "certificateSnapshot"> {
  if (!recordValue(value)) return {};
  const issuer = recordValue(value.issuer) ? stringValue(value.issuer.CN) ?? stringValue(value.issuer.O) : undefined;
  const subject = recordValue(value.subject) ? stringValue(value.subject.CN) : undefined;
  const validity = recordValue(value.validity) ? value.validity : undefined;
  const validFrom = validity ? stringValue(validity.not_before) : undefined;
  const validUntil = validity ? stringValue(validity.not_after) : undefined;
  const thumbprintSha256 = stringValue(value.thumbprint_sha256);
  const snapshot = {
    ...(issuer ? { issuer: issuer.slice(0, 200) } : {}),
    ...(subject ? { subject: subject.slice(0, 200) } : {}),
    ...(validFrom ? { validFrom } : {}),
    ...(validUntil ? { validUntil } : {}),
    ...(thumbprintSha256 ? { thumbprintSha256 } : {}),
  };
  return Object.keys(snapshot).length > 0 ? { certificateSnapshot: snapshot } : {};
}

function dateField<K extends string>(key: K, value: unknown): Partial<Record<K, string>> {
  const date = unixDate(value);
  return date ? { [key]: date } as Partial<Record<K, string>> : {};
}

function unixDate(value: unknown): string | undefined {
  const seconds = numberValue(value);
  if (seconds === undefined || seconds < 0) return undefined;
  const date = new Date(seconds * 1000);
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

function reportFreshness(value: string, now: number): "FRESH" | "STALE" {
  return now - Date.parse(value) > 90 * 24 * 60 * 60_000 ? "STALE" : "FRESH";
}

function refreshFreshness(report: VirusTotalObjectReport, now: number): VirusTotalObjectReport {
  return report.lastAnalysisAt ? { ...report, freshness: reportFreshness(report.lastAnalysisAt, now) } : report;
}

function validAnalysisAttributes(attributes: Record<string, unknown>): boolean {
  if (attributes.last_analysis_stats !== undefined && !statsSchema.safeParse(attributes.last_analysis_stats).success) return false;
  if (attributes.last_analysis_results !== undefined && !engineResultsSchema.safeParse(attributes.last_analysis_results).success) return false;
  return true;
}

async function waitForCaller(pending: Promise<VirusTotalObjectReport>, signal?: AbortSignal): Promise<VirusTotalObjectReport> {
  if (!signal) return pending;
  if (signal.aborted) return { state: "TIMED_OUT", cache: "MISS", errorCode: "VIRUSTOTAL_ABORTED" };
  return new Promise((resolve) => {
    const abort = () => resolve({ state: "TIMED_OUT", cache: "MISS", errorCode: "VIRUSTOTAL_ABORTED" });
    signal.addEventListener("abort", abort, { once: true });
    void pending.then(
      (report) => resolve(report),
      () => resolve({ state: "FAILED", cache: "MISS", errorCode: "VIRUSTOTAL_LOOKUP_FAILED" }),
    ).finally(() => signal.removeEventListener("abort", abort));
  });
}

async function readBoundedBody(response: Response): Promise<{ body?: string; errorCode?: string }> {
  if (!response.body) return { errorCode: "VIRUSTOTAL_BODY_READ_FAILED" };
  // Node's fetch returns a native Web Stream. Browser E2E typings also load the
  // DOM declaration, whose generic overloads differ from node:stream/web.
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion -- Required by root E2E DOM typings; redundant only in the API-only TypeScript program.
  const stream = Readable.fromWeb(response.body as unknown as import("node:stream/web").ReadableStream);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let body = "";
  let bytes = 0;
  try {
    for await (const rawChunk of stream) {
      const value: unknown = rawChunk;
      if (!(value instanceof Uint8Array)) {
        stream.destroy();
        return { errorCode: "VIRUSTOTAL_BODY_READ_FAILED" };
      }
      bytes += value.byteLength;
      if (bytes > MAX_RESPONSE_BYTES) {
        stream.destroy();
        return { errorCode: "VIRUSTOTAL_RESPONSE_TOO_LARGE" };
      }
      body += decoder.decode(value, { stream: true });
    }
    body += decoder.decode();
    return { body };
  } catch {
    return { errorCode: "VIRUSTOTAL_BODY_READ_FAILED" };
  }
}

function retryAfter(value: string | null): { retryAfterSeconds?: number } {
  if (!value) return {};
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return { retryAfterSeconds: Math.ceil(seconds) };
  const date = Date.parse(value);
  return Number.isFinite(date) ? { retryAfterSeconds: Math.max(0, Math.ceil((date - Date.now()) / 1000)) } : {};
}

function firstOperationalError(...reports: VirusTotalObjectReport[]): string | undefined {
  return reports.find((report) => report.state !== "AVAILABLE")?.errorCode;
}

function recordValue(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function safeCount(value: unknown): number {
  const count = numberValue(value);
  return count === undefined ? 0 : Math.max(0, Math.trunc(count));
}
