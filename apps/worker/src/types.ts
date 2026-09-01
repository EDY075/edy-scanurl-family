import type { Check, ScanReport, Source } from '../../web/src/types';
import type { CnpjObservation } from '../../web/src/evidence/cnpj';

export interface Env {
  FAMILY: DurableObjectNamespace;
  SERVICE_ENABLED: string;
  VIRUSTOTAL_ENABLED: string;
  ALLOW_BROWSER_REVIEW: string;
  /** Exact HTTPS origins, comma-separated. Empty until web publication approval. */
  WEB_ALLOWED_ORIGINS?: string;
  VIRUSTOTAL_API_KEY?: string;
  RATE_LIMIT_SECRET: string;
}

export interface WorkerExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

export interface ScanJob {
  scanId: string;
  status: 'SUCCEEDED' | 'FAILED' | 'SCAN_REJECTED';
  progress: { completed: number; total: number; current: string };
  report?: ScanReport;
  error?: string;
  rejection?: { code: string; message: string };
}

export interface DnsData {
  a: string[];
  aaaa: string[];
  ns: string[];
  mx: { priority: number; exchange: string }[];
  caa: string[];
  dnssec: 'SIGNED' | 'NOT_OBSERVED' | 'UNKNOWN';
  status?: 'available' | 'limited';
  failedQueries?: string[];
  durationMs?: number;
}

export interface RdapData {
  status: 'available' | 'limited' | 'unavailable';
  registrationDate?: string;
  updatedDate?: string;
  registrar?: string;
  nameservers: string[];
  statuses: string[];
  sourceUrl?: string;
  reason?: string;
  attempted?: boolean;
  durationMs?: number;
}

export interface CrawlReceipt {
  page: number;
  attempted: boolean;
  outcome: 'FETCHED' | 'FAILED' | 'SKIPPED';
  reason: string;
  durationMs: number;
}

export interface HttpData {
  status: 'available' | 'limited' | 'unavailable';
  httpsValidated: boolean;
  finalOrigin?: string;
  redirects: number;
  headers: string[];
  securityHeaders: Record<string, boolean>;
  pagesFetched: number;
  pagesDiscovered: number;
  cnpjClaims: string[];
  cnpjObservations?: CnpjObservation[];
  cnpjTruncated?: boolean;
  policyEvidence?: { id: string; sourceUrls: string[] }[];
  companyNames: string[];
  emails: string[];
  phones: string[];
  socialLinks: string[];
  paymentMethods: string[];
  policies: Record<string, boolean>;
  reason?: string;
  attempted?: boolean;
  durationMs?: number;
  pagesSkipped?: number;
  discoveryTruncated?: boolean;
  crawlManifest?: CrawlReceipt[];
}

export interface VirusTotalObjectReport {
  state: 'AVAILABLE' | 'NO_DATA' | 'RATE_LIMITED' | 'TIMED_OUT' | 'FAILED';
  cache: 'MISS';
  id?: string;
  objectType?: string;
  freshness?: 'FRESH' | 'STALE' | 'UNKNOWN';
  stats?: { harmless: number; undetected: number; suspicious: number; malicious: number; timeout: number; other: number; total: number };
  engines?: { engine: string; category: string; result?: string; method?: string; engineVersion?: string; engineUpdate?: string }[];
  reputation?: number;
  communityVotes?: { harmless: number; malicious: number };
  categories?: { source: string; label: string }[];
  tags?: string[];
  firstSubmissionAt?: string;
  lastSubmissionAt?: string;
  lastAnalysisAt?: string;
  creationAt?: string;
  lastModificationAt?: string;
  registrar?: string;
  whoisStatus?: 'AVAILABLE_REDACTED' | 'PRIVACY_REDACTED' | 'UNAVAILABLE';
  whoisAt?: string;
  finalOrigin?: string;
  lastHttpResponseCode?: number;
  errorCode?: string;
  retryAfterSeconds?: number;
  attempted?: boolean;
}

export interface VirusTotalData {
  status: 'available' | 'limited' | 'unavailable';
  state: 'AVAILABLE' | 'PARTIAL' | 'NO_DATA' | 'RATE_LIMITED' | 'TIMED_OUT' | 'FAILED' | 'DISABLED_NO_CREDENTIALS';
  reason: string;
  domain?: VirusTotalObjectReport;
  url?: VirusTotalObjectReport;
  sourceUrl?: string;
  attempted?: boolean;
  durationMs?: number;
}

export interface ScanEvidence {
  target: { origin: string; domain: string };
  dns: DnsData;
  rdap: RdapData;
  http: HttpData;
  virusTotal: VirusTotalData;
  subrequests: number;
}

export type { Check, ScanReport, Source };
