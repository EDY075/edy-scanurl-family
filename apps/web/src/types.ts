export type Locale = 'pt-BR' | 'en';
export type Theme = 'light' | 'dark' | 'system';
export type Verdict = 'BUY' | 'CAUTION' | 'DO_NOT_BUY' | 'INSUFFICIENT_DATA';
export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH';
export type Impact = 'positive' | 'neutral' | 'warning' | 'negative' | 'critical';
export type CheckStatus = 'PASS' | 'WARNING' | 'FAIL' | 'CRITICAL' | 'UNKNOWN' | 'NOT_CHECKED' | 'NOT_APPLICABLE';
export type ScanMode = 'real' | 'demo';
export type DemoScenarioId = 'trusted' | 'caution' | 'high-risk' | 'insufficient' | 'confirmed-phishing' | 'business-mismatch';

export interface Source {
  id: string;
  name: string;
  tier: 1 | 2 | 3 | 4;
  category: string;
  collectedAt?: string;
  sourceUpdatedAt?: string;
  url?: string;
  status: 'available' | 'limited' | 'unavailable';
}

export interface Check {
  id: string;
  category: string;
  title: string;
  description: string;
  impact: Impact;
  status?: CheckStatus;
  points: number;
  sourceId: string;
  value?: string;
}

export interface ScoreArea {
  id: string;
  label: string;
  score: number;
  max: number;
  coverage: number;
}

export interface Company {
  legalName: string;
  tradeName: string;
  registration: string;
  status: string;
  openedAt: string;
  activity: string;
  location: string;
  match: 'MATCH' | 'PARTIAL_MATCH' | 'MISMATCH' | 'UNKNOWN';
}

export interface ScanReport {
  id: string;
  mode: ScanMode;
  demoScenarioId?: DemoScenarioId;
  inputUrl: string;
  normalizedUrl: string;
  domain: string;
  scannedAt: string;
  verdict: Verdict;
  score: number | null;
  confidence: Confidence;
  coverage: number;
  scanCompletion?: number;
  summary: string;
  recommendation: string;
  company?: Company;
  storeEvidence?: {
    version: 1;
    collection: 'available' | 'limited' | 'unavailable';
    cnpjs: import('./evidence/cnpj').CnpjObservation[];
    cnpjTruncated?: boolean;
    registration: 'NOT_CHECKED';
    match: 'UNKNOWN';
    policies: { id: string; sourceUrls: string[] }[];
  };
  checks: Check[];
  scoreAreas: ScoreArea[];
  sources: Source[];
  technical: {
    domainAge: string;
    domainUpdatedAt?: string;
    registrar: string;
    nameservers?: string[];
    dns: string[];
    tls: string;
    tlsIssuer: string;
    redirects: string[];
    finalHostname?: string;
    headers: string[];
    threatStatus: string;
    salesVolume: string;
    paymentSignals: string[];
    decisionCoverage?: number;
    confirmedCriticalThreat?: boolean;
    pagesDiscovered?: number;
    pagesFetched?: number;
    silentSkips?: number;
    checkTrace?: {
      check: string;
      category: string;
      title: string;
      attempted: boolean;
      finalState: string;
      provider: string;
      durationMs: number;
      evidenceCount: number;
      reason: string;
    }[];
    virusTotal?: {
      state: 'AVAILABLE' | 'DISABLED_BY_POLICY' | 'DISABLED_NO_CREDENTIALS' | 'DISABLED_NOT_PROVISIONED' | 'RATE_LIMITED' | 'NO_DATA' | 'TIMED_OUT' | 'FAILED' | 'PARTIAL';
      reason: string;
      collectedAt?: string;
      policyMode?: string;
      disclosure?: string;
      domain?: VirusTotalObjectReport;
      url?: VirusTotalObjectReport;
      registrationCorrelation?: 'MATCH' | 'MINOR_DIFFERENCE' | 'CONFLICT' | 'UNKNOWN';
    };
  };
}

export interface VirusTotalObjectReport {
  state: 'AVAILABLE' | 'NO_DATA' | 'RATE_LIMITED' | 'TIMED_OUT' | 'FAILED';
  cache: 'HIT' | 'MISS';
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
  dnsSnapshot?: { type: string; value: string; ttl?: number }[];
  dnsSnapshotAt?: string;
  certificateSnapshot?: { issuer?: string; subject?: string; validFrom?: string; validUntil?: string; thumbprintSha256?: string };
  certificateSnapshotAt?: string;
  finalOrigin?: string;
  lastHttpResponseCode?: number;
  errorCode?: string;
  retryAfterSeconds?: number;
}

export interface HistoryEntry {
  id: string;
  domain: string;
  scannedAt: string;
  verdict: Verdict;
  score: number | null;
  confidence: Confidence;
  mode: ScanMode;
  report?: ScanReport;
}

export interface ScanProgress {
  key: string;
  state: 'pending' | 'active' | 'complete' | 'limited';
}
