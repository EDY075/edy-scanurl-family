export type ProviderStatus =
  | "SUCCEEDED"
  | "PARTIAL"
  | "NO_DATA"
  | "TIMED_OUT"
  | "RATE_LIMITED"
  | "FAILED"
  | "DISABLED_BY_POLICY"
  | "DISABLED_NO_CREDENTIALS"
  | "DISABLED_NOT_PROVISIONED";

export type ProviderCategory =
  | "DOMAIN"
  | "DNS"
  | "TLS"
  | "HTTP"
  | "TRANSPARENCY"
  | "BUSINESS"
  | "THREAT"
  | "CONSUMER";

export interface ProviderContext {
  scanId: string;
  domain: string;
  targetUrl: string;
  signal?: AbortSignal;
}

export interface ProviderResult<T = unknown> {
  providerId: string;
  status: ProviderStatus;
  category: ProviderCategory;
  startedAt: string;
  completedAt: string;
  data?: T;
  sourceUrl?: string | undefined;
  errorCode?: string | undefined;
}

export interface ScanProvider<T = unknown> {
  readonly id: string;
  readonly version: string;
  readonly category: ProviderCategory;
  execute(context: ProviderContext): Promise<ProviderResult<T>>;
}

export interface ProviderComplianceRecord {
  provider: string;
  termsUrl: string;
  commercialStatus: "ALLOWED" | "CONDITIONAL" | "PROHIBITED" | "UNKNOWN";
  authentication: string;
  cost: string;
  quota: string;
  dataSent: string;
  retention: string;
  caching: string;
  redistribution: string;
  attribution: string;
  lastReviewed: string;
  enabled: boolean;
  killSwitch: string;
  disabledReason?: ProviderStatus;
}

export function providerResult<T>(
  provider: Pick<ScanProvider<T>, "id" | "category">,
  startedAt: string,
  status: ProviderStatus,
  details: Partial<ProviderResult<T>> = {},
): ProviderResult<T> {
  return {
    providerId: provider.id,
    category: provider.category,
    startedAt,
    completedAt: new Date().toISOString(),
    status,
    ...details,
  };
}
