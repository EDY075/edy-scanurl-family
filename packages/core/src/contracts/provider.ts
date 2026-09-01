import type { Evidence, EvidenceCategory, Provenance } from "../domain.js";

export type ProviderRunStatus =
  | "SUCCEEDED"
  | "PARTIAL"
  | "NO_DATA"
  | "TIMED_OUT"
  | "RATE_LIMITED"
  | "FAILED"
  | "DISABLED_BY_POLICY"
  | "DISABLED_NO_CREDENTIALS";

export interface ScanTarget {
  origin: string;
  hostname: string;
  jurisdiction: string;
  transientPath?: string;
}

export interface ProviderContext {
  scanId: string;
  providerRunId: string;
  target: ScanTarget;
  provenance: Provenance;
  requestedAt: string;
  deadlineAt: string;
  signal: AbortSignal;
}

export interface ProviderResult {
  status: ProviderRunStatus;
  evidence: readonly Evidence[];
  warnings: readonly string[];
  retryAfterMs?: number;
  limitedCoverageReason?: string;
}

export interface ProviderAdapter {
  readonly id: string;
  readonly version: string;
  readonly categories: readonly EvidenceCategory[];
  readonly jurisdictions: readonly string[];
  supports(target: ScanTarget): boolean;
  execute(context: ProviderContext): Promise<ProviderResult>;
}

export function providerFailureStatusToCheckStatus(
  status: ProviderRunStatus
): "UNKNOWN" | "NOT_CHECKED" | null {
  switch (status) {
    case "TIMED_OUT":
    case "RATE_LIMITED":
    case "FAILED":
    case "NO_DATA":
      return "UNKNOWN";
    case "DISABLED_BY_POLICY":
    case "DISABLED_NO_CREDENTIALS":
      return "NOT_CHECKED";
    case "SUCCEEDED":
    case "PARTIAL":
      return null;
  }
}
