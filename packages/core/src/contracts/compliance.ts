export type ComplianceDecision =
  | "ENABLED"
  | "DISABLED_BY_POLICY"
  | "DISABLED_NO_CREDENTIALS"
  | "DISABLED_ZERO_COST_POLICY"
  | "DISABLED_KILL_SWITCH";

export interface ProviderComplianceRecord {
  providerId: string;
  termsUrl?: string;
  licenseStatus: "CONFIRMED" | "UNCONFIRMED" | "PROHIBITED";
  commercialStatus: "ALLOWED" | "RESTRICTED" | "PROHIBITED" | "UNKNOWN";
  authentication: "NONE" | "API_KEY" | "OAUTH2" | "CONTRACT";
  cost: "FREE" | "FREEMIUM" | "PAID" | "UNKNOWN";
  quota: string;
  dataSent: readonly string[];
  retention: string;
  caching: string;
  redistribution: string;
  attribution: string;
  lastReviewedAt: string;
  credentialsAvailable: boolean;
  enabled: boolean;
  killSwitch: boolean;
}

export function decideProviderCompliance(
  record: ProviderComplianceRecord,
  options: { zeroCostOnly: boolean }
): ComplianceDecision {
  if (record.killSwitch) return "DISABLED_KILL_SWITCH";
  if (!record.enabled || record.licenseStatus !== "CONFIRMED") return "DISABLED_BY_POLICY";
  if (record.commercialStatus !== "ALLOWED") return "DISABLED_BY_POLICY";
  if (record.authentication !== "NONE" && !record.credentialsAvailable) {
    return "DISABLED_NO_CREDENTIALS";
  }
  if (options.zeroCostOnly && record.cost !== "FREE") return "DISABLED_ZERO_COST_POLICY";
  return "ENABLED";
}
