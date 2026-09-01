import { z } from "zod";

const HttpUrlSchema = z.url().refine((value) => {
  const protocol = new URL(value).protocol;
  return protocol === "http:" || protocol === "https:";
}, "Only HTTP(S) source URLs are allowed");

export const evidenceCategories = [
  "BUSINESS_IDENTITY",
  "DOMAIN_HISTORY",
  "TECHNICAL_SECURITY",
  "THREAT_IMPERSONATION",
  "CONSUMER_REPUTATION",
  "STORE_TRANSPARENCY",
  "COMMERCE_PAYMENT",
  "PUBLIC_PRESENCE",
  "EVIDENCE_CONSISTENCY"
] as const;

export const checkStatuses = [
  "PASS",
  "WARNING",
  "FAIL",
  "CRITICAL",
  "UNKNOWN",
  "NOT_CHECKED",
  "NOT_APPLICABLE"
] as const;

export const provenances = ["REAL", "DEMO"] as const;
export const sourceTiers = [1, 2, 3, 4, 5] as const;
export const findingCertainties = [
  "CONFIRMED",
  "CORROBORATED",
  "PROBABLE",
  "UNVERIFIED"
] as const;

export const EvidenceSchema = z.object({
  id: z.string().min(1),
  scanId: z.string().min(1),
  providerRunId: z.string().min(1),
  subjectType: z.string().min(1),
  subjectKey: z.string().min(1),
  category: z.enum(evidenceCategories),
  claimType: z.string().min(1),
  value: z.unknown(),
  normalizedValue: z.unknown(),
  sourceId: z.string().min(1),
  sourceTier: z.union(sourceTiers.map((tier) => z.literal(tier))),
  collectionMethod: z.string().min(1),
  collectedAt: z.iso.datetime(),
  sourceUpdatedAt: z.iso.datetime().optional(),
  validUntil: z.iso.datetime().optional(),
  impact: z.enum(["POSITIVE", "NEUTRAL", "WARNING", "NEGATIVE", "CRITICAL"]),
  severity: z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  findingCertainty: z.enum(findingCertainties),
  sourceUrlAllowed: HttpUrlSchema.optional(),
  rawDigest: z.string().min(1).optional(),
  provenance: z.enum(provenances),
  rulesetVersion: z.string().min(1)
});

export type EvidenceCategory = (typeof evidenceCategories)[number];
export type CheckStatus = (typeof checkStatuses)[number];
export type Provenance = (typeof provenances)[number];
export type SourceTier = (typeof sourceTiers)[number];
export type FindingCertainty = (typeof findingCertainties)[number];
export type Evidence = z.infer<typeof EvidenceSchema>;

export interface Finding {
  id: string;
  ruleId: string;
  controlId: string;
  category: EvidenceCategory;
  status: CheckStatus;
  title: string;
  reason: string;
  evidenceIds: readonly string[];
  material: boolean;
  strongNegative: boolean;
  provenance: Provenance;
}

export interface DetectionSummary {
  approved: number;
  warnings: number;
  problems: number;
  critical: number;
  unknown: number;
  notChecked: number;
}

export function summarizeDetections(findings: readonly Finding[]): DetectionSummary {
  const count = (status: CheckStatus): number =>
    findings.filter((finding) => finding.status === status).length;

  return {
    approved: count("PASS"),
    warnings: count("WARNING"),
    problems: count("FAIL"),
    critical: count("CRITICAL"),
    unknown: count("UNKNOWN"),
    notChecked: count("NOT_CHECKED")
  };
}
