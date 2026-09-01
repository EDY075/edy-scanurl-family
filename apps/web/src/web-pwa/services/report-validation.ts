import type { ScanReport } from "../../types";
import { ApiError, record } from "./api";
import { normalizeStoreUrl } from "../utils/url";
import { validateStoreEvidence } from "./store-evidence";
function string(value: unknown, maximum = 3000): value is string {
  return typeof value === "string" && value.length <= maximum;
}
function percent(value: unknown): boolean {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 100
  );
}
export function validateReport(value: unknown): ScanReport {
  const data = record(value);
  if (
    data.mode !== "real" ||
    !string(data.id, 64) ||
    !string(data.domain, 253) ||
    !string(data.scannedAt, 40) ||
    !Number.isFinite(Date.parse(data.scannedAt)) ||
    !["BUY", "CAUTION", "DO_NOT_BUY", "INSUFFICIENT_DATA"].includes(
      String(data.verdict),
    ) ||
    !["LOW", "MEDIUM", "HIGH", "VERY_HIGH"].includes(String(data.confidence)) ||
    !(data.score === null || percent(data.score)) ||
    !percent(data.coverage) ||
    !string(data.summary) ||
    !string(data.recommendation) ||
    !string(data.inputUrl) ||
    !string(data.normalizedUrl) ||
    !Array.isArray(data.checks) ||
    data.checks.length > 200 ||
    !Array.isArray(data.sources) ||
    data.sources.length > 100 ||
    !Array.isArray(data.scoreAreas)
  )
    throw new ApiError("response");
  try {
    if (new URL(normalizeStoreUrl(data.domain)).hostname !== data.domain)
      throw new Error();
  } catch {
    throw new ApiError("response");
  }
  for (const item of data.checks) {
    const check = record(item);
    if (
      !["id", "title", "description", "category", "sourceId"].every((key) =>
        string(check[key]),
      ) ||
      !["positive", "neutral", "warning", "negative", "critical"].includes(
        String(check.impact),
      ) ||
      (check.status !== undefined && check.status !== null &&
        (typeof check.status !== "string" ||
          ![
            "PASS",
            "WARNING",
            "FAIL",
            "CRITICAL",
            "UNKNOWN",
            "NOT_CHECKED",
            "NOT_APPLICABLE",
          ].includes(check.status))) ||
      typeof check.points !== "number" ||
      !Number.isFinite(check.points) ||
      (check.value !== undefined && !string(check.value))
    )
      throw new ApiError("response");
  }
  for (const item of data.sources) {
    const source = record(item);
    if (
      !["id", "name", "category"].every((key) => string(source[key])) ||
      !["available", "limited", "unavailable"].includes(
        String(source.status),
      ) ||
      (source.url !== undefined && !string(source.url))
    )
      throw new ApiError("response");
  }
  const technical = record(data.technical);
  if (technical.confirmedCriticalThreat !== undefined && typeof technical.confirmedCriticalThreat !== 'boolean') throw new ApiError('response');
  if (
    technical.decisionCoverage !== undefined &&
    !percent(technical.decisionCoverage)
  )
    throw new ApiError("response");
  for (const key of [
    "domainAge",
    "registrar",
    "tls",
    "tlsIssuer",
    "threatStatus",
  ])
    if (!string(technical[key])) throw new ApiError("response");
  for (const key of ['dns','nameservers','headers','redirects']) {
    const items = technical[key];
    if(items !== undefined && items !== null && (!Array.isArray(items) || items.length > 100 || !items.every(item => string(item,2048)))) throw new ApiError('response');
  }
  if (technical.finalHostname !== undefined && !string(technical.finalHostname,253)) throw new ApiError('response');
  if (technical.virusTotal !== undefined) {
    const vt = record(technical.virusTotal);
    if (
      ![
        "AVAILABLE",
        "DISABLED_BY_POLICY",
        "DISABLED_NO_CREDENTIALS",
        "DISABLED_NOT_PROVISIONED",
        "RATE_LIMITED",
        "NO_DATA",
        "TIMED_OUT",
        "FAILED",
        "PARTIAL",
      ].includes(String(vt.state))
    )
      throw new ApiError("response");
    for (const field of ["domain", "url"]) {
      if (vt[field] === undefined) continue;
      const item = record(vt[field]);
      if (
        ![
          "AVAILABLE",
          "NO_DATA",
          "RATE_LIMITED",
          "TIMED_OUT",
          "FAILED",
        ].includes(String(item.state))
      )
        throw new ApiError("response");
      if (item.stats !== undefined) {
        const stats = record(item.stats);
        if (
          ![
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
            "timeout",
            "other",
            "total",
          ].every(
            (key) =>
              Number.isInteger(stats[key]) &&
              Number(stats[key]) >= 0 &&
              Number(stats[key]) <= 10000,
          )
        )
          throw new ApiError("response");
      }
    }
  }
  if (data.storeEvidence !== undefined) {
    try {
      validateStoreEvidence(data.storeEvidence, data.domain);
    } catch {
      throw new ApiError("response");
    }
  }
  // Fields consumed by this UI have been validated; raw HTML is never rendered.
  return data as unknown as ScanReport;
}
