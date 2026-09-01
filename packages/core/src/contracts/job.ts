import type { Provenance } from "../domain.js";
import type { ScanTarget } from "./provider.js";

export const scanJobStatuses = [
  "QUEUED",
  "RUNNING",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
  "SCAN_REJECTED"
] as const;

export const scanProgressPhases = [
  "QUEUED",
  "RUNNING",
  "PARTIAL_RESULTS_AVAILABLE",
  "FINALIZING"
] as const;

export type ScanJobStatus = (typeof scanJobStatuses)[number];
export type ScanProgressPhase = (typeof scanProgressPhases)[number];

export interface ScanJobRequest {
  scanId: string;
  target: ScanTarget;
  provenance: Provenance;
  requestedAt: string;
}

export interface ScanRejection {
  kind: "SCAN_REJECTED";
  scanId: string;
  reasonCode: string;
  safeMessage: string;
  rejectedAt: string;
}

export interface ScanJobSnapshot {
  scanId: string;
  status: ScanJobStatus;
  progressPhase: ScanProgressPhase;
  completionMode?: "COMPLETE" | "LIMITED_COVERAGE";
  completedProviderIds: readonly string[];
  pendingProviderIds: readonly string[];
  lastProgressAt: string;
}

export interface ScanProgressEvent {
  kind: "PROGRESS";
  scanId: string;
  phase: ScanProgressPhase;
  completedProviderIds: readonly string[];
  pendingProviderIds: readonly string[];
  occurredAt: string;
}

export interface ScanJobCoordinator {
  enqueue(request: ScanJobRequest): Promise<ScanJobSnapshot>;
  cancel(scanId: string): Promise<ScanJobSnapshot>;
  getSnapshot(scanId: string): Promise<ScanJobSnapshot | null>;
  subscribe(scanId: string, signal: AbortSignal): AsyncIterable<ScanProgressEvent>;
}
