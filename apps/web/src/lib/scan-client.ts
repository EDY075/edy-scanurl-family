import { createDemoReport } from '../demo/fixtures';
import type { DemoScenarioId, ScanMode, ScanReport } from '../types';
import { getApiBaseUrl } from './analysis-engine';

interface CreateScanResponse { scanId: string; }
interface ApiErrorResponse { code?: string; reason?: string; retryAfterSeconds?: number; }
interface ScanStatusResponse {
  status: 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'SCAN_REJECTED';
  progress?: { completed: number; total: number; current: string };
  report?: ScanReport;
}

const wait = (milliseconds: number) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

async function fetchRealReport(url: string, onProgress: (step: number) => void): Promise<ScanReport> {
  const apiBaseUrl = getApiBaseUrl();
  const createResponse = await fetch(`${apiBaseUrl}/scans`, {
    method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
  });
  if (!createResponse.ok) {
    const error = await safeApiError(createResponse);
    if (createResponse.status === 429 || error.code === 'RATE_LIMITED') throw new Error('rate_limited');
    if (error.code === 'SCAN_REJECTED') throw new Error('scan_rejected');
    if (createResponse.status === 401 || createResponse.status >= 500) throw new Error('api_unavailable');
    throw new Error('scan_failed');
  }
  const { scanId } = await createResponse.json() as CreateScanResponse;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    await wait(1200);
    const response = await fetch(`${apiBaseUrl}/scans/${encodeURIComponent(scanId)}`, { credentials: 'same-origin' });
    if (!response.ok) {
      if (response.status === 404) throw new Error('scan_expired');
      if (response.status === 429) throw new Error('rate_limited');
      throw new Error(response.status === 401 || response.status >= 500 ? 'api_unavailable' : 'scan_failed');
    }
    const scan = await response.json() as ScanStatusResponse;
    const providerProgress = scan.progress?.total
      ? Math.round((scan.progress.completed / scan.progress.total) * 4) + 1
      : 1;
    onProgress(Math.min(5, providerProgress));
    if (scan.status === 'SUCCEEDED') {
      if (!scan.report) throw new Error('report_missing');
      return scan.report;
    }
    if (scan.status === 'FAILED' || scan.status === 'SCAN_REJECTED') throw new Error(scan.status.toLowerCase());
  }
  throw new Error('scan_timeout');
}

async function safeApiError(response: Response): Promise<ApiErrorResponse> {
  try { return await response.json() as ApiErrorResponse; } catch { return {}; }
}

export async function requestScan(url: string, mode: ScanMode, demoScenarioId: DemoScenarioId, onProgress: (step: number) => void): Promise<ScanReport> {
  if (mode === 'real') return fetchRealReport(url, onProgress);
  for (let step = 0; step < 6; step += 1) {
    onProgress(step);
    await wait(step === 0 ? 250 : 420);
  }
  return createDemoReport(url, demoScenarioId);
}
