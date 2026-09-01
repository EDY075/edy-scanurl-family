import type { HistoryEntry, ScanReport } from '../types';

const STORAGE_KEY = 'edy-scanurl-history-v1';

export function loadHistory(): HistoryEntry[] {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return value ? JSON.parse(value) as HistoryEntry[] : [];
  } catch { return []; }
}

export function saveToHistory(report: ScanReport): HistoryEntry[] {
  const entry: HistoryEntry = { id: report.id, domain: report.domain, scannedAt: report.scannedAt, verdict: report.verdict, score: report.score, confidence: report.confidence, mode: report.mode, report };
  const next = [entry, ...loadHistory().filter((item) => item.domain !== entry.domain)].slice(0, 20);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  return next;
}

export function clearStoredHistory(): HistoryEntry[] {
  localStorage.removeItem(STORAGE_KEY);
  return [];
}
