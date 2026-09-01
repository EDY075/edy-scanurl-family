export interface LocalScanHistoryItem {
  scanId: string;
  domain: string;
  verdict: "BUY" | "CAUTION" | "DO_NOT_BUY" | "INSUFFICIENT_DATA";
  score: number | null;
  confidence: "LOW" | "MEDIUM" | "HIGH" | "VERY_HIGH";
  checkedAt: string;
}

export interface PlatformStorageAdapter {
  readRecentScans(limit: number): Promise<readonly LocalScanHistoryItem[]>;
  writeRecentScan(item: LocalScanHistoryItem, limit: number): Promise<void>;
  clearRecentScans(): Promise<void>;
}

export interface PlatformShareAdapter {
  canShare(): boolean;
  shareText(input: { title: string; text: string; url?: string }): Promise<"SHARED" | "COPIED">;
}

export interface PlatformAdapter {
  readonly kind: "WEB" | "TAURI_WINDOWS" | "CAPACITOR_ANDROID" | "CAPACITOR_IOS";
  readonly storage: PlatformStorageAdapter;
  readonly share: PlatformShareAdapter;
  getVersion(): Promise<string>;
  openExternal(url: string): Promise<void>;
}
