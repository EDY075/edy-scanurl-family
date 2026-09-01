const STORAGE_KEY = 'edy-personal-analysis-engine';

interface CapacitorRuntime {
  isNativePlatform?: () => boolean;
}

declare global {
  interface Window {
    Capacitor?: CapacitorRuntime;
  }
}

export function isNativePersonalApp(): boolean {
  return window.Capacitor?.isNativePlatform?.() === true;
}

export function normalizePrivateEngineOrigin(value: string): string {
  const parsed = new URL(value.trim());
  if (
    parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port ||
    parsed.pathname !== '/' || parsed.search || parsed.hash ||
    !parsed.hostname.toLowerCase().endsWith('.ts.net')
  ) throw new Error('INVALID_PRIVATE_ENGINE_URL');
  return parsed.origin;
}

export function getPrivateEngineOrigin(): string | null {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (!stored) return null;
  try { return normalizePrivateEngineOrigin(stored); } catch { return null; }
}

export function setPrivateEngineOrigin(value: string): string {
  const origin = normalizePrivateEngineOrigin(value);
  localStorage.setItem(STORAGE_KEY, origin);
  return origin;
}

export function getApiBaseUrl(): string {
  if (!isNativePersonalApp()) return '/api/v1';
  const privateOrigin = getPrivateEngineOrigin();
  if (!privateOrigin) throw new Error('analysis_engine_not_configured');
  return `${privateOrigin}/api/v1`;
}
