import { getApiBaseUrl, getPrivateEngineOrigin, isNativePersonalApp } from './analysis-engine';

export interface AnalysisEngineStatus {
  mode: 'DEVICE_REVIEW' | 'STANDARD' | 'PERSONAL_MOBILE';
  connected: boolean;
  expiresAt?: string | null;
}

export async function initializeDeviceReviewPairing(): Promise<void> {
  const parameters = new URLSearchParams(window.location.hash.slice(1));
  const token = parameters.get('review');
  if (!token) return;

  // Remove the one-time token before any service worker, analytics, UI or error path can observe it.
  window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
  const response = await fetch('/device-review/pair', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  });
  if (!response.ok) throw new Error('DEVICE_REVIEW_PAIRING_FAILED');
}

export async function probeAnalysisEngine(): Promise<AnalysisEngineStatus> {
  if (isNativePersonalApp()) {
    const privateOrigin = getPrivateEngineOrigin();
    if (!privateOrigin) return { mode: 'PERSONAL_MOBILE', connected: false };
    try {
      const response = await fetch(`${getApiBaseUrl()}/providers`, { cache: 'no-store' });
      return { mode: 'PERSONAL_MOBILE', connected: response.ok };
    } catch { return { mode: 'PERSONAL_MOBILE', connected: false }; }
  }
  try {
    const response = await fetch('/device-review/status', { credentials: 'same-origin', cache: 'no-store' });
    if (response.ok) return await response.json() as AnalysisEngineStatus;
  } catch {
    // The standard local preview does not expose the Device Review status endpoint.
  }

  try {
    const response = await fetch('/api/v1/providers', { credentials: 'same-origin', cache: 'no-store' });
    return { mode: 'STANDARD', connected: response.ok };
  } catch {
    return { mode: 'STANDARD', connected: false };
  }
}
