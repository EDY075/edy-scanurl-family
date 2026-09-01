import { afterEach, describe, expect, it, vi } from 'vitest';
import { initializeDeviceReviewPairing, probeAnalysisEngine } from './device-review';

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, '', '/');
  localStorage.clear();
  sessionStorage.clear();
});

describe('Device Review pairing', () => {
  it('removes the one-time fragment and exchanges it only for an HttpOnly session', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify({ connected: true }), { status: 200 })));
    vi.stubGlobal('fetch', fetchMock);
    window.history.replaceState(null, '', '/#review=one-time-secret');

    await initializeDeviceReviewPairing();

    expect(window.location.hash).toBe('');
    expect(fetchMock).toHaveBeenCalledWith('/device-review/pair', expect.objectContaining({
      method: 'POST', credentials: 'same-origin', body: JSON.stringify({ token: 'one-time-secret' }),
    }));
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('reports Device Review state and falls back to the standard API probe', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ mode: 'DEVICE_REVIEW', connected: true }), { status: 200 }))
      .mockResolvedValueOnce(new Response('not found', { status: 404 }))
      .mockResolvedValueOnce(new Response('[]', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(probeAnalysisEngine()).resolves.toMatchObject({ mode: 'DEVICE_REVIEW', connected: true });
    await expect(probeAnalysisEngine()).resolves.toEqual({ mode: 'STANDARD', connected: true });
  });
});
