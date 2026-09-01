import { afterEach, describe, expect, it } from 'vitest';
import { getApiBaseUrl, getPrivateEngineOrigin, isNativePersonalApp, normalizePrivateEngineOrigin, setPrivateEngineOrigin } from './analysis-engine';

afterEach(() => {
  localStorage.clear();
  Reflect.deleteProperty(window, 'Capacitor');
});

describe('personal mobile analysis engine', () => {
  it('accepts only a clean private Tailscale HTTPS origin', () => {
    expect(normalizePrivateEngineOrigin('https://edy.example.ts.net')).toBe('https://edy.example.ts.net');
    for (const value of ['http://edy.example.ts.net', 'https://example.com', 'https://edy.example.ts.net/path', 'https://user@edy.example.ts.net']) {
      expect(() => normalizePrivateEngineOrigin(value)).toThrow('INVALID_PRIVATE_ENGINE_URL');
    }
  });

  it('keeps browser and PWA requests same-origin', () => {
    expect(isNativePersonalApp()).toBe(false);
    expect(getApiBaseUrl()).toBe('/api/v1');
  });

  it('requires explicit private configuration inside Capacitor', () => {
    window.Capacitor = { isNativePlatform: () => true };
    expect(() => getApiBaseUrl()).toThrow('analysis_engine_not_configured');
    expect(setPrivateEngineOrigin('https://edy.example.ts.net/')).toBe('https://edy.example.ts.net');
    expect(getPrivateEngineOrigin()).toBe('https://edy.example.ts.net');
    expect(getApiBaseUrl()).toBe('https://edy.example.ts.net/api/v1');
  });
});
