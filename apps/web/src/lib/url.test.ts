import { describe, expect, it } from 'vitest';
import { displayDomain, normalizeStoreUrl } from './url';

describe('URL safety helpers', () => {
  it('adds HTTPS and removes the fragment', () => {
    expect(normalizeStoreUrl(' loja.example/path#private ')).toBe('https://loja.example/path');
  });

  it('rejects unsupported and malformed targets', () => {
    expect(() => normalizeStoreUrl('javascript:alert(1)')).toThrow();
    expect(() => normalizeStoreUrl('not-a-domain')).toThrow();
  });

  it('returns a human-readable domain', () => {
    expect(displayDomain('https://www.loja.example/path')).toBe('loja.example');
  });
});
