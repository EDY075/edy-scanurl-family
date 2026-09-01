import { describe, expect, it } from 'vitest';
import { storeOrigin } from './family-client';
import { rawSignatureToDer } from './family-native';

describe('Family client privacy boundary', () => {
  it.each([
    ['https://loja.example/pedido?token=secret#private', 'https://loja.example/'],
    ['loja.example/carrinho?id=123', 'https://loja.example/'],
    ['  https://LOJA.example:443/path  ', 'https://loja.example/'],
    ['http://loja.example:80/path', 'http://loja.example/'],
  ])('sends only the origin of %s', (input, output) => {
    expect(storeOrigin(input)).toBe(output);
  });
  it.each(['', 'file:///etc/passwd', 'javascript:alert(1)', 'https://user:pass@loja.example/', 'https://loja.example:8080/', 'loja.example other.example', 'localhost', 'x'.repeat(2049)])('rejects unsafe or ambiguous input %s', (input) => {
    expect(() => storeOrigin(input)).toThrow('scan_rejected');
  });
});

describe('Family P-256 DER adapter', () => {
  it('encodes positive integers with their required leading zero', () => {
    const raw = new Uint8Array(64);
    raw[0] = 0x80;
    raw[63] = 1;
    const der = rawSignatureToDer(raw.buffer);
    expect(Array.from(der.slice(0, 5))).toEqual([0x30, 38, 2, 33, 0]);
    expect(Array.from(der.slice(-3))).toEqual([2, 1, 1]);
    expect(der.length).toBe(40);
  });
  it('removes redundant leading zeroes without dropping the integer', () => {
    const raw = new Uint8Array(64);
    raw[31] = 1;
    raw[63] = 127;
    expect(Array.from(rawSignatureToDer(raw.buffer))).toEqual([0x30, 6, 2, 1, 1, 2, 1, 127]);
  });
  it.each([0, 32, 63, 65, 72])('rejects a signature of %s bytes', (length) => {
    expect(() => rawSignatureToDer(new ArrayBuffer(length))).toThrow('invalid_signature');
  });
});
