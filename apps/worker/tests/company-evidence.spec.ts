import { describe, expect, it } from 'vitest';
import { extractCnpj, mergeCnpj } from '../src/company-evidence';
import { validCnpj } from '../../web/src/evidence/cnpj';

const url = new URL('https://example.com/contato');
describe('numeric CNPJ observations', () => {
  it('repeated declarations do not exhaust the distinct-identifier budget', () => {
    expect(extractCnpj('CNPJ 11222333000181 '.repeat(40) + 'CNPJ 04252011000110', url)).toHaveLength(2);
  });
  it.each(['11.222.333/0001-81', '11222333000181'])('detects formatted or bare labelled CNPJ %s', (value) => {
    expect(extractCnpj(`<footer>CNPJ: ${value}</footer>`, url)).toEqual([{ value: '11222333000181', checksum: 'VALID', provenance: [{ url: url.href, location: 'FOOTER' }] }]);
  });
  it('validates both mathematical check digits without consulting registration', () => {
    expect(validCnpj('11222333000181')).toBe(true);
    expect(validCnpj('11222333000182')).toBe(false);
    expect(validCnpj('11222333000171')).toBe(false);
  });
  it('retains explicitly declared invalid checksum as an observation', () => {
    expect(extractCnpj('CNPJ 11.222.333/0001-82', url)[0]?.checksum).toBe('INVALID');
  });
  it('merges duplicate formatted and bare numbers with distinct provenance', () => {
    const result = mergeCnpj([...extractCnpj('<footer>CNPJ 11.222.333/0001-81</footer>CNPJ:11222333000181', url), ...extractCnpj('CNPJ 11222333000181', new URL('https://example.com/sobre'))]);
    expect(result).toHaveLength(1); expect(result[0]?.provenance).toHaveLength(3);
  });
  it('keeps distinct CNPJs rather than silently selecting a company', () => {
    expect(extractCnpj('CNPJ 11222333000181 e CNPJ 04252011000110', url)).toHaveLength(2);
  });
  it('finds only named tax identifiers in structured data', () => {
    expect(extractCnpj('<script type="application/ld+json">{"taxID":"11222333000181","productId":"04252011000110"}</script>', url)).toMatchObject([{ value: '11222333000181', provenance: [{ location: 'STRUCTURED_DATA' }] }]);
  });
  it.each(['Sem identificação empresarial', 'Pedido 11222333000181', 'CNPJ 00000000000000', 'Código 1112223330001819', '<script>"CNPJ 11222333000181"</script>', 'CPF 123.456.789-01'])('rejects missing numbers and false positives: %s', (text) => {
    expect(extractCnpj(text, url)).toEqual([]);
  });
  it('never stores query or fragment in provenance', () => {
    expect(extractCnpj('CNPJ 11222333000181', new URL('https://example.com/contato?secret=private#x'))[0]?.provenance[0]?.url).toBe(url.href);
  });
});
