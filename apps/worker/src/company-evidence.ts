import { normalizeCnpj, validCnpj, type CnpjObservation } from '../../web/src/evidence/cnpj';

/** Bounded passive extraction; never fetches, follows links or retains raw text. */
export function extractCnpj(html: string, pageUrl: URL, maximum = 8): CnpjObservation[] {
  const observations: CnpjObservation[] = [];
  const cleanUrl = new URL(pageUrl); cleanUrl.search = ''; cleanUrl.hash = '';
  const scan = (text: string, location: CnpjObservation['provenance'][number]['location'], structured = false) => {
    const plain = text.replace(/<[^>]*>/g, ' ').replace(/&(?:nbsp|#160);/gi, ' ').replace(/\s+/g, ' ');
    for (const match of plain.matchAll(/(?<![\w\d])\d{2}[.\s]?\d{3}[.\s]?\d{3}[/\s]?\d{4}[-\s]?\d{2}(?![\w\d])/g)) {
      const value = normalizeCnpj(match[0]);
      const labelled = structured || /\bcnpj\s*[:nº°.\s-]*$/i.test(plain.slice(Math.max(0, match.index - 40), match.index));
      // Bare order/tracking numbers are not business declarations. Invalid
      // digits are retained only when explicitly declared as CNPJ.
      if ((!labelled && (!validCnpj(value) || !match[0].includes('/'))) || /^(\d)\1+$/.test(value)) continue;
      const existing = observations.find((item) => item.value === value);
      const provenance = { url: cleanUrl.href, location };
      if (existing) {
        if (existing.provenance.length < 6 && !existing.provenance.some((item) => item.url === provenance.url && item.location === location)) existing.provenance.push(provenance);
      } else if (observations.length < maximum) observations.push({ value, checksum: validCnpj(value) ? 'VALID' : 'INVALID', provenance: [provenance] });
    }
  };
  const visible = html.slice(0, 900_000).replace(/<(script|style|noscript|iframe|object|embed)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' ');
  for (const footer of visible.matchAll(/<footer\b[^>]*>([\s\S]*?)<\/footer\s*>/gi)) scan(footer[1] ?? '', 'FOOTER');
  scan(visible.replace(/<footer\b[^>]*>[\s\S]*?<\/footer\s*>/gi, ' '), 'PAGE');
  for (const script of html.slice(0, 900_000).matchAll(/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script\s*>/gi)) {
    for (const field of (script[1] ?? '').matchAll(/"(?:taxID|vatID|cnpj)"\s*:\s*"([^"<>]{1,60})"/gi)) scan(field[1] ?? '', 'STRUCTURED_DATA', true);
  }
  return mergeCnpj(observations, maximum);
}

export function mergeCnpj(items: CnpjObservation[], maximum = 8): CnpjObservation[] {
  const byValue = new Map<string, CnpjObservation>();
  for (const item of items) {
    const existing = byValue.get(item.value);
    if (existing) {
      for (const source of item.provenance) if (existing.provenance.length < 6 && !existing.provenance.some((p) => p.url === source.url && p.location === source.location)) existing.provenance.push(source);
    } else if (byValue.size < maximum) byValue.set(item.value, { ...item, provenance: [...item.provenance] });
  }
  return [...byValue.values()];
}
