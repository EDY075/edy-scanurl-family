export function normalizeStoreUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('empty');
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const parsed = new URL(candidate);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('protocol');
  if (!parsed.hostname.includes('.') && parsed.hostname !== 'localhost') throw new Error('hostname');
  parsed.hash = '';
  return parsed.toString();
}

export function displayDomain(value: string): string {
  try {
    return new URL(value).hostname.replace(/^www\./, '');
  } catch {
    return value;
  }
}
