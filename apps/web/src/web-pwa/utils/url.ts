import { extractFamilyUrl } from "../../family/family-presentation";

/** Client convenience guard. DNS and redirects remain server-enforced. */
export function normalizeStoreUrl(input: string): string {
  if (
    input.length > 8192 ||
    input.includes("\\") ||
    /(?:javascript|data|file|ftp|mailto):/i.test(input)
  )
    throw new Error("invalid_url");
  for (const char of input)
    if (
      (char.charCodeAt(0) < 32 && !["\n", "\r", "\t"].includes(char)) ||
      char.charCodeAt(0) === 127
    )
      throw new Error("invalid_url");
  const value = extractFamilyUrl(input);
  const url = new URL(value);
  const host = url.hostname.toLowerCase();
  if (
    url.username ||
    url.password ||
    url.port ||
    host.length > 253 ||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(
      host,
    )
  )
    throw new Error("invalid_url");
  if (
    /(^|\.)(localhost|local|internal|lan|home|test|invalid|onion)$/.test(
      host,
    ) ||
    host === "metadata.google.internal" ||
    host === "metadata.google" ||
    host.endsWith(".nip.io") ||
    host.endsWith(".sslip.io")
  )
    throw new Error("invalid_url");
  // Intentionally submit the public origin only; discard product path/tracking.
  return `${url.origin}/`;
}

export function validStoreUrl(value: string): string | null {
  try {
    return normalizeStoreUrl(value);
  } catch {
    return null;
  }
}
