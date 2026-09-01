import { isIP } from "node:net";
import { z } from "zod";

export class TargetRejectedError extends Error {
  readonly code = "SCAN_REJECTED";

  constructor(
    message: string,
    readonly reason: string,
  ) {
    super(message);
    this.name = "TargetRejectedError";
  }
}

const inputSchema = z.string().trim().min(1).max(2_048);
const blockedHostnames = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
  "metadata",
  "instance-data",
]);

export interface NormalizedTarget {
  requestUrl: URL;
  origin: string;
  domain: string;
  persistedTarget: string;
}

export function normalizeTarget(input: string): NormalizedTarget {
  const parsedInput = inputSchema.safeParse(input);
  if (!parsedInput.success) {
    throw new TargetRejectedError("Informe uma URL válida.", "MALFORMED_URL");
  }

  let url: URL;
  try {
    url = new URL(
      /^[a-z][a-z\d+.-]*:/i.test(parsedInput.data)
        ? parsedInput.data
        : `https://${parsedInput.data}`,
    );
  } catch {
    throw new TargetRejectedError("A URL não pôde ser interpretada.", "MALFORMED_URL");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new TargetRejectedError("Somente URLs HTTP e HTTPS são permitidas.", "UNSUPPORTED_PROTOCOL");
  }
  if (url.username || url.password) {
    throw new TargetRejectedError("URLs com credenciais não são permitidas.", "CREDENTIAL_URL");
  }
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new TargetRejectedError("A porta informada não é permitida.", "UNSUPPORTED_PORT");
  }

  const domain = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!domain || blockedHostnames.has(domain) || domain.endsWith(".localhost") || domain.endsWith(".local")) {
    throw new TargetRejectedError("O destino informado não é público.", "INTERNAL_HOSTNAME");
  }
  if (isIP(domain) !== 0) {
    throw new TargetRejectedError("Endereços IP literais não são aceitos.", "IP_LITERAL");
  }
  if (!domain.includes(".") || domain.length > 253) {
    throw new TargetRejectedError("Informe um domínio público válido.", "INVALID_PUBLIC_DOMAIN");
  }

  url.hash = "";
  url.search = "";
  const persisted = new URL(url.origin);
  return {
    requestUrl: url,
    origin: url.origin,
    domain,
    persistedTarget: persisted.toString(),
  };
}

export function redactUrl(value: string): string {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}/[redacted]`;
  } catch {
    return "[invalid-url]";
  }
}
