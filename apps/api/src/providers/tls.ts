import tls from "node:tls";
import { EgressGuard } from "../security/egress-guard.js";
import { providerResult, type ProviderContext, type ProviderResult, type ScanProvider } from "./contracts.js";

export interface TlsData {
  available: boolean;
  authorized: boolean;
  authorizationError?: string | undefined;
  protocol?: string | undefined;
  cipher?: string | undefined;
  issuer?: string | undefined;
  subject?: string | undefined;
  validFrom?: string | undefined;
  validTo?: string | undefined;
  daysRemaining?: number | undefined;
  fingerprint256?: string | undefined;
}

export class TlsProvider implements ScanProvider<TlsData> {
  readonly id = "tls-direct";
  readonly version = "1.0.0";
  readonly category = "TLS" as const;

  constructor(private readonly guard = new EgressGuard()) {}

  async execute(context: ProviderContext): Promise<ProviderResult<TlsData>> {
    const startedAt = new Date().toISOString();
    try {
      const target = await this.guard.validate(`https://${context.domain}/`);
      const selected = target.addresses[0];
      if (!selected) return providerResult(this, startedAt, "NO_DATA", { errorCode: "DNS_NO_PUBLIC_ADDRESS" });
      const data = await inspectTls(context.domain, selected.address, this.guard, target.addresses.map((x) => x.address), context.signal);
      return providerResult(this, startedAt, "SUCCEEDED", { data });
    } catch (error) {
      const code = safeErrorCode(error);
      return providerResult(this, startedAt, /TIMEOUT|DEADLINE|ABORT/.test(code) ? "TIMED_OUT" : "FAILED", { errorCode: code });
    }
  }
}

function inspectTls(
  hostname: string,
  address: string,
  guard: EgressGuard,
  allowedAddresses: string[],
  signal?: AbortSignal,
): Promise<TlsData> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error("TLS_ABORTED"));
    const socket = tls.connect({
      host: address,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 6_000,
      ALPNProtocols: ["h2", "http/1.1"],
    });
    const onAbort = () => socket.destroy(new Error("TLS_ABORTED"));
    signal?.addEventListener("abort", onAbort, { once: true });
    socket.once("secureConnect", () => {
      try {
        guard.assertConnectedAddress(socket.remoteAddress ?? "", allowedAddresses);
        const certificate = socket.getPeerCertificate(true);
        const validTo = parseCertificateDate(certificate.valid_to);
        const rawAuthorizationError: unknown = socket.authorizationError;
        const authorizationError = rawAuthorizationError instanceof Error
          ? rawAuthorizationError.message
          : typeof rawAuthorizationError === "string"
            ? rawAuthorizationError
            : undefined;
        resolve({
          available: true,
          authorized: socket.authorized,
          authorizationError,
          protocol: socket.getProtocol() ?? undefined,
          cipher: socket.getCipher().name,
          issuer: formatName(certificate.issuer),
          subject: formatName(certificate.subject),
          validFrom: parseCertificateDate(certificate.valid_from)?.toISOString(),
          validTo: validTo?.toISOString(),
          daysRemaining: validTo ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000) : undefined,
          fingerprint256: certificate.fingerprint256,
        });
      } catch (error) {
        reject(error instanceof Error ? error : new Error("TLS_INSPECTION_FAILED"));
      } finally {
        signal?.removeEventListener("abort", onAbort);
        socket.end();
      }
    });
    socket.once("timeout", () => socket.destroy(new Error("TLS_TIMEOUT")));
    socket.once("error", (error) => {
      signal?.removeEventListener("abort", onAbort);
      reject(error instanceof Error ? error : new Error("TLS_SOCKET_FAILED"));
    });
  });
}

function parseCertificateDate(value?: string): Date | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function formatName(value?: Record<string, string | string[] | undefined>): string | undefined {
  if (!value) return undefined;
  const commonName = Array.isArray(value.CN) ? value.CN.join(", ") : value.CN;
  const organization = Array.isArray(value.O) ? value.O.join(", ") : value.O;
  const fallback = Object.values(value).flatMap((item) => Array.isArray(item) ? item : item ? [item] : []).join(", ");
  return commonName ?? organization ?? (fallback || undefined);
}

function safeErrorCode(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 100) : "TLS_FAILED";
}
