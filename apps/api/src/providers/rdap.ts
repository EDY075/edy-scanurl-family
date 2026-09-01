import { GuardedFetcher } from "../security/guarded-fetch.js";
import { providerResult, type ProviderContext, type ProviderResult, type ScanProvider } from "./contracts.js";

interface BootstrapData {
  services: [string[], string[]][];
}

export interface RdapData {
  handle?: string | undefined;
  statuses: string[];
  registrationDate?: string | undefined;
  updatedDate?: string | undefined;
  expirationDate?: string | undefined;
  nameservers: string[];
  registrar?: string | undefined;
  rdapServer: string;
}

const BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";

export class RdapProvider implements ScanProvider<RdapData> {
  readonly id = "rdap";
  readonly version = "1.0.0";
  readonly category = "DOMAIN" as const;
  private bootstrap?: { loadedAt: number; data: BootstrapData };

  constructor(private readonly fetcher = new GuardedFetcher()) {}

  async execute(context: ProviderContext): Promise<ProviderResult<RdapData>> {
    const startedAt = new Date().toISOString();
    try {
      const bootstrap = await this.loadBootstrap(context.signal);
      const tld = context.domain.split(".").at(-1)?.toLowerCase();
      const service = bootstrap.services.find(([tlds]) => tld && tlds.map((item) => item.toLowerCase()).includes(tld));
      const base = service?.[1]?.[0];
      if (!base) return providerResult(this, startedAt, "NO_DATA", { errorCode: "RDAP_SERVICE_NOT_FOUND" });
      const sourceUrl = new URL(`domain/${encodeURIComponent(context.domain)}`, ensureTrailingSlash(base)).toString();
      const response = await this.fetcher.fetch(sourceUrl, {
        maxBytes: 1024 * 1024,
        maxRedirects: 2,
        allowedContentTypes: ["application/rdap+json", "application/json"],
        signal: context.signal,
      });
      if (response.statusCode === 404) return providerResult(this, startedAt, "NO_DATA", { sourceUrl });
      if (response.statusCode === 429) return providerResult(this, startedAt, "RATE_LIMITED", { sourceUrl });
      if (response.statusCode < 200 || response.statusCode >= 300) {
        return providerResult(this, startedAt, "FAILED", { sourceUrl, errorCode: `RDAP_HTTP_${String(response.statusCode)}` });
      }
      const payload = JSON.parse(response.body.toString("utf8")) as Record<string, unknown>;
      return providerResult(this, startedAt, "SUCCEEDED", { sourceUrl, data: normalizeRdap(payload, base) });
    } catch (error) {
      const code = error instanceof Error ? error.message.slice(0, 100) : "RDAP_FAILED";
      return providerResult(this, startedAt,
        code.includes("RATE_LIMITED") ? "RATE_LIMITED" : /TIMEOUT|DEADLINE|ABORT/.test(code) ? "TIMED_OUT" : "FAILED",
        { errorCode: code });
    }
  }

  private async loadBootstrap(signal?: AbortSignal): Promise<BootstrapData> {
    if (this.bootstrap && Date.now() - this.bootstrap.loadedAt < 86_400_000) return this.bootstrap.data;
    const response = await this.fetcher.fetch(BOOTSTRAP_URL, {
      maxBytes: 1024 * 1024,
      maxRedirects: 1,
      allowedContentTypes: ["application/json"],
      signal,
    });
    if (response.statusCode === 429) throw new Error("IANA_BOOTSTRAP_RATE_LIMITED");
    if (response.statusCode !== 200) throw new Error(`IANA_BOOTSTRAP_HTTP_${String(response.statusCode)}`);
    const data = JSON.parse(response.body.toString("utf8")) as BootstrapData;
    if (!Array.isArray(data.services)) throw new Error("IANA_BOOTSTRAP_INVALID");
    this.bootstrap = { loadedAt: Date.now(), data };
    return data;
  }
}

function normalizeRdap(payload: Record<string, unknown>, rdapServer: string): RdapData {
  const events = Array.isArray(payload.events) ? payload.events as Record<string, unknown>[] : [];
  const event = (actions: string[]) => events.find((item) => actions.includes(String(item.eventAction)));
  const nameservers = Array.isArray(payload.nameservers)
    ? (payload.nameservers as Record<string, unknown>[]).flatMap((entry) => typeof entry.ldhName === "string" ? [entry.ldhName] : [])
    : [];
  const entities = Array.isArray(payload.entities) ? payload.entities as Record<string, unknown>[] : [];
  const registrarEntity = entities.find((entry) => Array.isArray(entry.roles) && (entry.roles as unknown[]).includes("registrar"));
  return {
    handle: typeof payload.handle === "string" ? payload.handle : undefined,
    statuses: Array.isArray(payload.status) ? payload.status.map(String) : [],
    registrationDate: stringValue(event(["registration"])?.eventDate),
    updatedDate: stringValue(event(["last changed", "last update of RDAP database"])?.eventDate),
    expirationDate: stringValue(event(["expiration"])?.eventDate),
    nameservers,
    registrar: extractVcardName(registrarEntity?.vcardArray),
    rdapServer,
  };
}

function extractVcardName(vcard: unknown): string | undefined {
  if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return undefined;
  const fn = (vcard[1] as unknown[]).find((entry) => Array.isArray(entry) && entry[0] === "fn") as unknown[] | undefined;
  return fn && typeof fn[3] === "string" ? fn[3] : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function ensureTrailingSlash(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
}
