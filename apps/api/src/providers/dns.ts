import { lookup, Resolver } from "node:dns/promises";
import { providerResult, type ProviderContext, type ProviderResult, type ScanProvider } from "./contracts.js";

export interface DnsData {
  a: string[];
  aaaa: string[];
  ns: string[];
  mx: { exchange: string; priority: number }[];
  caa: unknown[];
  dnssec: "SIGNED" | "NOT_OBSERVED" | "UNKNOWN";
}

export class DnsProvider implements ScanProvider<DnsData> {
  readonly id = "dns-direct";
  readonly version = "1.0.0";
  readonly category = "DNS" as const;

  constructor(
    private readonly resolverFactory: () => Resolver = () => new Resolver(),
    private readonly addressLookup: (domain: string) => Promise<{ address: string; family: number }[]> =
      (domain) => lookup(domain, { all: true, verbatim: true }),
  ) {}

  async execute(context: ProviderContext): Promise<ProviderResult<DnsData>> {
    const startedAt = new Date().toISOString();
    const resolver = this.resolverFactory();
    let rejectAbort: ((error: Error) => void) | undefined;
    const abortResult = new Promise<never>((_resolve, reject) => { rejectAbort = reject; });
    const abort = () => {
      resolver.cancel();
      rejectAbort?.(new Error("DNS_ABORTED"));
    };
    try {
      if (context.signal?.aborted) return providerResult(this, startedAt, "TIMED_OUT", { errorCode: "DNS_ABORTED" });
      context.signal?.addEventListener("abort", abort, { once: true });
      if (context.signal?.aborted) abort();
      const queries = Promise.all([
        settle(() => this.addressLookup(context.domain)),
        settle(() => resolver.resolveNs(context.domain)),
        settle(() => resolver.resolveMx(context.domain)),
        settle(() => resolver.resolveCaa(context.domain)),
        settle(() => resolver.resolve(context.domain, "DS") as Promise<unknown[]>),
      ]);
      const [addressResult, nsResult, mxResult, caaResult, dsResult] = await (context.signal ? Promise.race([queries, abortResult]) : queries);
      if (context.signal?.aborted) return providerResult(this, startedAt, "TIMED_OUT", { errorCode: "DNS_ABORTED" });
      const a = addressResult.data.filter((entry) => entry.family === 4).map((entry) => entry.address);
      const aaaa = addressResult.data.filter((entry) => entry.family === 6).map((entry) => entry.address);
      if (a.length + aaaa.length === 0) {
        const addressFailure = addressResult.state === "FAILED";
        return providerResult(this, startedAt, addressFailure ? "FAILED" : "NO_DATA", { errorCode: addressFailure ? "DNS_ADDRESS_LOOKUP_FAILED" : "DNS_NO_ADDRESS" });
      }
      const partial = [addressResult, nsResult, mxResult, caaResult, dsResult].some((result) => result.state === "FAILED");
      return providerResult(this, startedAt, partial ? "PARTIAL" : "SUCCEEDED", {
        data: {
          a,
          aaaa,
          ns: nsResult.data,
          mx: mxResult.data,
          caa: caaResult.data,
          dnssec: dsResult.state === "FAILED" ? "UNKNOWN" : dsResult.data.length > 0 ? "SIGNED" : "NOT_OBSERVED",
        },
        ...(partial ? { errorCode: "DNS_PARTIAL_QUERY_FAILURE" } : {}),
      });
    } catch (error) {
      if (context.signal?.aborted || errorCode(error) === "DNS_ABORTED") {
        return providerResult(this, startedAt, "TIMED_OUT", { errorCode: "DNS_ABORTED" });
      }
      return providerResult(this, startedAt, "FAILED", { errorCode: errorCode(error) });
    } finally {
      context.signal?.removeEventListener("abort", abort);
    }
  }
}

type QueryState = "OBSERVED" | "NO_DATA" | "FAILED";

async function settle<T>(operation: () => Promise<T>): Promise<{ data: T extends unknown[] ? T : never[]; state: QueryState }> {
  try {
    const data = (await operation()) as T extends unknown[] ? T : never[];
    return { data, state: data.length > 0 ? "OBSERVED" : "NO_DATA" };
  } catch (error) {
    const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : "";
    return { data: [] as T extends unknown[] ? T : never[], state: ["ENODATA", "ENOTFOUND"].includes(code) ? "NO_DATA" : "FAILED" };
  }
}

function errorCode(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 80) : "DNS_FAILED";
}
