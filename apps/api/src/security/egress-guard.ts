import { lookup } from "node:dns/promises";
import { assertPublicAddresses, classifyAddress } from "./ip-policy.js";
import { normalizeTarget, type NormalizedTarget } from "./target.js";

export interface ResolvedTarget extends NormalizedTarget {
  addresses: { address: string; family: 4 | 6 }[];
}

export type ResolveHost = (hostname: string) => Promise<{ address: string; family: 4 | 6 }[]>;

export class EgressGuard {
  constructor(private readonly resolveHost: ResolveHost = defaultResolve) {}

  async validate(input: string | URL): Promise<ResolvedTarget> {
    const normalized = normalizeTarget(input.toString());
    const addresses = deduplicate(await this.resolveHost(normalized.domain));
    assertPublicAddresses(addresses.map((entry) => entry.address));
    return { ...normalized, addresses };
  }

  assertConnectedAddress(address: string, allowedAddresses: readonly string[]): void {
    const decision = classifyAddress(address);
    if (!decision.allowed || !allowedAddresses.includes(address)) {
      throw new Error("DNS_REBINDING_BLOCKED");
    }
  }
}

async function defaultResolve(hostname: string): Promise<{ address: string; family: 4 | 6 }[]> {
  const results = await lookup(hostname, { all: true, verbatim: true });
  return results.flatMap((entry) => entry.family === 4 || entry.family === 6
    ? [{ address: entry.address, family: entry.family }]
    : []);
}

function deduplicate(values: { address: string; family: 4 | 6 }[]) {
  return [...new Map(values.map((value) => [`${String(value.family)}:${value.address}`, value])).values()];
}
