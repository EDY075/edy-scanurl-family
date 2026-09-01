import ipaddr from "ipaddr.js";

const blockedRanges = new Set([
  "unspecified",
  "broadcast",
  "multicast",
  "linkLocal",
  "loopback",
  "private",
  "reserved",
  "carrierGradeNat",
  "uniqueLocal",
  "ipv4Mapped",
  "rfc6052",
  "6to4",
  "teredo",
  "benchmarking",
  "amt",
  "as112v4",
]);

export interface AddressDecision {
  address: string;
  allowed: boolean;
  range: string;
}

export function classifyAddress(address: string): AddressDecision {
  try {
    const parsed = ipaddr.parse(address);
    // Azure infrastructure VIP is publicly numbered but is not a scan target.
    if (parsed.toString() === "168.63.129.16") return { address, allowed: false, range: "cloudInfrastructure" };
    const range = parsed.range();
    if (parsed.kind() === "ipv6") {
      const ipv6 = parsed as ipaddr.IPv6;
      if (ipv6.isIPv4MappedAddress()) {
        return { address, allowed: false, range: "ipv4Mapped" };
      }
    }
    return { address, allowed: !blockedRanges.has(range), range };
  } catch {
    return { address, allowed: false, range: "invalid" };
  }
}

export function assertPublicAddresses(addresses: readonly string[]): void {
  if (addresses.length === 0) {
    throw new Error("DNS_NO_PUBLIC_ADDRESS");
  }
  const decisions = addresses.map(classifyAddress);
  const blocked = decisions.filter((decision) => !decision.allowed);
  if (blocked.length > 0) {
    throw new Error(`EGRESS_BLOCKED:${blocked.map((item) => item.range).join(",")}`);
  }
}
