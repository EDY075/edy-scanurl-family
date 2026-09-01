import type { ScanProvider } from "./contracts.js";
import { providerComplianceRegistry } from "./compliance.js";
import { DnsProvider } from "./dns.js";
import { HttpTransparencyProvider } from "./http-transparency.js";
import { RdapProvider } from "./rdap.js";
import { TlsProvider } from "./tls.js";
import { createVirusTotalProviderFromEnvironment } from "./virus-total.js";

export class ProviderRegistry {
  private readonly providers = new Map<string, ScanProvider>();

  constructor(providers: readonly ScanProvider[] = defaultProviders()) {
    for (const provider of providers) {
      if (this.providers.has(provider.id)) throw new Error(`Duplicate provider: ${provider.id}`);
      this.providers.set(provider.id, provider);
    }
  }

  enabled(): readonly ScanProvider[] {
    return [...this.providers.values()];
  }
}

function defaultProviders(): ScanProvider[] {
  const providers = filterEnabled([
    new RdapProvider(),
    new DnsProvider(),
    new TlsProvider(),
    new HttpTransparencyProvider(),
  ]);
  const virusTotal = createVirusTotalProviderFromEnvironment();
  if (virusTotal) providers.push(virusTotal);
  return providers;
}

function filterEnabled(providers: readonly ScanProvider[]): ScanProvider[] {
  return providers.filter((provider) => {
    const record = providerComplianceRegistry.find((item) => item.provider === provider.id);
    if (!record?.enabled) return false;
    const value = process.env[record.killSwitch];
    return value === undefined || !["0", "false", "off"].includes(value.toLowerCase());
  });
}
