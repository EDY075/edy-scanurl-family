import { providerComplianceRegistry } from "../providers/compliance.js";
import type { ScanProvider } from "../providers/contracts.js";
import { DnsProvider } from "../providers/dns.js";
import { HttpTransparencyProvider } from "../providers/http-transparency.js";
import { RdapProvider } from "../providers/rdap.js";
import { TlsProvider } from "../providers/tls.js";
import { VirusTotalProvider } from "../providers/virus-total.js";
import { FamilyError, type FamilyStore } from "./store.js";

/** Never invokes the personal/local .env factory. Explicit operator attestation is not legal clearance. */
export function familyProviderRegistry(store: FamilyStore, env: NodeJS.ProcessEnv): { enabled(): readonly ScanProvider[] } {
  const providers: ScanProvider[] = [new RdapProvider(), new DnsProvider(), new TlsProvider(), new HttpTransparencyProvider()];
  const enabled = providers.filter((provider) => {
    const record = providerComplianceRegistry.find((entry) => entry.provider === provider.id);
    return record?.enabled && !["0", "false", "off"].includes((env[record.killSwitch] ?? "").toLowerCase());
  });
  if (env.VIRUSTOTAL_ENABLED === "true") {
    if (env.PROJECT_USE_MODE !== "FAMILY_NONCOMMERCIAL_HOSTED" || env.VT_HOSTED_USE_ACCEPTED !== "true" || !env.VT_LICENSE_REFERENCE?.trim() || env.FAMILY_SINGLE_REPLICA !== "true" || env.VIRUSTOTAL_SUBMIT_NEW_URLS !== "false" || env.VIRUSTOTAL_REANALYZE !== "false" || !/^[a-f0-9]{64}$/i.test(env.VIRUSTOTAL_API_KEY ?? "")) throw new FamilyError("FAMILY_VT_LICENSE_CONFIGURATION_REQUIRED", 503);
    enabled.push(new VirusTotalProvider({ apiKey: env.VIRUSTOTAL_API_KEY ?? "", reserveRequest: () => store.reserveVtRequest(), policyMode: "PUBLIC_NONCOMMERCIAL_HOSTED_OPERATOR_AUTHORIZED" }));
  }
  return { enabled: () => enabled };
}
