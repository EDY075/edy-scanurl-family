import { afterEach, describe, expect, it } from "vitest";
import { ProviderRegistry } from "../src/providers/registry.js";
import { createVirusTotalProviderFromEnvironment, effectiveLocalHost, virusTotalRuntimeStatus } from "../src/providers/virus-total.js";

const validKey = "a".repeat(64);
const originalEnv = { ...process.env };

afterEach(() => {
  for (const key of Object.keys(process.env)) {
    if (!(key in originalEnv)) Reflect.deleteProperty(process.env, key);
  }
  Object.assign(process.env, originalEnv);
});

function localEnvironment(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    HOST: "127.0.0.1",
    PROJECT_USE_MODE: "LOCAL_NONCOMMERCIAL",
    VIRUSTOTAL_ENABLED: "true",
    VIRUSTOTAL_SUBMIT_NEW_URLS: "false",
    VIRUSTOTAL_REANALYZE: "false",
    VIRUSTOTAL_API_KEY: validKey,
    ...overrides,
  };
}

describe("VirusTotal local runtime policy", () => {
  it("enables only the explicit local non-commercial read-only mode", () => {
    expect(virusTotalRuntimeStatus(localEnvironment())).toEqual({
      enabled: true,
      reason: "ENABLED_LOCAL_NONCOMMERCIAL",
      backendOnly: true,
      submitNewUrls: false,
      reanalyze: false,
    });
    expect(createVirusTotalProviderFromEnvironment(localEnvironment())?.id).toBe("virus-total-public");
  });

  it.each([
    [{ VIRUSTOTAL_ENABLED: "false" }, "DISABLED"],
    [{ PROJECT_USE_MODE: "COMMERCIAL" }, "DISABLED_BY_USE_MODE"],
    [{ HOST: "0.0.0.0" }, "DISABLED_BY_DEPLOYMENT"],
    [{ NODE_ENV: "production" }, "DISABLED_BY_DEPLOYMENT"],
    [{ VIRUSTOTAL_SUBMIT_NEW_URLS: "true" }, "DISABLED_BY_WRITE_CAPABILITY"],
    [{ VIRUSTOTAL_REANALYZE: "true" }, "DISABLED_BY_WRITE_CAPABILITY"],
    [{ VIRUSTOTAL_SUBMIT_NEW_URLS: undefined }, "DISABLED_BY_WRITE_CAPABILITY"],
    [{ VIRUSTOTAL_API_KEY: "short" }, "DISABLED_NO_CREDENTIALS"],
  ])("fails closed for %o", (overrides, reason) => {
    const env = localEnvironment(overrides);
    expect(virusTotalRuntimeStatus(env)).toMatchObject({ enabled: false, reason });
    if (env.VIRUSTOTAL_ENABLED === "true") {
      expect(() => createVirusTotalProviderFromEnvironment(env)).toThrow(`VIRUSTOTAL_CONFIGURATION_REJECTED:${reason}`);
    } else {
      expect(createVirusTotalProviderFromEnvironment(env)).toBeUndefined();
    }
  });

  it("adds the provider to the registry only when every guard passes", () => {
    Object.assign(process.env, localEnvironment());
    expect(new ProviderRegistry().enabled().map((provider) => provider.id)).toContain("virus-total-public");
    process.env.VIRUSTOTAL_REANALYZE = "true";
    expect(() => new ProviderRegistry()).toThrow("VIRUSTOTAL_CONFIGURATION_REJECTED:DISABLED_BY_WRITE_CAPABILITY");
  });

  it("rejects remote CORS while local Community mode is enabled", () => {
    const env = localEnvironment({ CORS_ORIGIN: "https://scan.example" });
    expect(virusTotalRuntimeStatus(env)).toMatchObject({ enabled: false, reason: "DISABLED_BY_DEPLOYMENT" });
    expect(() => createVirusTotalProviderFromEnvironment(env)).toThrow("VIRUSTOTAL_CONFIGURATION_REJECTED:DISABLED_BY_DEPLOYMENT");
  });

  it.each([undefined, "", "   "])("normalizes an absent or blank HOST to an explicit loopback bind", (host) => {
    const env = localEnvironment({ HOST: host });
    expect(effectiveLocalHost(env)).toBe("127.0.0.1");
    expect(virusTotalRuntimeStatus(env)).toMatchObject({ enabled: true, reason: "ENABLED_LOCAL_NONCOMMERCIAL" });
  });

  it("never returns the API key in runtime diagnostics", () => {
    const status = virusTotalRuntimeStatus(localEnvironment());
    expect(JSON.stringify(status)).not.toContain(validKey);
    expect(status).not.toHaveProperty("apiKey");
  });
});
