import { afterEach, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { scanStore } from "./api";

// Explicit opt-in only. Uses the exact web client against the real API, not a
// browser UI. The transport/signature/report are real; only key persistence is
// replaced by a test-process key to avoid accessing any user's browser data.
vi.mock("./identity", async (importOriginal) => {
  const original = await importOriginal<typeof import("./identity")>();
  return {
    ...original,
    getBrowserIdentity: async () => {
      const pair = await webcrypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"],
      );
      const spki = await webcrypto.subtle.exportKey("spki", pair.publicKey);
      return {
        privateKey: pair.privateKey,
        publicKeySpki: Buffer.from(spki).toString("base64"),
        deviceId: Buffer.from(
          await webcrypto.subtle.digest("SHA-256", spki),
        ).toString("hex"),
      };
    },
  };
});
afterEach(() => {
  vi.unstubAllGlobals();
});
it.runIf(process.env.EDY_WEB_LIVE === "true")(
  "validates the real Worker contract for atelierdrahaiter.com.br (one scan)",
  async () => {
    vi.stubGlobal("crypto", webcrypto);
    const phases: string[] = [];
    const report = await scanStore(
      "https://atelierdrahaiter.com.br/",
      (phase) => phases.push(phase),
    );
    expect(report.mode).toBe("real");
    expect(report.domain).toBe("atelierdrahaiter.com.br");
    expect(report.checks.length).toBeGreaterThan(0);
    expect(report.sources.length).toBeGreaterThan(0);
    expect(phases).toEqual([
      "validating",
      "authenticating",
      "collecting",
      "preparing",
    ]);
  },
  45_000,
);
