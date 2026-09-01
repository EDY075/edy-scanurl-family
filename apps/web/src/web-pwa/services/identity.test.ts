import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { IDBFactory } from "fake-indexeddb";

beforeEach(() => {
  vi.resetModules();
  vi.stubGlobal("crypto", webcrypto);
  vi.stubGlobal("indexedDB", new IDBFactory());
});
afterEach(() => {
  vi.unstubAllGlobals();
});
describe("Browser identity persistence — in-memory IndexedDB test adapter", () => {
  it("persists the same device across a module reload", async () => {
    const first = await (await import("./identity")).getBrowserIdentity();
    vi.resetModules();
    const second = await (await import("./identity")).getBrowserIdentity();
    expect(second.deviceId).toBe(first.deviceId);
    expect(second.publicKeySpki).toBe(first.publicKeySpki);
  });
  it("never exports the private P-256 key", async () => {
    const identity = await (await import("./identity")).getBrowserIdentity();
    expect(identity.privateKey.extractable).toBe(false);
    await expect(
      webcrypto.subtle.exportKey("pkcs8", identity.privateKey),
    ).rejects.toThrow();
    expect(identity.deviceId).toMatch(/^[a-f0-9]{64}$/);
  });
  it("serializes concurrent callers to the same identity", async () => {
    const client = await import("./identity");
    const [a, b, c] = await Promise.all([
      client.getBrowserIdentity(),
      client.getBrowserIdentity(),
      client.getBrowserIdentity(),
    ]);
    expect(new Set([a.deviceId, b.deviceId, c.deviceId]).size).toBe(1);
  });
  it("rechecks the write transaction across two separate module instances", async () => {
    const first = await import("./identity");
    vi.resetModules();
    const second = await import("./identity");
    const [a, b] = await Promise.all([
      first.getBrowserIdentity(),
      second.getBrowserIdentity(),
    ]);
    expect(a.deviceId).toBe(b.deviceId);
  });
  it("fails explicitly when browser storage is unavailable", async () => {
    vi.stubGlobal("indexedDB", undefined);
    await expect(
      (await import("./identity")).getBrowserIdentity(),
    ).rejects.toThrow("storage");
  });
});
