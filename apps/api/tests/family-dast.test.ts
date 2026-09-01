import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { createFamilyApp } from "../src/family/app.js";
import { FamilyStore, sha256 } from "../src/family/store.js";

it("Family local DAST: real TCP/SQLite/registry, no mocks or external scans", async () => {
  const path = join(mkdtempSync(join(tmpdir(), "edy-family-dast-")), "family.sqlite");
  const store = new FamilyStore(path);
  const app = createFamilyApp({ store, audience: "https://family.example", env: { NODE_ENV: "production" } });
  const base = await app.listen({ host: "127.0.0.1", port: 0 });
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeySpki = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const headers = { "content-type": "application/json", origin: "https://localhost" };
  try {
    const health = await fetch(`${base}/health`);
    expect(health.status).toBe(200);
    expect(health.headers.get("cache-control")).toBe("no-store, private");
    expect((await fetch(`${base}/health`, { headers: { origin: "http://127.0.0.1:4180" } })).status).toBe(403);
    const enrollResponse = await fetch(`${base}/family/v1/enroll`, { method: "POST", headers, body: JSON.stringify({ publicKeySpki }) });
    const enrolled = await enrollResponse.json() as { deviceId: string; status: string };
    expect(enrolled.status).toBe("PENDING");
    expect(enrollResponse.headers.get("access-control-allow-origin")).toBe("https://localhost");
    const admin = new FamilyStore(path, Date.now, { admin: true });
    admin.approve(enrolled.deviceId); admin.close();
    const body = JSON.stringify({ url: "http://169.254.169.254/latest/meta-data/" });
    const challengeRequest = { deviceId: enrolled.deviceId, method: "POST", path: "/family/v1/scans", bodyHash: sha256(body) };
    const challengeResponse = await fetch(`${base}/family/v1/challenge`, { method: "POST", headers, body: JSON.stringify(challengeRequest) });
    expect(challengeResponse.status).toBe(200);
    const challenge = await challengeResponse.json() as { challengeId: string; message: string };
    const signed = { ...headers, "x-family-device": enrolled.deviceId, "x-family-challenge": challenge.challengeId, "x-family-signature": sign("sha256", Buffer.from(challenge.message), pair.privateKey).toString("base64") };
    const response = await fetch(`${base}/family/v1/scans`, { method: "POST", headers: signed, body });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ code: "SCAN_REJECTED" });
    expect((await fetch(`${base}/family/v1/scans`, { method: "POST", headers: signed, body })).status).toBe(403);
    expect((await fetch(`${base}/api/v1/scans`, { method: "POST", headers, body })).status).toBe(404);
    expect((await fetch(`${base}/family/v1/approve`, { method: "POST", headers, body: "{}" })).status).toBe(404);
    expect((await fetch(`${base}/family/v1/scans`, { method: "POST", headers: { ...headers, "x-forwarded-for": "127.0.0.1" }, body })).status).toBe(403);
    expect((await fetch(`${base}/family/v1/enroll`, { method: "POST", headers, body: "x".repeat(4097) })).status).toBe(413);
  } finally { await app.close(); store.close(); }
});
