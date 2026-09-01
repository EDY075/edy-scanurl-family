import { generateKeyPairSync, sign, randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createFamilyApp, validateFamilyAudience } from "../src/family/app.js";
import { FamilyStore, sha256 } from "../src/family/store.js";
import { familyProviderRegistry } from "../src/family/providers.js";
import { VirusTotalProvider } from "../src/providers/virus-total.js";
import type { ScanJobSnapshot } from "../src/services/scan-orchestrator.js";
import type { FastifyInstance } from "fastify";
import type { DatabaseSync } from "node:sqlite";

const audience = "https://family.example";
const scanPath = "/family/v1/scans";
const held: { app?: FastifyInstance; store: FamilyStore }[] = [];
afterEach(async () => { for (const fixture of held.splice(0)) { await fixture.app?.close(); try { fixture.store.close(); } catch { /* explicit storage-failure test already closed it */ } } });
function key() {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return { ...pair, spki: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64") };
}
function setup(persistent = false) {
  let now = Date.UTC(2026, 7, 30, 12);
  const path = persistent ? join(mkdtempSync(join(tmpdir(), "edy-family-test-")), "family.sqlite") : ":memory:";
  const store = new FamilyStore(path, () => now);
  const fixture = { store }; held.push(fixture);
  const pair = key(); const device = store.enroll(pair.spki); store.approve(device.deviceId);
  return { store, pair, deviceId: device.deviceId, path, now: () => now, advance: (ms: number) => { while (ms > 0) { const step = Math.min(ms, 20_000); now += step; store.heartbeat(); ms -= step; } } };
}
function proof(fixture: ReturnType<typeof setup>, method = "POST", path = scanPath, body = "{}") {
  const challenge = fixture.store.challenge(fixture.deviceId, method, path, sha256(body), audience);
  return { ...challenge, signature: sign("sha256", Buffer.from(challenge.message), fixture.pair.privateKey).toString("base64") };
}
function authenticate(fixture: ReturnType<typeof setup>, p: ReturnType<typeof proof>, body = "{}", method = "POST", path = scanPath) {
  fixture.store.authenticate(fixture.deviceId, p.challengeId, p.signature, method, path, Buffer.from(body), audience);
}
function appFor(fixture: ReturnType<typeof setup>, running = false) {
  const jobs = new Map<string, ScanJobSnapshot>();
  const create = vi.fn(() => { const job: ScanJobSnapshot = { scanId: randomUUID(), status: running ? "RUNNING" : "SUCCEEDED", progress: { completed: 0, total: 0, current: "TEST" } }; jobs.set(job.scanId, job); return job; });
  const app = createFamilyApp({ store: fixture.store, audience, env: {}, orchestrator: { create, get: (id) => jobs.get(id) } });
  held.push({ store: fixture.store, app });
  return { app, create };
}
function signedHeaders(fixture: ReturnType<typeof setup>, p: ReturnType<typeof proof>) {
  return { "content-type": "application/json", "x-family-device": fixture.deviceId, "x-family-challenge": p.challengeId, "x-family-signature": p.signature };
}

describe("Family durable proof-of-possession", () => {
  it("uses SHA256 SPKI identities and exact canonical challenge; pending is not authorized", () => {
    const f = setup(); const pair = key(); const enrolled = f.store.enroll(pair.spki);
    expect(enrolled.deviceId).toBe(sha256(Buffer.from(pair.spki, "base64")));
    expect(enrolled.status).toBe("PENDING");
    expect(() => f.store.challenge(enrolled.deviceId, "POST", scanPath, sha256("{}"), audience)).toThrow("FAMILY_DEVICE_PENDING");
    const p = proof(f);
    const fields = p.message.split("\n");
    expect(fields).toHaveLength(8);
    expect(fields.slice(0, 4)).toEqual(["EDY-FAMILY-V1", audience, f.deviceId, p.challengeId]);
    expect(fields.slice(5)).toEqual(["POST", scanPath, sha256("{}")]);
    authenticate(f, p);
    expect(() => authenticate(f, p)).toThrow("FAMILY_SIGNATURE_REJECTED");
  });
  it("rejects wrong body, audience, path, device and signature; revocation invalidates outstanding challenges", () => {
    const f = setup(); const p = proof(f);
    expect(() => authenticate(f, p, "{ } ")).toThrow();
    expect(() => authenticate(f, p, "{}", "POST", `${scanPath}?x=1`)).toThrow();
    expect(() => f.store.authenticate(f.deviceId, p.challengeId, p.signature, "POST", scanPath, Buffer.from("{}"), "https://other.example")).toThrow();
    const other = key(); const enrolled = f.store.enroll(other.spki); f.store.approve(enrolled.deviceId);
    expect(() => f.store.authenticate(enrolled.deviceId, p.challengeId, p.signature, "POST", scanPath, Buffer.from("{}"), audience)).toThrow();
    expect(() => authenticate(f, { ...p, signature: "AA==" })).toThrow();
    f.store.revoke(f.deviceId);
    expect(() => authenticate(f, p)).toThrow("FAMILY_DEVICE_REVOKED");
    expect(f.store.enroll(f.pair.spki).status).toBe("REVOKED");
    expect(() => f.store.approve(f.deviceId)).toThrow();
  });
  it("expires challenges at 60s; rejects forbidden methods/routes and non-P256 keys", () => {
    const f = setup(); const p = proof(f); f.advance(60_000);
    expect(() => authenticate(f, p)).toThrow();
    for (const [method, path] of [["POST", "/admin"], ["GET", scanPath], ["POST", `${scanPath}/${randomUUID()}`], ["DELETE", scanPath]]) expect(() => f.store.challenge(f.deviceId, method ?? "", path ?? "", sha256(""), audience)).toThrow();
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(() => f.store.enroll(rsa.publicKey.export({ format: "der", type: "spki" }).toString("base64"))).toThrow("FAMILY_INVALID_KEY");
    expect(() => f.store.enroll("bad")).toThrow("FAMILY_INVALID_KEY");
  });
  it("persists replay protection, quotas and private snapshots across restart; interrupted jobs fail", () => {
    const f = setup(true); const p = proof(f); authenticate(f, p);
    const interrupted = f.store.reserveJob(f.deviceId);
    const done = f.store.reserveJob(f.deviceId); f.store.saveJob(done.scanId, { ...done, status: "SUCCEEDED" });
    f.store.close();
    const reopened = new FamilyStore(f.path, f.now); held.push({ store: reopened });
    expect(() => reopened.authenticate(f.deviceId, p.challengeId, p.signature, "POST", scanPath, Buffer.from("{}"), audience)).toThrow();
    expect(reopened.getJob(f.deviceId, interrupted.scanId)?.status).toBe("FAILED");
    expect(reopened.getJob(f.deviceId, done.scanId)?.status).toBe("SUCCEEDED");
    for (let i = 0; i < 18; i++) { const job = reopened.reserveJob(f.deviceId); reopened.saveJob(job.scanId, { ...job, status: "SUCCEEDED" }); }
    expect(() => reopened.reserveJob(f.deviceId)).toThrow("FAMILY_RATE_LIMITED");
  });
  it("refuses a second live worker but allows owner approval from separate administrative connection", () => {
    const f = setup(true);
    expect(() => new FamilyStore(f.path, f.now)).toThrow("FAMILY_INSTANCE_ACTIVE");
    const admin = new FamilyStore(f.path, f.now, { admin: true }); held.push({ store: admin });
    const p = key(); const device = f.store.enroll(p.spki); admin.approve(device.deviceId);
    expect(f.store.enroll(p.spki).status).toBe("ACTIVE");
  });
  it("bounds pending24h, active devices20, queue10 and jobs15min", () => {
    const f = setup();
    for (let i = 0; i < 19; i++) { const device = f.store.enroll(key().spki); f.store.approve(device.deviceId); }
    const excess = f.store.enroll(key().spki);
    expect(() => f.store.approve(excess.deviceId)).toThrow("FAMILY_DEVICE_CAPACITY");
    const first = f.store.reserveJob(f.deviceId);
    for (let i = 0; i < 9; i++) f.store.reserveJob(f.deviceId);
    expect(() => f.store.reserveJob(f.deviceId)).toThrow("FAMILY_QUEUE_FULL");
    f.store.saveJob(first.scanId, { ...first, status: "SUCCEEDED" });
    f.advance(15 * 60_000);
    expect(f.store.getJob(f.deviceId, first.scanId)).toBeUndefined();
    f.advance(24 * 60 * 60_000);
    expect(f.store.list().find((device) => device.id === excess.deviceId)).toBeUndefined();
  });
  it("keeps VT sliding4/60 across midnight and restart, with durable500/day", () => {
    const f = setup(true);
    for (let i = 0; i < 4; i++) expect(f.store.reserveVtRequest()).toBe(true);
    expect(f.store.reserveVtRequest()).toBe(false);
    f.store.close(); const store = new FamilyStore(f.path, f.now); held.push({ store });
    expect(store.reserveVtRequest()).toBe(false);
    store.close();
    let now = Date.UTC(2026, 7, 30, 23, 59, 59);
    const midnight = new FamilyStore(":memory:", () => now); held.push({ store: midnight });
    for (let i = 0; i < 4; i++) expect(midnight.reserveVtRequest()).toBe(true);
    now += 2_000;
    expect(midnight.reserveVtRequest()).toBe(false);
  });
  it("fails closed on database write failures", () => {
    const f = setup(); const db = (f.store as unknown as { db: DatabaseSync }).db;
    db.exec("PRAGMA query_only=ON");
    expect(() => f.store.reserveJob(f.deviceId)).toThrow();
    db.exec("PRAGMA query_only=OFF");
    expect(f.store.reserveJob(f.deviceId).status).toBe("QUEUED");
  });
  it("rolls back SQLite FULL writes without fabricating completion", () => {
    const f = setup(true); const job = f.store.reserveJob(f.deviceId);
    const db = (f.store as unknown as { db: DatabaseSync }).db;
    const pageCount = db.prepare("PRAGMA page_count").get() as { page_count: number };
    db.exec(`PRAGMA max_page_count=${String(pageCount.page_count)}`);
    expect(() => f.store.saveJob(job.scanId, { ...job, status: "FAILED", error: "x".repeat(2_000_000) })).toThrow();
    expect(f.store.getJob(f.deviceId, job.scanId)?.status).toBe("QUEUED");
  });
  it("caps100 family scans/day and100 pending enrollments", () => {
    const f = setup();
    const deviceIds = [f.deviceId];
    for (let i = 0; i < 4; i++) { const enrolled = f.store.enroll(key().spki); f.store.approve(enrolled.deviceId); deviceIds.push(enrolled.deviceId); }
    for (const id of deviceIds) for (let i = 0; i < 20; i++) { const job = f.store.reserveJob(id); f.store.saveJob(job.scanId, { ...job, status: "SUCCEEDED" }); }
    const next = f.store.enroll(key().spki); f.store.approve(next.deviceId);
    expect(() => f.store.reserveJob(next.deviceId)).toThrow("FAMILY_RATE_LIMITED");
    for (let i = 0; i < 100; i++) { if (i % 20 === 0) f.advance(60_000); f.store.enroll(key().spki); }
    f.advance(60_000);
    expect(() => f.store.enroll(key().spki)).toThrow("FAMILY_ENROLLMENT_CAPACITY");
  });
  it("enforces durable500 VT requests/day even after minute windows refill", () => {
    const f = setup();
    for (let i = 0; i < 125; i++) { for (let j = 0; j < 4; j++) expect(f.store.reserveVtRequest()).toBe(true); f.advance(60_000); }
    expect(f.store.reserveVtRequest()).toBe(false);
  });
  it("provider durable reservation refusal prevents every upstream GET", async () => {
    const upstream = vi.fn(() => Promise.reject(new Error("NETWORK_NOT_EXPECTED")));
    const provider = new VirusTotalProvider({ apiKey: "synthetic-test-key", fetchImpl: upstream, reserveRequest: () => false });
    const result = await provider.execute({ scanId: "test", domain: "example.com", targetUrl: "https://example.com/" });
    expect(result.status).toBe("RATE_LIMITED"); expect(upstream).not.toHaveBeenCalled();
  });
  it("disables VT by default and rejects local credentials/flags without hosted authorization", () => {
    const f = setup();
    expect(familyProviderRegistry(f.store, {}).enabled().some((p) => p.id === "virus-total-public")).toBe(false);
    expect(() => familyProviderRegistry(f.store, { VIRUSTOTAL_ENABLED: "true", PROJECT_USE_MODE: "LOCAL_NONCOMMERCIAL" })).toThrow("FAMILY_VT_LICENSE_CONFIGURATION_REQUIRED");
    expect(validateFamilyAudience("http://127.0.0.1:8788")).toBe("http://127.0.0.1:8788");
    expect(() => validateFamilyAudience("http://127.0.0.1:8788", true)).toThrow();
    expect(() => validateFamilyAudience("https://family.example/path")).toThrow();
    for (const invalid of ["https://127.0.0.1", "https://[::1]", "https://localhost", "https://family.local", "https://family.invalid", "https://x.y.ts.net", "https://family.example:444", "https://family.example."]) expect(() => validateFamilyAudience(invalid, true)).toThrow();
  });
});

describe("Family HTTP isolation", () => {
  it("requires raw-body signatures, atomically rejects simultaneous replay, and enforces owner access", async () => {
    const f = setup(); const { app } = appFor(f);
    const body = '{"url":"https://example.com/"}'; const p = proof(f, "POST", scanPath, body);
    const responses = await Promise.all([app.inject({ method: "POST", url: scanPath, headers: signedHeaders(f, p), payload: body }), app.inject({ method: "POST", url: scanPath, headers: signedHeaders(f, p), payload: body })]);
    expect(responses.map((response) => response.statusCode).sort()).toEqual([202, 403]);
    const success = responses.find((response) => response.statusCode === 202);
    if (!success) throw new Error("MISSING_ACCEPTED_RESPONSE");
    const scanId = success.json<{ scanId: string }>().scanId;
    const path = `${scanPath}/${scanId}`;
    const otherPair = key(); const otherId = f.store.enroll(otherPair.spki).deviceId; f.store.approve(otherId);
    const other = { ...f, pair: otherPair, deviceId: otherId }; const op = proof(other, "GET", path, "");
    expect((await app.inject({ method: "GET", url: path, headers: signedHeaders(other, op) })).statusCode).toBe(404);
    const own = proof(f, "GET", path, "");
    expect((await app.inject({ method: "GET", url: path, headers: signedHeaders(f, own) })).statusCode).toBe(200);
    expect((await app.inject({ method: "GET", url: path })).statusCode).toBe(403);
    expect((await app.inject({ method: "POST", url: "/family/v1/approve" })).statusCode).toBe(404);
  });
  it("does not start more than2 scans and refuses excess bounded queue", async () => {
    const f = setup(); const { app, create } = appFor(f, true);
    const body = '{"url":"https://example.com/"}';
    for (let i = 0; i < 10; i++) { const p = proof(f, "POST", scanPath, body); expect((await app.inject({ method: "POST", url: scanPath, payload: body, headers: signedHeaders(f, p) })).statusCode).toBe(202); }
    const p = proof(f, "POST", scanPath, body);
    expect((await app.inject({ method: "POST", url: scanPath, payload: body, headers: signedHeaders(f, p) })).statusCode).toBe(429);
    expect(create).toHaveBeenCalledTimes(2);
  });
  it("keeps bad enroll bounded, rejects external origins and large bodies, no stack or secret errors", async () => {
    const f = setup(); const { app } = appFor(f);
    expect((await app.inject({ url: "/health", headers: { origin: "https://attacker.example" } })).statusCode).toBe(403);
    const bad = await app.inject({ method: "POST", url: scanPath, headers: { "content-type": "application/json", origin: "https://localhost" }, payload: "x".repeat(4097) });
    expect(bad.statusCode).toBe(413); expect(bad.headers["access-control-allow-origin"]).toBe("https://localhost");
    for (let i = 0; i < 30; i++) await app.inject({ method: "POST", url: "/family/v1/enroll", headers: { "content-type": "application/json" }, payload: "{}" });
    expect((await app.inject({ method: "POST", url: "/family/v1/enroll", headers: { "content-type": "application/json" }, payload: "{}" })).statusCode).toBe(429);
    f.store.close(); const response = await app.inject({ url: "/health" });
    expect(response.statusCode).toBe(503); expect(response.json()).toEqual({ code: "FAMILY_STORAGE_UNAVAILABLE" });
  });
});
