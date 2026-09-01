import { createHash, createPublicKey, randomBytes, randomUUID, verify } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { ScanJobSnapshot } from "../services/scan-orchestrator.js";

export class FamilyError extends Error {
  constructor(readonly code: string, readonly statusCode = 403) { super(code); }
}
export type DeviceStatus = "PENDING" | "ACTIVE" | "REVOKED";
interface Device { id: string; spki: string; status: DeviceStatus }
interface Challenge { device: string; method: string; path: string; body_hash: string; message: string; expires: number }
const MINUTE = 60_000;
const DAY = 86_400_000;
export const sha256 = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");
export const familyPath = /^\/family\/v1\/scans(?:\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?$/;

/** One live worker, durable counters/nonces, separate administrative connection. */
export class FamilyStore {
  private readonly db: DatabaseSync;
  private readonly leaseId: string | undefined;
  constructor(path: string, private readonly now: () => number = Date.now, options: { admin?: boolean } = {}) {
    this.db = new DatabaseSync(path, { allowExtension: false });
    this.db.exec(`PRAGMA busy_timeout=2000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, spki TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('PENDING','ACTIVE','REVOKED')), created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY, device TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, method TEXT NOT NULL, path TEXT NOT NULL, body_hash TEXT NOT NULL, message TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS counters(key TEXT PRIMARY KEY, amount INTEGER NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES devices(id), snapshot TEXT NOT NULL, terminal INTEGER NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS worker(id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS vt_requests(at INTEGER NOT NULL);`);
    if (!options.admin) {
      this.leaseId = randomUUID();
      try {
        this.db.exec("BEGIN IMMEDIATE");
        const prior = this.db.prepare("SELECT expires FROM worker WHERE id=1").get() as { expires: number } | undefined;
        if (prior && prior.expires > now()) throw new FamilyError("FAMILY_INSTANCE_ACTIVE", 503);
        this.db.prepare("INSERT OR REPLACE INTO worker VALUES(1,?,?)").run(this.leaseId, now() + 30_000);
        const interrupted = this.db.prepare("SELECT id FROM jobs WHERE terminal=0").all() as { id: string }[];
        for (const job of interrupted) this.db.prepare("UPDATE jobs SET terminal=1,snapshot=? WHERE id=?").run(JSON.stringify({ scanId: job.id, status: "FAILED", error: "FAMILY_RESTART_INTERRUPTED", progress: { completed: 0, total: 0, current: "FAILED" } }), job.id);
        this.db.exec("COMMIT");
      } catch (error) { this.db.exec("ROLLBACK"); this.db.close(); throw error; }
    }
  }

  private transaction<T>(operation: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (this.leaseId) {
        const lease = this.db.prepare("SELECT owner,expires FROM worker WHERE id=1").get() as { owner: string; expires: number } | undefined;
        if (lease?.owner !== this.leaseId || lease.expires <= this.now()) throw new FamilyError("FAMILY_WORKER_LEASE_LOST", 503);
        this.db.prepare("UPDATE worker SET expires=? WHERE id=1").run(this.now() + 30_000);
      }
      const result = operation(); this.db.exec("COMMIT"); return result;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  private clean(): void {
    const now = this.now();
    this.db.prepare("DELETE FROM challenges WHERE expires<=?").run(now);
    this.db.prepare("DELETE FROM counters WHERE expires<=?").run(now);
    this.db.prepare("DELETE FROM jobs WHERE expires<=? AND terminal=1").run(now);
    this.db.prepare("DELETE FROM devices WHERE status='PENDING' AND created<=?").run(now - DAY);
  }
  heartbeat(): void { this.transaction(() => this.clean()); }
  ingress(kind: "enroll" | "challenge" | "signed" | "other"): void {
    this.transaction(() => { this.clean(); this.limit(`http:${kind}`, kind === "enroll" ? 30 : 600, MINUTE); });
  }
  private limit(key: string, maximum: number, duration: number): void {
    const window = Math.floor(this.now() / duration);
    const fullKey = `${key}:${String(window)}`;
    const row = this.db.prepare("SELECT amount FROM counters WHERE key=?").get(fullKey) as { amount: number } | undefined;
    if ((row?.amount ?? 0) >= maximum) throw new FamilyError("FAMILY_RATE_LIMITED", 429);
    this.db.prepare("INSERT INTO counters VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET amount=amount+1").run(fullKey, (window + 1) * duration);
  }
  private active(id: string): Device {
    const device = this.db.prepare("SELECT id,spki,status FROM devices WHERE id=?").get(id) as Device | undefined;
    if (device?.status === "REVOKED") throw new FamilyError("FAMILY_DEVICE_REVOKED");
    if (device?.status === "PENDING") throw new FamilyError("FAMILY_DEVICE_PENDING");
    if (device?.status !== "ACTIVE") throw new FamilyError("FAMILY_DEVICE_NOT_ACTIVE");
    return device;
  }
  enroll(publicKeySpki: string): { deviceId: string; status: DeviceStatus } {
    return this.transaction(() => {
      this.clean(); this.limit("enroll", 30, MINUTE);
      if (publicKeySpki.length > 256 || !/^[A-Za-z0-9+/]+={0,2}$/.test(publicKeySpki)) throw new FamilyError("FAMILY_INVALID_KEY", 400);
      let canonical: Buffer;
      try {
        const input = Buffer.from(publicKeySpki, "base64");
        const key = createPublicKey({ key: input, format: "der", type: "spki" });
        if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error();
        canonical = key.export({ format: "der", type: "spki" });
        if (canonical.toString("base64") !== publicKeySpki) throw new Error();
      } catch { throw new FamilyError("FAMILY_INVALID_KEY", 400); }
      const deviceId = sha256(canonical);
      const existing = this.db.prepare("SELECT status FROM devices WHERE id=?").get(deviceId) as { status: DeviceStatus } | undefined;
      if (existing) return { deviceId, status: existing.status };
      const count = this.db.prepare("SELECT COUNT(*) AS total, SUM(status='PENDING') AS pending FROM devices").get() as { total: number; pending: number };
      if (count.total >= 1_000 || count.pending >= 100) throw new FamilyError("FAMILY_ENROLLMENT_CAPACITY", 429);
      this.db.prepare("INSERT INTO devices VALUES(?,?,'PENDING',?)").run(deviceId, publicKeySpki, this.now());
      return { deviceId, status: "PENDING" };
    });
  }
  approve(id: string): void {
    this.transaction(() => {
      this.clean();
      const row = this.db.prepare("SELECT status FROM devices WHERE id=?").get(id) as { status: DeviceStatus } | undefined;
      if (row?.status !== "PENDING") throw new FamilyError("FAMILY_APPROVAL_REQUIRES_PENDING", 409);
      const count = this.db.prepare("SELECT COUNT(*) AS n FROM devices WHERE status='ACTIVE'").get() as { n: number };
      if (count.n >= 20) throw new FamilyError("FAMILY_DEVICE_CAPACITY", 409);
      this.db.prepare("UPDATE devices SET status='ACTIVE' WHERE id=?").run(id);
    });
  }
  revoke(id: string): void {
    this.transaction(() => {
      this.db.prepare("UPDATE devices SET status='REVOKED' WHERE id=?").run(id);
      this.db.prepare("DELETE FROM challenges WHERE device=?").run(id);
    });
  }
  list(): { id: string; status: DeviceStatus }[] { return this.db.prepare("SELECT id,status FROM devices ORDER BY created").all() as { id: string; status: DeviceStatus }[]; }

  challenge(deviceId: string, method: string, path: string, bodyHash: string, audience: string): { challengeId: string; message: string } {
    return this.transaction(() => {
      this.clean(); this.limit("challenge", 600, MINUTE); this.active(deviceId);
      this.limit(`challenge:${deviceId}`, 90, MINUTE);
      if (!/^[a-f0-9]{64}$/.test(bodyHash) || !familyPath.test(path) || !((method === "POST" && path === "/family/v1/scans") || (method === "GET" && path !== "/family/v1/scans" && bodyHash === sha256("")))) throw new FamilyError("FAMILY_INVALID_CHALLENGE", 400);
      const challengeId = randomUUID();
      const message = `EDY-FAMILY-V1\n${audience}\n${deviceId}\n${challengeId}\n${randomBytes(32).toString("base64url")}\n${method}\n${path}\n${bodyHash}`;
      this.db.prepare("INSERT INTO challenges VALUES(?,?,?,?,?,?,?)").run(challengeId, deviceId, method, path, bodyHash, message, this.now() + MINUTE);
      return { challengeId, message };
    });
  }

  authenticate(deviceId: string, challengeId: string, signature: string, method: string, path: string, body: Buffer, audience: string): void {
    this.transaction(() => {
      this.clean(); const device = this.active(deviceId);
      const challenge = this.db.prepare("SELECT * FROM challenges WHERE id=?").get(challengeId) as Challenge | undefined;
      if (challenge?.device !== deviceId || challenge.expires <= this.now() || challenge.method !== method || challenge.path !== path || challenge.body_hash !== sha256(body) || !challenge.message.startsWith(`EDY-FAMILY-V1\n${audience}\n`)) throw new FamilyError("FAMILY_SIGNATURE_REJECTED");
      let valid = false;
      try {
        const bytes = Buffer.from(signature, "base64");
        if (signature.length <= 104 && bytes.toString("base64") === signature) valid = verify("sha256", Buffer.from(challenge.message), { key: Buffer.from(device.spki, "base64"), type: "spki", format: "der", dsaEncoding: "der" }, bytes);
      } catch { /* Invalid encodings have the same public outcome. */ }
      if (!valid) throw new FamilyError("FAMILY_SIGNATURE_REJECTED");
      this.db.prepare("DELETE FROM challenges WHERE id=?").run(challengeId);
      if (method === "GET") this.limit(`poll:${deviceId}`, 60, MINUTE);
    });
  }

  reserveJob(owner: string): ScanJobSnapshot {
    return this.transaction(() => {
      this.clean(); this.active(owner);
      const count = this.db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE terminal=0").get() as { n: number };
      if (count.n >= 10) throw new FamilyError("FAMILY_QUEUE_FULL", 429);
      this.limit(`scan:${owner}`, 20, DAY); this.limit("scan:family", 100, DAY);
      const job: ScanJobSnapshot = { scanId: randomUUID(), status: "QUEUED", progress: { completed: 0, total: 0, current: "QUEUED" } };
      this.db.prepare("INSERT INTO jobs VALUES(?,?,?,0,?)").run(job.scanId, owner, JSON.stringify(job), this.now() + 15 * MINUTE);
      return job;
    });
  }
  saveJob(id: string, snapshot: ScanJobSnapshot): void {
    this.transaction(() => {
      const terminal = !["QUEUED", "RUNNING"].includes(snapshot.status);
      this.db.prepare("UPDATE jobs SET snapshot=?,terminal=? WHERE id=?").run(JSON.stringify({ ...snapshot, scanId: id }), terminal ? 1 : 0, id);
    });
  }
  assertJobOwnerActive(id: string): void {
    this.transaction(() => {
      const row = this.db.prepare("SELECT owner FROM jobs WHERE id=?").get(id) as { owner: string } | undefined;
      if (!row) throw new FamilyError("FAMILY_JOB_MISSING", 404);
      this.active(row.owner);
    });
  }
  getJob(owner: string, id: string): ScanJobSnapshot | undefined {
    return this.transaction(() => {
      this.active(owner);
      const row = this.db.prepare("SELECT snapshot FROM jobs WHERE id=? AND owner=? AND expires>?").get(id, owner, this.now()) as { snapshot: string } | undefined;
      return row ? JSON.parse(row.snapshot) as ScanJobSnapshot : undefined;
    });
  }
  reserveVtRequest(): boolean {
    return this.transaction(() => {
      const now = this.now(); const start = Math.floor(now / DAY) * DAY;
      this.db.prepare("DELETE FROM vt_requests WHERE at<?").run(Math.min(start, now - MINUTE));
      const count = this.db.prepare("SELECT SUM(at>=?) AS daily,SUM(at>?) AS recent FROM vt_requests").get(start, now - MINUTE) as { daily: number; recent: number };
      if (count.daily >= 500 || count.recent >= 4) return false;
      this.db.prepare("INSERT INTO vt_requests VALUES(?)").run(now); return true;
    });
  }
  close(): void {
    if (this.leaseId) this.db.prepare("DELETE FROM worker WHERE id=1 AND owner=?").run(this.leaseId);
    this.db.close();
  }
}
