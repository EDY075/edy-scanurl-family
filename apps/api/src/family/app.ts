import Fastify, { LogController, type FastifyInstance, type FastifyRequest } from "fastify";
import { z } from "zod";
import { isIP } from "node:net";
import { ScanOrchestrator, type ScanJobSnapshot } from "../services/scan-orchestrator.js";
import { normalizeTarget, TargetRejectedError } from "../security/target.js";
import { FamilyError, FamilyStore, familyPath } from "./store.js";
import { familyProviderRegistry } from "./providers.js";
import { decorateFamilySnapshot } from "./domain-warning.js";

interface Orchestrator { create(input: string): ScanJobSnapshot; get(id: string): ScanJobSnapshot | undefined }
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const enrollment = z.object({ publicKeySpki: z.string().max(256) }).strict();
const challengeBody = z.object({ deviceId: hash, method: z.enum(["GET", "POST"]), path: z.string().max(100), bodyHash: hash }).strict();
const scanBody = z.object({ url: z.string().trim().min(1).max(2_048) }).strict();
const terminal = (job: ScanJobSnapshot) => !["QUEUED", "RUNNING"].includes(job.status);
function json(request: FastifyRequest): unknown {
  if (!Buffer.isBuffer(request.body)) throw new FamilyError("INVALID_REQUEST", 400);
  try { return JSON.parse(request.body.toString("utf8")) as unknown; } catch { throw new FamilyError("INVALID_REQUEST", 400); }
}
function header(request: FastifyRequest, name: string, max: number): string {
  const value = request.headers[name];
  if (typeof value !== "string" || value.length > max) throw new FamilyError("FAMILY_SIGNATURE_REJECTED");
  return value;
}
export function validateFamilyAudience(value: string, production = false): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new FamilyError("FAMILY_AUDIENCE_INVALID", 503); }
  if (url.origin !== value || url.username || url.password || !(url.protocol === "https:" || (!production && url.origin === "http://127.0.0.1:8788"))) throw new FamilyError("FAMILY_AUDIENCE_INVALID", 503);
  if (url.protocol === "https:") {
    const hostname = url.hostname;
    if (url.port || hostname.length > 253 || !hostname.includes(".") || isIP(hostname.replace(/^\[|\]$/g, "")) !== 0 || /(?:^|\.)(?:localhost|local|invalid)$|\.ts\.net$/.test(hostname) || !hostname.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new FamilyError("FAMILY_AUDIENCE_INVALID", 503);
  }
  return value;
}

export function createFamilyApp(options: { store: FamilyStore; audience: string; orchestrator?: Orchestrator; env?: NodeJS.ProcessEnv }): FastifyInstance {
  const { store } = options;
  const env = options.env ?? process.env;
  const audience = validateFamilyAudience(options.audience, env.NODE_ENV === "production");
  const orchestrator = options.orchestrator ?? new ScanOrchestrator(familyProviderRegistry(store, env));
  const app = Fastify({ logger: false, logController: new LogController({ disableRequestLogging: true }), trustProxy: false, bodyLimit: 4_096, requestTimeout: 12_000, connectionTimeout: 15_000, routerOptions: { maxParamLength: 100 } });
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("application/json", { parseAs: "buffer", bodyLimit: 4_096 }, (_request, body, done) => { done(null, body); });
  let storageFailed = false;
  let closed = false;
  const queue: { id: string; input: string }[] = [];
  const active = new Map<string, { internalId: string; last: string }>();
  const failed = (id: string): ScanJobSnapshot => ({ scanId: id, status: "FAILED", error: "FAMILY_EXECUTION_INTERRUPTED", progress: { completed: 0, total: 0, current: "FAILED" } });
  function pump(): void {
    if (closed || storageFailed) return;
    try {
      store.heartbeat();
      for (const [id, entry] of active) {
        const snapshot = orchestrator.get(entry.internalId) ?? failed(id);
        const serialized = JSON.stringify(snapshot);
        if (entry.last !== serialized) { store.saveJob(id, snapshot.status === "SUCCEEDED" && snapshot.report ? decorateFamilySnapshot(snapshot) : snapshot); entry.last = serialized; }
        if (terminal(snapshot)) active.delete(id);
      }
      while (active.size < 2 && queue.length > 0) {
        const next = queue.shift();
        if (!next) break;
        try {
          store.assertJobOwnerActive(next.id);
          const job = orchestrator.create(next.input);
          active.set(next.id, { internalId: job.scanId, last: "" });
          store.saveJob(next.id, job.status === "SUCCEEDED" && job.report ? decorateFamilySnapshot(job) : job);
        } catch (error) {
          if (error instanceof FamilyError && error.statusCode >= 500) throw error;
          store.saveJob(next.id, failed(next.id));
        }
      }
    } catch { storageFailed = true; }
  }
  const timer = setInterval(pump, 250);
  timer.unref();
  app.addHook("onClose", () => { closed = true; clearInterval(timer); });
  app.addHook("onRequest", (request, reply, done) => {
    try {
      if (storageFailed) throw new FamilyError("FAMILY_STORAGE_UNAVAILABLE", 503);
      const path = request.url;
      store.ingress(path === "/family/v1/enroll" ? "enroll" : path === "/family/v1/challenge" ? "challenge" : familyPath.test(path) ? "signed" : "other");
      const origin = request.headers.origin;
      const allowedOrigin = origin === "https://localhost" || (env.NODE_ENV !== "production" && origin === "http://127.0.0.1:4180");
      if (origin && !allowedOrigin) throw new FamilyError("ORIGIN_NOT_ALLOWED");
      if (origin && allowedOrigin) {
        void reply.header("Access-Control-Allow-Origin", origin).header("Vary", "Origin")
          .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
          .header("Access-Control-Allow-Headers", "Content-Type, X-Family-Device, X-Family-Challenge, X-Family-Signature");
      }
      done();
    } catch (error) { done(error instanceof FamilyError ? error : new FamilyError("FAMILY_STORAGE_UNAVAILABLE", 503)); }
  });
  app.addHook("onSend", (_request, reply, payload, done) => {
    void reply.header("Cache-Control", "no-store, private").header("X-Content-Type-Options", "nosniff").header("Referrer-Policy", "no-referrer");
    done(null, payload);
  });
  app.options("/family/v1/*", (_request, reply) => reply.code(204).send());
  app.get("/health", () => ({ status: "ok", mode: "FAMILY", persistence: "sqlite", authentication: "DEVICE_SIGNATURE" }));
  app.post("/family/v1/enroll", (request) => {
    const body = enrollment.safeParse(json(request));
    if (!body.success) throw new FamilyError("INVALID_REQUEST", 400);
    return store.enroll(body.data.publicKeySpki);
  });
  app.post("/family/v1/challenge", (request) => {
    const body = challengeBody.safeParse(json(request));
    if (!body.success) throw new FamilyError("INVALID_REQUEST", 400);
    return store.challenge(body.data.deviceId, body.data.method, body.data.path, body.data.bodyHash, audience);
  });
  function authenticate(request: FastifyRequest): string {
    const device = header(request, "x-family-device", 64);
    store.authenticate(device, header(request, "x-family-challenge", 36), header(request, "x-family-signature", 104), request.method, request.url, Buffer.isBuffer(request.body) ? request.body : Buffer.alloc(0), audience);
    return device;
  }
  app.post("/family/v1/scans", (request, reply) => {
    const owner = authenticate(request);
    const body = scanBody.safeParse(json(request));
    if (!body.success) throw new FamilyError("INVALID_REQUEST", 400);
    const target = normalizeTarget(body.data.url);
    const job = store.reserveJob(owner);
    queue.push({ id: job.scanId, input: target.requestUrl.toString() });
    pump();
    if (storageFailed) throw new FamilyError("FAMILY_STORAGE_UNAVAILABLE", 503);
    return reply.code(202).send({ scanId: job.scanId, status: job.status });
  });
  app.get("/family/v1/scans/:scanId", (request, reply) => {
    const owner = authenticate(request);
    const params = z.object({ scanId: z.uuid() }).safeParse(request.params);
    if (!params.success) throw new FamilyError("INVALID_SCAN_ID", 400);
    const job = store.getJob(owner, params.data.scanId);
    return job ? reply.send(job) : reply.code(404).send({ code: "SCAN_NOT_FOUND" });
  });
  app.setErrorHandler((error, _request, reply) => {
    const rejected = error instanceof TargetRejectedError;
    const status = error instanceof FamilyError ? error.statusCode : rejected ? 400 : (error as { statusCode?: number }).statusCode === 413 ? 413 : 503;
    const code = error instanceof FamilyError ? error.code : rejected ? "SCAN_REJECTED" : status === 413 ? "PAYLOAD_TOO_LARGE" : "FAMILY_UNAVAILABLE";
    if (status === 429) void reply.header("Retry-After", "60");
    void reply.code(status).send({ code });
  });
  return app;
}
