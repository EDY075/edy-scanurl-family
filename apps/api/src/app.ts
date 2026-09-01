import cors from "@fastify/cors";
import Fastify, { LogController, type FastifyInstance } from "fastify";
import { z } from "zod";
import { assertComplianceRegistry, providerComplianceRegistry } from "./providers/compliance.js";
import { virusTotalRuntimeStatus } from "./providers/virus-total.js";
import { InMemoryTokenBucket } from "./services/rate-limiter.js";
import { ScanOrchestrator } from "./services/scan-orchestrator.js";
import { normalizeTarget, TargetRejectedError } from "./security/target.js";

const createScanSchema = z.object({ url: z.string().trim().min(1).max(2_048) }).strict();

export function createApp(options: {
  orchestrator?: ScanOrchestrator;
  ipRateLimiter?: InMemoryTokenBucket;
  domainRateLimiter?: InMemoryTokenBucket;
  globalRateLimiter?: InMemoryTokenBucket;
} = {}): FastifyInstance {
  assertComplianceRegistry();
  const orchestrator = options.orchestrator ?? new ScanOrchestrator();
  const ipRateLimiter = options.ipRateLimiter ?? new InMemoryTokenBucket(12, 6);
  const domainRateLimiter = options.domainRateLimiter ?? new InMemoryTokenBucket(30, 15);
  const globalRateLimiter = options.globalRateLimiter ?? new InMemoryTokenBucket(120, 60, 1);
  const configuredOrigin = process.env.CORS_ORIGIN;
  const allowLocalOrigins = process.env.NODE_ENV !== "production";
  const app = Fastify({
    logController: new LogController({ disableRequestLogging: true }),
    logger: {
      level: process.env.LOG_LEVEL ?? "info",
      redact: {
        paths: ["req.headers.authorization", "req.headers.cookie", "req.body.url", "res.headers.set-cookie"],
        censor: "[REDACTED]",
      },
    },
    bodyLimit: 16 * 1024,
    requestTimeout: 12_000,
    trustProxy: false,
  });

  void app.register(cors, {
    origin: (origin, callback) => {
      if (
        !origin ||
        origin === configuredOrigin ||
        (allowLocalOrigins && /^https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?$/.test(origin))
      ) return callback(null, true);
      callback(new Error("ORIGIN_NOT_ALLOWED"), false);
    },
    methods: ["GET", "POST", "OPTIONS"],
  });

  app.addHook("onSend", (_request, reply, payload, done) => {
    void reply.header("X-Content-Type-Options", "nosniff");
    void reply.header("Referrer-Policy", "no-referrer");
    void reply.header("Cache-Control", "no-store, private");
    done(null, payload);
  });

  app.get("/health", () => ({ status: "ok", version: "0.1.0", persistence: "ephemeral" }));

  app.get("/api/v1/providers", () => {
    const virusTotalRuntime = virusTotalRuntimeStatus();
    return providerComplianceRegistry.map(({ provider, enabled, commercialStatus, cost, quota, lastReviewed, disabledReason }) => {
      if (provider !== "virus-total-public" || !virusTotalRuntime.enabled) {
        return { provider, enabled, commercialStatus, cost, quota, lastReviewed, disabledReason };
      }
      return {
        provider,
        enabled: true,
        commercialStatus: "CONDITIONAL" as const,
        cost,
        quota,
        lastReviewed,
        runtimeMode: virusTotalRuntime.reason,
      };
    });
  });

  app.post("/api/v1/scans", (request, reply) => {
    const body = createScanSchema.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ code: "INVALID_REQUEST", message: "Informe uma URL válida." });
    let target;
    try {
      target = normalizeTarget(body.data.url);
    } catch (error) {
      if (error instanceof TargetRejectedError) {
        return reply.code(400).send({ code: "SCAN_REJECTED", reason: error.reason, message: error.message });
      }
      throw error;
    }
    const limits = [ipRateLimiter.consume(`ip:${request.ip}`)];
    if (limits[0]?.allowed) limits.push(domainRateLimiter.consume(`domain:${target.domain}`));
    if (limits.every((limit) => limit.allowed)) limits.push(globalRateLimiter.consume("global"));
    const remaining = Math.min(...limits.map((limit) => limit.remaining));
    void reply.header("X-RateLimit-Remaining", String(remaining));
    const blocked = limits.find((limit) => !limit.allowed);
    if (blocked) {
      void reply.header("Retry-After", String(blocked.retryAfterSeconds));
      return reply.code(429).send({ code: "RATE_LIMITED", retryAfterSeconds: blocked.retryAfterSeconds });
    }
    const job = orchestrator.create(target.requestUrl.toString());
    return reply.code(202).send({ scanId: job.scanId, status: job.status });
  });

  app.get("/api/v1/scans/:scanId", (request, reply) => {
    const params = z.object({ scanId: z.uuid() }).safeParse(request.params);
    if (!params.success) return reply.code(400).send({ code: "INVALID_SCAN_ID" });
    const job = orchestrator.get(params.data.scanId);
    if (!job) return reply.code(404).send({ code: "SCAN_NOT_FOUND" });
    return reply.send(job);
  });

  app.setErrorHandler((error, _request, reply) => {
    const safeError = error instanceof Error ? error : new Error("UNKNOWN_ERROR");
    const statusCode = safeError.message === "ORIGIN_NOT_ALLOWED" ? 403
      : typeof (error as { statusCode?: unknown }).statusCode === "number"
        ? Math.min(599, Math.max(400, (error as { statusCode: number }).statusCode))
        : 500;
    if (statusCode >= 500) app.log.error({ err: { name: safeError.name, message: safeError.message } }, "request_failed");
    const code = statusCode === 403 ? "ORIGIN_NOT_ALLOWED" : statusCode === 413 ? "PAYLOAD_TOO_LARGE" : statusCode < 500 ? "INVALID_REQUEST" : "INTERNAL_ERROR";
    void reply.code(statusCode).send({ code, message: statusCode < 500 ? "A solicitação não foi aceita." : "Não foi possível concluir a solicitação." });
  });

  return app;
}
