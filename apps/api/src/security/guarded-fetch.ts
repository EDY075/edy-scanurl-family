import http, { type IncomingHttpHeaders, type IncomingMessage } from "node:http";
import https from "node:https";
import { EgressGuard, type ResolvedTarget } from "./egress-guard.js";

export interface GuardedFetchOptions {
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  allowedContentTypes?: readonly string[];
  allowedOrigin?: string;
  allowedUrl?: ((url: URL) => boolean) | undefined;
  requireContentType?: boolean;
  signal?: AbortSignal | undefined;
}

interface ResolvedFetchOptions {
  timeoutMs: number;
  maxBytes: number;
  maxRedirects: number;
  allowedContentTypes: readonly string[];
  allowedOrigin?: string;
  allowedUrl?: (url: URL) => boolean;
  requireContentType: boolean;
  signal?: AbortSignal;
}

interface FetchBudget {
  deadlineAt: number;
  remainingBytes: number;
}

export interface GuardedResponse {
  finalUrl: string;
  statusCode: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
  redirectChain: string[];
  remoteAddress: string;
}

const DEFAULT_TYPES = ["text/html", "application/xhtml+xml", "text/plain"];

export class GuardedFetcher {
  constructor(private readonly guard = new EgressGuard()) {}

  async fetch(input: string, options: GuardedFetchOptions = {}): Promise<GuardedResponse> {
    const config = {
      timeoutMs: options.timeoutMs ?? 6_000,
      maxBytes: options.maxBytes ?? 512 * 1024,
      maxRedirects: options.maxRedirects ?? 3,
      allowedContentTypes: options.allowedContentTypes ?? DEFAULT_TYPES,
      requireContentType: options.requireContentType ?? false,
      ...(options.allowedOrigin ? { allowedOrigin: normalizeOrigin(options.allowedOrigin) } : {}),
      ...(options.allowedUrl ? { allowedUrl: options.allowedUrl } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
    };
    return this.fetchHop(input, config, [], {
      deadlineAt: Date.now() + config.timeoutMs,
      remainingBytes: config.maxBytes,
    });
  }

  private async fetchHop(
    input: string,
    options: ResolvedFetchOptions,
    redirects: string[],
    budget: FetchBudget,
  ): Promise<GuardedResponse> {
    const requestedUrl = new URL(input);
    if (options.allowedOrigin && requestedUrl.origin !== options.allowedOrigin) {
      throw new Error("CROSS_ORIGIN_BLOCKED");
    }
    if (options.allowedUrl && !options.allowedUrl(requestedUrl)) throw new Error("URL_POLICY_BLOCKED");
    const remainingMs = budget.deadlineAt - Date.now();
    if (remainingMs <= 0) throw new Error("FETCH_DEADLINE_EXCEEDED");
    if (budget.remainingBytes <= 0) throw new Error("RESPONSE_TOO_LARGE");
    const target = await this.guard.validate(input);
    const response = await requestPinned(
      target,
      this.guard,
      remainingMs,
      budget.remainingBytes,
      options.allowedContentTypes,
      options.requireContentType,
      options.signal,
    );
    budget.remainingBytes -= response.body.length;

    if (isRedirect(response.statusCode) && response.headers.location) {
      if (redirects.length >= options.maxRedirects) throw new Error("REDIRECT_LIMIT_EXCEEDED");
      const next = new URL(response.headers.location, target.requestUrl);
      if (target.requestUrl.protocol === "https:" && next.protocol !== "https:") {
        throw new Error("HTTPS_DOWNGRADE_BLOCKED");
      }
      if (options.allowedOrigin && next.origin !== options.allowedOrigin) {
        throw new Error("CROSS_ORIGIN_REDIRECT_BLOCKED");
      }
      if (options.allowedUrl && !options.allowedUrl(next)) throw new Error("URL_POLICY_BLOCKED");
      const nextUrl = next.toString();
      if (redirects.includes(nextUrl)) throw new Error("REDIRECT_LOOP");
      return this.fetchHop(nextUrl, options, [...redirects, target.requestUrl.toString()], budget);
    }

    const rawContentType = response.headers["content-type"];
    const contentType = (Array.isArray(rawContentType) ? rawContentType.join(";") : rawContentType ?? "").toLowerCase();
    if (options.requireContentType && !contentType) throw new Error("CONTENT_TYPE_REQUIRED");
    if (contentType && !options.allowedContentTypes.some((allowed) => contentType.startsWith(allowed))) {
      throw new Error("CONTENT_TYPE_BLOCKED");
    }

    return {
      ...response,
      finalUrl: target.requestUrl.toString(),
      redirectChain: redirects,
    };
  }
}

interface PinnedResponse {
  statusCode: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
  remoteAddress: string;
}

function requestPinned(
  target: ResolvedTarget,
  guard: EgressGuard,
  timeoutMs: number,
  maxBytes: number,
  allowedContentTypes: readonly string[],
  requireContentType: boolean,
  signal?: AbortSignal,
): Promise<PinnedResponse> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error("FETCH_ABORTED"));
    const url = target.requestUrl;
    const selected = target.addresses[0];
    if (!selected) return reject(new Error("DNS_NO_PUBLIC_ADDRESS"));

    const requestOptions: https.RequestOptions = {
      protocol: url.protocol,
      hostname: selected.address,
      port: url.port || (url.protocol === "https:" ? 443 : 80),
      method: "GET",
      path: `${url.pathname}${url.search}`,
      headers: {
        accept: "text/html,application/xhtml+xml,text/plain;q=0.8",
        "accept-encoding": "identity",
        "user-agent": "EDY-ScanURL/0.1 (+passive trust verification)",
        connection: "close",
        host: url.host,
      },
      family: selected.family,
      servername: url.hostname,
      rejectUnauthorized: true,
    };
    const requestFn = url.protocol === "https:" ? https.request : http.request;
    const absoluteTimer = setTimeout(() => request.destroy(new Error("FETCH_DEADLINE_EXCEEDED")), timeoutMs);
    const request = requestFn(requestOptions, (response: IncomingMessage) => {
      const remoteAddress = response.socket.remoteAddress ?? "";
      try {
        guard.assertConnectedAddress(remoteAddress, target.addresses.map((entry) => entry.address));
      } catch (error) {
        response.destroy();
        reject(error instanceof Error ? error : new Error("EGRESS_VALIDATION_FAILED"));
        return;
      }

      const rawContentType = response.headers["content-type"];
      const contentType = (Array.isArray(rawContentType) ? rawContentType.join(";") : rawContentType ?? "").toLowerCase();
      if (isRedirect(response.statusCode ?? 0)) {
        response.destroy();
        cleanup();
        resolve({
          statusCode: response.statusCode ?? 0,
          headers: response.headers,
          body: Buffer.alloc(0),
          remoteAddress,
        });
        return;
      }
      if (
        (requireContentType && !contentType) ||
        (contentType &&
        !allowedContentTypes.some((allowed) => contentType.startsWith(allowed))
        )
      ) {
        response.destroy();
        cleanup();
        reject(new Error(contentType ? "CONTENT_TYPE_BLOCKED" : "CONTENT_TYPE_REQUIRED"));
        return;
      }

      let size = 0;
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > maxBytes) {
          response.destroy(new Error("RESPONSE_TOO_LARGE"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        cleanup();
        resolve({
          statusCode: response.statusCode ?? 0,
          headers: response.headers,
          body: Buffer.concat(chunks),
          remoteAddress,
        });
      });
      response.on("error", (error) => {
        cleanup();
        reject(error);
      });
    });
    const onAbort = () => request.destroy(new Error("FETCH_ABORTED"));
    const cleanup = () => {
      clearTimeout(absoluteTimer);
      signal?.removeEventListener("abort", onAbort);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    request.setTimeout(Math.min(timeoutMs, 3_000), () => request.destroy(new Error("FETCH_IDLE_TIMEOUT")));
    request.on("error", (error) => {
      cleanup();
      reject(error);
    });
    request.end();
  });
}

function isRedirect(statusCode: number): boolean {
  return [301, 302, 303, 307, 308].includes(statusCode);
}

function normalizeOrigin(value: string): string {
  return new URL(value).origin;
}
