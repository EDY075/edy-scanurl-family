import type { ScanReport } from "../../types";
import { API_ORIGIN, TRANSPORT_ORIGIN } from "./config";
import {
  base64,
  getBrowserIdentity,
  hashText,
  signatureToDer,
} from "./identity";
import { normalizeStoreUrl } from "../utils/url";


export type ScanPhase =
  "validating" | "authenticating" | "collecting" | "preparing";
export type HealthState = "checking" | "online" | "degraded" | "offline" | "unavailable";
export class ApiError extends Error {
  constructor(
    readonly code: string,
    readonly retryAfter = 0,
  ) {
    super(code);
  }
}
const UUID =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const isOffline = () => !navigator.onLine;
export function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new ApiError("response");
  return value as Record<string, unknown>;
}

export async function requestJson(
  path: string,
  options: RequestInit = {},
  timeout = 22_000,
): Promise<Record<string, unknown>> {
  if (isOffline()) throw new ApiError('offline');
  const controller = new AbortController();
  const abort = () => {
    controller.abort();
  };
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const timer = setTimeout(abort, timeout);
  try {
    const response = await fetch(`${TRANSPORT_ORIGIN}${path}`, {
      ...options,
      signal: controller.signal,
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) {
      const retry = Math.min(
        86_400,
        Math.max(0, Number(response.headers.get("Retry-After")) || 0),
      );
      let siteInaccessible = false;
      if (response.status === 503 && response.headers.get('Content-Type')?.includes('application/json') && response.body) {
        const reader = response.body.getReader(); let size = 0; let text = ''; const decoder = new TextDecoder();
        try {
          for (;;) { const chunk = await reader.read(); if(chunk.done) break; size += chunk.value.byteLength; if(size > 4096) break; text += decoder.decode(chunk.value, {stream:true}); }
          if(size <= 4096) { const body = record(JSON.parse(text + decoder.decode()) as unknown); siteInaccessible = body.reason === 'DNS_NO_PUBLIC_ADDRESS'; }
        } catch { /* Untrusted error bodies never reach the UI. */ }
        finally { void reader.cancel().catch(() => undefined); }
      }
      throw new ApiError(siteInaccessible ? 'inaccessible' :
        response.status === 429
          ? "rate_limited"
          : response.status === 403
            ? "authentication"
            : response.status === 400
              ? "scan_rejected"
              : response.status === 404
                ? "expired"
                : "unavailable",
        retry,
      );
    }
    if (
      !response.headers.get("Content-Type")?.includes("application/json") ||
      !response.body
    )
      throw new ApiError("response");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let total = 0;
    let text = "";
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        total += chunk.value.byteLength;
        if (total > 2 * 1024 * 1024) throw new ApiError("response");
        text += decoder.decode(chunk.value, { stream: true });
      }
    } finally {
      void reader.cancel().catch(() => undefined);
    }
    return record(JSON.parse(text + decoder.decode()) as unknown);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      controller.signal.aborted
        ? "timeout"
        : isOffline()
          ? "offline"
          : "unavailable",
    );
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
  }
}

export async function checkHealth(signal?: AbortSignal): Promise<HealthState> {
  try {
    const data = await requestJson("/health", { signal }, 4500);
    return data.status === "ok" && data.authentication === "DEVICE_SIGNATURE"
      ? "online"
      : "degraded";
  } catch {
    return !navigator.onLine ? "offline" : "degraded";
  }
}

export function validateChallenge(
  value: unknown,
  expected: {
    deviceId: string;
    method: string;
    path: string;
    bodyHash: string;
  },
  now = Date.now(),
): { challengeId: string; message: string } {
  const data = record(value);
  if (
    typeof data.challengeId !== "string" ||
    !UUID.test(data.challengeId) ||
    typeof data.message !== "string" ||
    data.message.length > 1200 ||
    typeof data.expiresAt !== "string"
  )
    throw new ApiError("authentication");
  const expires = Date.parse(data.expiresAt);
  if (!Number.isFinite(expires) || expires <= now || expires > now + 120_000)
    throw new ApiError("authentication");
  const lines = data.message.split("\n");
  if (
    lines.length !== 8 ||
    lines[0] !== "EDY-FAMILY-V1" ||
    lines[1] !== API_ORIGIN ||
    lines[2] !== expected.deviceId ||
    lines[3] !== data.challengeId ||
    !/^[a-f0-9]{64}$/.test(lines[4]) ||
    lines[5] !== expected.method ||
    lines[6] !== expected.path ||
    lines[7] !== expected.bodyHash
  )
    throw new ApiError("authentication");
  return { challengeId: data.challengeId, message: data.message };
}


export async function scanStore(
  input: string,
  phase: (value: ScanPhase) => void,
): Promise<ScanReport> {
  phase("validating");
  const url = normalizeStoreUrl(input);
  phase("authenticating");
  const identity = await getBrowserIdentity();
  const enrollment = await requestJson("/family/v1/enroll", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ publicKeySpki: identity.publicKeySpki }),
  });
  if (
    enrollment.deviceId !== identity.deviceId ||
    enrollment.status !== "ACTIVE"
  )
    throw new ApiError("authentication");
  const signed = async (method: "POST" | "GET", path: string, body = "") => {
    const expected = {
      deviceId: identity.deviceId,
      method,
      path,
      bodyHash: await hashText(body),
    };
    const raw = await requestJson("/family/v1/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(expected),
    });
    const challenge = validateChallenge(raw, expected);
    const signature = base64(
      signatureToDer(
        await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          identity.privateKey,
          new TextEncoder().encode(challenge.message),
        ),
      ),
    );
    return requestJson(path, {
      method,
      ...(method === "POST" ? { body } : {}),
      headers: {
        "Content-Type": "application/json",
        "X-Family-Device": identity.deviceId,
        "X-Family-Challenge": challenge.challengeId,
        "X-Family-Signature": signature,
      },
    });
  };
  phase("collecting");
  const job = await signed("POST", "/family/v1/scans", JSON.stringify({ url }));
  if (
    typeof job.scanId !== "string" ||
    !UUID.test(job.scanId) ||
    job.status !== "QUEUED"
  )
    throw new ApiError("response");
  phase("preparing");
  const result = await signed("GET", `/family/v1/scans/${job.scanId}`);
  if (result.scanId !== job.scanId || result.status !== "SUCCEEDED")
    throw new ApiError("unavailable");
  const { validateReport } = await import("./report-validation");
  const report = validateReport(result.report);
  if (report.id !== job.scanId || report.domain !== new URL(url).hostname)
    throw new ApiError("response");
  return report;
}

export function friendlyError(error: unknown): string {
  const code = error instanceof Error ? error.message : "";
  const messages: Record<string, string> = {
    offline:
      "Você está sem conexão. Conecte-se à internet para verificar um site.",
    timeout:
      "A análise demorou mais que o esperado. Não recebemos a resposta a tempo. Você pode tentar novamente.",
    rate_limited:
      "Já fizemos várias verificações. Aguarde antes de tentar novamente.",
    authentication:
      "Não conseguimos confirmar o acesso deste navegador. Tente novamente. Se continuar, use um navegador atualizado.",
    storage:
      "O navegador não permitiu guardar a identificação segura. Verifique as permissões de armazenamento ou use um navegador atualizado.",
    invalid_url:
      "Confira o endereço. Não reconhecemos esse endereço como um link válido. Use um endereço público, sem senhas, portas ou endereços internos.",
    inaccessible: 'Não conseguimos acessar este site. O endereço pode estar fora do ar, bloqueando verificações ou ter sido digitado incorretamente.',
    unavailable: 'Não conseguimos verificar agora. O serviço está temporariamente indisponível. Tente novamente em alguns instantes.',
    multiple_urls:
      "Encontramos mais de um link. Cole apenas o endereço da loja que deseja verificar.",
    scan_rejected:
      "Esse endereço não pôde ser verificado com segurança. Confira o link da loja.",
    response:
      "O serviço respondeu, mas não foi possível validar a análise. Nenhum resultado de confiança foi atribuído.",
    expired:
      "Esse resultado não está mais disponível. Faça uma nova verificação.",
    clipboard:
      "Não conseguimos ler a área de transferência. Toque no campo e cole o link manualmente.",
  };
  return (
    messages[code] ??
    "Algo não saiu como esperado. Não foi possível concluir esta verificação."
  );
}
