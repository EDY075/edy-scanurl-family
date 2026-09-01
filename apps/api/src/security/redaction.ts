const secretKeys = /authorization|cookie|token|secret|password|api[-_]?key|session/i;

export function redactRecord(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactRecord);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, nested]) => [
        key,
        secretKeys.test(key) ? "[REDACTED]" : redactRecord(nested),
      ]),
    );
  }
  if (typeof value === "string") {
    return value
      .replace(/([?&][^=\s]+)=([^&#\s]+)/g, "$1=[REDACTED]")
      .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]");
  }
  return value;
}
