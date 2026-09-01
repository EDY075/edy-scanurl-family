import { DEFAULT_API_ORIGIN } from "./api-origin";

export function apiOrigin(value: unknown): string {
  const url = new URL(
    typeof value === "string" && value ? value : DEFAULT_API_ORIGIN,
  );
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.port ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  )
    throw new Error("configuration");
  return url.origin;
}

export const API_ORIGIN = apiOrigin(import.meta.env.VITE_API_BASE_URL);
// A relative transport exists ONLY in explicit local-review builds.
export const TRANSPORT_ORIGIN =
  import.meta.env.VITE_WEB_LOCAL_PROXY === "true" ? "" : API_ORIGIN;
