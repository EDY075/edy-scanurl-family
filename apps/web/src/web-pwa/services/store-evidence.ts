import { getDomain } from "tldts";
import { validCnpj } from "../../evidence/cnpj";
import { validStoreUrl } from "../utils/url";

/** Reject malformed additive evidence rather than trusting backend casts. */
export function validateStoreEvidence(value: unknown, domain: string): void {
  const object = (input: unknown): Record<string, unknown> => {
    if (!input || typeof input !== "object" || Array.isArray(input))
      throw new Error("response");
    return input as Record<string, unknown>;
  };
  const url = (input: unknown) => {
    if (
      typeof input !== "string" ||
      input.length > 2048 ||
      !validStoreUrl(input)
    )
      throw new Error("response");
    const parsed = new URL(input);
    if (
      parsed.search ||
      parsed.hash ||
      getDomain(parsed.hostname) !== getDomain(domain)
    )
      throw new Error("response");
  };
  const data = object(value);
  if (data.cnpjTruncated !== undefined && typeof data.cnpjTruncated !== 'boolean') throw new Error('response');
  if (
    data.version !== 1 ||
    !["available", "limited", "unavailable"].includes(
      String(data.collection),
    ) ||
    data.registration !== "NOT_CHECKED" ||
    data.match !== "UNKNOWN" ||
    !Array.isArray(data.cnpjs) ||
    data.cnpjs.length > 8 ||
    !Array.isArray(data.policies) ||
    data.policies.length > 8
  )
    throw new Error("response");
  const seen = new Set<string>();
  for (const raw of data.cnpjs) {
    const item = object(raw);
    if (
      typeof item.value !== "string" ||
      !/^\d{14}$/.test(item.value) ||
      seen.has(item.value) ||
      item.checksum !== (validCnpj(item.value) ? "VALID" : "INVALID") ||
      !Array.isArray(item.provenance) ||
      item.provenance.length < 1 ||
      item.provenance.length > 6
    )
      throw new Error("response");
    seen.add(item.value);
    for (const rawSource of item.provenance) {
      const source = object(rawSource);
      if (
        !["FOOTER", "PAGE", "STRUCTURED_DATA"].includes(String(source.location))
      )
        throw new Error("response");
      url(source.url);
    }
  }
  const policyIds = new Set<string>();
  for (const raw of data.policies) {
    const item = object(raw);
    if (
      typeof item.id !== "string" ||
      ![
        "contact",
        "privacy",
        "terms",
        "returns",
        "refund",
        "shipping",
        "legal",
        "about",
      ].includes(item.id) ||
      policyIds.has(item.id) ||
      !Array.isArray(item.sourceUrls) ||
      item.sourceUrls.length < 1 ||
      item.sourceUrls.length > 3
    )
      throw new Error("response");
    policyIds.add(item.id);
    item.sourceUrls.forEach(url);
  }
  if (
    data.collection === "unavailable" &&
    (data.cnpjs.length || data.policies.length)
  )
    throw new Error("response");
}
