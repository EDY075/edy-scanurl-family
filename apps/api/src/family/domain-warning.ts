import { domainToUnicode } from "node:url";
import { getDomain, getDomainWithoutSuffix } from "tldts";
import type { ScanJobSnapshot } from "../services/scan-orchestrator.js";

// Small, explicit comparison set, NOT a trust allowlist or exhaustive brand database.
const referenceDomains = ["mercadolivre.com.br", "amazon.com.br", "amazon.com", "magazineluiza.com.br", "shopee.com.br", "shopee.com", "shopee.sg"] as const;
export interface DomainNameWarning { reference: string; reason: "SIMILAR_SPELLING" | "BRAND_IN_SUBDOMAIN" | "MIXED_SCRIPT" }
function closeSpelling(left: string, right: string): boolean {
  if (left === right) return true;
  if (Math.abs(left.length - right.length) > 1) return false;
  if (left.length === right.length) {
    const positions = Array.from(left).flatMap((char, index) => char === right[index] ? [] : [index]);
    if (positions.length === 1) return true;
    const [a, b] = positions;
    return positions.length === 2 && a !== undefined && b === a + 1 && left[a] === right[b] && left[b] === right[a];
  }
  const [short, long] = left.length < right.length ? [left, right] : [right, left];
  let i = 0; let j = 0; let skipped = false;
  while (i < short.length && j < long.length) {
    if (short[i] === long[j]) { i += 1; j += 1; }
    else if (!skipped) { skipped = true; j += 1; }
    else return false;
  }
  return true;
}
export function inspectDomainName(input: string): DomainNameWarning | undefined {
  let hostname: string;
  try { hostname = new URL(`https://${input}`).hostname.toLowerCase().replace(/\.$/, ""); } catch { return undefined; }
  const registrable = getDomain(hostname, { allowPrivateDomains: true });
  if (!registrable || referenceDomains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))) return undefined;
  const unicode = domainToUnicode(registrable);
  if (/\p{Script=Latin}/u.test(unicode) && /[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(unicode)) return { reference: hostname, reason: "MIXED_SCRIPT" };
  const label = getDomainWithoutSuffix(registrable, { allowPrivateDomains: true }) ?? "";
  for (const reference of referenceDomains) {
    const brand = getDomainWithoutSuffix(reference) ?? "";
    if (hostname.includes(`${reference}.`) || hostname.split(".").slice(0, -2).includes(brand)) return { reference, reason: "BRAND_IN_SUBDOMAIN" };
    // Prefix/suffix promotional words are a clue, never proof of impersonation.
    if (brand.length >= 5 && (closeSpelling(label, brand) || label.startsWith(`${brand}-`) || label.endsWith(`-${brand}`))) return { reference, reason: "SIMILAR_SPELLING" };
  }
  return undefined;
}
export function decorateFamilySnapshot(snapshot: ScanJobSnapshot): ScanJobSnapshot {
  const report = snapshot.report;
  if (snapshot.status !== "SUCCEEDED" || !report || report.checks.some((check) => check.id === "FAMILY_DOMAIN_LOOKALIKE")) return snapshot;
  const warning = inspectDomainName(report.domain);
  if (!warning) return snapshot;
  const sourceId = "family-domain-heuristic";
  return { ...snapshot, report: { ...report,
    checks: [...report.checks, {
      id: "FAMILY_DOMAIN_LOOKALIKE", category: "DOMAIN", title: "Domínio parecido: confira o endereço",
      description: warning.reason === "MIXED_SCRIPT" ? "O nome combina alfabetos diferentes. Confira cada caractere pelo canal oficial da loja; isso não prova golpe."
        : `O nome lembra ${warning.reference}, mas não é esse domínio. A comparação é uma pista limitada, não prova de golpe.`,
      status: "WARNING", impact: "warning", points: 0, sourceId, value: warning.reference,
    }],
    sources: [...report.sources, { id: sourceId, name: "EDY Family — comparação limitada do nome", tier: 4, category: "DOMAIN", collectedAt: report.scannedAt, status: "available" }],
  } };
}
