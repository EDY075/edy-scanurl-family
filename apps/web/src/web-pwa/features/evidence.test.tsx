import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, fireEvent } from "@testing-library/react";
import type { Check, ScanReport } from "../../types";
import { resultEvidence, sourceConsultation } from "./evidence";
import { EvidenceSection } from "./evidence-section";
import { validateStoreEvidence } from "../services/store-evidence";

const check = (
  id: string,
  status: Check["status"] = "UNKNOWN",
  sourceId = "site",
): Check => ({
  id,
  status,
  sourceId,
  title: id,
  category: "TEST",
  description: "Observação apenas para teste.",
  points: 0,
  impact: "neutral",
});
function report(
  checks = [
    check("BUSINESS_CNPJ_SITE"),
    check("BUSINESS_OFFICIAL_VALIDATION", "NOT_CHECKED", "registry"),
  ],
): ScanReport {
  return {
    id: "test",
    mode: "real",
    inputUrl: "https://example.com/",
    normalizedUrl: "https://example.com/",
    domain: "example.com",
    scannedAt: new Date().toISOString(),
    verdict: "INSUFFICIENT_DATA",
    score: null,
    confidence: "LOW",
    coverage: 30,
    summary: "Test only",
    recommendation: "Test only",
    checks,
    sources: [
      {
        id: "site",
        name: "Site de teste",
        category: "TEST",
        tier: 4,
        status: "available",
      },
      {
        id: "registry",
        name: "Cadastro de teste",
        category: "TEST",
        tier: 1,
        status: "unavailable",
      },
    ],
    scoreAreas: [],
    technical: {
      domainAge: "Não confirmado",
      registrar: "",
      dns: [],
      tls: "",
      tlsIssuer: "",
      redirects: [],
      headers: [],
      threatStatus: "",
      salesVolume: "",
      paymentSignals: [],
    },
  };
}
const store = (): NonNullable<ScanReport["storeEvidence"]> => ({
  version: 1,
  collection: "available",
  registration: "NOT_CHECKED",
  match: "UNKNOWN",
  cnpjs: [
    {
      value: "11222333000181",
      checksum: "VALID",
      provenance: [{ url: "https://example.com/contato", location: "FOOTER" }],
    },
  ],
  policies: [{ id: "privacy", sourceUrls: ["https://example.com/privacy"] }],
});
afterEach(cleanup);
describe("canonical result evidence", () => {
  it.each([false, true])('keeps strongest duplicate impact independent of order: %s', (reversed) => {
    const neutral = check('HTTP_HEADERS'); const negative = check('HTTP_HEADERS'); delete negative.status; negative.impact = 'negative';
    const input = report(reversed ? [negative, neutral] : [neutral, negative]);
    expect(resultEvidence(input)[0]?.state).toBe('FAIL');
    expect(resultEvidence(input)[0]?.explanation).not.toContain('não foi considerada');
  });
  it('does not weaken an explicit VT failure when technical details contain only suspicious detections', () => {
    const input = report([check('THREAT_VIRUSTOTAL', 'FAIL')]);
    input.technical.virusTotal = { state: 'PARTIAL', reason: 'TEST', domain: { state: 'AVAILABLE', cache: 'MISS', freshness: 'FRESH', stats: { malicious: 0, suspicious: 1, harmless: 20, undetected: 40, timeout: 0, other: 0, total: 61 } } };
    expect(resultEvidence(input)[0]?.state).toBe('FAIL');
  });
  it('distinguishes a failed DS query from an observed absence of DS', () => {
    const input = report([check('DOMAIN_DNSSEC')]); input.sources[0].status = 'limited';
    input.checks[0].description = 'A consulta DS ficou indisponível; não é tratada como ausência.';
    expect(resultEvidence(input)[0]?.state).toBe('UNAVAILABLE');
    input.checks[0].description = 'Registro DS não observado; isso não prova risco.';
    expect(resultEvidence(input)[0]?.state).toBe('INFO');
  });
  it.each(['BUSINESS_CNPJ_SITE', 'TRANSPARENCY_POLICIES', 'HTTP_HEADERS'])('never downgrades an explicit negative impact: %s', (id) => {
    const input = report([check(id)]);
    input.checks[0].status = undefined; input.checks[0].impact = 'negative';
    expect(resultEvidence(input).find((entry) => entry.checkId === id)?.state).toBe('FAIL');
  });
  it('preserves checksum alerts when additive observations contradict them', () => {
    const input = report(); input.storeEvidence = store(); input.checks.push(check('BUSINESS_CNPJ_CHECKSUM', 'FAIL'));
    expect(resultEvidence(input).find((item) => item.checkId === 'BUSINESS_CNPJ_CHECKSUM')?.state).toBe('FAIL');
  });
  it("result evidence items have unique ids", () => {
    const input = report();
    input.checks.push(...input.checks);
    const items = resultEvidence(input);
    expect(items.map((item) => item.id)).toEqual([
      "company_identity",
      "company_registration",
    ]);
    expect(new Set(items.map((item) => item.title)).size).toBe(items.length);
  });
  it("does not hide conflicting duplicate observations", () => {
    const input = report([
      check("TLS_HTTPS", "PASS"),
      check("TLS_HTTPS", "FAIL"),
    ]);
    expect(resultEvidence(input)).toHaveLength(1);
    expect(resultEvidence(input)[0]).toMatchObject({ state: "FAIL" });
    expect(resultEvidence(input)[0]?.details.join(" ")).toContain(
      "conflitantes",
    );
  });
  it("keeps found digits, official registration and ownership separate", () => {
    const input = report();
    input.storeEvidence = store();
    const identity = resultEvidence(input)[0];
    expect(identity).toMatchObject({
      state: "INFO",
      title: "CNPJ encontrado no site",
    });
    expect(identity.details.join(" ")).toContain("11.222.333/0001-81");
    expect(identity.details.join(" ")).toContain(
      "Correspondência empresa e site: não determinada",
    );
    expect(resultEvidence(input)[1]).toMatchObject({
      state: "NOT_CHECKED",
      title: "CNPJ cadastral não consultado",
    });
  });
  it("supports legacy reports honestly without fabricated page provenance", () => {
    const input = report();
    input.checks[0].value = "11222333000181";
    expect(resultEvidence(input)[0]?.details).toContain(
      "Página exata não informada por esta versão do serviço.",
    );
  });
  it("distinguishes no CNPJ from source unavailable", () => {
    const input = report();
    expect(resultEvidence(input)[0]?.state).toBe("INFO");
    input.sources[0].status = "unavailable";
    expect(resultEvidence(input)[0]).toMatchObject({
      state: "UNAVAILABLE",
      title: "Leitura do CNPJ indisponível",
    });
  });
  it("keeps all distinct CNPJs and renders invalid digits once", () => {
    const input = report();
    input.storeEvidence = store();
    input.storeEvidence.cnpjs.push({
      value: "11222333000182",
      checksum: "INVALID",
      provenance: [{ url: "https://example.com/", location: "PAGE" }],
    });
    input.checks.push(check("BUSINESS_CNPJ_CHECKSUM", "FAIL"));
    const items = resultEvidence(input);
    expect(items).toHaveLength(2);
    expect(items[0]?.state).toBe("FAIL");
    expect(items[0]?.details.join(" ")).toContain("11.222.333/0001-82");
  });
  it("reputation unavailable is not missing buyer reviews", () => {
    const input = report([check("CONSUMER_REPUTATION")]);
    input.sources[0].status = "unavailable";
    expect(resultEvidence(input)[0]).toMatchObject({
      state: "UNAVAILABLE",
      label: "Fonte indisponível",
    });
    input.checks[0].status = "NOT_CHECKED";
    expect(resultEvidence(input)[0]).toMatchObject({
      state: "NOT_CHECKED",
      label: "Não avaliada",
    });
    expect(sourceConsultation(input, input.sources[0])).toBe("Não consultada");
  });
  it("shows only policy categories actually provided with provenance", () => {
    const input = report([check("TRANSPARENCY_POLICIES", "PASS")]);
    input.storeEvidence = store();
    expect(
      resultEvidence(input).find((item) => item.id === "policy_privacy"),
    ).toMatchObject({ state: "PASS", urls: ["https://example.com/privacy"] });
    expect(
      resultEvidence(input).some((item) => item.id === "policy_returns"),
    ).toBe(false);
    delete input.storeEvidence;
    expect(resultEvidence(input)[0]?.state).toBe("INFO");
    expect(resultEvidence(input)[0]?.details.join(" ")).toContain("agregado");
  });
  it.each([
    [0, 0, "INFO"],
    [1, 0, "FAIL"],
    [0, 1, "WARNING"],
  ] as const)(
    "threat intelligence malicious=%i suspicious=%i => %s",
    (malicious, suspicious, state) => {
      const input = report([check("THREAT_VIRUSTOTAL")]);
      input.technical.virusTotal = {
        state: "PARTIAL",
        reason: "TEST",
        domain: {
          state: "AVAILABLE",
          cache: "MISS",
          freshness: "FRESH",
          stats: {
            malicious,
            suspicious,
            harmless: 20,
            undetected: 40,
            timeout: 0,
            other: 0,
            total: 60 + malicious + suspicious,
          },
        },
        url: { state: "NO_DATA", cache: "MISS" },
      };
      expect(resultEvidence(input)[0]?.state).toBe(state);
      expect(resultEvidence(input)[0]?.details.join(" ")).toContain(
        "sem relatório",
      );
    },
  );
  it("does not treat a stale clean VT report as current evidence", () => {
    const input = report([check("THREAT_VIRUSTOTAL")]);
    input.technical.virusTotal = {
      state: "AVAILABLE",
      reason: "TEST",
      domain: {
        state: "AVAILABLE",
        cache: "MISS",
        freshness: "STALE",
        stats: {
          malicious: 0,
          suspicious: 0,
          harmless: 60,
          undetected: 0,
          timeout: 0,
          other: 0,
          total: 60,
        },
      },
    };
    expect(resultEvidence(input)[0]?.label).toBe("Dados inconclusivos");
  });
  it.each([
    ["PASS", "available", "PASS"],
    ["UNKNOWN", "available", "INFO"],
    ["WARNING", "available", "WARNING"],
    ["FAIL", "available", "FAIL"],
    ["UNKNOWN", "unavailable", "UNAVAILABLE"],
    ["NOT_CHECKED", "unavailable", "NOT_CHECKED"],
  ] as const)(
    "UI %s / %s renders %s accessibly",
    (status, sourceStatus, state) => {
      const input = report([check("DOMAIN_RDAP", status)]);
      input.sources[0].status = sourceStatus;
      const { container, getByText } = render(
        <EvidenceSection report={input} />,
      );
      const row = container.querySelector(`[data-evidence-state="${state}"]`);
      expect(row).not.toBeNull();
      fireEvent.click(getByText("Registro do domínio"));
      expect(row?.querySelector("summary strong")?.textContent).toBe(
        "Registro do domínio",
      );
      expect(
        row?.querySelector(".evidence-body p")?.textContent.length,
      ).toBeGreaterThan(0);
    },
  );
});
describe("additive evidence boundary", () => {
  it("accepts bounded actual site evidence", () =>
    expect(() => validateStoreEvidence(store(), "example.com")).not.toThrow());
  it.each([
    "script-url",
    "private-url",
    "foreign-url",
    "query",
    "checksum",
    "duplicate",
    "pretend-active",
    "unavailable-positive",
    "unknown-policy",
  ])("rejects unsafe or contradictory evidence: %s", (mode) => {
    const input = store();
    if (mode === "script-url")
      input.cnpjs[0].provenance[0].url = "javascript:alert(1)";
    if (mode === "private-url")
      input.cnpjs[0].provenance[0].url = "http://127.0.0.1/";
    if (mode === "foreign-url")
      input.cnpjs[0].provenance[0].url = "https://elsewhere.com/";
    if (mode === "query")
      input.cnpjs[0].provenance[0].url += "?session=private";
    if (mode === "checksum") input.cnpjs[0].checksum = "INVALID";
    if (mode === "duplicate") input.cnpjs.push(input.cnpjs[0]);
    if (mode === "pretend-active")
      Object.assign(input, { registration: "ACTIVE" });
    if (mode === "unavailable-positive") input.collection = "unavailable";
    if (mode === "unknown-policy") input.policies[0].id = "invented";
    expect(() => validateStoreEvidence(input, "example.com")).toThrow();
  });
});
