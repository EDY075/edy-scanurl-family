import { describe, expect, it } from "vitest";
import { extractTransparencySignals } from "../src/security/html-signals.js";
import { redactRecord } from "../src/security/redaction.js";

describe("hostile content handling", () => {
  it("extracts passive signals without preserving scripts or form values", () => {
    const result = extractTransparencySignals(
      `<html><head><title>Loja Sintética</title><script>alert('x')</script></head>
       <body><form><input value="secret"></form>
       <p>CNPJ 12.345.678/0001-AB</p><p>contato@synthetic.example</p>
       <a href="/privacidade">Privacidade</a><a href="https://instagram.com/synthetic">Instagram</a>
       <p>Aceitamos PIX e cartão.</p></body></html>`,
      "https://synthetic.example",
    );
    expect(result.pageTitle).toBe("Loja Sintética");
    expect(result.cnpjCandidates).toContain("12.345.678/0001-AB");
    expect(result.declaredPolicies.privacy).toBe(true);
    expect(result.policies.privacy).toBe(false);
    expect(result.socialLinks).toContain("https://instagram.com/synthetic");
    expect(result.paymentMethods).toEqual(["PIX", "CARD"]);
  });

  it("redacts secrets recursively", () => {
    expect(
      redactRecord({ authorization: "Bearer abc", nested: { url: "https://x.example/?token=abc", cookie: "sid=x" } }),
    ).toEqual({ authorization: "[REDACTED]", nested: { url: "https://x.example/?token=[REDACTED]", cookie: "[REDACTED]" } });
  });

  it("does not accept lookalike social hosts or active protocols", () => {
    const result = extractTransparencySignals(
      `<a href="https://evilinstagram.com/store">Fake</a><a href="javascript:https://instagram.com/store">Active</a>`,
      "https://synthetic.example",
    );
    expect(result.socialLinks).toEqual([]);
  });

  it("extracts bounded JSON-LD site claims, sameAs and commerce signals without executing code", () => {
    const result = extractTransparencySignals(
      `<script type="application/ld+json">{"@type":"OnlineStore","name":"Loja Exemplo","legalName":"Loja Exemplo Ltda.","telephone":"+55 11 99999-0000","address":{"streetAddress":"Rua Um, 10","addressLocality":"São Paulo"},"sameAs":["https://instagram.com/loja","https://evilinstagram.com/loja"]}</script>
       <a href="/contato">Contato</a><a href="/produtos/item">Produto</a>
       <p>Aceitamos cartão e boleto. Powered by WooCommerce.</p>`,
      "https://synthetic.example/",
    );
    expect(result.structuredOrganizations[0]?.type).toBe("OnlineStore");
    expect(result.companyNames).toContain("Loja Exemplo Ltda.");
    expect(result.socialLinks).toEqual(["https://instagram.com/loja"]);
    expect(result.relevantLinks).toContainEqual({ url: "https://synthetic.example/contato", kind: "CONTACT" });
    expect(result.catalogFound).toBe(true);
    expect(result.platforms).toContain("WooCommerce");
    expect(result.paymentMethods).toEqual(["CARD", "BOLETO"]);
  });

  it("confirms a policy only when substantive policy content was fetched", () => {
    const result = extractTransparencySignals(
      `<main><h1>Política de privacidade</h1><p>${"Tratamos dados pessoais conforme a LGPD e explicamos cookies, finalidade, retenção e direitos do titular. ".repeat(8)}</p></main>`,
      "https://synthetic.example/privacidade",
      "PRIVACY",
    );
    expect(result.policies.privacy).toBe(true);
  });
});
