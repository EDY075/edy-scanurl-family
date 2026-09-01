import { describe, expect, it } from "vitest";
import { inspectDomainName } from "../src/family/domain-warning.js";

describe("Family lexical warnings — deterministic test inputs, no live requests", () => {
  it.each(["amazon.com.br", "www.amazon.com", "m.magazineluiza.com.br", "shopee.com.br", "atelierdrahaiter.com.br"])("does not manufacture a warning for %s", (domain) => {
    expect(inspectDomainName(domain)).toBeUndefined();
  });
  it.each(["amazom.com.br", "amzon.com.br", "amazonn.com.br", "amzaon.com.br", "amazon-ofertas.example", "amazon.com.br.loja.example", "shopee-oferta.example"])("warns about a similar name %s", (domain) => {
    expect(inspectDomainName(domain)).toBeDefined();
  });
  it("labels mixed scripts as a clue, not a malware detection", () => {
    expect(inspectDomainName("аmazon.com.br")?.reason).toBe("MIXED_SCRIPT");
  });
});
