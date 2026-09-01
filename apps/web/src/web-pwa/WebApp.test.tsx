/* eslint-disable @typescript-eslint/unbound-method -- Assertions inspect vi.fn clipboard mocks, never invoke detached browser methods. */
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebApp } from "./WebApp";
import type { ScanReport } from "../types";
import { resultSnapshot, sanitizeHistory } from "./features/history";
import { shareResult, shareText } from "./features/results";
import * as matchers from "@testing-library/jest-dom/matchers";
expect.extend(matchers);

const service = vi.hoisted(() => ({
  checkHealth: vi.fn(),
  scanStore: vi.fn(),
}));
vi.mock("./services/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./services/api")>()),
  ...service,
}));
function report(verdict: ScanReport["verdict"] = "BUY"): ScanReport {
  return {
    id: "test-only",
    mode: "real",
    inputUrl: "https://example.com/pedido?private=1",
    normalizedUrl: "https://example.com/",
    domain: "example.com",
    scannedAt: new Date().toISOString(),
    verdict,
    score: verdict === "BUY" ? 92 : 21,
    confidence: "HIGH",
    coverage: 94,
    summary: "Synthetic test-only",
    recommendation: "Synthetic test-only",
    checks: [
      {
        id: "domain.age",
        title: "Idade do domínio",
        description: "Test-only",
        category: "domain",
        impact: "positive",
        points: 10,
        status: "PASS",
        sourceId: "rdap",
      },
    ],
    scoreAreas: [],
    sources: [
      {
        id: "rdap",
        name: "Registro",
        category: "domain",
        tier: 1,
        status: "available",
      },
    ],
    technical: {
      domainAge: "10 anos",
      registrar: "Registro",
      dns: [],
      tls: "HTTPS",
      tlsIssuer: "",
      redirects: [],
      headers: [],
      threatStatus: "",
      salesVolume: "",
      paymentSignals: [],
    },
  };
}
beforeEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
  service.checkHealth.mockResolvedValue("online");
  service.scanStore.mockResolvedValue(report());
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      readText: vi
        .fn()
        .mockResolvedValue("Veja: https://example.com/produto?token=private"),
      writeText: vi.fn().mockResolvedValue(undefined),
    },
  });
  Object.defineProperty(navigator, "share", {
    configurable: true,
    value: undefined,
  });
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => {
    callback(0);
    return 0;
  });
  vi.stubGlobal(
    "matchMedia",
    vi
      .fn()
      .mockReturnValue({
        matches: false,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
async function open() {
  render(<WebApp />);
  await screen.findByText("Serviço online");
}
async function scan() {
  fireEvent.change(screen.getByLabelText("Endereço da loja"), {
    target: { value: "example.com" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Verificar site" }));
  await screen.findByRole("heading", { name: "example.com" });
}
describe("Web/PWA — test-only service fixtures", () => {
  it('submits Enter exactly once from the URL field', async () => {
    await open();
    fireEvent.change(screen.getByLabelText('Endereço da loja'), {target:{value:'example.com'}});
    fireEvent.keyDown(screen.getByLabelText('Endereço da loja'), {key:'Enter'});
    await screen.findByRole('heading',{name:'Pode comprar com cautela'});
    expect(service.scanStore).toHaveBeenCalledTimes(1);
  });
  it('offers an explicit safe PWA refresh when an update is ready', async () => {
    await open();
    fireEvent(window, new Event('edy-update-ready'));
    expect(screen.getByRole('button',{name:'Atualizar aplicativo'})).toBeEnabled();
  });
  it("starts dark, with history off and no scan before user action", async () => {
    await open();
    expect(document.querySelector(".web-app")).toHaveAttribute(
      "data-theme",
      "dark",
    );
    expect(
      screen.getByLabelText("Guardar um resumo das próximas verificações"),
    ).not.toBeChecked();
    expect(service.scanStore).not.toHaveBeenCalled();
    expect(
      screen.getByRole("button", { name: "Verificar site" }),
    ).toBeDisabled();
  });
  it("keeps a valid URL enabled when health is degraded", async () => {
    service.checkHealth.mockResolvedValue("degraded");
    render(<WebApp />);
    await screen.findByText("Serviço com instabilidade");
    fireEvent.change(screen.getByLabelText("Endereço da loja"), {
      target: { value: "example.com" },
    });
    expect(
      screen.getByRole("button", { name: "Verificar site" }),
    ).toBeEnabled();
  });
  it("keeps a valid URL enabled while health has not returned", () => {
    service.checkHealth.mockReturnValue(new Promise(() => undefined));
    render(<WebApp />);
    fireEvent.change(screen.getByLabelText("Endereço da loja"), {
      target: { value: "example.com" },
    });
    expect(
      screen.getByRole("button", { name: "Verificar site" }),
    ).toBeEnabled();
  });
  it("extracts pasted message and removes product identifiers", async () => {
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Colar link" }));
    await waitFor(() =>
      expect(screen.getByLabelText("Endereço da loja")).toHaveValue(
        "https://example.com/",
      ),
    );
    expect(service.scanStore).not.toHaveBeenCalled();
  });
  it("handles clipboard access denied", async () => {
    vi.mocked(navigator.clipboard.readText).mockRejectedValue(new Error());
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Colar link" }));
    await screen.findByText(/Toque no campo e cole o link manualmente/);
  });
  it("clears the field and restores focus", async () => {
    await open();
    fireEvent.change(screen.getByLabelText("Endereço da loja"), {
      target: { value: "example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Limpar endereço" }));
    expect(screen.getByLabelText("Endereço da loja")).toHaveValue("");
    expect(screen.getByLabelText("Endereço da loja")).toHaveFocus();
  });
  it("renders a low-risk real-contract fixture with collapsed sources", async () => {
    await open();
    await scan();
    expect(
      screen.getByRole("heading", { name: "Pode comprar com cautela" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Ver detalhes técnicos").closest("details"),
    ).not.toHaveAttribute("open");
    expect(
      screen.getByRole("button", { name: "Verificar outro site" }),
    ).toBeInTheDocument();
    expect(localStorage.getItem("edy-web-history-v1")).toBeNull();
  });
  it("renders high risk without changing server score", async () => {
    service.scanStore.mockResolvedValue(report("DO_NOT_BUY"));
    await open();
    await scan();
    expect(
      screen.getByRole("heading", { name: "Melhor evitar agora" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Recomendamos não realizar o pagamento enquanto os sinais encontrados não forem esclarecidos.")).toBeInTheDocument();
  });
  it("renders insufficient information as partial, not moderate risk or trusted", async () => {
    service.scanStore.mockResolvedValue({
      ...report("INSUFFICIENT_DATA"),
      score: null,
      coverage: 20,
    });
    await open();
    await scan();
    expect(
      screen.getByRole("heading", { name: "Vale confirmar alguns dados" }),
    ).toBeInTheDocument();
  });
  it("shows a genuine request error and permits explicit retry", async () => {
    service.scanStore
      .mockRejectedValueOnce(new Error("unavailable"))
      .mockResolvedValueOnce(report());
    await open();
    fireEvent.change(screen.getByLabelText("Endereço da loja"), {
      target: { value: "example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verificar site" }));
    await screen.findByRole("alert");
    expect(service.scanStore).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Tentar novamente" }));
    await screen.findByRole("heading", { name: "Pode comprar com cautela" });
    expect(service.scanStore).toHaveBeenCalledTimes(2);
  });
  it("saves only allowlisted local summary and reopens it without another scan", async () => {
    await open();
    fireEvent.click(
      screen.getByLabelText("Guardar um resumo das próximas verificações"),
    );
    await scan();
    const raw = localStorage.getItem("edy-web-history-v1") ?? "";
    expect(raw).not.toMatch(
      /inputUrl|private|company|registration|technical|publicKey|checks/,
    );
    fireEvent.click(
      screen.getByRole("button", { name: /example.com.*A consulta salva/ }),
    );
    await screen.findByText(/Este é um resumo salvo/);
    expect(service.scanStore).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Limpar histórico" }));
    expect(localStorage.getItem("edy-web-history-v1")).toBeNull();
  });
  it("deletes an individual history item", async () => {
    await open();
    fireEvent.click(
      screen.getByLabelText("Guardar um resumo das próximas verificações"),
    );
    await scan();
    fireEvent.click(
      screen.getByRole("button", { name: "Excluir example.com do histórico" }),
    );
    expect(localStorage.getItem("edy-web-history-v1")).toBeNull();
  });
  it("persists all three theme choices", async () => {
    await open();
    fireEvent.click(screen.getByLabelText("Escolher tema"));
    fireEvent.click(screen.getByRole("button", { name: "Claro" }));
    expect(document.querySelector(".web-app")).toHaveAttribute(
      "data-theme",
      "light",
    );
    expect(localStorage.getItem("edy-family-theme-v1")).toBe("light");
    fireEvent.click(
      screen.getByRole("button", { name: "Usar tema do sistema" }),
    );
    expect(localStorage.getItem("edy-family-theme-v1")).toBe("system");
    fireEvent.click(screen.getByRole("button", { name: "Escuro" }));
    expect(document.querySelector(".web-app")).toHaveAttribute(
      "data-theme",
      "dark",
    );
  });
  it("offers keyboard-native education accordions", async () => {
    await open();
    const tip = screen.getByText("Pressão para pagar agora");
    expect(tip.closest("summary")).not.toBeNull();
    expect(tip.closest("details")).not.toHaveAttribute("open");
  });
  it("shares only a human-readable summary through clipboard fallback", async () => {
    const saved = resultSnapshot(report());
    expect(await shareResult(saved)).toBe("copied");
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      shareText(saved),
    );
    expect(shareText(saved)).not.toMatch(/token|private|inputUrl|id:/);
  });
  it("does not copy after the user cancels the native share sheet", async () => {
    Object.defineProperty(navigator, "share", {
      configurable: true,
      value: vi
        .fn()
        .mockRejectedValue(new DOMException("Cancel", "AbortError")),
    });
    expect(await shareResult(resultSnapshot(report()))).toBe("cancelled");
    expect(navigator.clipboard.writeText).not.toHaveBeenCalled();
  });
  it("expires old records and strips unexpected fields", () => {
    const item = resultSnapshot(report());
    expect(sanitizeHistory([{ ...item, secret: "not-kept" }])[0]).toEqual(item);
    expect(
      sanitizeHistory([{ ...item, time: "2000-01-01T00:00:00Z" }]),
    ).toEqual([]);
    expect(sanitizeHistory([{ ...item, domain: "127.0.0.1" }])).toEqual([]);
  });
});
