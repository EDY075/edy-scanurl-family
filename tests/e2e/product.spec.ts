import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

async function assertNoHorizontalOverflow(page: Page): Promise<void> {
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport + 1);
}

async function runDemo(page: Page, scenarioLabel: string, expectedVerdict: string): Promise<void> {
  const trigger = page.getByRole("button", { name: "Experimentar demonstração", exact: true });
  if (await trigger.isVisible().catch(() => false)) await trigger.click();
  await page.getByRole("button", { name: scenarioLabel, exact: true }).click();
  await page.getByRole("button", { name: "Verificar site", exact: true }).click();
  await expect(page.getByRole("heading", { name: expectedVerdict, exact: true })).toBeVisible();
  await expect(page.getByText("DEMO · DADOS SINTÉTICOS", { exact: true })).toBeVisible();
  await assertNoHorizontalOverflow(page);
}

test("home remains usable without horizontal overflow", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Verifique antes de comprar");
  await expect(page.getByRole("button", { name: "Verificar site", exact: true })).toBeVisible();
  const brandGeometry = await page.evaluate(() => {
    const mark = document.querySelector(".official-brand-mark")?.getBoundingClientRect();
    const lockup = document.querySelector(".brand")?.getBoundingClientRect();
    const tools = document.querySelector(".header-tools")?.getBoundingClientRect();
    return {
      markWidth: mark?.width ?? 0,
      markHeight: mark?.height ?? 0,
      lockupRatio: (lockup?.width ?? 0) / document.documentElement.clientWidth,
      toolsGap: (tools?.left ?? 0) - (lockup?.right ?? 0),
    };
  });
  const mobile = (page.viewportSize()?.width ?? 1440) <= 760;
  expect(brandGeometry.markWidth).toBe(mobile ? 28 : 32);
  expect(brandGeometry.markHeight).toBe(brandGeometry.markWidth);
  expect(brandGeometry.lockupRatio).toBeLessThanOrEqual(mobile ? 0.4 : 0.3);
  expect(brandGeometry.toolsGap).toBeGreaterThanOrEqual(24);
  await assertNoHorizontalOverflow(page);
});

test("running state exposes operational progress", async ({ page }, testInfo) => {
  const capturePath = testInfo.project.name === "desktop-1440"
    ? "docs/review-v4/desktop/02-running.png"
    : testInfo.project.name === "mobile-390"
      ? "docs/review-v4/mobile/03-running.png"
      : null;
  test.skip(!capturePath, "Running evidence is captured at representative desktop and mobile sizes.");
  if (!capturePath) return;
  await page.goto("/");
  await page.getByRole("button", { name: "Experimentar demonstração", exact: true }).click();
  await page.getByRole("button", { name: "Cautela", exact: true }).click();
  await page.getByRole("button", { name: "Verificar site", exact: true }).click();
  await expect(page.getByRole("heading", { name: /^Verificando / })).toBeVisible();
  await expect(page.locator(".progress-counter")).toContainText("/ 06");
  await page.screenshot({ path: capturePath });
});

test("decision report remains responsive across the viewport matrix", async ({ page }) => {
  test.slow();
  await page.goto("/");
  await runDemo(page, "Risco elevado", "Não recomendo comprar");
  await expect(page.locator(".decision-metrics")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Motivos críticos", exact: true })).toBeVisible();
  await assertNoHorizontalOverflow(page);

  const viewportWidth = page.viewportSize()?.width ?? 1440;
  if (viewportWidth <= 412) {
    const order = await page.locator(".decision-sheet").evaluate((sheet) => {
      const reasonsBottom = sheet.querySelector(".state-highlights")?.getBoundingClientRect().bottom ?? 0;
      const metricsTop = sheet.querySelector(".decision-metrics")?.getBoundingClientRect().top ?? 0;
      return { reasonsBottom, metricsTop };
    });
    expect(order.reasonsBottom).toBeLessThanOrEqual(order.metricsTop);
  }
});

test("six synthetic scenarios remain distinct and reports disclose provenance", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-390", "One complete functional journey is sufficient; layout runs in every project.");
  test.slow();
  const scenarios = [
    ["Loja consolidada", "Bons sinais para compra"],
    ["Cautela", "Compre com cautela"],
    ["Risco elevado", "Não recomendo comprar"],
    ["Poucos dados", "Dados insuficientes"],
    ["Phishing confirmado", "Não recomendo comprar"],
    ["Empresa divergente", "Não recomendo comprar"],
  ] as const;
  await page.goto("/");
  for (const [scenario, verdict] of scenarios) {
    await runDemo(page, scenario, verdict);
    await page.getByRole("button", { name: "Nova análise", exact: true }).first().click();
  }
});

test("technical disclosure, sources, history and clear-history work", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-1440", "Desktop interaction gate.");
  test.slow();
  await page.goto("/");
  await runDemo(page, "Cautela", "Compre com cautela");
  await page.getByRole("button", { name: "Verificações", exact: true }).click();
  await expect(page.locator('section[aria-labelledby="group-business"]')).toBeVisible();
  await page.getByRole("button", { name: "Técnico", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Evidências técnicas", exact: true })).toBeVisible();
  await page
    .getByLabel("Seções do relatório", { exact: true })
    .getByRole("button", { name: "Fontes", exact: true })
    .click();
  await expect(page.getByText("Receita Federal · CNPJ", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copiar resumo", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Compartilhar", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Nova análise", exact: true }).first().click();
  await expect(page.getByLabel("Endereço da loja")).toHaveValue("");
  await page.getByRole("button", { name: "Histórico", exact: true }).first().click();
  await expect(page.getByRole("heading", { name: "Suas análises" })).toBeVisible();
  await page.getByRole("button", { name: "Abrir relatório", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Compre com cautela", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Nova análise", exact: true }).first().click();
  await page.getByRole("button", { name: "Histórico", exact: true }).first().click();
  await page.getByRole("button", { name: "Limpar histórico", exact: true }).click();
  await expect(page.getByText("Nenhuma análise por aqui ainda.", { exact: true })).toBeVisible();
});

test("English and dark theme persist", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-1280", "i18n/theme interaction gate.");
  await page.goto("/");
  await page.getByRole("button", { name: "Idioma", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Check before you buy");
  await page.getByRole("button", { name: "Appearance", exact: true }).click();
  await expect.poll(() => page.locator("html").getAttribute("data-theme")).toBe("dark");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
});

test("real mode reaches the local API without exposing discarded URL data", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-1280", "Real-provider journey runs once against the local API.");
  test.slow();
  await page.goto("/");
  const input = page.getByLabel("Endereço da loja");
  await input.fill("https://example.com/private?token=browser-e2e-secret#discarded");
  await page.getByRole("button", { name: "Verificar site", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Dados insuficientes", exact: true })).toBeVisible({ timeout: 35_000 });
  await expect(page.getByText("DEMO · DADOS SINTÉTICOS", { exact: true })).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("browser-e2e-secret");
  await expect(page.locator("body")).toContainText("example.com");
});

test("home and report have no serious WCAG A/AA violations", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "tablet-768", "Accessibility gate runs once.");
  test.slow();
  await page.goto("/");
  let result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(result.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
  await runDemo(page, "Cautela", "Compre com cautela");
  result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(result.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
  await page.getByRole("button", { name: "Verificações", exact: true }).click();
  const firstCheck = page.locator(".check-row").first();
  await firstCheck.focus();
  await page.keyboard.press("Enter");
  await expect(firstCheck).toHaveAttribute("aria-expanded", "true");
  result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(result.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
});

test("PWA manifest, service worker and offline shell are functional", async ({ page, context }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-1366", "PWA gate runs once.");
  test.slow();
  await page.goto("/");
  expect(await page.evaluate(() => window.isSecureContext)).toBe(true);
  const manifest = await page.evaluate(async () => {
    const response = await fetch("/manifest.webmanifest");
    return response.json() as Promise<{ name: string; display: string; start_url: string; scope: string; icons: { sizes: string; purpose?: string }[] }>;
  });
  expect(manifest.name).toContain("EDY ScanURL");
  expect(manifest.display).toBe("standalone");
  expect(manifest.start_url).toBe("/");
  expect(manifest.scope).toBe("/");
  expect(manifest.icons.map((icon) => icon.sizes)).toEqual(expect.arrayContaining(["192x192", "512x512"]));
  expect(manifest.icons.some((icon) => icon.purpose === "maskable")).toBe(true);
  await page.evaluate(async () => navigator.serviceWorker.ready);
  await context.setOffline(true);
  await page.getByLabel("Endereço da loja").fill("example.com");
  await page.getByRole("button", { name: "Verificar site", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveText("Motor de análise indisponível.");
  await page.reload();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Verifique antes de comprar");
  await context.setOffline(false);
});

test("visual matrix captures the primary themes and locales", async ({ page }, testInfo) => {
  const matrix: Record<string, { locale: "pt-BR" | "en"; theme: "light" | "dark" }> = {
    "mobile-360": { locale: "pt-BR", theme: "light" },
    "mobile-412": { locale: "pt-BR", theme: "dark" },
    "desktop-1366": { locale: "en", theme: "light" },
    "desktop-1920": { locale: "en", theme: "dark" },
  };
  const settings = matrix[testInfo.project.name];
  if (!settings) {
    test.skip(true, "This project is covered by the viewport overflow gate.");
    return;
  }
  await page.addInitScript((values) => {
    localStorage.setItem("edy-locale", values.locale);
    localStorage.setItem("edy-theme", values.theme);
  }, settings);
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("lang", settings.locale);
  await expect(page.locator("html")).toHaveAttribute("data-theme", settings.theme);
  await assertNoHorizontalOverflow(page);
  await page.screenshot({
    path: `docs/screenshots/home-${testInfo.project.name}-${settings.locale}-${settings.theme}.png`,
    fullPage: true,
  });
});
