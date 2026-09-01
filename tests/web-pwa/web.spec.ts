import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mkdir } from "node:fs/promises";

const matrix = [
  [360, 800],
  [390, 844],
  [412, 915],
  [768, 1024],
  [1366, 768],
  [1440, 900],
  [1920, 1080],
] as const;
test("mobile and desktop, light/dark, keyboard and WCAG", async ({ page }) => {
  await mkdir("docs/web-pwa/screenshots", { recursive: true });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Antes de comprar, verifique o site." }),
  ).toBeVisible();
  for (const theme of ["Escuro", "Claro"]) {
    await page.getByLabel("Escolher tema").click();
    await page.getByRole("button", { name: theme, exact: true }).click();
    await page.getByLabel("Escolher tema").click();
    for (const [width, height] of matrix) {
      await page.setViewportSize({ width, height });
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
      ).toBe(true);
      await expect(page.getByLabel("Endereço da loja")).toBeVisible();
      const input = await page.getByLabel("Endereço da loja").boundingBox();
      expect(input?.width).toBeGreaterThan(190);
      if (width < 500) {
        const button = await page
          .getByRole("button", { name: "Verificar site", exact: true })
          .boundingBox();
        expect((button?.y ?? height) + (button?.height ?? 0)).toBeLessThan(
          height,
        );
      }
      await page.screenshot({
        path: `docs/web-pwa/screenshots/home-${theme.toLowerCase()}-${String(width)}x${String(height)}.png`,
        fullPage: true,
      });
    }
    const axe = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze();
    expect(axe.violations).toEqual([]);
  }
  await page.getByLabel("Endereço da loja").fill("https://localhost");
  await expect(
    page.getByRole("button", { name: "Verificar site", exact: true }),
  ).toBeDisabled();
  await page.getByLabel("Endereço da loja").fill("example.com");
  await expect(
    page.getByRole("button", { name: "Verificar site", exact: true }),
  ).toBeEnabled();
});

test("genuine request attempt after failed health, controlled retry (test-only network fixtures)", async ({
  page,
}) => {
  let attempts = 0;
  await page.route("**/health", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: '{"code":"SERVICE_DISABLED"}',
    }),
  );
  await page.route("**/family/v1/enroll", (route) => {
    attempts += 1;
    return route.fulfill({
      status: 503,
      contentType: "application/json",
      body: '{"code":"FAMILY_UNAVAILABLE"}',
    });
  });
  await page.goto("/");
  await page.getByLabel("Endereço da loja").fill("example.com");
  await expect(
    page.getByRole("button", { name: "Verificar site", exact: true }),
  ).toBeEnabled();
  await page
    .getByRole("button", { name: "Verificar site", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText(
    "temporariamente indisponível",
  );
  expect(attempts).toBe(1);
  await page.getByRole("button", { name: "Tentar novamente" }).click();
  await expect.poll(() => attempts).toBe(2);
  await expect(page.getByRole("alert")).toBeVisible();
});

test("paste → actual Worker scan → result → local history → copy → new scan", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("/");
  await page.getByLabel("Guardar um resumo das próximas verificações").check();
  await page.evaluate(() =>
    navigator.clipboard.writeText(
      "Confira esta loja: https://atelierdrahaiter.com.br/produto?tracking=test-only",
    ),
  );
  await page.getByRole("button", { name: "Colar link", exact: true }).click();
  await expect(page.getByLabel("Endereço da loja")).toHaveValue(
    "https://atelierdrahaiter.com.br/",
  );
  await page
    .getByRole("button", { name: "Verificar site", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "atelierdrahaiter.com.br", exact: true }),
  ).toBeVisible({ timeout: 40_000 });
  await expect(
    page.getByText("Ver detalhes técnicos", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Ver detalhes técnicos", { exact: true }).locator(".."),
  ).not.toHaveAttribute("open");
  const missingDisclosure = page.locator('details.missing-checks');
  await expect(missingDisclosure.getByText(/Ver quais ficaram sem dados/)).toBeVisible();
  await missingDisclosure.locator('summary').click();
  await expect(missingDisclosure.getByText('O que não foi possível confirmar', { exact: true })).toBeVisible();
  await expect(missingDisclosure.getByText('Motivo:', { exact: true }).first()).toBeVisible();
  await page.screenshot({
    path: "docs/web-pwa/screenshots/coverage-missing-expanded-mobile-dark.png",
    fullPage: true,
  });
  await page.screenshot({
    path: "docs/web-pwa/screenshots/result-real-mobile-dark.png",
    fullPage: true,
  });
  const technicalDetails = page.locator('details.technical-details');
  await technicalDetails.locator(':scope > summary').click();
  await expect(technicalDetails.getByText('Força da conclusão', { exact: true })).toBeVisible();
  await expect(technicalDetails.getByText('Baixa', { exact: true })).toBeVisible();
  await expect(technicalDetails.getByText('Ainda faltam verificações importantes para uma conclusão mais forte.', { exact: true })).toBeVisible();
  await expect(technicalDetails.getByText('Confiança da análise', { exact: true })).toHaveCount(0);
  await expect(technicalDetails.getByText('Verificações com informação', { exact: true })).toBeVisible();
  await expect(technicalDetails.getByText('Cobertura ponderada da decisão', { exact: true })).toBeVisible();
  await expect(technicalDetails.getByText('Considera a importância das verificações disponíveis para a decisão final.', { exact: true })).toBeVisible();
  await expect(technicalDetails.getByText('Esses percentuais medem apenas a disponibilidade das verificações. Não representam porcentagem de segurança, chance de fraude nem confiabilidade da empresa.', { exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await technicalDetails.screenshot({ path: 'docs/web-pwa/screenshots/final-copy/after-mobile-dark.png' });
  await technicalDetails.locator(':scope > summary').scrollIntoViewIfNeeded();
  await page.screenshot({ path: 'docs/web-pwa/screenshots/final-copy/after-mobile-dark-viewport.png' });
  await page.getByLabel('Escolher tema').click();
  await page.getByRole('button', { name: 'Claro', exact: true }).click();
  await page.setViewportSize({ width: 1366, height: 768 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await technicalDetails.screenshot({ path: 'docs/web-pwa/screenshots/final-copy/after-desktop-light.png' });
  await technicalDetails.locator(':scope > summary').scrollIntoViewIfNeeded();
  await page.screenshot({ path: 'docs/web-pwa/screenshots/final-copy/after-desktop-light-viewport.png' });
  const axe = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
  await page
    .getByRole("button", { name: "Copiar resumo", exact: true })
    .click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toContain(
    "atelierdrahaiter.com.br",
  );
  await page.getByRole("button", { name: "Verificar outro site" }).click();
  await expect(page.getByLabel("Endereço da loja")).toBeFocused();
  await page
    .getByRole("button", { name: /atelierdrahaiter.com.br.*A consulta salva/ })
    .click();
  await expect(page.getByText(/Este é um resumo salvo/)).toBeVisible();
  await page.getByRole("button", { name: "Limpar histórico" }).click();
  await expect(
    page.getByText("Histórico limpo neste navegador."),
  ).toBeVisible();
});

test("offline shell without storing scan responses in Cache Storage", async ({
  page,
  context,
}) => {
  const network = await context.newCDPSession(page);
  const setOffline = async (offline: boolean) => {
    await context.setOffline(offline);
    await network.send('Network.overrideNetworkState', {
      offline, latency: 0, downloadThroughput: -1, uploadThroughput: -1,
    });
  };
  await page.goto("/");
  await page.evaluate(() => navigator.serviceWorker.ready);
  await page.reload();
  const cached = await page.evaluate(async () => {
    const keys = await caches.keys();
    const paths: string[] = [];
    for (const key of keys) {
      const cache = await caches.open(key);
      paths.push(
        ...(await cache.keys()).map((request) => new URL(request.url).pathname),
      );
    }
    return paths;
  });
  expect(
    cached.some((path) => path.startsWith("/family/") || path === "/health"),
  ).toBe(false);
  try {
    await setOffline(true);
    await page.reload();
    // Chromium may lose the emulated navigator state on the new document
    // even while transport remains blocked; reinforce the native state.
    await setOffline(true);
    await expect.poll(() => page.evaluate(() => navigator.onLine)).toBe(false);
    await expect(page.getByText('Você está offline', { exact: true })).toBeVisible();
    await expect(page.getByText('O EDY ScanURL Family pode abrir sem internet, mas uma conexão é necessária para verificar novos sites.', { exact: false })).toBeVisible();
    await page.getByLabel('Endereço da loja').fill('example.com');
    await page.getByRole('button', { name: 'Verificar site', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('Você está sem conexão');
    await expect(page.locator('.results')).toHaveCount(0);
  } finally {
    await setOffline(false);
    await network.detach();
  }
  await expect(page.getByText('Você está offline', { exact: true })).not.toBeVisible();
  await page.getByRole('button', { name: 'Tentar novamente', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'example.com', exact: true })).toBeVisible({ timeout: 40_000 });
});
