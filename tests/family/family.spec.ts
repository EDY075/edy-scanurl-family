import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { resolve } from 'node:path';
import { FamilyStore } from '../../apps/api/src/family/store';

// Browser review uses a separate local DB and generated device keys. No fixture results.
async function approveReviewDevice(page: Page) {
  if (process.env.FAMILY_WORKER_REVIEW === 'true') {
    await expect(page.getByRole('button', { name: 'Verificar site', exact: true })).toBeEnabled();
    await expect(page.locator('.family-access')).toHaveCount(0);
    return;
  }
  await expect(page.locator('.family-device-code')).toBeVisible();
  const id = (await page.locator('.family-device-code').innerText()).trim();
  expect(id).toMatch(/^[a-f0-9]{64}$/);
  const store = new FamilyStore(resolve('.runtime/review.sqlite'), Date.now, { admin: true });
  try { store.approve(id); } finally { store.close(); }
  await page.getByRole('button', { name: 'Conferir acesso' }).click();
  await expect(page.getByRole('button', { name: 'Verificar site', exact: true })).toBeEnabled();
}

test('Family home accessibility, responsive layout and no manual engine settings', async ({ page }) => {
  await page.goto('/');
  await approveReviewDevice(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => localStorage.getItem('edy-family-theme-v1'))).toBe('dark');
  await expect(page.getByLabel('Endereço da loja')).toHaveValue('');
  await expect(page.getByRole('button', { name: 'Colar link copiado' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText(/Tailscale|Motor de análise|backend|demonstração/i);
  for (const width of [320, 360, 390, 412, 768, 1280, 1920]) {
    await page.setViewportSize({ width, height: 900 });
    const dimensions = await page.evaluate(() => { const input = document.querySelector('input'); return { width: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth, font: input ? getComputedStyle(input).fontSize : '0' }; });
    expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.width + 1);
    expect(Number.parseFloat(dimensions.font)).toBeGreaterThanOrEqual(18);
  }
  const accessibility = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(accessibility.violations).toEqual([]);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: 'docs/qa/family-home-mobile-dark.png', fullPage: true });
  await page.getByRole('button', { name: 'Tema' }).click();
  await page.getByLabel('Claro').check();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  expect(await page.evaluate(() => localStorage.getItem('edy-family-theme-v1'))).toBe('light');
  await page.getByRole('button', { name: 'Concluir' }).click();
  await page.screenshot({ path: 'docs/qa/family-home-mobile-light.png', fullPage: true });
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.getByRole('button', { name: 'Tema' }).click();
  await page.getByLabel('Usar tema do sistema').check();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => localStorage.getItem('edy-family-theme-v1'))).toBe('system');
  await page.emulateMedia({ colorScheme: 'light' });
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.getByRole('button', { name: 'Concluir' }).click();
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.screenshot({ path: 'docs/qa/family-home-desktop-light.png', fullPage: true });
});

test('Real Family scan, privacy, optional history and cleanup', async ({ page }) => {
  await page.goto('/');
  await approveReviewDevice(page);
  await page.getByText('Histórico e privacidade', { exact: true }).click();
  await page.getByLabel('Guardar histórico neste aparelho').check();
  const outgoing: string[] = [];
  page.on('request', (request) => { if (request.method() === 'POST' && request.url().endsWith('/family/v1/scans')) outgoing.push(request.postData() ?? ''); });
  await page.getByLabel('Endereço da loja').fill('https://atelierdrahaiter.com.br/pedido?pedido=PRIVACY_CANARY#secret');
  await page.getByRole('button', { name: 'Verificar site', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: /Confiável|Atenção|Alto risco/ })).toBeVisible({ timeout: 60_000 });
  expect(outgoing).toEqual([JSON.stringify({ url: 'https://atelierdrahaiter.com.br/' })]);
  await expect(page.getByText(/ajuda a reduzir riscos, mas não garante/)).toBeVisible();
  const result = page.locator('.family-result');
  const reasons = page.locator('.family-reasons');
  const recommendation = page.locator('.family-recommendation');
  const next = page.getByRole('button', { name: 'Verificar outro site' });
  const positions = await Promise.all([result, reasons, recommendation, next].map(async (item) => (await item.boundingBox())?.y ?? -1));
  const [resultY = -1, reasonsY = -1, recommendationY = -1, nextY = -1] = positions;
  expect(resultY).toBeLessThan(reasonsY); expect(reasonsY).toBeLessThan(recommendationY); expect(recommendationY).toBeLessThan(nextY);
  await expect(page.locator('.family-main > .family-details:not(.family-privacy)')).not.toHaveAttribute('open', '');
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.screenshot({ path: 'docs/qa/family-real-result-mobile-dark.png', fullPage: true });
  await page.getByRole('button', { name: 'Tema' }).click();
  await page.getByLabel('Claro').check();
  await page.getByRole('button', { name: 'Concluir' }).click();
  await page.screenshot({ path: 'docs/qa/family-real-result-mobile-light.png', fullPage: true });
  await page.getByText('Ver informações e fontes', { exact: true }).click();
  if (process.env.FAMILY_WORKER_REVIEW === 'true') {
    await expect(page.getByRole('heading', { name: 'Consulta de ameaças' })).toBeVisible();
  } else {
    await expect(page.getByText(/VirusTotal não estava disponível/)).toBeVisible();
  }
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations).toEqual([]);
  const history = await page.evaluate(() => localStorage.getItem('edy-family-history-v1'));
  expect(history).toContain('atelierdrahaiter.com.br');
  expect(history).not.toMatch(/PRIVACY_CANARY|pedido|secret|report|score/);
  if (await page.locator('.family-privacy').getAttribute('open') === null) await page.getByText('Histórico e privacidade', { exact: true }).click();
  await page.getByRole('button', { name: 'Limpar histórico', exact: true }).click();
  await page.getByRole('button', { name: 'Sim, apagar histórico' }).click();
  await expect(page.getByText('Nenhuma consulta guardada.')).toBeVisible();
});
