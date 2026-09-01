import { expect, test } from '@playwright/test';

// Executable regression for a compatible Chromium runner. Browser-client
// evidence is recorded separately; do not claim this CLI ran without a receipt.
test.use({ baseURL: 'http://127.0.0.1:4182' });
test('native keyboard: Tab, Shift+Tab, Space buttons and all result summaries', async ({ page }) => {
  await page.goto('/');
  const theme = page.getByLabel('Escolher tema', { exact: true });
  await theme.press('Space');
  await expect(page.getByRole('button', { name: 'Escuro', exact: true })).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Escuro', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Claro', exact: true })).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(page.getByRole('button', { name: 'Escuro', exact: true })).toBeFocused();
  for (const name of ['Claro', 'Usar tema do sistema', 'Escuro']) {
    const button = page.getByRole('button', { name, exact: true });
    await button.press('Space'); await expect(button).toHaveAttribute('aria-pressed', 'true');
  }
  await theme.press('Space');
  await page.getByRole('textbox', { name: 'Endereço da loja' }).fill('example.com');
  await page.getByRole('button', { name: 'Limpar endereço', exact: true }).press('Space');
  await expect(page.getByRole('textbox', { name: 'Endereço da loja' })).toHaveValue('');
  await page.getByRole('textbox', { name: 'Endereço da loja' }).fill('atelierdrahaiter.com.br');
  await page.getByRole('button', { name: 'Verificar site', exact: true }).press('Space');
  await expect(page.getByRole('heading', { name: 'atelierdrahaiter.com.br', exact: true })).toBeVisible({ timeout: 40_000 });
  const technical = page.locator('summary').filter({ hasText: 'Ver detalhes técnicos' });
  await technical.press('Space');
  await expect(page.getByRole('heading', { name: 'Detalhes técnicos da análise' })).toBeVisible();
  for (const summary of await page.locator('details.evidence-item > summary').all()) {
    await summary.press('Space'); await expect(summary.locator('..')).toHaveAttribute('open', '');
    await summary.press('Space'); await expect(summary.locator('..')).not.toHaveAttribute('open');
  }
  await technical.press('Space');
  await expect(page.getByRole('heading', { name: 'Detalhes técnicos da análise' })).not.toBeVisible();
  await page.getByRole('button', { name: 'Verificar outro site', exact: true }).press('Space');
  await expect(page.getByRole('textbox', { name: 'Endereço da loja' })).toBeFocused();
});
