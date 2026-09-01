import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as matchers from '@testing-library/jest-dom/matchers';
import type { ScanReport } from '../types';
import { FamilyApp } from './FamilyApp';
import { FAMILY_HISTORY_ENABLED_KEY, FAMILY_HISTORY_KEY, FAMILY_THEME_KEY } from './family-presentation';

expect.extend(matchers);

// All service results in this file are explicitly synthetic test-only fixtures.
const client = vi.hoisted(() => ({ requestFamilyScan: vi.fn(), getFamilyAvailability: vi.fn(), readPastedLink: vi.fn(), takeSharedLink: vi.fn(), onSharedLink: vi.fn() }));
vi.mock('./family-client', () => client);

function testReport(): ScanReport {
  return { id: 'test-only', mode: 'real', inputUrl: 'https://loja.example/pedido?segredo=1', normalizedUrl: 'https://loja.example/', domain: 'loja.example', scannedAt: new Date().toISOString(), verdict: 'INSUFFICIENT_DATA', score: null, confidence: 'LOW', coverage: 30, summary: 'TEST ONLY', recommendation: 'TEST ONLY', checks: [], scoreAreas: [], sources: [], technical: { domainAge: '', registrar: '', dns: [], tls: '', tlsIssuer: '', redirects: [], headers: [], threatStatus: '', salesVolume: '', paymentSignals: [] } };
}

describe('FamilyApp — mocked services only in tests', () => {
  beforeEach(() => {
    vi.resetAllMocks(); localStorage.clear();
    client.getFamilyAvailability.mockResolvedValue({ state: 'READY' });
    client.takeSharedLink.mockResolvedValue('');
    client.readPastedLink.mockResolvedValue('https://loja.example');
    client.onSharedLink.mockReturnValue(() => undefined);
    client.requestFamilyScan.mockResolvedValue(testReport());
    vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => { callback(0); return 0; });
    vi.stubGlobal('matchMedia', vi.fn().mockImplementation(() => ({ matches: false, media: '(prefers-color-scheme: dark)', addEventListener: vi.fn(), removeEventListener: vi.fn() })));
  });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
  async function ready() { render(<FamilyApp />); await waitFor(() => expect(screen.getByRole('button', { name: 'Verificar site' })).not.toBeDisabled()); }
  async function runScan() { fireEvent.change(screen.getByLabelText('Endereço da loja'), { target: { value: 'https://loja.example/pedido?segredo=1' } }); fireEvent.click(screen.getByRole('button', { name: 'Verificar site' })); await screen.findByRole('heading', { level: 1, name: 'Atenção' }); }

  it('shows a clean home, with local history off by default', async () => {
    await ready();
    expect(screen.getByLabelText('Endereço da loja')).toHaveValue('');
    expect(screen.getByLabelText('Guardar histórico neste aparelho')).not.toBeChecked();
    expect(document.body.textContent).not.toMatch(/Tailscale|backend|Motor de análise|Demo|porta 8787/);
    expect(client.requestFamilyScan).not.toHaveBeenCalled();
    expect(localStorage.getItem(FAMILY_HISTORY_KEY)).toBeNull();
  });
  it('starts dark and persists light or system theme choices from the visible header control', async () => {
    await ready();
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(localStorage.getItem(FAMILY_THEME_KEY)).toBe('dark');
    fireEvent.click(screen.getByRole('button', { name: 'Tema' }));
    fireEvent.click(screen.getByLabelText('Claro'));
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(localStorage.getItem(FAMILY_THEME_KEY)).toBe('light');
    fireEvent.click(screen.getByLabelText('Usar tema do sistema'));
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(localStorage.getItem(FAMILY_THEME_KEY)).toBe('system');
  });
  it('pastes a WhatsApp message without starting a scan', async () => {
    client.readPastedLink.mockResolvedValue('Veja esta loja: https://loja.example/oferta. Obrigada!');
    await ready(); fireEvent.click(screen.getByRole('button', { name: 'Colar link copiado' }));
    await waitFor(() => expect(screen.getByLabelText('Endereço da loja')).toHaveValue('https://loja.example/oferta'));
    expect(client.requestFamilyScan).not.toHaveBeenCalled();
  });
  it('receives both launch and later shared links without starting a scan', async () => {
    client.takeSharedLink.mockResolvedValue('https://inicio.example/');
    let receive: ((text: string) => void) | undefined;
    client.onSharedLink.mockImplementation((callback: (text: string) => void) => { receive = callback; return () => undefined; });
    await ready(); await waitFor(() => expect(screen.getByLabelText('Endereço da loja')).toHaveValue('https://inicio.example/'));
    act(() => receive?.('Olha https://depois.example/'));
    expect(screen.getByLabelText('Endereço da loja')).toHaveValue('https://depois.example/');
    expect(client.requestFamilyScan).not.toHaveBeenCalled();
  });
  it('rejects multiple pasted links with a clear explanation', async () => {
    client.readPastedLink.mockResolvedValue('https://um.example https://dois.example');
    await ready(); fireEvent.click(screen.getByRole('button', { name: 'Colar link copiado' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Há mais de um link');
    expect(client.requestFamilyScan).not.toHaveBeenCalled();
  });
  it('keeps operational failures separate from verdicts and restores focus', async () => {
    client.requestFamilyScan.mockRejectedValue(new Error('offline'));
    await ready(); fireEvent.change(screen.getByLabelText('Endereço da loja'), { target: { value: 'loja.example' } }); fireEvent.click(screen.getByRole('button', { name: 'Verificar site' }));
    const error = await screen.findByRole('alert'); expect(error).toHaveTextContent('Confira sua internet');
    expect(screen.queryByRole('heading', { level: 1, name: 'Alto risco' })).toBeNull();
    await waitFor(() => expect(error).toHaveFocus());
  });
  it('does not save a result when history was not enabled', async () => {
    await ready(); await runScan();
    expect(localStorage.getItem(FAMILY_HISTORY_KEY)).toBeNull();
    expect(screen.getByRole('heading', { level: 1, name: 'Atenção' })).toHaveFocus();
    expect(screen.getByText(/Não há informações suficientes/)).toBeVisible();
    const result = screen.getByRole('heading', { level: 1, name: 'Atenção' }).closest('section');
    const reasons = screen.getByRole('heading', { level: 2, name: 'Por que apareceu esse resultado?' }).closest('section');
    const recommendation = screen.getByRole('heading', { level: 2, name: 'O que fazer agora' }).closest('section');
    const next = screen.getByRole('button', { name: 'Verificar outro site' });
    expect(result).not.toBeNull(); expect(reasons).not.toBeNull(); expect(recommendation).not.toBeNull();
    if (!result || !reasons || !recommendation) throw new Error('missing result hierarchy');
    expect(result.compareDocumentPosition(reasons) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(reasons.compareDocumentPosition(recommendation) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(recommendation.compareDocumentPosition(next) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText('Ver informações e fontes').closest('details')).not.toHaveAttribute('open');
  });
  it('exposes loading and queues a shared link without interrupting or starting a second scan', async () => {
    let resolveScan: ((report: ScanReport) => void) | undefined;
    let receive: ((text: string) => void) | undefined;
    client.requestFamilyScan.mockImplementation(() => new Promise<ScanReport>((resolve) => { resolveScan = resolve; }));
    client.onSharedLink.mockImplementation((callback: (text: string) => void) => { receive = callback; return () => undefined; });
    await ready(); fireEvent.change(screen.getByLabelText('Endereço da loja'), { target: { value: 'loja.example' } }); fireEvent.click(screen.getByRole('button', { name: 'Verificar site' }));
    expect(screen.getByRole('heading', { name: 'Verificando com cuidado' })).toHaveFocus();
    expect(screen.getByRole('progressbar', { name: 'Verificação em andamento' })).toBeInTheDocument();
    act(() => receive?.('https://outra.example/'));
    await act(async () => { resolveScan?.(testReport()); await Promise.resolve(); });
    expect(screen.getByRole('heading', { level: 1, name: 'Atenção' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Ver o link recebido' }));
    expect(screen.getByLabelText('Endereço da loja')).toHaveValue('https://outra.example/');
    expect(client.requestFamilyScan).toHaveBeenCalledTimes(1);
  });
  it('does not resurrect stale opt-out history', async () => {
    localStorage.setItem(FAMILY_HISTORY_KEY, JSON.stringify([{ domain: 'anterior.example', verdict: 'Confiável', time: new Date().toISOString(), report: 'private' }]));
    await ready();
    expect(localStorage.getItem(FAMILY_HISTORY_KEY)).toBeNull();
    expect(screen.getByLabelText('Guardar histórico neste aparelho')).not.toBeChecked();
  });
  it('saves only opted-in minimal history and requires a click before a repeat scan', async () => {
    await ready(); fireEvent.click(screen.getByLabelText('Guardar histórico neste aparelho')); await runScan();
    await waitFor(() => expect(localStorage.getItem(FAMILY_HISTORY_KEY)).not.toBeNull());
    const value = JSON.parse(localStorage.getItem(FAMILY_HISTORY_KEY) ?? '[]') as unknown;
    expect(value).toEqual([{ domain: 'loja.example', verdict: 'Atenção', time: expect.any(String) as unknown }]);
    expect(localStorage.getItem(FAMILY_HISTORY_KEY)).not.toMatch(/segredo|pedido|report|score|normalizedUrl/);
    fireEvent.click(screen.getByRole('button', { name: 'Preparar nova verificação de loja.example', hidden: true }));
    expect(screen.getByLabelText('Endereço da loja')).toHaveValue('loja.example');
    expect(client.requestFamilyScan).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Limpar histórico', hidden: true }));
    expect(screen.getByRole('button', { name: 'Sim, apagar histórico', hidden: true })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Sim, apagar histórico', hidden: true }));
    await waitFor(() => expect(localStorage.getItem(FAMILY_HISTORY_KEY)).toBe('[]'));
    fireEvent.click(screen.getByLabelText('Guardar histórico neste aparelho'));
    expect(localStorage.getItem(FAMILY_HISTORY_ENABLED_KEY)).toBeNull();
    expect(localStorage.getItem(FAMILY_HISTORY_KEY)).toBeNull();
  });
  it.each(['UNCONFIGURED', 'PENDING', 'REVOKED'])('never scans while access is %s', async (state) => {
    client.getFamilyAvailability.mockResolvedValue({ state, deviceId: 'public-device-code' }); render(<FamilyApp />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Conferir acesso' })).not.toBeDisabled());
    expect(screen.getByRole('button', { name: 'Verificar site' })).toBeDisabled();
    expect(client.requestFamilyScan).not.toHaveBeenCalled();
    if (state !== 'REVOKED') expect(screen.getByRole('heading', { name: 'Ainda estamos preparando o acesso da família' })).toBeInTheDocument();
  });
});
