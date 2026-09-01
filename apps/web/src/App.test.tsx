import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { createDemoReport } from './demo/fixtures';
import { requestScan } from './lib/scan-client';

vi.mock('./lib/scan-client', () => ({ requestScan: vi.fn() }));

describe('EDY ScanURL shell', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.mocked(requestScan).mockReset();
    vi.mocked(requestScan).mockResolvedValue(createDemoReport('https://history.example', 'trusted'));
  });
  afterEach(() => cleanup());

  it('starts in real mode and reveals synthetic scenarios only on request', async () => {
    const user = userEvent.setup();
    render(<App />);
    expect(screen.getByRole('heading', { name: /verifique antes de comprar/i })).not.toBeNull();
    expect(screen.getByLabelText('Endereço da loja').getAttribute('value')).toBe('');
    expect(screen.queryByText(/100% sintéticos/i)).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Experimentar demonstração' }));
    expect(screen.getByText(/100% sintéticos/i)).not.toBeNull();
    expect(screen.getByRole('button', { name: 'Loja consolidada' })).not.toBeNull();
    await user.click(screen.getByRole('button', { name: 'Voltar à análise real' }));
    expect(screen.queryByText(/100% sintéticos/i)).toBeNull();
  });

  it('switches the primary navigation to English', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: 'Idioma' }));
    expect(screen.getByRole('heading', { name: /check before you buy/i })).not.toBeNull();
    expect(screen.getAllByText('History').length).toBeGreaterThan(0);
    await user.click(screen.getAllByRole('button', { name: 'History' })[0]);
    expect(screen.getByText('My checks')).not.toBeNull();
  });

  it('shows a validation error without starting a scan', async () => {
    const user = userEvent.setup();
    render(<App />);
    const input = screen.getByLabelText('Endereço da loja');
    await user.clear(input);
    await user.type(input, 'not-a-domain');
    await user.click(screen.getByRole('button', { name: /verificar site/i }));
    expect(screen.getByRole('alert').textContent).toMatch(/endereço válido/i);
  });

  it('repeats a history scan with the stored mode instead of stale React state', async () => {
    localStorage.setItem('edy-scanurl-history-v1', JSON.stringify([{
      id: 'history-real', domain: 'history.example', scannedAt: '2026-08-30T12:00:00.000Z',
      verdict: 'INSUFFICIENT_DATA', score: null, confidence: 'LOW', mode: 'real',
    }]));
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getAllByRole('button', { name: 'Histórico' })[0]);
    await user.click(screen.getByRole('button', { name: /analisar novamente/i }));
    expect(requestScan).toHaveBeenCalledWith('https://history.example/', 'real', 'insufficient', expect.any(Function));
  });
});
