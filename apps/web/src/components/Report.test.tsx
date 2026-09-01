import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDemoReport } from '../demo/fixtures';
import { localizeReport } from '../demo/localize';
import { getCopy } from '../lib/i18n';
import { DecisionReportV4 } from './DecisionReportV4';

describe('Report', () => {
  afterEach(() => { cleanup(); Object.defineProperty(navigator, 'share', { configurable: true, value: undefined }); });

  it('localizes technical labels in Portuguese and English', () => {
    const report = createDemoReport('https://localization.example', 'trusted');
    const { rerender } = render(<DecisionReportV4 report={report} copy={getCopy('pt-BR')} locale="pt-BR" onBack={vi.fn()} onRescan={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Técnico' }));
    fireEvent.click(screen.getByRole('button', { name: 'Domínio' }));
    expect(screen.getAllByRole('heading', { name: 'Domínio' }).length).toBeGreaterThan(0);
    expect(screen.getByText('Idade observada')).not.toBeNull();

    rerender(<DecisionReportV4 report={report} copy={getCopy('en')} locale="en" onBack={vi.fn()} onRescan={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Domain' }));
    expect(screen.getAllByRole('heading', { name: 'Domain' }).length).toBeGreaterThan(0);
    expect(screen.getByText('Observed age')).not.toBeNull();
  });

  it('renders an unassessed zero-weight area without NaN or a misleading 0/0', () => {
    const report = createDemoReport('https://zero-weight.example', 'trusted');
    report.scoreAreas[0] = { ...report.scoreAreas[0], score: 0, max: 0, coverage: 0 };
    const { container } = render(<DecisionReportV4 report={report} copy={getCopy('pt-BR')} locale="pt-BR" onBack={vi.fn()} onRescan={vi.fn()} />);
    const firstArea = container.querySelector('.score-table > div');
    expect(firstArea?.textContent).toContain('—');
    expect(firstArea?.textContent).not.toContain('0/0');
    expect(container.innerHTML).not.toContain('NaN');
  });

  it('keeps unknown and not checked states explicit and non-positive', () => {
    const report = createDemoReport('https://limited.example', 'insufficient');
    render(<DecisionReportV4 report={report} copy={getCopy('pt-BR')} locale="pt-BR" onBack={vi.fn()} onRescan={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Verificações' }));
    expect(screen.getAllByText('Desconhecido').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Não consultado').length).toBeGreaterThan(0);
  });

  it('places insufficient coverage before the verified ledger on mobile-friendly markup', () => {
    const report = createDemoReport('https://limited.example', 'insufficient');
    const { container } = render(<DecisionReportV4 report={report} copy={getCopy('pt-BR')} locale="pt-BR" onBack={vi.fn()} onRescan={vi.fn()} />);
    const metrics = container.querySelector('.decision-metrics');
    const ledger = container.querySelector('.insufficient-state');
    expect(metrics).not.toBeNull();
    expect(ledger).not.toBeNull();
    expect(metrics && ledger ? metrics.compareDocumentPosition(ledger) & 4 : 0).toBe(4);
    expect(screen.getByText('Nenhum sinal confirmado')).not.toBeNull();
  });

  it('groups localized English evidence without losing business, security or commerce', () => {
    const report = localizeReport(createDemoReport('https://grouping.example', 'confirmed-phishing'), 'en');
    render(<DecisionReportV4 report={report} copy={getCopy('en')} locale="en" onBack={vi.fn()} onRescan={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Checks' }));
    expect(screen.getByRole('heading', { name: 'Business' })).not.toBeNull();
    expect(screen.getByRole('heading', { name: 'Security' })).not.toBeNull();
    expect(screen.getByRole('heading', { name: 'Commerce' })).not.toBeNull();
  });

  it('does not truncate a warning behind positive checks in a BUY summary', () => {
    const report = createDemoReport('https://warning-priority.example', 'trusted');
    report.checks.splice(5, 0,
      { ...report.checks[0], id: 'extra-pass-1', title: 'Sinal positivo extra um' },
      { ...report.checks[1], id: 'extra-pass-2', title: 'Sinal positivo extra dois' },
    );
    render(<DecisionReportV4 report={report} copy={getCopy('pt-BR')} locale="pt-BR" onBack={vi.fn()} onRescan={vi.fn()} />);
    expect(document.querySelector('.priority-reasons > ol .check-status')?.textContent).toContain('Verificado');
    expect(screen.getByRole('heading', { name: 'Reclamações recentes sobre atraso' })).not.toBeNull();
    expect(screen.getByText('Atenção residual')).not.toBeNull();
  });

  it('never truncates a critical finding behind positive checks in a BUY summary', () => {
    const report = createDemoReport('https://critical-priority.example', 'trusted');
    report.checks.push({
      ...report.checks[0],
      id: 'late-critical',
      title: 'Sinal crítico tardio',
      description: 'Uma inconsistência upstream não pode ocultar este risco.',
      impact: 'critical',
      status: 'CRITICAL',
    });
    render(<DecisionReportV4 report={report} copy={getCopy('pt-BR')} locale="pt-BR" onBack={vi.fn()} onRescan={vi.fn()} />);
    expect(screen.getByRole('heading', { name: 'Sinal crítico tardio' })).not.toBeNull();
  });

  it('derives check filter counts from explicit statuses and filters without color inference', () => {
    const report = createDemoReport('https://filters.example', 'confirmed-phishing');
    render(<DecisionReportV4 report={report} copy={getCopy('pt-BR')} locale="pt-BR" onBack={vi.fn()} onRescan={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Verificações' }));
    const criticalCount = report.checks.filter((item) => item.status === 'CRITICAL').length;
    const filter = screen.getByRole('button', { name: `Críticas ${String(criticalCount)}` });
    fireEvent.click(filter);
    expect(filter.getAttribute('aria-pressed')).toBe('true');
    expect(document.querySelectorAll('.check-record').length).toBe(criticalCount);
  });

  it('fully localizes real report content and unavailable source freshness in English', () => {
    const report = createDemoReport('https://real-localization.example', 'insufficient');
    report.mode = 'real';
    report.summary = 'Não foi possível obter evidências suficientes para recomendar esta compra.';
    report.recommendation = 'Evite pagamentos irreversíveis até confirmar a identidade da empresa por outras fontes.';
    report.checks[0] = { ...report.checks[0], id: 'DOMAIN_AGE', category: 'DOMAIN', title: 'Idade do domínio', description: 'NO_USABLE_EVIDENCE', value: '0 evidência(s)' };
    report.sources[0] = { ...report.sources[0], name: 'RDAP autoritativo', category: 'DOMAIN', status: 'unavailable', collectedAt: undefined };
    const localized = localizeReport(report, 'en');
    render(<DecisionReportV4 report={localized} copy={getCopy('en')} locale="en" onBack={vi.fn()} onRescan={vi.fn()} />);
    expect(screen.getByText(/not enough evidence/i)).not.toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Checks' }));
    expect(screen.getAllByText('Domain age').length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: 'Sources' }));
    expect(screen.getByText('Authoritative RDAP')).not.toBeNull();
    expect(screen.getByText('Not queried')).not.toBeNull();
  });

  it('keeps accessible action names and copies when native share rejects', async () => {
    const share = vi.fn().mockRejectedValue(new DOMException('denied', 'NotAllowedError'));
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'share', { configurable: true, value: share });
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    const report = createDemoReport('https://share.example', 'insufficient');
    render(<DecisionReportV4 report={report} copy={getCopy('pt-BR')} locale="pt-BR" onBack={vi.fn()} onRescan={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Copiar resumo' })).not.toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Compartilhar' }));
    await vi.waitFor(() => expect(writeText).toHaveBeenCalled());
  });

  it('renders only actual VirusTotal counts and keeps the engine matrix collapsed by default', () => {
    const report = createDemoReport('https://vt-ui.example', 'insufficient');
    report.technical.virusTotal = {
      state: 'AVAILABLE',
      reason: '1 suspicious detection; this does not replace the EDY verdict.',
      collectedAt: '2026-08-30T12:00:00Z',
      registrationCorrelation: 'MATCH',
      domain: {
        state: 'AVAILABLE', cache: 'MISS', freshness: 'FRESH', lastAnalysisAt: '2026-08-30T11:00:00Z',
        stats: { malicious: 0, suspicious: 1, harmless: 7, undetected: 55, timeout: 0, other: 0, total: 63 },
        engines: [{ engine: 'Synthetic Vendor', category: 'suspicious', result: 'phishing' }],
        reputation: -2, communityVotes: { harmless: 3, malicious: 1 }, categories: [{ source: 'Synthetic taxonomy', label: 'shopping' }],
      },
      url: { state: 'NO_DATA', cache: 'MISS' },
    };
    render(<DecisionReportV4 report={report} copy={getCopy('pt-BR')} locale="pt-BR" onBack={vi.fn()} onRescan={vi.fn()} />);
    expect(screen.getByText('Consultado')).not.toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Técnico' }));
    fireEvent.click(screen.getByRole('button', { name: 'VirusTotal' }));
    expect(screen.getByText(/0 maliciosa · 1 suspeita · 7 inofensiva · 55 não detectada/)).not.toBeNull();
    const details = screen.getByText('Exibir resultados das engines (1)').closest('details');
    expect(details?.hasAttribute('open')).toBe(false);
    fireEvent.click(screen.getByText('Exibir resultados das engines (1)'));
    expect(screen.getByText('Synthetic Vendor')).not.toBeNull();
  });
});
