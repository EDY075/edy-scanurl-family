import { afterEach, describe, expect, it, vi } from 'vitest';
import * as matchers from '@testing-library/jest-dom/matchers';
import { act, cleanup, render, renderHook, screen, within } from '@testing-library/react';
import type { Check, ScanReport } from '../../types';
import { analysisCoverage, humanSignals, riskLevel } from './decision';
import { resultEvidence } from './evidence';
import { resultSnapshot, sanitizeHistory, savedRisk, savedSummary, useLocalHistory } from './history';
import { Results, shareText } from './results';

expect.extend(matchers);

// Synthetic data belongs only to this test file, never to the runtime scanner.
function check(id: string, status: Check['status'], impact: Check['impact'] = 'neutral'): Check {
  return { id, status, impact, title: `Verificação ${id}`, description: `Observação de teste ${id}`,
    category: 'domain', points: 0, sourceId: 'test-source' };
}

function report(checks: Check[]): ScanReport {
  return {
    id: 'test-only-risk-coverage', mode: 'real', inputUrl: 'https://shop.example.com/',
    normalizedUrl: 'https://shop.example.com/', domain: 'shop.example.com',
    scannedAt: new Date().toISOString(), verdict: 'INSUFFICIENT_DATA', score: null,
    confidence: 'LOW', coverage: 30, summary: 'Synthetic test only', recommendation: 'Synthetic test only',
    scoreAreas: [], checks,
    sources: [{ id: 'test-source', name: 'Fonte sintética de teste', category: 'domain', tier: 1, status: 'available' }],
    technical: { domainAge: '', registrar: '', dns: [], tls: '', tlsIssuer: '', redirects: [], headers: [],
      threatStatus: '', salesVolume: '', paymentSignals: [], decisionCoverage: 30 },
  };
}

function missingReport(): ScanReport {
  const input = report([
    check('KNOWN', 'PASS', 'positive'),
    ...Array.from({ length: 7 }, (_, index) => check(`MISSING_${String(index)}`, 'UNKNOWN')),
    check('UNEXECUTED', 'NOT_CHECKED'),
    { ...check('OFFLINE_SOURCE', 'UNKNOWN'), sourceId: 'unavailable-source' },
  ]);
  input.sources.push({ id: 'unavailable-source', name: 'Fonte indisponível de teste', category: 'domain', tier: 2, status: 'unavailable' });
  return input;
}

afterEach(() => {
  cleanup();
  localStorage.clear();
});

describe('risk and coverage have independent evidence semantics', () => {
  it.each(['UNKNOWN', 'NOT_CHECKED', 'NOT_APPLICABLE'] as const)(
    'keeps neutral %s out of warning and failure buckets', status => {
      const input = report([check('NEUTRAL', status)]);
      const signals = humanSignals(input);
      expect(signals.attention).toHaveLength(0);
      expect(signals.risks).toHaveLength(0);
      expect(signals.positive).toHaveLength(0);
      expect(signals.missing).toHaveLength(1);
      expect(resultEvidence(input)[0].state).not.toMatch(/WARNING|FAIL/);
      expect(riskLevel(input)).toBe('UNDETERMINED');
    },
  );

  it('treats an unavailable source as missing evidence, not failure', () => {
    const input = report([check('SOURCE_MISSING', 'UNKNOWN')]);
    input.sources[0].status = 'unavailable';
    expect(resultEvidence(input)[0].state).toBe('UNAVAILABLE');
    const signals = humanSignals(input);
    expect(signals.missing).toHaveLength(1);
    expect(signals.attention).toHaveLength(0);
    expect(signals.risks).toHaveLength(0);
    expect(riskLevel(input)).toBe('UNDETERMINED');
  });

  it('does not turn an uncorroborated positive into either a positive or a risk', () => {
    const input = report([check('UNSUPPORTED_PASS', 'PASS', 'positive')]);
    input.sources[0].status = 'unavailable';
    const signals = humanSignals(input);
    expect(signals.positive).toHaveLength(0);
    expect(signals.missing[0].state).toBe('UNAVAILABLE');
    expect(signals.attention).toHaveLength(0);
    expect(signals.risks).toHaveLength(0);
  });

  it('renders partial analysis with no invented moderate risk when many checks lack data', () => {
    const input = missingReport();
    expect(riskLevel(input)).toBe('UNDETERMINED');
    expect(analysisCoverage(input)).toBe('PARTIAL');
    const signals = humanSignals(input);
    expect(signals.missing).toHaveLength(9);
    expect(signals.positive).toHaveLength(1);
    expect(signals.attention).toHaveLength(0);
    expect(signals.risks).toHaveLength(0);
    const { container } = render(<Results report={input} saved={null} reset={vi.fn()} />);
    expect(screen.getByText('ANÁLISE PARCIAL')).toBeInTheDocument();
    expect(screen.getByText('Nenhuma evidência negativa relevante foi encontrada nas verificações concluídas.')).toBeInTheDocument();
    expect(screen.queryByText('RISCO MODERADO')).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Pontos de atenção reais' })).not.toBeInTheDocument();
    expect(container.querySelector('.results')).toHaveClass('partial');
    expect(container.querySelector('.attention-count')).toBeNull();
    expect(container.querySelector('.risk-count')).toBeNull();
    expect(screen.getByText('Nenhum indício negativo encontrado')).toBeInTheDocument();
    expect(screen.getByText('Parcial', { exact: true })).toBeInTheDocument();
    const missingDisclosure = screen.getByText('Ver quais ficaram sem dados (9)').closest('details');
    expect(missingDisclosure).not.toBeNull();
    expect(missingDisclosure).not.toHaveAttribute('open');
    expect(within(missingDisclosure as HTMLElement).getByText('Veja o motivo de cada item. Esses limites não são alertas contra a loja.')).toBeInTheDocument();
    expect(within(missingDisclosure as HTMLElement).getAllByText('Motivo:')).toHaveLength(9);
  });

  it('labels conclusion strength without presenting coverage as site safety', () => {
    const input = missingReport();
    input.coverage = 61.54;
    input.technical.decisionCoverage = 25;
    const { container } = render(<Results report={input} saved={null} reset={vi.fn()} />);
    const technicalDetails = container.querySelector('.technical-details');
    expect(technicalDetails).not.toBeNull();
    const details = within(technicalDetails as HTMLElement);
    expect(details.getByText('Força da conclusão')).toBeInTheDocument();
    expect(details.getByText('Baixa')).toBeInTheDocument();
    expect(details.getByText('Ainda faltam verificações importantes para uma conclusão mais forte.')).toBeInTheDocument();
    expect(details.queryByText('Confiança da análise')).not.toBeInTheDocument();
    expect(details.getByText('Verificações com informação')).toBeInTheDocument();
    expect(details.getByText('61.54%')).toBeInTheDocument();
    expect(details.getByText('Cobertura ponderada da decisão')).toBeInTheDocument();
    expect(details.getByText('25%')).toBeInTheDocument();
    expect(details.getByText('Considera a importância das verificações disponíveis para a decisão final.')).toBeInTheDocument();
    expect(details.getByText('Pontuação dos sinais')).toBeInTheDocument();
    expect(details.getByText('Não publicada: cobertura insuficiente')).toBeInTheDocument();
    expect(details.getByText('Esses percentuais medem apenas a disponibilidade das verificações. Não representam porcentagem de segurança, chance de fraude nem confiabilidade da empresa.')).toBeInTheDocument();
  });

  it.each([
    ['MEDIUM', 'Moderada'],
    ['HIGH', 'Alta'],
    ['VERY_HIGH', 'Alta'],
  ] as const)('uses one of the three approved conclusion-strength states for %s', (confidence, label) => {
    const input = report([check('CONFIRMED', 'PASS', 'positive')]);
    input.confidence = confidence;
    const { container } = render(<Results report={input} saved={null} reset={vi.fn()} />);
    const technicalDetails = container.querySelector('.technical-details');
    expect(technicalDetails).not.toBeNull();
    const details = within(technicalDetails as HTMLElement);
    expect(details.getByText('Força da conclusão')).toBeInTheDocument();
    expect(details.getByText(label)).toBeInTheDocument();
    expect(details.queryByText('Ainda faltam verificações importantes para uma conclusão mais forte.')).not.toBeInTheDocument();
  });

  it('counts positives, actual warnings, failures and missing checks separately', () => {
    const input = report([
      check('PASS_A', 'PASS', 'positive'), check('PASS_B', 'PASS', 'positive'),
      check('WARNING_A', 'WARNING', 'warning'), check('WARNING_B', 'WARNING', 'warning'),
      check('FAIL_A', 'FAIL', 'negative'), check('UNKNOWN_A', 'UNKNOWN'),
      check('UNCHECKED_A', 'NOT_CHECKED'), check('UNKNOWN_B', 'UNKNOWN'),
    ]);
    const signals = humanSignals(input);
    expect([signals.positive.length, signals.attention.length, signals.risks.length, signals.missing.length]).toEqual([2, 2, 1, 3]);
    expect(new Set([...signals.positive, ...signals.attention, ...signals.risks, ...signals.missing].map(item => item.id)).size).toBe(8);
    render(<Results report={input} saved={null} reset={vi.fn()} />);
    const counts = within(screen.getByRole('list', { name: 'Resumo das evidências' }));
    expect(counts.getAllByRole('listitem').map(item => item.textContent)).toEqual([
      '2 sinais positivos', '2 pontos de atenção reais', '1 risco encontrado', '3 verificações sem dados suficientes',
    ]);
  });

  it.each([
    ['FAIL', 'negative', 'HIGH', 'RISCO ALTO', 'Alto'],
    ['WARNING', 'warning', 'MODERATE', 'RISCO MODERADO', 'Pontos de atenção encontrados'],
  ] as const)('preserves actual %s while independently showing partial coverage', (status, impact, level, label, observed) => {
    const input = missingReport();
    input.checks.push(check('ACTUAL_FINDING', status, impact));
    expect(riskLevel(input)).toBe(level);
    expect(analysisCoverage(input)).toBe('PARTIAL');
    render(<Results report={input} saved={null} reset={vi.fn()} />);
    expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByText(observed)).toBeInTheDocument();
    expect(screen.getByText('Parcial', { exact: true })).toBeInTheDocument();
  });

  it('does not promote divergent duplicate UNKNOWN observations into WARNING', () => {
    const first = check('DUPLICATE_UNKNOWN', 'UNKNOWN');
    const input = report([first, { ...first, description: 'Outra observação incompleta' }]);
    const evidence = resultEvidence(input);
    expect(evidence).toHaveLength(1);
    expect(evidence[0].state).toBe('INFO');
    expect(evidence[0].details.join(' ')).toContain('observações conflitantes');
    expect(humanSignals(input).missing).toHaveLength(1);
    expect(humanSignals(input).attention).toHaveLength(0);
    expect(humanSignals(input).risks).toHaveLength(0);
    expect(riskLevel(input)).toBe('UNDETERMINED');
  });

  it('treats a PASS contradicted by a neutral duplicate as unconfirmed, not warning', () => {
    const input = report([check('CONFLICT', 'PASS', 'positive'), check('CONFLICT', 'UNKNOWN')]);
    expect(resultEvidence(input)[0].state).toBe('INFO');
    expect(humanSignals(input).positive).toHaveLength(0);
    expect(humanSignals(input).missing).toHaveLength(1);
    expect(humanSignals(input).attention).toHaveLength(0);
    expect(riskLevel(input)).toBe('UNDETERMINED');
  });

  it.each([
    ['UNKNOWN', 'neutral', 'UNDETERMINED', 'ANÁLISE PARCIAL'],
    ['WARNING', 'warning', 'MODERATE', 'RISCO MODERADO'],
    ['FAIL', 'negative', 'HIGH', 'RISCO ALTO'],
  ] as const)('preserves %s semantics through snapshot, JSON history, reopening and share text', (status, impact, level, label) => {
    const input = missingReport();
    input.checks.push(check('FINDING', status, impact));
    const snapshot = resultSnapshot(input);
    const restored = sanitizeHistory(JSON.parse(JSON.stringify([snapshot])) as unknown)[0];
    expect(restored.risk).toBe(level);
    expect(savedRisk(restored)).toBe(level);
    expect(restored.analysisCoverage).toBe('PARTIAL');
    expect(shareText(restored)).toBe(shareText(snapshot));
    expect(shareText(restored)).toContain(label);
    expect(shareText(restored)).toContain('Cobertura da análise:\nParcial');
    if (level === 'UNDETERMINED') {
      expect(savedSummary(restored).tone).toBe('partial');
      expect(shareText(restored)).toContain('Sem conclusão de risco');
      expect(shareText(restored)).not.toMatch(/RISCO MODERADO|RISCO BAIXO|RISCO ALTO/);
    }
    render(<Results report={null} saved={restored} reset={vi.fn()} />);
    expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByText('Parcial', { exact: true })).toBeInTheDocument();
    expect(screen.getByText(/Este é um resumo salvo, não uma consulta atual/)).toBeInTheDocument();
  });

  it('persists and reloads undetermined risk independently from partial coverage in local history', () => {
    localStorage.setItem('edy-web-history-enabled', 'true');
    const first = renderHook(() => useLocalHistory());
    act(() => { first.result.current.add(missingReport()); });
    expect(first.result.current.items[0].risk).toBe('UNDETERMINED');
    first.unmount();
    const reopened = renderHook(() => useLocalHistory());
    expect(reopened.result.current.items).toHaveLength(1);
    expect(reopened.result.current.items[0].risk).toBe('UNDETERMINED');
    expect(reopened.result.current.items[0].analysisCoverage).toBe('PARTIAL');
    expect(shareText(reopened.result.current.items[0])).not.toContain('RISCO MODERADO');
  });

  it('does not revive the old incomplete MODERATE fallback as an actual warning', () => {
    const legacy = { ...resultSnapshot(missingReport()), risk: 'MODERATE' as const };
    delete legacy.analysisCoverage;
    const restored = sanitizeHistory([legacy])[0];
    expect(savedRisk(restored)).toBe('UNDETERMINED');
    expect(savedSummary(restored).tone).toBe('partial');
    expect(shareText(restored)).toContain('ANÁLISE PARCIAL');
    expect(shareText(restored)).not.toContain('RISCO MODERADO');
  });

  it('does not downgrade full coverage because real negative evidence lowered confidence', () => {
    const input = report([check('CONFIRMED_FAILURE', 'FAIL', 'negative')]);
    input.verdict = 'DO_NOT_BUY';
    input.confidence = 'MEDIUM';
    input.coverage = 100;
    input.technical.decisionCoverage = 100;
    expect(riskLevel(input)).toBe('HIGH');
    expect(humanSignals(input).missing).toHaveLength(0);
    expect(analysisCoverage(input)).toBe('SUFFICIENT');
  });

  it('keeps LOW observed risk independent from a missing nameserver check', () => {
    const input = report([check('DOMAIN_DNS', 'PASS', 'positive'), check('DOMAIN_NAMESERVERS', 'UNKNOWN')]);
    input.verdict = 'BUY';
    input.score = 95;
    input.confidence = 'HIGH';
    input.coverage = 90;
    input.technical.decisionCoverage = 95;
    expect(riskLevel(input)).toBe('LOW');
    expect(analysisCoverage(input)).toBe('PARTIAL');
    expect(resultSnapshot(input)).toMatchObject({ risk: 'LOW', analysisCoverage: 'PARTIAL' });
    render(<Results report={input} saved={null} reset={vi.fn()} />);
    expect(screen.getByText('RISCO BAIXO')).toBeInTheDocument();
    expect(screen.getByText('Parcial', { exact: true })).toBeInTheDocument();
  });

  it('labels sufficient but undetermined analysis consistently in live, saved and shared results', () => {
    const input = report([check('DOMAIN_DNS', 'PASS', 'positive')]);
    input.verdict = 'CAUTION';
    input.score = 75;
    input.confidence = 'HIGH';
    input.coverage = 100;
    input.technical.decisionCoverage = 100;
    expect(riskLevel(input)).toBe('UNDETERMINED');
    expect(analysisCoverage(input)).toBe('SUFFICIENT');
    const view = render(<Results report={input} saved={null} reset={vi.fn()} />);
    expect(screen.getByText('ANÁLISE INCONCLUSIVA')).toBeInTheDocument();
    expect(screen.queryByText('ANÁLISE PARCIAL')).not.toBeInTheDocument();
    const restored = sanitizeHistory(JSON.parse(JSON.stringify([resultSnapshot(input)])) as unknown)[0];
    expect(restored).toMatchObject({ risk: 'UNDETERMINED', analysisCoverage: 'SUFFICIENT' });
    view.rerender(<Results report={null} saved={restored} reset={vi.fn()} />);
    expect(screen.getByText('ANÁLISE INCONCLUSIVA')).toBeInTheDocument();
    expect(shareText(restored)).toContain('ANÁLISE INCONCLUSIVA');
    expect(shareText(restored)).toContain('Cobertura da análise:\nSuficiente');
    expect(shareText(restored)).not.toContain('ANÁLISE PARCIAL');
  });
});
