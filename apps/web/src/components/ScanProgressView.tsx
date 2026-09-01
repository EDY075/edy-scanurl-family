import { Check, Minus } from 'lucide-react';
import type { Copy } from '../lib/i18n';

export function ScanProgressView({ copy, domain, activeStep, mode }: { copy: Copy; domain: string; activeStep: number; mode: 'real' | 'demo' }) {
  const completed = Math.min(activeStep, copy.progress.length);
  return (
    <main id="main-content" className="progress-page">
      <header className="progress-heading">
        <p className="eyebrow">{mode === 'demo' ? copy.demoBadge : copy.realLabel}</p>
        <h1>{copy.progressTitle} <span>{domain}</span></h1>
        <p>{copy.progressBody}</p>
        <strong className="progress-counter" aria-live="polite">{String(completed).padStart(2, '0')} / {String(copy.progress.length).padStart(2, '0')}</strong>
      </header>
      <ol className="progress-list" aria-label={copy.progressTitle}>
        {copy.progress.map((label, index) => {
          const state = index < activeStep ? 'complete' : index === activeStep ? 'active' : 'pending';
          const stateLabel = state === 'complete' ? copy.progressComplete : state === 'active' ? copy.progressActive : copy.progressPending;
          return (
            <li key={label} className={state}>
              <span className="progress-index">{state === 'complete' ? <Check /> : state === 'active' ? <i aria-hidden="true" /> : <Minus />}</span>
              <strong>{label}</strong>
              <small>{stateLabel}</small>
            </li>
          );
        })}
      </ol>
    </main>
  );
}
