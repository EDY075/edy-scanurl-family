import { ArrowRight, FlaskConical, LockKeyhole, Search, ShieldCheck, X } from 'lucide-react';
import type { Copy } from '../lib/i18n';
import { demoScenarios } from '../demo/fixtures';
import type { DemoScenarioId, ScanMode } from '../types';

interface HomeProps {
  copy: Copy;
  url: string;
  error: string;
  mode: ScanMode;
  scenario: DemoScenarioId;
  onUrlChange: (value: string) => void;
  onModeChange: (mode: ScanMode) => void;
  onScenarioChange: (scenarioId: DemoScenarioId, domain: string) => void;
  onSubmit: () => void;
}

export function Home({ copy, url, error, mode, scenario, onUrlChange, onModeChange, onScenarioChange, onSubmit }: HomeProps) {
  return (
    <main id="main-content" className="home">
      <section className="product-entry">
        <div className="product-intro">
          <p className="eyebrow">{copy.heroEyebrow}</p>
          <h1>{copy.heroTitle}</h1>
          <p className="hero-lead">{copy.heroBody}</p>
        </div>

        <div className="home-trust-orbit" aria-hidden="true">
          <svg viewBox="0 0 360 360" focusable="false">
            <circle className="orbit-ring orbit-ring-outer" cx="180" cy="180" r="132" />
            <circle className="orbit-ring orbit-ring-middle" cx="180" cy="180" r="94" />
            <circle className="orbit-ring orbit-ring-inner" cx="180" cy="180" r="56" />
            <circle className="orbit-node" cx="180" cy="48" r="4" />
            <circle className="orbit-node" cx="292" cy="110" r="4" />
            <circle className="orbit-node" cx="300" cy="236" r="4" />
            <circle className="orbit-node" cx="94" cy="282" r="4" />
            <circle className="orbit-node" cx="54" cy="158" r="4" />
            <g className="orbit-official-mark" transform="translate(153 153) scale(.56)">
              <path className="official-concept04" d="M74 69C65 80 48 83 34 75C18 66 16 44 29 29C41 15 64 14 78 29L52 57Q50 60 47 58L40 51" />
            </g>
          </svg>
        </div>

        <div className="scan-composer">
          <label htmlFor="store-url">{copy.inputLabel}</label>
          <div className={`url-field ${error ? 'field-error' : ''}`}>
            <LockKeyhole size={18} aria-hidden="true" />
            <input id="store-url" inputMode="url" autoComplete="url" autoCapitalize="none" autoCorrect="off" spellCheck={false} enterKeyHint="go" value={url} onChange={(event) => onUrlChange(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && onSubmit()} placeholder={copy.inputPlaceholder} aria-describedby={error ? 'url-error' : 'privacy-note'} aria-invalid={Boolean(error)} />
            <button type="button" onClick={onSubmit}><Search size={19} /> <span>{copy.scan}</span><ArrowRight size={18} /></button>
          </div>
          {error ? <p className="input-error" id="url-error" role="alert">{error}</p> : <p className="field-note" id="privacy-note"><ShieldCheck size={15} /> {copy.safeNote}</p>}

          <ul className="trust-benefits" aria-label={copy.trustBenefitsLabel}>
            {copy.trustBenefits.map((item) => <li key={item}>{item}</li>)}
          </ul>

          <div className="demo-disclosure">
            {mode === 'real' ? (
              <button className="demo-trigger" type="button" onClick={() => onModeChange('demo')}><FlaskConical />{copy.tryDemo}</button>
            ) : (
              <div className="demo-active-row"><p className="demo-inline"><strong>{copy.demoBadge}</strong> · {copy.demoBody}</p><button type="button" onClick={() => onModeChange('real')}><X />{copy.returnReal}</button></div>
            )}
          </div>

          {mode === 'demo' && (
            <div className="scenario-picker">
              <span>{copy.exploreScenario}</span>
              <div>
                {demoScenarios.map((item, index) => (
                  <button key={item.id} type="button" className={scenario === item.id ? 'selected' : ''} onClick={() => onScenarioChange(item.id, item.domain)}>
                    <i className={`status-mark verdict-${item.verdict.toLowerCase()}`} aria-hidden="true" /> {copy.scenarioLabels[index]}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
        <div className="home-evidence" aria-labelledby="clarity-title">
          <div>
            <p className="eyebrow">{copy.howLabel}</p>
            <h2 id="clarity-title">{copy.howTitle}</h2>
            <p>{copy.howBody}</p>
          </div>
          <ol className="scope-rail" aria-label={copy.howTitle}>
            {copy.scopeLabels.map((label, index) => <li key={label}><span>{String(index + 1).padStart(2, '0')}</span>{label}</li>)}
          </ol>
        </div>
      </section>
    </main>
  );
}
