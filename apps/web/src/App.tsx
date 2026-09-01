import { useEffect, useMemo, useState } from 'react';
import { Clock3, Globe2, Home as HomeIcon, Languages, Moon, Settings as SettingsIcon, Sun } from 'lucide-react';
import { Brand } from './components/Brand';
import { History } from './components/History';
import { Home } from './components/Home';
import { DecisionReportV4 } from './components/DecisionReportV4';
import { ScanProgressView } from './components/ScanProgressView';
import { Settings } from './components/Settings';
import { getCopy } from './lib/i18n';
import { clearStoredHistory, loadHistory, saveToHistory } from './lib/history';
import { requestScan } from './lib/scan-client';
import { localizeReport } from './demo/localize';
import { displayDomain, normalizeStoreUrl } from './lib/url';
import type { DemoScenarioId, HistoryEntry, Locale, ScanMode, ScanReport, Theme } from './types';

type View = 'home' | 'progress' | 'report' | 'history' | 'settings';

export function App() {
  const [view, setView] = useState<View>('home');
  const [locale, setLocale] = useState<Locale>(() => localStorage.getItem('edy-locale') === 'en' ? 'en' : 'pt-BR');
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem('edy-theme');
    return stored === 'light' || stored === 'dark' ? stored : 'light';
  });
  const [mode, setMode] = useState<ScanMode>('real');
  const [scenario, setScenario] = useState<DemoScenarioId>('trusted');
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [progress, setProgress] = useState(0);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);
  const copy = useMemo(() => getCopy(locale), [locale]);
  const displayedReport = useMemo(() => report ? localizeReport(report, locale) : null, [report, locale]);

  useEffect(() => {
    const applyTheme = () => {
      const actual = theme === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme;
      document.documentElement.dataset.theme = actual;
      document.documentElement.lang = locale;
      document.querySelector('meta[name="theme-color"]')?.setAttribute('content', actual === 'dark' ? '#111715' : '#f4f1e9');
    };
    applyTheme();
    localStorage.setItem('edy-theme', theme);
    localStorage.setItem('edy-locale', locale);
    const media = matchMedia('(prefers-color-scheme: dark)');
    media.addEventListener('change', applyTheme);
    return () => media.removeEventListener('change', applyTheme);
  }, [theme, locale]);

  const navigate = (next: View) => { setView(next); window.scrollTo({ top: 0, behavior: 'smooth' }); };
  const startScan = async (rescanUrl?: string, scenarioOverride?: DemoScenarioId, modeOverride?: ScanMode) => {
    setError('');
    try {
      const normalized = normalizeStoreUrl(rescanUrl ?? url);
      setUrl(normalized);
      setProgress(0);
      navigate('progress');
      const result = await requestScan(normalized, modeOverride ?? mode, scenarioOverride ?? scenario, setProgress);
      setReport(result);
      setHistory(saveToHistory(result));
      navigate('report');
    } catch (scanError) {
      const errorCode = scanError instanceof Error ? scanError.message : 'unknown';
      const message = ['empty', 'protocol', 'hostname'].includes(errorCode) ? copy.invalidUrl
        : errorCode === 'rate_limited' ? copy.rateLimitedError
          : errorCode === 'scan_timeout' ? copy.timeoutError
            : errorCode === 'scan_rejected' ? copy.rejectedError
              : ['scan_failed', 'scan_expired', 'report_missing', 'failed'].includes(errorCode) ? copy.failedError
                : copy.realError;
      setError(message);
      navigate('home');
    }
  };
  const changeScenario = (scenarioId: DemoScenarioId, domain: string) => { setScenario(scenarioId); setUrl(`https://${domain}`); setError(''); };
  const handleHistoryRescan = (entry: HistoryEntry) => {
    const scenarioForVerdict: Record<HistoryEntry['verdict'], DemoScenarioId> = { BUY: 'trusted', CAUTION: 'caution', DO_NOT_BUY: 'high-risk', INSUFFICIENT_DATA: 'insufficient' };
    const selectedScenario = scenarioForVerdict[entry.verdict];
    setMode(entry.mode); setUrl(`https://${entry.domain}`); setScenario(selectedScenario); void startScan(`https://${entry.domain}`, selectedScenario, entry.mode);
  };
  const handleHistoryOpen = (entry: HistoryEntry) => { if (entry.report) { setReport(entry.report); navigate('report'); } };
  const handleNewScan = () => { setUrl(''); setError(''); setReport(null); navigate('home'); };

  return (
    <div className="app-shell">
      <header className="app-header">
        <button type="button" className="brand-button" onClick={() => navigate('home')}><Brand /></button>
        <nav className="desktop-nav" aria-label={copy.navLabel}><button className={view === 'home' ? 'active' : ''} type="button" onClick={() => navigate('home')}>{copy.navHome}</button><button className={view === 'history' ? 'active' : ''} type="button" onClick={() => navigate('history')}>{copy.navHistory}</button><button className={view === 'settings' ? 'active' : ''} type="button" onClick={() => navigate('settings')}>{copy.navSettings}</button></nav>
        <div className="header-tools"><button type="button" onClick={() => setLocale(locale === 'pt-BR' ? 'en' : 'pt-BR')} aria-label={copy.language}><Languages /><span>{locale === 'pt-BR' ? 'PT' : 'EN'}</span></button><button type="button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label={copy.appearance}>{theme === 'dark' ? <Sun /> : <Moon />}</button></div>
      </header>

      {view === 'home' && <Home copy={copy} url={url} error={error} mode={mode} scenario={scenario} onUrlChange={(value) => { setUrl(value); setError(''); }} onModeChange={setMode} onScenarioChange={changeScenario} onSubmit={() => void startScan()} />}
      {view === 'progress' && <ScanProgressView copy={copy} domain={displayDomain(url)} activeStep={progress} mode={mode} />}
      {view === 'report' && displayedReport && <DecisionReportV4 report={displayedReport} copy={copy} locale={locale} onBack={handleNewScan} onRescan={() => void startScan(displayedReport.normalizedUrl)} />}
      {view === 'history' && <History copy={copy} locale={locale} history={history} onOpen={handleHistoryOpen} onRescan={handleHistoryRescan} onClear={() => setHistory(clearStoredHistory())} />}
      {view === 'settings' && <Settings copy={copy} locale={locale} theme={theme} onLocaleChange={setLocale} onThemeChange={setTheme} />}

      {!['progress', 'report'].includes(view) && <nav className="mobile-nav" aria-label={copy.navLabel}><button type="button" className={view === 'home' ? 'active' : ''} onClick={() => navigate('home')}><HomeIcon /><span>{copy.navHome}</span></button><button type="button" className={view === 'history' ? 'active' : ''} onClick={() => navigate('history')}><Clock3 /><span>{copy.navHistory}</span></button><button type="button" className={view === 'settings' ? 'active' : ''} onClick={() => navigate('settings')}><SettingsIcon /><span>{copy.navSettings}</span></button></nav>}
      <footer className="app-footer"><Brand compact /><p>{copy.disclaimer}</p><span>© 2026 EDY ScanURL</span><Globe2 /></footer>
    </div>
  );
}
