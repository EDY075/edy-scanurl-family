import { Check, Languages, LockKeyhole, MonitorCog, Moon, Server, Sun, WifiOff } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { probeAnalysisEngine, type AnalysisEngineStatus } from '../lib/device-review';
import { getPrivateEngineOrigin, isNativePersonalApp, setPrivateEngineOrigin } from '../lib/analysis-engine';
import type { Copy } from '../lib/i18n';
import type { Locale, Theme } from '../types';

export function Settings({ copy, locale, theme, onLocaleChange, onThemeChange }: { copy: Copy; locale: Locale; theme: Theme; onLocaleChange: (locale: Locale) => void; onThemeChange: (theme: Theme) => void }) {
  const themes: { id: Theme; label: string; icon: ReactNode }[] = [{ id: 'light', label: copy.light, icon: <Sun /> }, { id: 'dark', label: copy.dark, icon: <Moon /> }, { id: 'system', label: copy.system, icon: <MonitorCog /> }];
  const [engine, setEngine] = useState<AnalysisEngineStatus>({ mode: 'STANDARD', connected: false });
  const nativeApp = isNativePersonalApp();
  const [engineUrl, setEngineUrl] = useState(() => getPrivateEngineOrigin() ?? '');
  const [engineMessage, setEngineMessage] = useState('');
  useEffect(() => { void probeAnalysisEngine().then(setEngine); }, []);
  const saveEngine = async () => {
    try {
      setPrivateEngineOrigin(engineUrl);
      setEngineMessage(copy.engineSaved);
      setEngine(await probeAnalysisEngine());
    } catch { setEngineMessage(copy.engineUrlInvalid); }
  };
  return (
    <main id="main-content" className="subpage settings-page">
      <header className="subpage-heading"><p className="eyebrow">{copy.settingsEyebrow}</p><h1>{copy.settingsTitle}</h1><p>{copy.settingsBody}</p></header>
      <section className="settings-card"><div className="setting-title"><span><Languages /></span><div><h2>{copy.language}</h2><p>{copy.interfaceCopy}</p></div></div><div className="choice-grid two"><button type="button" className={locale === 'pt-BR' ? 'selected' : ''} onClick={() => onLocaleChange('pt-BR')}>Português (Brasil){locale === 'pt-BR' && <Check />}</button><button type="button" className={locale === 'en' ? 'selected' : ''} onClick={() => onLocaleChange('en')}>English{locale === 'en' && <Check />}</button></div></section>
      <section className="settings-card"><div className="setting-title"><span><Sun /></span><div><h2>{copy.appearance}</h2><p>{copy.appearanceCopy}</p></div></div><div className="choice-grid">{themes.map((item) => <button type="button" key={item.id} className={theme === item.id ? 'selected' : ''} onClick={() => onThemeChange(item.id)}>{item.icon}<span>{item.label}</span>{theme === item.id && <Check />}</button>)}</div></section>
      <section className={`settings-card engine-card ${engine.connected ? 'engine-connected' : 'engine-offline'}`}>
        <div className="setting-title"><span>{engine.connected ? <Server /> : <WifiOff />}</span><div><h2>{copy.analysisEngine}</h2><p>{engine.mode === 'DEVICE_REVIEW' ? copy.localPcEngine : engine.mode === 'PERSONAL_MOBILE' ? copy.privatePcEngine : copy.currentDeviceEngine}</p></div></div>
        <strong role="status"><i aria-hidden="true" />{engine.connected ? copy.connected : copy.offline}</strong>
        {nativeApp && <div className="engine-config"><label htmlFor="analysis-engine-url">{copy.privateEngineUrl}</label><div><input id="analysis-engine-url" type="url" inputMode="url" autoCapitalize="none" autoCorrect="off" spellCheck={false} value={engineUrl} placeholder="https://device.tailnet.ts.net" onChange={(event) => { setEngineUrl(event.target.value); setEngineMessage(''); }} /><button type="button" onClick={() => void saveEngine()}>{copy.saveEngine}</button></div><p>{copy.privateEngineHelp}</p>{engineMessage && <small role="status">{engineMessage}</small>}</div>}
      </section>
      <section className="settings-card privacy-card"><div className="setting-title"><span><LockKeyhole /></span><div><h2>{copy.privacy}</h2><p>{copy.privacyBody}</p></div></div><ul>{copy.privacyBullets.map((item) => <li key={item}><Check /> {item}</li>)}</ul></section>
    </main>
  );
}
