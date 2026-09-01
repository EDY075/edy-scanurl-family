import { useEffect, useLayoutEffect, useRef, useState, type FormEvent } from 'react';
import { Brand } from '../components/Brand';
import type { ScanReport } from '../types';
import { requestFamilyScan, getFamilyAvailability, readPastedLink, takeSharedLink, onSharedLink } from './family-client';
import { describeFamilyVirusTotal, explainFamilyCheck, extractFamilyUrl, familyErrorMessage, FAMILY_HISTORY_ENABLED_KEY, FAMILY_HISTORY_KEY, FAMILY_THEME_KEY, parseFamilyTheme, safeFamilyDomain, safeFamilySourceUrl, sanitizeFamilyHistory, summarizeFamilyReport, type FamilyHistoryItem, type FamilyTheme } from './family-presentation';
import './family.css';

type Availability = Awaited<ReturnType<typeof getFamilyAvailability>>;
const formatTime = (value: string) => new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value));
const enabledInitially = () => { try { return localStorage.getItem(FAMILY_HISTORY_ENABLED_KEY) === 'true'; } catch { return false; } };
const storedHistory = () => { try { return enabledInitially() ? sanitizeFamilyHistory(JSON.parse(localStorage.getItem(FAMILY_HISTORY_KEY) ?? '[]') as unknown) : []; } catch { return []; } };
const initialTheme = () => { try { return parseFamilyTheme(localStorage.getItem(FAMILY_THEME_KEY)); } catch { return 'dark' as const; } };
const themeChoices: { value: FamilyTheme; label: string }[] = [{ value: 'dark', label: 'Escuro' }, { value: 'light', label: 'Claro' }, { value: 'system', label: 'Usar tema do sistema' }];

export function FamilyApp() {
  const [availability, setAvailability] = useState<Availability | null>(null);
  const [checkingAccess, setCheckingAccess] = useState(true);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [sharedWaiting, setSharedWaiting] = useState('');
  const [historyEnabled, setHistoryEnabled] = useState(enabledInitially);
  const [history, setHistory] = useState<FamilyHistoryItem[]>(storedHistory);
  const [confirmClear, setConfirmClear] = useState(false);
  const [theme, setTheme] = useState<FamilyTheme>(initialTheme);
  const [systemDark, setSystemDark] = useState(true);
  const [themeOpen, setThemeOpen] = useState(false);
  const themeButtonRef = useRef<HTMLButtonElement>(null);
  const selectedThemeRef = useRef<HTMLInputElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const busyRef = useRef(false);
  const active = useRef(true);
  const acceptLinkRef = useRef<(text: string) => void>(() => undefined);
  const optInRef = useRef(historyEnabled);
  const resolvedTheme = theme === 'system' ? (systemDark ? 'dark' : 'light') : theme;

  useEffect(() => {
    const media = typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-color-scheme: dark)') : undefined;
    if (!media) return;
    const updateSystemTheme = () => setSystemDark(media.matches);
    updateSystemTheme();
    media.addEventListener('change', updateSystemTheme);
    return () => media.removeEventListener('change', updateSystemTheme);
  }, []);

  useLayoutEffect(() => {
    document.documentElement.dataset.theme = resolvedTheme;
    document.documentElement.style.colorScheme = resolvedTheme;
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', resolvedTheme === 'dark' ? '#141918' : '#f7f6f0');
  }, [resolvedTheme]);

  useEffect(() => {
    try { localStorage.setItem(FAMILY_THEME_KEY, theme); }
    catch { setNotice('O tema foi aplicado, mas não foi possível guardar essa preferência neste aparelho.'); }
  }, [theme]);
  useEffect(() => { if (themeOpen) selectedThemeRef.current?.focus(); }, [themeOpen]);

  function closeTheme() { setThemeOpen(false); themeButtonRef.current?.focus(); }

  async function refreshAccess() {
    setCheckingAccess(true);
    try { const status = await getFamilyAvailability(); if (active.current) setAvailability(status); }
    catch { if (active.current) setAvailability({ state: 'OFFLINE' }); }
    finally { if (active.current) setCheckingAccess(false); }
  }

  function acceptLink(text: string) {
    if (!text.trim()) return;
    if (busyRef.current) { setSharedWaiting(text); return; }
    try {
      const url = extractFamilyUrl(text);
      setInput(url); setReport(null); setError('');
      setNotice('Link recebido. Confira o endereço e toque em “Verificar site” quando quiser.');
      requestAnimationFrame(() => inputRef.current?.focus());
    } catch (reason) { setError(familyErrorMessage(reason)); }
  }
  acceptLinkRef.current = acceptLink;

  useEffect(() => {
    active.current = true;
    document.documentElement.lang = 'pt-BR';
    document.title = 'EDY ScanURL Family';
    void refreshAccess();
    void takeSharedLink().then((text) => { if (active.current) acceptLinkRef.current(text); }).catch(() => { /* Sharing is optional; manual paste remains available. */ });
    const unsubscribe = onSharedLink((text) => { if (active.current) acceptLinkRef.current(text); });
    return () => { active.current = false; unsubscribe(); };
  }, []);

  useEffect(() => { if (busy || report) headingRef.current?.focus(); else if (error) errorRef.current?.focus(); }, [busy, report, error]);
  useEffect(() => {
    optInRef.current = historyEnabled;
    try {
      if (historyEnabled) {
        localStorage.setItem(FAMILY_HISTORY_ENABLED_KEY, 'true');
        localStorage.setItem(FAMILY_HISTORY_KEY, JSON.stringify(sanitizeFamilyHistory(history)));
      } else {
        localStorage.removeItem(FAMILY_HISTORY_ENABLED_KEY);
        localStorage.removeItem(FAMILY_HISTORY_KEY);
      }
    } catch { setNotice('Não foi possível guardar o histórico neste aparelho. Você pode continuar verificando sem salvar.'); }
  }, [history, historyEnabled]);

  async function paste() {
    try { const text = await readPastedLink(); if (!text.trim()) throw new Error('clipboard'); acceptLink(text); }
    catch { setError(familyErrorMessage(new Error('clipboard'))); }
  }

  async function scan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busyRef.current) return;
    setError(''); setNotice('');
    let url: string;
    try { url = extractFamilyUrl(input); } catch (reason) { setError(familyErrorMessage(reason)); return; }
    if (availability?.state !== 'READY') { setError(familyErrorMessage(new Error(availability?.state === 'OFFLINE' ? 'offline' : availability?.state === 'PENDING' ? 'device_pending' : availability?.state === 'REVOKED' ? 'device_revoked' : 'not_activated'))); return; }
    setInput(url); busyRef.current = true; setBusy(true); setReport(null);
    try {
      const result = await requestFamilyScan(url, () => undefined);
      const presentation = summarizeFamilyReport(result);
      if (!active.current) return;
      setReport(result);
      if (optInRef.current) {
        const domain = safeFamilyDomain(result.domain);
        if (domain) setHistory((old) => sanitizeFamilyHistory([{ domain, verdict: presentation.verdict, time: new Date().toISOString() }, ...old]));
      }
    } catch (reason) {
      if (active.current) { setError(familyErrorMessage(reason)); void refreshAccess(); }
    } finally { busyRef.current = false; if (active.current) setBusy(false); }
  }

  function newScan(domain = '') {
    setReport(null); setInput(domain); setError(''); setNotice(domain ? 'Endereço preparado. Toque em “Verificar site” para fazer uma nova consulta.' : '');
    window.scrollTo({ top: 0, behavior: 'auto' });
    requestAnimationFrame(() => inputRef.current?.focus());
  }
  const result = report ? summarizeFamilyReport(report) : null;
  const preparing = !availability || ['UNCONFIGURED', 'PENDING'].includes(availability.state);
  const canScan = availability?.state === 'READY' && !checkingAccess;

  return <div className="family-app">
    <a className="family-skip" href="#family-main">Pular para o conteúdo</a>
    <header className="family-header"><div className="family-brand-wrap"><Brand /><span>Family</span></div><button className="family-theme-button" type="button" ref={themeButtonRef} aria-expanded={themeOpen} aria-controls="family-theme-panel" onClick={() => setThemeOpen((open) => !open)}><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="8" /><path d="M12 4a8 8 0 0 1 0 16Z" /></svg>Tema</button></header>
    {themeOpen && <section id="family-theme-panel" className="family-theme-panel" aria-label="Tema do aplicativo" onKeyDown={(event) => { if (event.key === 'Escape') { event.preventDefault(); closeTheme(); } }}><fieldset><legend>Escolha o tema</legend>{themeChoices.map((choice) => <label key={choice.value} className="family-theme-choice"><input type="radio" name="family-theme" value={choice.value} checked={theme === choice.value} ref={theme === choice.value ? selectedThemeRef : undefined} onChange={() => setTheme(choice.value)} /><span>{choice.label}</span></label>)}</fieldset><button type="button" className="family-secondary" onClick={closeTheme}>Concluir</button></section>}
    <main id="family-main" className="family-main">
      {busy ? <section className="family-loading" aria-busy="true"><h1 ref={headingRef} tabIndex={-1}>Verificando com cuidado</h1><p>Estamos consultando as informações da loja. Aguarde um momento.</p><progress aria-label="Verificação em andamento" /><p>Você não precisa abrir o site nem informar dados de pagamento.</p></section>
        : report && result ? <>
          <section className={`family-result family-${result.tone}`} aria-labelledby="family-verdict">
            <p className="family-domain">{report.domain}</p><h1 id="family-verdict" ref={headingRef} tabIndex={-1}><span aria-hidden="true">{result.tone === 'good' ? '✓' : result.tone === 'risk' ? '!' : '!'}</span>{result.verdict}</h1>
            <p className="family-summary">{result.summary}</p>
          </section>
          <section className="family-reasons"><h2>Por que apareceu esse resultado?</h2>{result.reasons.length ? <ul>{result.reasons.map((reason) => <li key={reason.id}><h3>{reason.title}</h3><p>{reason.explanation}</p></li>)}</ul> : <p>A consulta não trouxe explicações suficientes. Confirme a loja por outra fonte antes de pagar.</p>}</section>
          <section className="family-recommendation" aria-labelledby="family-recommendation-title"><h2 id="family-recommendation-title">O que fazer agora</h2><p>{result.recommendation}</p></section>
          <button className="family-primary" type="button" onClick={() => newScan()}>Verificar outro site</button>
          <p className="family-disclaimer family-result-disclaimer">A verificação ajuda a reduzir riscos, mas não garante que a compra seja segura nem que a loja faça a entrega.</p>
          <details className="family-details"><summary>Ver informações e fontes</summary><p>Consulta realizada em {Number.isFinite(Date.parse(report.scannedAt)) ? formatTime(report.scannedAt) : 'data não informada'}. As informações podem mudar.</p>
            <h2>Consulta de ameaças</h2>{describeFamilyVirusTotal(report).map((text) => <p key={text}>{text}</p>)}
            <h2>Fontes consultadas</h2>{report.sources.length ? <ul className="family-source-list">{report.sources.map((source) => <li key={source.id}><h3>{source.name}</h3><p>{source.status === 'available' ? 'Trouxe informações para a consulta.' : source.status === 'limited' ? 'Trouxe apenas parte das informações.' : 'Não foi possível obter informações desta fonte.'}</p>{safeFamilySourceUrl(source.url) && <a href={safeFamilySourceUrl(source.url)} target="_blank" rel="noopener noreferrer">Consultar {source.name} <span>(abre outra página)</span></a>}</li>)}</ul> : <p>Nenhuma fonte foi informada no resultado.</p>}
            <details><summary>Ver o resumo das verificações</summary><ul>{report.checks.map((check) => { const source = report.sources.find((item) => item.id === check.sourceId); const reason = explainFamilyCheck(check, source?.status); return <li key={check.id}><h3>{reason.title}</h3><p>{reason.explanation}</p>{source && <p>Fonte: {source.name}</p>}</li>; })}</ul></details>
          </details>
        </> : <>
          <section className="family-intro"><h1>Antes de comprar,<br />verifique o site.</h1><p>Cole o link da loja. Nós ajudamos você a entender os sinais de confiança e de risco.</p></section>
          {!canScan && <section className="family-access" aria-labelledby="family-access-title"><h2 id="family-access-title">{checkingAccess ? 'Conferindo seu acesso' : preparing ? 'Ainda estamos preparando o acesso da família' : availability.state === 'REVOKED' ? 'Vamos conferir seu acesso' : 'Não foi possível conectar agora'}</h2><p>{checkingAccess ? 'Isso deve levar apenas um momento.' : availability?.state === 'UNCONFIGURED' ? 'O serviço da família ainda não foi ativado. Fale com a pessoa responsável pelo aplicativo. Você já pode preparar o link que quer verificar.' : preparing ? 'Este aparelho está aguardando a liberação da pessoa responsável pela família. Você já pode preparar o link que quer verificar.' : availability.state === 'REVOKED' ? 'O acesso deste aparelho foi desativado. Fale com a pessoa responsável pela família.' : 'Confira sua internet; o serviço da família também pode estar temporariamente indisponível. Tente novamente em instantes.'}</p>{availability?.state === 'PENDING' && availability.deviceId && /^[a-z\d-]{4,80}$/i.test(availability.deviceId) && <p>Código do aparelho: <strong className="family-device-code">{availability.deviceId}</strong></p>}<button type="button" className="family-secondary" onClick={() => void refreshAccess()} disabled={checkingAccess}>Conferir acesso</button></section>}
          <form className="family-form" onSubmit={(event) => void scan(event)} noValidate><label htmlFor="family-url">Endereço da loja</label><input id="family-url" ref={inputRef} type="text" inputMode="url" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} enterKeyHint="go" maxLength={8192} placeholder="Ex.: loja.com.br" value={input} aria-invalid={!!error} aria-describedby={`family-url-help${error ? ' family-error' : ''}`} onChange={(event) => { setInput(event.target.value); setError(''); setNotice(''); }} /><p id="family-url-help">Pode ser o link ou uma mensagem com apenas um link.</p><button className="family-secondary" type="button" onClick={() => void paste()}>Colar link copiado</button><button className="family-primary" type="submit" disabled={!canScan}>Verificar site</button></form>
          <p className="family-disclaimer">Não pedimos senha, documentos nem dados do cartão.</p>
        </>}
      {error && <div id="family-error" className="family-error" ref={errorRef} tabIndex={-1} role="alert">{error}</div>}
      {notice && <p className="family-notice" role="status">{notice}</p>}
      {sharedWaiting && !busy && <section className="family-access"><h2>Recebemos outro link</h2><p>Você decide quando verificar. Nenhuma nova consulta foi iniciada.</p><button className="family-secondary" type="button" onClick={() => { const text = sharedWaiting; setSharedWaiting(''); acceptLink(text); }}>Ver o link recebido</button></section>}
      {!busy && <details className="family-details family-privacy"><summary>Histórico e privacidade</summary><h2>Seus dados</h2><p>Ao tocar em “Verificar site”, apenas o endereço principal da loja é enviado ao serviço da família para análise. O caminho e os dados adicionais do link são descartados antes do envio. O endereço da loja pode ser consultado em fontes externas de segurança.</p><p>O histórico fica desligado até você escolher guardar. Se ativar, salvamos neste aparelho apenas o nome do site, o resultado e a data — no máximo 20 consultas dos últimos 30 dias. Não guardamos aqui o caminho do link, seus parâmetros nem o relatório completo.</p><label className="family-checkbox"><input type="checkbox" checked={historyEnabled} onChange={(event) => { setHistoryEnabled(event.target.checked); if (!event.target.checked) { setHistory([]); setConfirmClear(false); } }} /><span>Guardar histórico neste aparelho</span></label>
        <p>Desligar esta opção apaga o histórico local. Isso não apaga registros que o serviço da família precise manter; fale com a pessoa responsável para saber sobre esses dados.</p>
        {historyEnabled && <><h2>Consultas recentes</h2>{history.length ? <ul className="family-history">{history.map((item, index) => <li key={`${item.time}-${String(index)}`}><h3>{item.domain}</h3><p>{item.verdict} · {formatTime(item.time)}</p><button type="button" className="family-secondary" onClick={() => newScan(item.domain)}>Preparar nova verificação de {item.domain}</button></li>)}</ul> : <p>Nenhuma consulta guardada.</p>}
          {history.length > 0 && (confirmClear ? <div className="family-clear-confirm"><p>Apagar as consultas guardadas neste aparelho?</p><button className="family-secondary" type="button" onClick={() => { setHistory([]); setConfirmClear(false); setNotice('Histórico apagado deste aparelho.'); }}>Sim, apagar histórico</button><button className="family-secondary" type="button" onClick={() => setConfirmClear(false)}>Cancelar</button></div> : <button className="family-secondary" type="button" onClick={() => setConfirmClear(true)}>Limpar histórico</button>)}</>}
      </details>}
    </main><footer className="family-footer">EDY ScanURL Family · Cuidado antes da compra.</footer>
  </div>;
}
