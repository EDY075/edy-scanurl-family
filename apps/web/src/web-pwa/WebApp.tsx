import { useEffect, useRef, useState } from "react";
import {
  LockKeyhole,
  Moon,
  Sun,
  Monitor,
  RefreshCw,
  ArrowUpRight,
} from "lucide-react";
import { Brand } from "../components/Brand";
import type { ScanReport } from "../types";
import { useTheme } from "./hooks/usePreferences";
import { useHealth } from "./hooks/useHealth";
import {
  ApiError,
  friendlyError,
  scanStore,
  type ScanPhase,
} from "./services/api";
import { Scanner } from "./features/scanner";
import { Results } from "./features/results";
import {
  HistoryPanel,
  useLocalHistory,
  type SavedResult,
} from "./features/history";
import { Education } from "./features/education";
import { InstallPrompt } from "./features/install";

export function WebApp() {
  const { theme, resolved, changeTheme } = useTheme();
  const health = useHealth();
  const history = useLocalHistory();
  const [report, setReport] = useState<ScanReport | null>(null);
  const [saved, setSaved] = useState<SavedResult | null>(null);
  const [phase, setPhase] = useState<ScanPhase | null>(null);
  const [error, setError] = useState("");
  const [retryAfter, setRetryAfter] = useState(0);
  const [updateReady, setUpdateReady] = useState(false);
  useEffect(() => {
    const ready = () => { setUpdateReady(true); };
    window.addEventListener('edy-update-ready', ready);
    return () => { window.removeEventListener('edy-update-ready', ready); };
  }, []);
  const scanActive = useRef(false);
  useEffect(() => {
    if (!retryAfter) return;
    const timer = setInterval(() => {
      setRetryAfter((value) => Math.max(0, value - 1));
    }, 1000);
    return () => {
      clearInterval(timer);
    };
  }, [retryAfter]);
  const scan = async (value: string) => {
    if (scanActive.current) return;
    scanActive.current = true;
    setError("");
    setSaved(null);
    try {
      const result = await scanStore(value, setPhase);
      setReport(result);
      history.add(result);
    } catch (failure) {
      setError(friendlyError(failure));
      if (failure instanceof ApiError && failure.code === "rate_limited")
        setRetryAfter(failure.retryAfter || 60);
    } finally {
      setPhase(null);
      scanActive.current = false;
    }
  };
  const reset = () => {
    setReport(null);
    setSaved(null);
    setError("");
    requestAnimationFrame(() => {
      document.getElementById("store-url")?.focus();
    });
  };
  return (
    <div className="web-app" data-theme={resolved}>
      <a
        className="skip-link"
        href={report || saved ? "#result-title" : "#scanner"}
      >
        Ir para a verificação
      </a>
      <header className="site-header shell">
        <a
          className="brand-link"
          href="/"
          title="Início"
        >
          <Brand />
          <span className="family-label">Family</span>
        </a>
        <nav className="header-nav" aria-label="Principal">
          <a href="#historico">Histórico</a>
          <a href="#dicas">Dicas de compra</a>
        </nav>
        <details className="theme-menu">
          <summary aria-label="Escolher tema">
            {theme === "system" ? (
              <Monitor size={18} />
            ) : theme === "dark" ? (
              <Moon size={18} />
            ) : (
              <Sun size={18} />
            )}
            <span>Tema</span>
          </summary>
          <div className="theme-options" role="group" aria-label="Aparência">
            {(["dark", "light", "system"] as const).map((option) => (
              <button
                key={option}
                aria-pressed={theme === option}
                onClick={() => {
                  changeTheme(option);
                }}
              >
                {option === "dark"
                  ? "Escuro"
                  : option === "light"
                    ? "Claro"
                    : "Usar tema do sistema"}
              </button>
            ))}
          </div>
        </details>
      </header>
      <main className="shell">
        {updateReady && <div className="offline-notice" role="status">Uma nova versão está pronta. <button className="text-button" disabled={phase !== null} onClick={() => { window.dispatchEvent(new Event('edy-apply-update')); }}>Atualizar aplicativo</button></div>}
        <div className="service-line" id="status">
          <span className={`service-status ${health.state}`} role="status">
            <span className="status-dot" />
            {health.state === "online"
              ? "Serviço online"
              : health.state === "checking"
                ? "Verificando serviço..."
                : health.state === "offline"
                  ? "Serviço temporariamente indisponível"
                  : health.state === 'unavailable' ? 'Serviço temporariamente indisponível' : "Serviço com instabilidade"}
          </span>
          {(health.state === "degraded" || health.state === 'unavailable') && (
            <button className="text-button" onClick={health.retry}>
              <RefreshCw size={14} />
              Conferir conexão
            </button>
          )}
          <span className="header-note">Uma pausa antes da compra.</span>
        </div>
        {health.offline && (
          <p className="offline-notice" role="status">
            <strong>Você está offline</strong><br />
            O EDY ScanURL Family pode abrir sem internet, mas uma conexão é necessária para verificar novos sites.
          </p>
        )}
        {report || saved ? (
          <Results report={report} saved={saved} reset={reset} />
        ) : (
          <section className="home-grid" aria-labelledby="hero-title">
            <div className="hero-copy">
              <p className="eyebrow">
                <span className="status-dot" /> MAIS CLAREZA. MENOS RISCO.
              </p>
              <h1 id="hero-title">
                Antes de comprar,
                <br />
                <em>verifique o site.</em>
              </h1>
              <p className="hero-description">
                Cole o link da loja. Nós analisamos sinais de confiança e risco
                para ajudar você a decidir com mais segurança.
              </p>
              <div className="privacy-line">
                <LockKeyhole size={16} /> Nenhuma senha solicitada. Nenhum
                cadastro manual.
              </div>
            </div>
            <Scanner
              onScan={scan}
              phase={phase}
              error={error}
              retryAfter={retryAfter}
            />
          </section>
        )}
        {!report && !saved && (
          <section className="how-section" id="como-funciona">
            <p className="eyebrow">DO LINK À DECISÃO</p>
            <h2>Você traz o link. Nós reunimos os sinais.</h2>
            <div className="how-grid">
              {[
                [
                  "01",
                  "Cole o endereço",
                  "Pode ser o link da loja ou de um produto.",
                ],
                [
                  "02",
                  "Confira os sinais",
                  "Consultamos fontes públicas e técnicas.",
                ],
                [
                  "03",
                  "Decida com mais clareza",
                  "Veja os motivos e o próximo passo recomendado.",
                ],
              ].map(([number, title, description]) => (
                <article key={number}>
                  <span className="step-number">{number}</span>
                  <h3>{title}</h3>
                  <p>{description}</p>
                </article>
              ))}
            </div>
          </section>
        )}
        <Education />
        <HistoryPanel
          history={history}
          reopen={(item) => {
            setReport(null);
            setSaved(item);
          }}
        />
        <section className="privacy-section section-block" id="privacidade">
          <div>
            <p className="eyebrow">PRIVACIDADE POR ESCOLHA</p>
            <h2>
              O cuidado é com a compra.
              <br />E com os seus dados.
            </h2>
          </div>
          <div>
            <p>
              Não pedimos senha, cartão ou documento. Enviamos apenas o endereço
              público da loja para a análise. Os detalhes do produto e os
              códigos do link são descartados.
            </p>
            <details id="seguranca">
              <summary>
                Como protegemos a verificação
                <ArrowUpRight size={17} />
              </summary>
              <p>
                Este navegador cria sua própria identificação criptográfica. A
                chave privada não é enviada ao servidor. Há limites de uso e
                bloqueios a endereços internos. Algumas fontes podem não
                responder: mostramos essas limitações sem transformar falta de
                dados em acusação.
              </p>
              <p>
                O resultado fica temporariamente no servidor para entrega e é
                removido após a leitura ou expiração. O histórico opcional é
                salvo somente neste navegador. Quem usa este navegador pode
                acessá-lo.
              </p>
            </details>
            <InstallPrompt />
          </div>
        </section>
      </main>
      <footer className="site-footer shell">
        <div>
          <span>EDY ScanURL Family</span>
          <small>Web · versão 1.0</small>
        </div>
        <div>
          <nav aria-label="Rodapé">
            <a href="#status">Status</a>
            <a href="#privacidade">Privacidade</a>
            <a href="#dicas">Como funciona</a>
            <a href="#seguranca">Segurança</a>
          </nav>
          <p>
            Os resultados do EDY ScanURL Family são informativos e não representam garantia absoluta sobre a segurança, legitimidade ou qualidade de um site, empresa, produto ou transação.
          </p>
        </div>
      </footer>
    </div>
  );
}
