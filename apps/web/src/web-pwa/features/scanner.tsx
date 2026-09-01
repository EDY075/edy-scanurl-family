import { useRef, useState } from "react";
import {
  ArrowRight,
  Check,
  Clipboard,
  Link2,
  X,
  LoaderCircle,
} from "lucide-react";
import { friendlyError, type ScanPhase } from "../services/api";
import { normalizeStoreUrl, validStoreUrl } from "../utils/url";

interface ScannerProps {
  onScan: (value: string) => Promise<void>;
  phase: ScanPhase | null;
  error: string;
  retryAfter: number;
}
const phaseText: Record<ScanPhase, string> = {
  validating: "Validando endereço",
  authenticating: "Preparando seu acesso seguro",
  collecting: "Verificando o domínio e consultando sinais de segurança",
  preparing: "Preparando seu resultado",
};
export function Scanner({ onScan, phase, error, retryAfter }: ScannerProps) {
  const [value, setValue] = useState("");
  const [message, setMessage] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const normalized = validStoreUrl(value);
  const busy = phase !== null;
  const accept = (text: string) => {
    try {
      setValue(normalizeStoreUrl(text));
      setMessage(
        "Link pronto. Vamos verificar apenas o endereço da loja, sem dados do produto.",
      );
    } catch (failure) {
      setValue(text.slice(0, 8192));
      setMessage(friendlyError(failure));
    }
  };
  const submit = () => {
    if (normalized && !busy && !retryAfter) {
      setMessage("");
      void onScan(normalized);
    }
  };
  return (
    <section
      className="scanner-panel"
      id="scanner"
      aria-labelledby="scanner-title"
    >
      <div className="panel-heading">
        <span className="eyebrow">SUA PRÓXIMA COMPRA</span>
        <Link2 size={20} />
      </div>
      <h2 id="scanner-title">Vamos conferir o link?</h2>
      <p>Um pequeno cuidado faz diferença.</p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
        noValidate
      >
        <label htmlFor="store-url">Endereço da loja</label>
        <div className="url-field">
          <Link2 size={18} />
          <input
            ref={input}
            id="store-url"
            type="text"
            inputMode="url"
            enterKeyHint="go"
            autoComplete="off"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            maxLength={8192}
            placeholder="https://exemplo.com.br"
            aria-describedby="scanner-hint scanner-feedback"
            aria-invalid={!!value.trim() && !normalized}
            disabled={busy}
            value={value}
            onChange={(event) => {
              setValue(event.target.value);
              setMessage("");
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && !event.nativeEvent.isComposing) {
                event.preventDefault();
                submit();
              }
            }}
            onPaste={(event) => {
              event.preventDefault();
              accept(event.clipboardData.getData("text"));
            }}
            onBlur={() => {
              if (value.trim() && !normalized) {
                try {
                  normalizeStoreUrl(value);
                } catch (failure) {
                  setMessage(friendlyError(failure));
                }
              }
            }}
          />
          {value && (
            <button
              type="button"
              disabled={busy}
              aria-label="Limpar endereço"
              onClick={() => {
                setValue("");
                setMessage("");
                input.current?.focus();
              }}
            >
              <X size={17} />
            </button>
          )}
        </div>
        <div className="scanner-actions">
          <p id="scanner-hint">
            Cole um link ou uma mensagem com um único endereço.
          </p>
          <button
            type="button"
            className="text-button"
            disabled={busy}
            onClick={() => {
              void navigator.clipboard
                .readText()
                .then(accept)
                .catch(() => {
                  setMessage(friendlyError(new Error("clipboard")));
                });
            }}
          >
            <Clipboard size={15} />
            Colar link
          </button>
        </div>
        <button
          className="primary-button"
          disabled={!normalized || busy || retryAfter > 0}
        >
          {busy ? (
            <>
              <LoaderCircle className="spin" size={18} /> Verificando…
            </>
          ) : retryAfter ? (
            `Aguarde ${String(retryAfter)} s`
          ) : (
            <>
              Verificar site <ArrowRight size={20} />
            </>
          )}
        </button>
      </form>
      <p className="scanner-note" id="scanner-feedback" role="status">
        {message ||
          "Análise de sinais públicos. Sem acessar sua conta na loja."}
      </p>
      {busy && (
        <div className="scan-progress" role="status">
          <div className="indeterminate" />
          <strong>{phaseText[phase]}</strong>
          <p>
            Consultando fontes disponíveis. Cadastro oficial e reputação pública não são consultados nesta versão.
          </p>
          <span>Sem estimativa de porcentagem ou garantia de cobertura.</span>
        </div>
      )}
      {error && (
        <div className="error-message" role="alert">
          <strong>{error.split('. ')[0]}</strong>
          <p>{error.split('. ').slice(1).join('. ')}</p>
          <button
            type="button"
            className="text-button"
            disabled={!normalized || busy || retryAfter > 0}
            onClick={submit}
          >
            Tentar novamente <ArrowRight size={16} />
          </button>
        </div>
      )}
      <div className="panel-bottom">
        <Check size={15} /> A decisão continua nas suas mãos.
      </div>
    </section>
  );
}
