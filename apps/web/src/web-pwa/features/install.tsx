import { useEffect, useState } from "react";
import { Download, ChevronDown } from "lucide-react";
interface InstallEvent extends Event {
  prompt(): Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
}
export function InstallPrompt() {
  const [prompt, setPrompt] = useState<InstallEvent | null>(null);
  const [installed, setInstalled] = useState(
    () => matchMedia("(display-mode: standalone)").matches,
  );
  const [message, setMessage] = useState("");
  const ios =
    /iPad|iPhone|iPod/.test(navigator.userAgent) ||
    (navigator.userAgent.includes("Macintosh") && navigator.maxTouchPoints > 1);
  useEffect(() => {
    const ready = (event: Event) => {
      event.preventDefault();
      setPrompt(event as InstallEvent);
    };
    const done = () => {
      setInstalled(true);
      setPrompt(null);
    };
    window.addEventListener("beforeinstallprompt", ready);
    window.addEventListener("appinstalled", done);
    return () => {
      window.removeEventListener("beforeinstallprompt", ready);
      window.removeEventListener("appinstalled", done);
    };
  }, []);
  if (installed) return null;
  return (
    <div className="install-prompt">
      {prompt ? (
        <button
          className="text-button"
          onClick={() => {
            void prompt
              .prompt()
              .then(() => prompt.userChoice)
              .then(() => {
                setPrompt(null);
              })
              .catch(() => {
                setMessage("Use a opção de instalação no menu do navegador.");
              });
          }}
        >
          <Download size={16} />
          Instalar EDY ScanURL
        </button>
      ) : ios ? (
        <details>
          <summary>
            Adicionar à tela de início
            <ChevronDown size={16} />
          </summary>
          <p>
            No Safari, toque em Compartilhar e em “Adicionar à Tela de Início”.
            Para uma nova verificação, você ainda precisa de internet.
          </p>
        </details>
      ) : (
        <details>
          <summary>
            Usar como aplicativo
            <ChevronDown size={16} />
          </summary>
          <p>
            Em um navegador compatível, abra o menu e procure “Instalar
            aplicativo” ou “Adicionar à tela inicial”. Se a opção não aparecer,
            continue usando este site normalmente.
          </p>
        </details>
      )}
      <p role="status">{message}</p>
    </div>
  );
}
