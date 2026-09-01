import {
  Check,
  ChevronDown,
  CircleHelp,
  Info,
  Minus,
  TriangleAlert,
  X,
} from "lucide-react";
import type { ScanReport } from "../../types";
import { resultEvidence, sourceConsultation } from "./evidence";
import { validStoreUrl } from "../utils/url";

const icons = {
  PASS: Check,
  INFO: Info,
  WARNING: TriangleAlert,
  FAIL: X,
  UNAVAILABLE: CircleHelp,
  NOT_CHECKED: Minus,
};
const groups = [
  "Identidade da empresa",
  "Sinais de fraude e ameaças",
  "Informações da loja",
  "Reputação pública",
  "Domínio e conexão",
  "Outras evidências",
];
export function EvidenceSection({ report }: { report: ScanReport }) {
  const items = resultEvidence(report);
  return (
    <section className="evidence-section" aria-labelledby="evidence-heading">
      <div className="evidence-heading">
        <div>
          <p className="eyebrow">EVIDÊNCIAS, NÃO PROMESSAS</p>
          <h3 id="evidence-heading">O que conseguimos verificar</h3>
        </div>
        <p>Abra um item para entender o sinal e sua origem.</p>
      </div>
      <div className="evidence-groups">
        {groups.map((group) => {
          const entries = items.filter((item) => item.group === group);
          if (!entries.length) return null;
          return (
            <section className={`evidence-group${group === 'Domínio e conexão' ? ' evidence-group-domain' : ''}`} key={group} aria-label={group}>
              <h4>{group}</h4>
              {entries.map((item) => {
                const Icon = icons[item.state];
                const source = report.sources.find(
                  (entry) => entry.id === item.sourceId,
                );
                return (
                  <details
                    className={`evidence-item state-${item.state.toLowerCase()}`}
                    key={item.id}
                    data-evidence-id={item.id}
                    data-evidence-state={item.state}
                  >
                    <summary>
                      <Icon size={17} aria-hidden="true" />
                      <span>
                        <strong>{item.title}</strong>
                        <span className="evidence-label">{item.label}</span>
                      </span>
                      <ChevronDown size={16} aria-hidden="true" />
                    </summary>
                    <div className="evidence-body">
                      <p>{item.explanation}</p>
                      {item.details.map((detail, index) => (
                        <p key={`${item.id}-${String(index)}`}>{detail}</p>
                      ))}
                      {item.urls.filter(validStoreUrl).map((url) => (
                        <a
                          href={url}
                          key={url}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Ver página de origem
                        </a>
                      ))}
                      <p className="evidence-source">
                        {source?.name ?? "Verificação interna"} ·{" "}
                        {source
                          ? sourceConsultation(report, source)
                          : "Fonte não informada"}
                      </p>
                    </div>
                  </details>
                );
              })}
            </section>
          );
        })}
      </div>
      <p className="fineprint">
        Cinza indica consulta ausente ou indisponível, não uma acusação contra a
        loja.
      </p>
    </section>
  );
}
