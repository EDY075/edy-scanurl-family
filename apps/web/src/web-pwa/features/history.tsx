import { useEffect, useState } from "react";
import { ArrowUpRight, Clock3, Trash2 } from "lucide-react";
import type { ScanReport } from "../../types";
import {
  summarizeFamilyReport,
  type FamilyVerdict,
} from "../../family/family-presentation";
import { readPreference, writePreference } from "../hooks/usePreferences";
import { validStoreUrl } from "../utils/url";
import { riskLevel, decisionCopy, decisionLabel, analysisCoverage, type AnalysisCoverage, type RiskLevel } from './decision';

export interface SavedResult {
  domain: string;
  time: string;
  verdict: FamilyVerdict;
  score: number | null;
  confidence: ScanReport["confidence"];
  coverage: number;
  decisionCoverage?: number;
  risk?: RiskLevel;
  insufficient?: boolean;
  analysisCoverage?: AnalysisCoverage;
}
const KEY = "edy-web-history-v1";
const ENABLED = "edy-web-history-enabled";
export function resultSnapshot(report: ScanReport): SavedResult {
  return {
    domain: report.domain,
    time: report.scannedAt,
    verdict: summarizeFamilyReport(report).verdict,
    score: report.score,
    confidence: report.confidence,
    coverage: report.coverage,
    ...(typeof report.technical.decisionCoverage === 'number' ? { decisionCoverage: report.technical.decisionCoverage } : {}),
    risk: riskLevel(report),
    analysisCoverage: analysisCoverage(report),
    insufficient: report.verdict === 'INSUFFICIENT_DATA',
  };
}
export function sanitizeHistory(
  input: unknown,
  now = Date.now(),
): SavedResult[] {
  if (!Array.isArray(input)) return [];
  return input
    .slice(0, 100)
    .flatMap((value: unknown) => {
      if (!value || typeof value !== "object") return [];
      const item = value as Record<string, unknown>;
      const normalized =
        typeof item.domain === "string" ? validStoreUrl(item.domain) : null;
      if (
        typeof item.domain !== "string" ||
        !normalized ||
        new URL(normalized).hostname !== item.domain ||
        typeof item.time !== "string" ||
        !Number.isFinite(Date.parse(item.time)) ||
        Date.parse(item.time) > now ||
        Date.parse(item.time) < now - 30 * 86400_000 ||
        !["Confiável", "Atenção", "Alto risco"].includes(
          String(item.verdict),
        ) ||
        !["LOW", "MEDIUM", "HIGH", "VERY_HIGH"].includes(
          String(item.confidence),
        ) ||
        !(
          item.score === null ||
          (typeof item.score === "number" &&
            item.score >= 0 &&
            item.score <= 100)
        ) ||
        typeof item.coverage !== "number" ||
        !Number.isFinite(item.coverage) ||
        item.coverage < 0 ||
        item.coverage > 100
      )
        return [];
      const decisionCoverage = typeof item.decisionCoverage === 'number' && Number.isFinite(item.decisionCoverage) && item.decisionCoverage >= 0 && item.decisionCoverage <= 100 ? item.decisionCoverage : undefined;
      return [
        {
          domain: item.domain,
          time: item.time,
          verdict: item.verdict as FamilyVerdict,
          score: item.score,
          confidence: item.confidence as ScanReport["confidence"],
          coverage: item.coverage,
          ...(decisionCoverage !== undefined ? { decisionCoverage } : {}),
          ...(['LOW', 'MODERATE', 'HIGH', 'CRITICAL', 'UNDETERMINED'].includes(String(item.risk)) ? { risk: item.risk === 'LOW' && !(item.verdict === 'Confiável' && typeof item.score === 'number' && item.score >= 80 && (decisionCoverage ?? item.coverage) >= 80 && ['HIGH','VERY_HIGH'].includes(String(item.confidence)) && item.insufficient !== true) ? 'UNDETERMINED' as const : item.risk as RiskLevel } : {}),
          ...(typeof item.insufficient === 'boolean' ? { insufficient: item.insufficient } : {}),
          ...(['PARTIAL','SUFFICIENT'].includes(String(item.analysisCoverage)) ? { analysisCoverage: item.insufficient === true || (decisionCoverage ?? item.coverage) < 80 ? 'PARTIAL' as const : item.analysisCoverage as AnalysisCoverage } : {}),
        },
      ];
    })
    .sort((a, b) => Date.parse(b.time) - Date.parse(a.time))
    .slice(0, 20);
}
export function savedRisk(item: SavedResult): RiskLevel {
  // Old incomplete MODERATE snapshots did not distinguish missing data from alerts.
  // Preserve explicit high/critical findings, but never manufacture a risk from an old fallback.
  if (item.verdict === 'Alto risco' || item.risk === 'HIGH' || item.risk === 'CRITICAL') return item.risk === 'CRITICAL' ? 'CRITICAL' : 'HIGH';
  if (!item.analysisCoverage && item.insufficient && item.risk === 'MODERATE') return 'UNDETERMINED';
  return item.risk ?? 'UNDETERMINED';
}
export function savedSummary(item: SavedResult) {
  const level = savedRisk(item);
  const copy = decisionCopy[level];
  return {
    verdict: item.verdict,
    tone: copy.tone,
    summary: `A consulta salva indicou: ${copy.title}.`,
    recommendation: copy.recommendation,
    reasons: [],
  };
}
export function useLocalHistory() {
  const [enabled, setEnabled] = useState(
    () => readPreference(ENABLED) === "true",
  );
  const [items, setItems] = useState<SavedResult[]>(() => {
    try {
      return readPreference(ENABLED) === "true"
        ? sanitizeHistory(JSON.parse(readPreference(KEY) ?? "[]") as unknown)
        : [];
    } catch {
      return [];
    }
  });
  const [notice, setNotice] = useState("");
  // Persist the sanitized subset on load as well, removing expired records.
  useEffect(() => {
    writePreference(KEY, enabled && items.length ? JSON.stringify(items) : null);
  }, [enabled, items]);
  const persist = (next: SavedResult[]) => {
    setItems(next);
    if (!writePreference(KEY, JSON.stringify(next)))
      setNotice("Não foi possível salvar o histórico neste navegador.");
  };
  return {
    enabled,
    items,
    notice,
    toggle: (value: boolean) => {
      setEnabled(value);
      if (!writePreference(ENABLED, String(value)))
        setNotice(
          "A preferência vale somente enquanto esta página estiver aberta.",
        );
      if (!value) {
        setItems([]);
        writePreference(KEY, null);
      }
    },
    add: (report: ScanReport) => {
      if (readPreference(ENABLED) === "true")
        persist(
          sanitizeHistory([
            resultSnapshot(report),
            ...items.filter((item) => item.domain !== report.domain),
          ]),
        );
    },
    remove: (domain: string) => {
      persist(items.filter((item) => item.domain !== domain));
    },
    clear: () => {
      setItems([]);
      writePreference(KEY, null);
      setNotice("Histórico limpo neste navegador.");
    },
  };
}
export type HistoryState = ReturnType<typeof useLocalHistory>;
export function HistoryPanel({
  history,
  reopen,
}: {
  history: HistoryState;
  reopen: (item: SavedResult) => void;
}) {
  return (
    <section
      className="history-section section-block"
      id="historico"
      aria-labelledby="history-title"
    >
      <div className="section-top">
        <div>
          <p className="eyebrow">SÓ NESTE NAVEGADOR</p>
          <h2 id="history-title">
            <Clock3 size={22} /> Verificações recentes
          </h2>
        </div>
        {history.items.length > 0 && (
          <button className="text-button" onClick={history.clear}>
            <Trash2 size={16} /> Limpar histórico
          </button>
        )}
      </div>
      <label className="history-optin">
        <input
          type="checkbox"
          checked={history.enabled}
          onChange={(event) => {
            history.toggle(event.target.checked);
          }}
        />{" "}
        Guardar um resumo das próximas verificações
      </label>
      <p className="fineprint">
        Suas verificações recentes ficam salvas somente neste dispositivo.{' '}
        Opcional. Até 20 lojas por 30 dias. Desativar apaga os resumos. Não
        guardamos o histórico no servidor.
      </p>
      {!history.items.length && (
        <p className="empty-history">
          Nenhum site verificado ainda.{' '}
          {history.enabled
            ? "Sua próxima verificação aparecerá aqui."
            : "Seu histórico está desativado. Você pode verificar uma loja normalmente."}
        </p>
      )}
      <ul className="history-list">
        {history.items.map((item) => (
          <li key={item.domain}>
            <button
              className="history-open"
              onClick={() => {
                reopen(item);
              }}
            >
              <span>
                <strong>{item.domain}</strong>
                <small>{savedSummary(item).summary}</small>
                <time dateTime={item.time}>{formatDate(item.time)}</time>
              </span>
              <span className={`verdict-small ${savedSummary(item).tone}`}>
                {decisionLabel(savedRisk(item), item.analysisCoverage ?? 'PARTIAL')}
                <ArrowUpRight size={16} />
              </span>
            </button>
            <button
              className="icon-button"
              aria-label={`Excluir ${item.domain} do histórico`}
              onClick={() => {
                history.remove(item.domain);
              }}
            >
              <Trash2 size={17} />
            </button>
          </li>
        ))}
      </ul>
      <p role="status" className="fineprint">
        {history.notice}
      </p>
    </section>
  );
}
export function formatDate(value: string): string {
  return new Date(value).toLocaleString("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
  });
}
