import { Clock3, ExternalLink, History as HistoryIcon, RefreshCw, Trash2 } from 'lucide-react';
import type { Copy } from '../lib/i18n';
import type { HistoryEntry, Locale } from '../types';

export function History({ copy, locale, history, onOpen, onRescan, onClear }: { copy: Copy; locale: Locale; history: HistoryEntry[]; onOpen: (entry: HistoryEntry) => void; onRescan: (entry: HistoryEntry) => void; onClear: () => void }) {
  return (
    <main id="main-content" className="subpage">
      <header className="subpage-heading"><p className="eyebrow"><HistoryIcon /> {copy.historyEyebrow}</p><h1>{copy.historyTitle}</h1><p>{copy.historyBody}</p></header>
      {history.length === 0 ? <section className="empty-state large"><span><HistoryIcon /></span><h2>{copy.emptyHistory}</h2><p>{copy.emptyHistoryBody}</p></section> : <>
          <div className="history-list">{history.map((entry) => <article key={entry.id} className={`history-item history-row verdict-border-${entry.verdict.toLowerCase()}`}><div><p className="history-meta"><span className={`history-mode mode-${entry.mode}`}>{entry.mode === 'demo' ? 'DEMO' : 'REAL'}</span><Clock3 /> {new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(entry.scannedAt))}</p><h2>{entry.domain}</h2><span>{copy.verdicts[entry.verdict]} · {copy.confidences[entry.confidence]}</span></div><strong>{entry.score ?? '—'}{entry.score !== null && <small>/100</small>}</strong><div className="history-actions"><button type="button" disabled={!entry.report} title={!entry.report ? copy.reportUnavailable : undefined} onClick={() => onOpen(entry)}><ExternalLink /> {entry.report ? copy.openReport : copy.reportUnavailable}</button><button type="button" onClick={() => onRescan(entry)}><RefreshCw /> {copy.rescan}</button></div></article>)}</div>
        <button className="danger-quiet-button" type="button" onClick={onClear}><Trash2 /> {copy.clearHistory}</button>
      </>}
    </main>
  );
}
