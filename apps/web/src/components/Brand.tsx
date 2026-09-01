export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand" role="img" aria-label="EDY ScanURL">
      <svg className="official-brand-mark" viewBox="0 0 96 96" aria-hidden="true" focusable="false">
        <path className="official-concept04" d="M74 69C65 80 48 83 34 75C18 66 16 44 29 29C41 15 64 14 78 29L52 57Q50 60 47 58L40 51" />
      </svg>
      {!compact && <span className="brand-name"><strong>EDY</strong> Scan<span>URL</span></span>}
    </div>
  );
}
