import type { DemoScenarioId, Locale, ScanReport, Verdict } from '../types';

const english: Record<DemoScenarioId, {
  summary: string;
  recommendation: string;
  checks: [string, string, string][];
}> = {
  trusted: {
    summary: 'Available evidence indicates a low level of observed purchase risk.',
    recommendation: 'For higher-value purchases, keep your usual safeguards: prefer a credit card or another method with chargeback protection.',
    checks: [
      ['Business', 'Business identified and active', 'Name, registration and address shown by the store match the public record.'],
      ['Domain', 'Domain with consistent history', 'The domain has more than seven years of stable technical history.'],
      ['Security', 'No known threat detected', 'The URL did not match the technical threat sources checked.'],
      ['Reputation', 'Strong complaint resolution', 'Available public history shows consistent replies and resolution.'],
      ['Transparency', 'Essential policies found', 'Returns, privacy, contact details and delivery terms are accessible.'],
      ['Reputation', 'Recent delivery-delay reports', 'Some recent reports mention late delivery, without a critical pattern.'],
    ],
  },
  caution: {
    summary: 'There are legitimate signals, but relevant inconsistencies call for a more protected purchase.',
    recommendation: 'Avoid Pix for a first purchase. Confirm the delivery timeframe in writing and prefer a virtual card with an adjusted limit.',
    checks: [
      ['Business', 'Active business registration', 'The record exists, but the store phone does not match the official source.'],
      ['Domain', 'Recent domain', 'The registration is less than a year old, reducing the available history.'],
      ['Security', 'Valid HTTPS', 'The connection is encrypted and no known technical threat was detected.'],
      ['Reputation', 'Growing complaint volume', 'Recent reports mention slow support and delayed delivery.'],
      ['Transparency', 'Incomplete return policy', 'The cooling-off period is not clearly presented.'],
    ],
  },
  'confirmed-phishing': {
    summary: 'A recognized source confirmed active phishing. The elevated risk overrides all other signals.',
    recommendation: 'Do not provide data or make a payment, and close the website. If you already paid, contact your financial institution immediately.',
    checks: [
      ['Threat', 'Active phishing confirmed', 'The URL is listed as an active threat by a recognized technical source.'],
      ['Business', 'Mismatched and inactive registration', 'The displayed number belongs to an inactive business with a different name.'],
      ['Domain', 'Domain created only days ago', 'The recent registration conflicts with the claim of ten years in business.'],
      ['Payment', 'Irreversible payment as the only option', 'Checkout offers only Pix and redirects to a different domain.'],
    ],
  },
  insufficient: {
    summary: 'The available sources do not provide enough coverage to calculate a responsible score.',
    recommendation: 'Do not decide based on this analysis. Look for verifiable business identification and a payment method with purchase protection.',
    checks: [
      ['Domain', 'Domain found', 'The domain responds, but very little public history is available.'],
      ['Business', 'Business not identified', 'No registration was found on the website for a reliable match.'],
      ['Coverage', 'Reputation source has no data', 'No records does not mean either positive or negative reputation.'],
    ],
  },
  'high-risk': {
    summary: 'Several strong signals indicate elevated risk, even without confirmed phishing or malware.',
    recommendation: 'Avoid purchasing for now. Confirm the business through an independent channel and do not use an irreversible payment method.',
    checks: [
      ['Business', 'Business registration is irregular', 'The observed registration status does not confirm regular operations.'],
      ['Domain', 'Very recent domain', 'The domain is only a few weeks old and has insufficient history.'],
      ['Reputation', 'Severe non-delivery pattern', 'Recent, consistent reports indicate orders that were not delivered.'],
      ['Payment', 'Only irreversible payment', 'The store offers only Pix and does not display a verifiable recipient.'],
      ['Threat', 'No confirmed technical threat', 'The checked sources did not confirm active phishing or malware.'],
    ],
  },
  'business-mismatch': {
    summary: 'The business identity displayed by the store does not match the official record found.',
    recommendation: 'Do not purchase until the store clarifies and corrects its business identification through verifiable channels.',
    checks: [
      ['Business', 'Mismatched business identity', 'The registration, legal name and activity found belong to a different commercial operation.'],
      ['Domain', 'Brand and domain are not correlated', 'The domain does not appear among the registered business’s public signals.'],
      ['Security', 'Valid HTTPS', 'The connection is encrypted, but that does not resolve the identity mismatch.'],
      ['Threat', 'No confirmed malware', 'No active technical threat was confirmed by the sources checked.'],
    ],
  },
};

const scoreLabels: Record<string, string> = {
  business: 'Business identity', domain: 'Domain and history', security: 'Technical security', reputation: 'Consumer reputation',
  transparency: 'Store transparency', presence: 'Public presence', commerce: 'Payment signals', consistency: 'Evidence consistency',
};

export function localizeReport(report: ScanReport, locale: Locale): ScanReport {
  if (locale === 'pt-BR') return report;
  if (report.mode === 'real') return localizeRealReport(report);
  const fallback: Record<Verdict, DemoScenarioId> = { BUY: 'trusted', CAUTION: 'caution', DO_NOT_BUY: 'high-risk', INSUFFICIENT_DATA: 'insufficient' };
  const text = english[report.demoScenarioId ?? fallback[report.verdict]];
  return {
    ...report,
    summary: text.summary,
    recommendation: text.recommendation,
    company: report.company ? {
      ...report.company,
      status: report.company.status === 'Ativa' ? 'Active' : report.company.status === 'Baixada' ? 'Inactive' : report.company.status,
      activity: report.company.activity.replace('Comércio varejista online', 'Online retail').replace('Comércio varejista', 'Retail').replace('Serviços promocionais', 'Promotional services'),
    } : undefined,
    checks: report.checks.map((check, index) => {
      const translated = text.checks.at(index);
      return translated ? { ...check, category: translated[0], title: translated[1], description: translated[2] } : check;
    }),
    scoreAreas: report.scoreAreas.map((area) => ({ ...area, label: scoreLabels[area.id] ?? area.label })),
    sources: report.sources.map((source) => ({
      ...source,
      category: ({ 'Identidade empresarial': 'Business identity', Domínio: 'Domain', Ameaças: 'Threats', 'TLS e cabeçalhos': 'TLS and headers', Reputação: 'Reputation' } as Record<string, string>)[source.category] ?? source.category,
      name: source.name === 'Observação técnica EDY' ? 'EDY technical observation' : source.name,
    })),
    technical: {
      ...report.technical,
      domainAge: report.technical.domainAge.replace('anos e', 'years and').replace('meses', 'months').replace('dias', 'days').replace('Não disponível', 'Unavailable'),
      tls: report.technical.tls.replace('válido até', 'valid until').replace('certificado válido', 'valid certificate').replace('TLS válido', 'Valid TLS'),
      redirects: report.technical.redirects.map((item) => item.replace('domínio principal', 'primary domain').replace('domínio externo', 'external domain')),
      threatStatus: report.technical.threatStatus.replace('Nenhuma correspondência nas fontes consultadas', 'No match in the sources checked').replace('Phishing ativo confirmado', 'Active phishing confirmed').replace('Cobertura parcial', 'Partial coverage'),
      salesVolume: 'Not publicly verifiable',
      paymentSignals: report.technical.paymentSignals.map((item) => ({ 'Cartão de crédito': 'Credit card', Boleto: 'Bank slip', 'Checkout no mesmo domínio': 'Checkout on the same domain', 'Somente Pix': 'Pix only', 'Recebedor não verificável': 'Recipient not verifiable', 'Checkout em domínio diferente': 'Checkout on a different domain', 'Não verificável': 'Not verifiable' } as Record<string, string>)[item] ?? item),
    },
  };
}

const realVerdictText: Record<Verdict, { summary: string; recommendation: string }> = {
  BUY: { summary: 'Good signals were observed in the available sources.', recommendation: 'Current evidence did not reveal a relevant blocker. Prefer a payment method with dispute protection for higher-value purchases.' },
  CAUTION: { summary: 'There are points you should confirm before buying.', recommendation: 'Confirm the business identity and prefer a payment method that supports disputes.' },
  DO_NOT_BUY: { summary: 'Strong evidence of elevated risk was observed.', recommendation: 'Do not purchase or provide card or identity data at this time.' },
  INSUFFICIENT_DATA: { summary: 'There was not enough evidence to responsibly recommend this purchase.', recommendation: 'Avoid irreversible payments until you confirm the business identity through other sources.' },
};

const realCheckTitles: Record<string, string> = {
  DOMAIN_RDAP: 'Authoritative RDAP', DOMAIN_AGE: 'Domain age', DOMAIN_UPDATED: 'Latest domain update', DOMAIN_REGISTRAR: 'Registrar',
  DOMAIN_DNS: 'DNS resolution', DOMAIN_NAMESERVERS: 'Authoritative nameservers', DOMAIN_MX: 'Mail exchangers (MX)', DOMAIN_CAA: 'Certificate authorities (CAA)', DOMAIN_DNSSEC: 'DNSSEC', DOMAIN_STATUS: 'Domain status',
  TLS_HTTPS: 'HTTPS available', TLS_CERTIFICATE: 'TLS certificate', TLS_HOSTNAME: 'Hostname compatibility', TLS_EXPIRATION: 'Certificate validity',
  HTTP_REDIRECTS: 'HTTP redirects', HTTP_FINAL_HOSTNAME: 'Final hostname', HTTP_HEADERS: 'HTTP headers', HTTP_CONTENT: 'Passive content',
  BUSINESS_SITE_IDENTITY: 'Business identity declared on the site', BUSINESS_CNPJ_SITE: 'Business registration declared on the site', BUSINESS_OFFICIAL_VALIDATION: 'Official business validation', BUSINESS_CORRELATION: 'Business and domain correlation', BUSINESS_STRUCTURED_DATA: 'Structured business data',
  TRANSPARENCY_CONTACT: 'Contact page or details', TRANSPARENCY_ADDRESS: 'Declared address', TRANSPARENCY_EMAIL: 'Declared email', TRANSPARENCY_PHONE: 'Declared phone', TRANSPARENCY_ABOUT: 'About content', TRANSPARENCY_PRIVACY: 'Privacy policy', TRANSPARENCY_TERMS: 'Terms of use', TRANSPARENCY_RETURNS: 'Returns policy', TRANSPARENCY_REFUND: 'Refund policy', TRANSPARENCY_SHIPPING: 'Shipping policy', TRANSPARENCY_LEGAL: 'Legal notice or identification',
  THREAT_WEB_RISK: 'Google Web Risk', THREAT_VIRUSTOTAL: 'VirusTotal', THREAT_URLHAUS: 'URLhaus', THREAT_PHISHTANK: 'PhishTank', CONSUMER_REPUTATION: 'Consumer reputation', PUBLIC_SOCIAL_PRESENCE: 'Declared social presence',
  COMMERCE_CATALOG: 'Commerce catalog', COMMERCE_PAYMENT_METHODS: 'Declared payment methods', COMMERCE_PLATFORM: 'Commerce platform', COMMERCE_CHECKOUT_DOMAIN: 'Declared checkout domain', EVIDENCE_CONSISTENCY: 'Self-claim consistency',
};

function localizeRealReport(report: ScanReport): ScanReport {
  const verdictText = realVerdictText[report.verdict];
  const traceById = new Map((report.technical.checkTrace ?? []).map((item) => [item.check, item.reason]));
  return {
    ...report,
    summary: verdictText.summary,
    recommendation: verdictText.recommendation,
    checks: report.checks.map((check) => ({
      ...check,
      category: ({ DOMAIN: 'Domain', DNS: 'DNS', TLS: 'TLS', HTTP: 'HTTP', BUSINESS: 'Business', TRANSPARENCY: 'Transparency', THREAT: 'Threat', CONSUMER: 'Consumer', PRESENCE: 'Public presence', COMMERCE: 'Commerce', CONSISTENCY: 'Consistency' } as Record<string, string>)[check.category] ?? check.category,
      title: check.id.startsWith('HTTP_HEADER_') ? `Header ${check.id.slice('HTTP_HEADER_'.length)}` : (realCheckTitles[check.id] ?? check.title),
      description: englishTraceReason(traceById.get(check.id) ?? check.description),
      value: check.value?.replace('evidência(s)', 'evidence item(s)'),
    })),
    sources: report.sources.map((source) => ({
      ...source,
      name: ({ 'RDAP autoritativo': 'Authoritative RDAP', 'DNS direto': 'Direct DNS', 'TLS direto': 'Direct TLS', 'Site analisado passivamente': 'Passively analyzed site', 'Receita Federal — base CNPJ': 'Federal Revenue — business registry dataset', 'Consumidor.gov.br — acesso credenciado': 'Consumidor.gov.br — credentialed access' } as Record<string, string>)[source.name] ?? source.name,
      category: ({ DOMAIN: 'Domain', TRANSPARENCY: 'Transparency', BUSINESS: 'Business', CONSUMER: 'Consumer', THREAT: 'Threat' } as Record<string, string>)[source.category] ?? source.category,
    })),
    scoreAreas: report.scoreAreas.map((area) => ({ ...area, label: scoreLabels[area.id] ?? area.label })),
    technical: {
      ...report.technical,
      domainAge: report.technical.domainAge.replace('ano(s)', 'year(s)').replace('Não confirmado', 'Not confirmed'),
      domainUpdatedAt: report.technical.domainUpdatedAt?.replace('Não confirmado', 'Not confirmed'),
      registrar: report.technical.registrar.replace('Não confirmado', 'Not confirmed'),
      tls: report.technical.tls.replace('válido', 'valid').replace('Não confirmado', 'Not confirmed'),
      tlsIssuer: report.technical.tlsIssuer.replace('Não confirmado', 'Not confirmed'),
      redirects: report.technical.redirects.map((item) => item.replace('redirecionamento(s) validado(s)', 'validated redirect(s)')),
      finalHostname: report.technical.finalHostname?.replace('Não confirmado', 'Not confirmed'),
      threatStatus: 'Not checked — commercial threat provider disabled',
      salesVolume: 'Not publicly verifiable',
      paymentSignals: report.technical.paymentSignals.map((item) => item.replace('Não verificável', 'Not verifiable')),
    },
  };
}

function englishTraceReason(reason: string): string {
  if (reason.includes('NOT_INDEPENDENTLY_VERIFIED') || reason.includes('Observado no próprio site')) return 'Observed on the site itself; not independently verified.';
  const labels: Record<string, string> = {
    OFFICIAL_PROVIDER_NOT_PROVISIONED: 'The free official source is not provisioned; validation remains unverified.',
    OFFICIAL_IDENTITY_NOT_AVAILABLE: 'Official identity data is unavailable for independent correlation.',
    BILLING_ACCOUNT_REQUIRED: 'A billing-enabled account is required; the provider was not queried.',
    COMMERCIAL_USE_PROHIBITED: 'The public API cannot be used in this commercial product.',
    COMMERCIAL_FAIR_USE_NOT_CONFIRMED: 'Commercial fair-use permission has not been confirmed.',
    PROVIDER_NOT_PROVISIONED: 'The provider is legally eligible but has not been provisioned with its operational controls.',
    AUTHORIZED_AUTOMATIC_SOURCE_UNAVAILABLE: 'No authorized automatic source is available for this check.',
    NO_COMMERCE_CONTEXT_OBSERVED: 'No commerce context was observed; this check is not applicable.',
    NO_USABLE_EVIDENCE: 'The check completed but returned no usable evidence.',
    CONFLICTING_SITE_CLAIMS: 'The site published conflicting claims; this is not an official-record mismatch.',
  };
  return labels[reason] ?? reason.replaceAll('_', ' ').toLocaleLowerCase('en');
}
