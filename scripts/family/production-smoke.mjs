import { webcrypto } from 'node:crypto';
import { build } from 'esbuild';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Bundle the approved UI validators in memory. No alternate risk/coverage logic.
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const sharedBundle = await build({
  stdin: {
    contents: `export {validateReport} from './apps/web/src/web-pwa/services/report-validation.ts';
      export {riskLevel,analysisCoverage,humanSignals} from './apps/web/src/web-pwa/features/decision.ts';
      export {resultEvidence} from './apps/web/src/web-pwa/features/evidence.ts';`,
    resolveDir: projectRoot,
  },
  bundle: true, platform: 'node', format: 'esm', write: false,
  define: { 'import.meta.env': '{}' }, logLevel: 'silent',
});
const shared = await import(`data:text/javascript;base64,${Buffer.from(sharedBundle.outputFiles[0].text).toString('base64')}`);

const apiOrigin = process.argv[2];
const targets = process.argv.slice(3);
if (!/^https:\/\/[a-z0-9.-]+\.workers\.dev$/i.test(apiOrigin ?? ''))
  throw new Error('INVALID_WORKER_ORIGIN');
if (!targets.length) throw new Error('MISSING_TARGETS');

const encoder = new TextEncoder();
const base64 = (value) => Buffer.from(value).toString('base64');
const hex = (value) => Buffer.from(value).toString('hex');
const pair = await webcrypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,
  ['sign', 'verify'],
);
const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey));
const deviceId = hex(await webcrypto.subtle.digest('SHA-256', spki));

const healthResponse = await fetch(`${apiOrigin}/health`, {
  redirect: 'error',
  cache: 'no-store',
});
const health = await healthResponse.json();
assert(healthResponse.status === 200, 'HEALTH_STATUS');
assert(health.status === 'ok' && health.mode === 'FAMILY_WORKER', 'HEALTH_BODY');
assert(/no-store/.test(healthResponse.headers.get('cache-control') ?? ''), 'HEALTH_CACHE');

const enrollment = await jsonFetch('/family/v1/enroll', {
  method: 'POST',
  body: JSON.stringify({ publicKeySpki: base64(spki) }),
});
assert(enrollment.status === 200, 'ENROLL_STATUS');
assert(enrollment.data.deviceId === deviceId && enrollment.data.status === 'ACTIVE', 'ENROLL_BODY');

const scans = [];
for (const target of targets) scans.push(await scan(target));

const summary = {
  recordedAt: new Date().toISOString(),
  status: scans.every((scan) => scan.currentSchema === 'PASS') ? 'PASS' : 'FAIL',
  apiOrigin,
  health: {
    httpStatus: healthResponse.status,
    body: health,
    cacheControl: healthResponse.headers.get('cache-control'),
    contentType: healthResponse.headers.get('content-type'),
  },
  authentication: 'DEVICE_SIGNATURE',
  durableObject: health.persistence === 'durable-object-sqlite',
  scans,
};
if (process.env.EDY_SMOKE_OUTPUT) {
  const output = resolve(process.env.EDY_SMOKE_OUTPUT);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, JSON.stringify(summary, null, 2) + '\n');
}
console.log(JSON.stringify(summary, null, 2));
if (summary.status !== 'PASS') process.exitCode = 1;

async function scan(target) {
  const normalized = new URL(target);
  normalized.search = '';
  normalized.hash = '';
  const body = JSON.stringify({ url: normalized.href });
  const created = await signed('POST', '/family/v1/scans', body);
  assert(created.status === 202 && typeof created.data.scanId === 'string', 'SCAN_CREATE');
  const result = await signed('GET', `/family/v1/scans/${created.data.scanId}`, '');
  assert(result.status === 200 && result.data.status === 'SUCCEEDED', 'SCAN_RESULT');
  const report = result.data.report;
  validateReport(report, created.data.scanId, normalized.hostname);
  shared.validateReport(report);
  const evidence = shared.resultEvidence(report);
  const signals = shared.humanSignals(report);

  const sourceById = new Map(report.sources.map((source) => [source.id, source]));
  const semantics = report.checks.map((check) => ({
    id: check.id,
    state: semanticState(check, sourceById.get(check.sourceId)),
  }));
  const counts = semantics.reduce((summary, item) => {
    summary[item.state] = (summary[item.state] ?? 0) + 1;
    return summary;
  }, {});
  const negativeCount = (counts.FAIL ?? 0) + (counts.CRITICAL ?? 0);
  const warningCount = counts.WARNING ?? 0;
  const missingCount =
    (counts.MISSING_EVIDENCE ?? 0) +
    (counts.UNAVAILABLE ?? 0) +
    (counts.NOT_CHECKED ?? 0);
  const displayRisk = shared.riskLevel(report);
  const analysisCoverage = shared.analysisCoverage(report);
  const cnpjs = report.storeEvidence?.cnpjs?.map((entry) => entry.value) ?? [];
  const checkIds = report.checks.map((check) => check.id);

  assert(new Set(checkIds).size === checkIds.length, 'DUPLICATE_CHECK_IDS');
  assert(new Set(report.sources.map((source) => source.id)).size === report.sources.length, 'DUPLICATE_SOURCE_IDS');
  assert(new Set(cnpjs).size === cnpjs.length, 'DUPLICATE_CNPJ');
  assert(new Set(evidence.map((item) => item.id)).size === evidence.length, 'DUPLICATE_EVIDENCE_IDS');
  assert(
    report.checks.every((check) =>
      !['UNKNOWN', 'NOT_CHECKED', 'NOT_APPLICABLE'].includes(check.status) ||
      !['negative', 'critical'].includes(check.impact)),
    'MISSING_BECAME_NEGATIVE',
  );

  return {
    target: normalized.origin + '/',
    domain: report.domain,
    verdict: report.verdict,
    score: report.score,
    confidence: report.confidence,
    coverage: report.coverage,
    decisionCoverage: report.technical.decisionCoverage ?? null,
    displayRisk,
    analysisCoverage,
    semanticCounts: counts,
    negativeEvidence: negativeCount,
    concreteWarnings: warningCount,
    insufficientChecks: missingCount,
    cnpjCount: report.storeEvidence ? cnpjs.length : null,
    cnpjUnique: report.storeEvidence ? new Set(cnpjs).size === cnpjs.length : null,
    checkIdsUnique: true,
    sourceIdsUnique: true,
    evidenceIdsUnique: true,
    approvedFrontendSchema: 'PASS',
    currentSchema: report.storeEvidence?.version === 1 && typeof report.technical.confirmedCriticalThreat === 'boolean' ? 'PASS' : 'FAIL',
    currentSchemaFields: {
      storeEvidenceVersion: report.storeEvidence?.version ?? null,
      confirmedCriticalThreatPresent: typeof report.technical.confirmedCriticalThreat === 'boolean',
      policyEvidenceCount: report.storeEvidence?.policies?.length ?? null,
      pagesFetched: report.technical.pagesFetched ?? null,
      checkTracePresent: Array.isArray(report.technical.checkTrace),
    },
    uiCounts: Object.fromEntries(Object.entries(signals).map(([key, values]) => [key, values.length])),
    uiEvidence: Object.fromEntries(Object.entries(signals).map(([group, values]) => [group, values.map((item) => ({
      id: item.id,
      checkId: item.checkId,
      state: item.state,
      title: item.title,
      label: item.label,
      explanation: item.explanation,
      sourceId: item.sourceId,
      sourceStatus: sourceById.get(item.sourceId)?.status ?? 'absent',
    }))])),
    checks: report.checks.map((check) => ({ id: check.id, status: check.status, impact: check.impact, points: check.points })),
    checkTrace: report.technical.checkTrace?.filter((entry) => report.checks.some((check) => check.id === entry.check)).map((entry) => ({
      check: entry.check,
      attempted: entry.attempted,
      finalState: entry.finalState,
      provider: entry.provider,
      reason: entry.reason,
    })) ?? [],
    virusTotalState: report.technical.virusTotal?.state ?? 'ABSENT',
  };
}

function semanticState(check, source) {
  if (check.status === 'FAIL' || check.status === 'CRITICAL' ||
      check.impact === 'negative' || check.impact === 'critical') return 'FAIL';
  if (check.status === 'WARNING' || check.impact === 'warning') return 'WARNING';
  if (check.status === 'NOT_CHECKED' || check.status === 'NOT_APPLICABLE') return 'NOT_CHECKED';
  if (source?.status === 'unavailable') return 'UNAVAILABLE';
  if (check.status === 'PASS') return 'PASS';
  return 'MISSING_EVIDENCE';
}

function validateReport(report, scanId, expectedDomain) {
  assert(report && typeof report === 'object', 'REPORT_OBJECT');
  assert(report.id === scanId && report.mode === 'real', 'REPORT_ID_MODE');
  assert(report.domain === expectedDomain, 'REPORT_DOMAIN');
  assert(['BUY', 'CAUTION', 'DO_NOT_BUY', 'INSUFFICIENT_DATA'].includes(report.verdict), 'REPORT_VERDICT');
  assert(report.score === null || (Number.isFinite(report.score) && report.score >= 0 && report.score <= 100), 'REPORT_SCORE');
  assert(Number.isFinite(report.coverage) && report.coverage >= 0 && report.coverage <= 100, 'REPORT_COVERAGE');
  assert(Array.isArray(report.checks) && report.checks.length > 0, 'REPORT_CHECKS');
  assert(Array.isArray(report.sources) && report.sources.length > 0, 'REPORT_SOURCES');
  assert(report.technical && typeof report.technical === 'object', 'REPORT_TECHNICAL');
  const serialized = JSON.stringify(report);
  assert(!/CLOUDFLARE_API_TOKEN|VIRUSTOTAL_API_KEY|RATE_LIMIT_SECRET|PRIVATE KEY/i.test(serialized), 'SECRET_MARKER');
}

async function jsonFetch(path, init) {
  const response = await fetch(`${apiOrigin}${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
    redirect: 'error',
    cache: 'no-store',
  });
  const text = await response.text();
  let data = {};
  try { data = JSON.parse(text); }
  catch { throw new Error(`NON_JSON:${response.status}`); }
  return { status: response.status, data };
}

async function signed(method, path, body) {
  const bodyHash = hex(await webcrypto.subtle.digest('SHA-256', encoder.encode(body)));
  const challenge = await jsonFetch('/family/v1/challenge', {
    method: 'POST',
    body: JSON.stringify({ deviceId, method, path, bodyHash }),
  });
  assert(challenge.status === 200 && typeof challenge.data.message === 'string', 'CHALLENGE');
  const raw = new Uint8Array(await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    pair.privateKey,
    encoder.encode(challenge.data.message),
  ));
  return jsonFetch(path, {
    method,
    body: method === 'POST' ? body : undefined,
    headers: {
      'X-Family-Device': deviceId,
      'X-Family-Challenge': challenge.data.challengeId,
      'X-Family-Signature': base64(rawToDer(raw)),
    },
  });
}

function rawToDer(raw) {
  const integer = (part) => {
    let index = 0;
    while (index < part.length - 1 && part[index] === 0) index += 1;
    const value = [...part.slice(index)];
    if ((value[0] ?? 0) >= 128) value.unshift(0);
    return [2, value.length, ...value];
  };
  const sequence = [...integer(raw.slice(0, 32)), ...integer(raw.slice(32))];
  return new Uint8Array([0x30, sequence.length, ...sequence]);
}

function assert(condition, code) {
  if (!condition) throw new Error(code);
}
