import { describe, expect, it } from 'vitest';
import type { ScanReport, Check } from '../../types';
import { riskLevel, humanSignals } from './decision';
import { resultSnapshot, sanitizeHistory, savedSummary } from './history';
import { shareText } from './results';
import { validateReport } from '../services/report-validation';

function report(): ScanReport {
  return { id:'test-only', mode:'real', inputUrl:'https://example.com/', normalizedUrl:'https://example.com/', domain:'example.com', scannedAt:new Date().toISOString(), verdict:'BUY', score:90, confidence:'HIGH', coverage:90, summary:'Test-only', recommendation:'Test-only', scoreAreas:[],
    checks:[{id:'DOMAIN_DNS', title:'DNS',description:'Resposta pública',category:'domain',impact:'positive',status:'PASS',points:10,sourceId:'dns'}],
    sources:[{id:'dns',name:'DNS',category:'domain',tier:1,status:'available'}],
    technical:{domainAge:'',registrar:'',dns:[],tls:'',tlsIssuer:'',redirects:[],headers:[],threatStatus:'',salesVolume:'',paymentSignals:[],decisionCoverage:90} };
}
describe('web-only risk decision independent from insufficient coverage', () => {
  it('allows LOW only with the actual BUY gates',()=>expect(riskLevel(report())).toBe('LOW'));
  it.each(['INSUFFICIENT_DATA','CAUTION'] as const)('does not override %s with a high displayed score',verdict=>expect(riskLevel({...report(),verdict})).toBe('UNDETERMINED'));
  it.each([null, 0, 79])('never approves missing/low score %s or infers concrete risk from it',score=>expect(riskLevel({...report(),score})).toBe('UNDETERMINED'));
  it('uses weighted coverage instead of check counts',()=>{const input=report();input.technical.decisionCoverage=25;expect(riskLevel(input)).toBe('UNDETERMINED');});
  it('rejects LOW with unavailable corroborating source',()=>{const input=report();input.sources[0].status='unavailable';expect(riskLevel(input)).toBe('UNDETERMINED');expect(humanSignals(input).positive).toHaveLength(0);});
  it('never upgrades missing evidence to a risk',()=>{const input=report();input.verdict='INSUFFICIENT_DATA';input.checks[0].status='UNKNOWN';input.checks[0].impact='neutral';expect(riskLevel(input)).toBe('UNDETERMINED');expect(humanSignals(input).risks).toHaveLength(0);expect(humanSignals(input).attention).toHaveLength(0);expect(humanSignals(input).missing).toHaveLength(1);});
  it('preserves actual negative evidence despite insufficient coverage',()=>{const input=report();input.verdict='INSUFFICIENT_DATA';input.score=null;input.checks[0].status='FAIL';input.checks[0].impact='negative';expect(riskLevel(input)).toBe('HIGH');});
  it('never infers a critical blocker from a low score or FAIL',()=>{const input=report();input.verdict='DO_NOT_BUY';input.checks[0].status='FAIL';expect(riskLevel(input)).toBe('HIGH');});
  it('requires a real backend-confirmed blocker for CRITICAL',()=>{const input=report();input.verdict='DO_NOT_BUY';input.technical.confirmedCriticalThreat=true;input.checks[0].status='CRITICAL';expect(riskLevel(input)).toBe('CRITICAL');});
  it('ignores contradictory critical metadata without negative evidence',()=>{const input=report();input.verdict='DO_NOT_BUY';input.technical.confirmedCriticalThreat=true;expect(riskLevel(input)).toBe('HIGH');});
  it('deduplicates counters and evidence ids',()=>{const input=report();input.checks.push({...input.checks[0]});expect(humanSignals(input).positive).toHaveLength(1);});
  it('null or undefined status never becomes PASS',()=>{for(const status of [undefined,null]) {const input=report();input.checks[0].status=status as Check['status'];const parsed=validateReport(input);expect(humanSignals(parsed).positive).toHaveLength(0);}});
  it('accepts old schema without additive evidence',()=>{const input=report();delete input.technical.confirmedCriticalThreat;expect(validateReport(input).domain).toBe('example.com');});
  it('rejects a malformed critical confirmation',()=>{const input=report();expect(()=>validateReport({...input,technical:{...input.technical,confirmedCriticalThreat:'true'}})).toThrow();});
  it('keeps insufficiency in the reduced local snapshot',()=>{const input=report();input.verdict='INSUFFICIENT_DATA';const saved=resultSnapshot(input);expect(sanitizeHistory([saved])[0].insufficient).toBe(true);expect(savedSummary(saved).tone).toBe('partial');});
  it('preserves weighted coverage and LOW across a history reload',()=>{const input=report();input.coverage=60;input.technical.decisionCoverage=90;const saved=sanitizeHistory([resultSnapshot(input)])[0];expect(saved.risk).toBe('LOW');expect(saved.decisionCoverage).toBe(90);});
  it('preserves a sufficient CAUTION as distinct from insufficient',()=>{const input=report();input.verdict='CAUTION';input.checks[0].status='WARNING';input.checks[0].impact='warning';const saved=sanitizeHistory([resultSnapshot(input)])[0];expect(saved.risk).toBe('MODERATE');expect(saved.insufficient).toBe(false);expect(saved.analysisCoverage).toBe('SUFFICIENT');});
  it('keeps a real risk in history, not the old presentation tone',()=>{const input=report();input.verdict='INSUFFICIENT_DATA';input.checks[0].status='FAIL';const saved=resultSnapshot(input);expect(savedSummary(saved).tone).toBe('risk');expect(shareText(saved)).toContain('RISCO ALTO');});
  it('downgrades corrupted local LOW instead of inventing moderate risk',()=>{const saved={...resultSnapshot(report()),score:null,confidence:'LOW',coverage:0};expect(sanitizeHistory([saved])[0].risk).toBe('UNDETERMINED');});
  it('shares exactly the human fields, never report internals',()=>{const text=shareText(resultSnapshot(report()));expect(text).toContain('Site:\nexample.com');expect(text).toContain('Resultado:\nPode comprar com cautela');expect(text).not.toMatch(/technical|signature|deviceId|token|inputUrl/);});
});
