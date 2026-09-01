import { AlertTriangle, Check, CircleHelp, ShieldX } from 'lucide-react';
import type { Verdict } from '../types';

export function VerdictIcon({ verdict, size = 22 }: { verdict: Verdict; size?: number }) {
  if (verdict === 'BUY') return <Check size={size} aria-hidden="true" />;
  if (verdict === 'CAUTION') return <AlertTriangle size={size} aria-hidden="true" />;
  if (verdict === 'DO_NOT_BUY') return <ShieldX size={size} aria-hidden="true" />;
  return <CircleHelp size={size} aria-hidden="true" />;
}
