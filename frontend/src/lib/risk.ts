export type CanonicalRiskLevel = 'RED' | 'YELLOW' | 'SAFE' | 'UNVERIFIED';

export function normalizeRiskLevel(level?: string | null): CanonicalRiskLevel {
  const l = String(level || '').trim().toUpperCase();
  if (!l || l === 'UNVERIFIED' || l === 'INSUFFICIENT' || l === 'UNKNOWN') return 'UNVERIFIED';
  if (l === 'RED' || l === 'HIGH' || l === 'CRITICAL' || l === 'DANGER' || l === 'CONFIRMED_RISK' || l === 'HIGH_RISK') {
    return 'RED';
  }
  if (l === 'YELLOW' || l === 'MEDIUM' || l === 'WARN' || l === 'WARNING' || l === 'ORANGE' || l === 'SUSPICIOUS') {
    return 'YELLOW';
  }
  if (l === 'GREEN' || l === 'SAFE' || l === 'LOW' || l === 'LIKELY_SAFE') {
    return 'SAFE';
  }
  return 'YELLOW';
}

export function riskBadge(level?: string | null): string {
  const c = normalizeRiskLevel(level);
  if (c === 'RED') return 'bg-danger-500/20 text-danger-500 border border-danger-500/30';
  if (c === 'YELLOW') return 'bg-warn-500/20 text-warn-500 border border-warn-500/30';
  if (c === 'UNVERIFIED') return 'bg-slate-500/20 text-slate-300 border border-slate-400/30';
  return 'bg-safe-500/20 text-safe-500 border border-safe-500/30';
}

export function riskGlow(level?: string | null): string {
  const c = normalizeRiskLevel(level);
  if (c === 'RED') return 'bg-danger-500';
  if (c === 'YELLOW') return 'bg-warn-500';
  if (c === 'UNVERIFIED') return 'bg-slate-500';
  return 'bg-safe-500';
}

export function riskTextClass(level?: string | null): string {
  const c = normalizeRiskLevel(level);
  if (c === 'RED') return 'text-danger-400';
  if (c === 'YELLOW') return 'text-warn-400';
  if (c === 'UNVERIFIED') return 'text-slate-300';
  return 'text-safe-400';
}

export function riskStrokeClass(level?: string | null): string {
  const c = normalizeRiskLevel(level);
  if (c === 'RED') return 'text-danger-500';
  if (c === 'YELLOW') return 'text-warn-400';
  if (c === 'UNVERIFIED') return 'text-slate-400';
  return 'text-safe-400';
}

export function riskSolidPillClass(level?: string | null): string {
  const c = normalizeRiskLevel(level);
  if (c === 'RED') return 'bg-danger-500 text-white';
  if (c === 'YELLOW') return 'bg-warn-400 text-black';
  if (c === 'UNVERIFIED') return 'bg-slate-500 text-white';
  return 'bg-safe-400 text-black';
}

export function riskRingBoxClass(level?: string | null): string {
  const c = normalizeRiskLevel(level);
  if (c === 'RED') return 'border-danger-500/30 text-danger-400 bg-danger-500/5';
  if (c === 'YELLOW') return 'border-warn-500/30 text-warn-400 bg-warn-500/5';
  if (c === 'UNVERIFIED') return 'border-slate-400/30 text-slate-300 bg-slate-500/10';
  return 'border-safe-500/30 text-safe-400 bg-safe-500/5';
}

export function scoreCssVarColor(score: number): string {
  if (score >= 70) return 'var(--sc-danger-500)';
  if (score >= 40) return 'var(--sc-warn-500)';
  return 'var(--sc-safe-500)';
}
