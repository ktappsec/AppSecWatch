import type { Posture, Severity } from "./types";

export const SEV: Severity[] = ["critical", "high", "medium", "low", "info"];

type Totals = Record<string, number>;

export function dominantSeverity(totals: Totals): Severity | null {
  for (const s of SEV) if ((totals[s] || 0) > 0) return s;
  return null;
}

const POSTURE_MAP: Record<Severity, Posture> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MODERATE",
  low: "LOW",
  info: "LOW",
};

export function posture(totals: Totals): Posture {
  const d = dominantSeverity(totals);
  return d ? POSTURE_MAP[d] : "LOW";
}

/** Client mirror of aggregator.risk_score (0–100). Keep in sync with the server. */
export function riskScore(totals: Totals): number {
  const d = dominantSeverity(totals);
  if (!d) return 0;
  const floor = { critical: 70, high: 45, medium: 25, low: 8, info: 3 }[d];
  const w: Record<Severity, number> = { critical: 45, high: 20, medium: 7, low: 2, info: 0.5 };
  const raw = SEV.reduce((a, s) => a + w[s] * Math.max(0, totals[s] || 0), 0);
  const headroom = 100 - floor;
  return Math.min(100, Math.round(floor + headroom * (raw / (raw + 120))));
}

/** Weighted 0–10 exposure score for a per-asset severity-count map (ranking + meter). */
export function exposureScore(counts: Totals): number {
  const w: Record<Severity, number> = { critical: 10, high: 6, medium: 3, low: 1.5, info: 0.3 };
  const raw = SEV.reduce((a, s) => a + w[s] * (counts[s] || 0), 0);
  return Math.min(10, Math.round(raw * 10) / 10);
}

/** Priority-weighted rank key = exposure × (priority/10), priority default 5. */
export function priorityWeightedScore(counts: Totals, priority?: number | null): number {
  return exposureScore(counts) * ((priority ?? 5) / 10);
}

/** Matrix row index for a 1–10 priority: 0=9–10, 1=7–8, 2=4–6, 3=1–3 (unset→lowest). */
export function priorityBand(p?: number | null): 0 | 1 | 2 | 3 {
  const v = p ?? 0;
  if (v >= 9) return 0;
  if (v >= 7) return 1;
  if (v >= 4) return 2;
  return 3;
}

/** Matrix column for the worst exposure present: 0=Critical…3=Low, 4=None. */
export function worstExposureCol(counts: Totals): 0 | 1 | 2 | 3 | 4 {
  if (counts.critical) return 0;
  if (counts.high) return 1;
  if (counts.medium) return 2;
  if (counts.low) return 3;
  return 4;
}

export function sumCounts(a: Totals): number {
  return SEV.reduce((n, s) => n + (a[s] || 0), 0);
}

/** Fleet exposure = per-severity sum of every asset's last-scan finding_counts. */
export function aggregateExposure(assets: { finding_counts?: Totals }[]): Totals {
  const t: Totals = {};
  for (const a of assets) {
    for (const s of SEV) t[s] = (t[s] || 0) + (a.finding_counts?.[s] || 0);
  }
  return t;
}
