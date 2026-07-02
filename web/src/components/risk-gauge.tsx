"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { useCountUp } from "@/lib/hooks";

export type Rating = "CRITICAL" | "HIGH" | "MODERATE" | "LOW";

const RATING_SEV: Record<Rating, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MODERATE: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

// Ramp the arc by RISK (low→green … critical→red), NOT the brand accent — a
// green risk gauge would falsely read "safe". Colors are CSS-var/color-mix so
// they stay theme-aware without JS.
const STOPS: [number, string][] = [
  [0, "low"],
  [0.4, "medium"],
  [0.72, "high"],
  [1, "critical"],
];
function rampColor(t: number): string {
  if (t <= STOPS[0][0]) return `var(--sev-${STOPS[0][1]})`;
  for (let i = 1; i < STOPS.length; i++) {
    if (t <= STOPS[i][0]) {
      const [p0, a] = STOPS[i - 1];
      const [p1, b] = STOPS[i];
      const pct = Math.round(((t - p0) / (p1 - p0 || 1)) * 100);
      return `color-mix(in srgb, var(--sev-${a}), var(--sev-${b}) ${pct}%)`;
    }
  }
  return `var(--sev-${STOPS[STOPS.length - 1][1]})`;
}

/** Segmented radial risk gauge (0–100). Number/rating colored by posture. */
export function RiskGauge({
  score,
  rating,
  size = 220,
  label = "/ 100 risk",
  className,
}: {
  score: number;
  rating?: Rating;
  size?: number;
  label?: string;
  className?: string;
}) {
  const s = Math.max(0, Math.min(100, score));
  const shown = Math.round(useCountUp(s));
  const N = 44;
  const start = -118;
  const sweep = 236;
  const cx = 115;
  const cy = 115;
  const rI = 72;
  const rO = 96;
  const segs = Array.from({ length: N }, (_, i) => {
    const t = i / (N - 1);
    const a = ((start + t * sweep) * Math.PI) / 180;
    const on = t <= s / 100;
    return {
      x1: cx + rI * Math.sin(a),
      y1: cy - rI * Math.cos(a),
      x2: cx + rO * Math.sin(a),
      y2: cy - rO * Math.cos(a),
      color: on ? rampColor(t) : "var(--overlay)",
      on,
    };
  });
  const numColor = rating ? RATING_SEV[rating] : rampColor(s / 100);
  return (
    <div className={cn("relative shrink-0", className)} style={{ width: size, height: (size * 170) / 230 }}>
      <svg viewBox="0 0 230 170" width="100%" height="100%">
        {segs.map((g, i) => (
          <line
            key={i}
            x1={g.x1.toFixed(1)}
            y1={g.y1.toFixed(1)}
            x2={g.x2.toFixed(1)}
            y2={g.y2.toFixed(1)}
            style={{ stroke: g.color }}
            strokeWidth={4.4}
            strokeLinecap="round"
            opacity={g.on ? 1 : 0.6}
          />
        ))}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center pt-4">
        <div
          className="text-[2.6rem] font-bold leading-none tracking-tight tabular-nums"
          style={{ color: numColor }}
        >
          {shown}
        </div>
        <div className="mt-1 text-xs text-muted-foreground">{label}</div>
      </div>
    </div>
  );
}
