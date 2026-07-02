"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

const TONE: Record<string, string> = {
  brand: "var(--brand)",
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
  warning: "var(--warning)",
  success: "var(--success)",
  muted: "var(--muted-foreground)",
};

/** Tiny inline area+line spark (no axes). `tone` maps to a token, or pass a raw color. */
export function Sparkline({
  data,
  tone = "brand",
  filled = true,
  strokeWidth = 2,
  className,
}: {
  data: number[];
  tone?: string;
  filled?: boolean;
  strokeWidth?: number;
  className?: string;
}) {
  const rid = React.useId().replace(/:/g, "");
  if (!data || data.length < 2) return <div className={className} />;
  const color = TONE[tone] ?? tone;
  const W = 200;
  const H = 40;
  const pad = 4;
  const mn = Math.min(...data);
  const mx = Math.max(...data);
  const xs = (i: number) => (i * W) / (data.length - 1);
  const ys = (v: number) => H - pad - ((v - mn) / (mx - mn || 1)) * (H - pad * 2);
  const line = data.map((v, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${ys(v).toFixed(1)}`).join(" ");
  const area = `${line} L${W},${H} L0,${H} Z`;
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className={cn("h-full w-full", className)}
      preserveAspectRatio="none"
      aria-hidden
    >
      {filled && (
        <>
          <defs>
            <linearGradient id={`spark-${rid}`} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stopColor={color} stopOpacity="0.26" />
              <stop offset="1" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={area} fill={`url(#spark-${rid})`} />
        </>
      )}
      <path
        d={line}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
