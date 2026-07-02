import * as React from "react";
import { cn } from "@/lib/utils";

const TONE: Record<string, string> = {
  brand: "var(--brand)",
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
  success: "var(--success)",
  warning: "var(--warning)",
};

/** Segmented "score" meter (the dashed exposure bar). `tone` maps to a token. */
export function ScoreMeter({
  value,
  max = 10,
  segments = 10,
  tone = "brand",
  className,
}: {
  value: number;
  max?: number;
  segments?: number;
  tone?: string;
  className?: string;
}) {
  const on = Math.max(0, Math.min(segments, Math.round((value / max) * segments)));
  const color = TONE[tone] ?? tone;
  return (
    <div className={cn("flex items-center gap-[3px]", className)} aria-hidden>
      {Array.from({ length: segments }, (_, i) => (
        <span
          key={i}
          className="h-2 w-[9px] rounded-[2px]"
          style={{ background: i < on ? color : "var(--overlay)" }}
        />
      ))}
    </div>
  );
}
