import * as React from "react";
import { cn } from "@/lib/utils";

export interface MatrixRow {
  /** priority band label, e.g. "9–10" */
  range: string;
  /** business-criticality word, e.g. "Critical" */
  label: string;
  /** asset counts per exposure column: [Critical, High, Medium, Low, None] */
  cells: number[];
}

const COLS = ["Critical", "High", "Medium", "Low", "None"];
const SEV = ["critical", "high", "medium", "low", null] as const;
const PW = [1, 0.72, 0.48, 0.28];
const CW = [1, 0.72, 0.48, 0.28, 0];

/**
 * Business priority (rows, high→low) × worst exposure (cols, critical→none).
 * Cell tint scales with urgency (priority × exposure); the single most-urgent
 * non-empty cell is ringed as "act first".
 */
export function PrioritizationMatrix({ rows, className }: { rows: MatrixRow[]; className?: string }) {
  let best = { u: -1, r: -1, c: -1 };
  rows.forEach((row, ri) =>
    row.cells.forEach((n, ci) => {
      const u = PW[ri] * CW[ci];
      if (n > 0 && u > best.u) best = { u, r: ri, c: ci };
    })
  );

  return (
    <div className={cn("grid items-center gap-1.5", className)} style={{ gridTemplateColumns: "auto repeat(5,1fr)" }}>
      <div />
      {COLS.map((c) => (
        <div key={c} className="text-center text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
          {c}
        </div>
      ))}
      {rows.map((row, ri) => (
        <React.Fragment key={row.range}>
          <div className="whitespace-nowrap pr-2 text-[11.5px] font-semibold text-muted-foreground">
            {row.range} · {row.label}
          </div>
          {row.cells.map((n, ci) => {
            const u = PW[ri] * CW[ci];
            const s = SEV[ci];
            const bg = s
              ? `color-mix(in srgb, var(--sev-${s}) ${Math.round(u * 74)}%, var(--card))`
              : "var(--overlay)";
            const isBest = ri === best.r && ci === best.c;
            const color = n === 0 ? "var(--muted-foreground)" : u >= 0.45 ? "#fff" : "var(--foreground)";
            return (
              <div
                key={ci}
                className={cn(
                  "grid min-h-[44px] place-items-center rounded-lg border border-border text-[15px] font-bold transition-transform hover:scale-[1.04]",
                  n === 0 && "opacity-55"
                )}
                style={{
                  background: bg,
                  color,
                  outline: isBest ? "2px solid var(--sev-high)" : undefined,
                  outlineOffset: isBest ? "1px" : undefined,
                }}
                title={`${row.range} priority · worst exposure ${COLS[ci]}: ${n} asset${n === 1 ? "" : "s"}`}
              >
                {n || ""}
              </div>
            );
          })}
        </React.Fragment>
      ))}
    </div>
  );
}
