import { cn } from "@/lib/utils";
import { SEVERITY_CLASSES, SEVERITY_ORDER, STATE_STYLES } from "@/lib/constants";
import type { JobState, Severity } from "@/lib/types";

const FALLBACK = SEVERITY_CLASSES.info;

/** Small severity-colored dot — the atom shared by badges/counts/tables. */
export function SeverityDot({ severity, className }: { severity: string; className?: string }) {
  const c = SEVERITY_CLASSES[severity] ?? FALLBACK;
  return <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", c.dot, className)} />;
}

/** Severity pill — token-driven dot + label. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const c = SEVERITY_CLASSES[severity] ?? FALLBACK;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
        c.badge,
        className
      )}
    >
      <SeverityDot severity={severity} />
      {severity}
    </span>
  );
}

/** Compact per-severity count row (dot + tabular count), ordered critical→info.
 * Renders nothing when every count is zero and `showEmpty` is off. */
export function SeverityCounts({
  counts,
  showEmpty = false,
  className,
}: {
  counts: Partial<Record<string, number>>;
  showEmpty?: boolean;
  className?: string;
}) {
  const entries = SEVERITY_ORDER.filter((s) => showEmpty || (counts[s] ?? 0) > 0);
  if (entries.length === 0) return null;
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      {entries.map((s) => (
        <span key={s} className="inline-flex items-center gap-1 text-xs tabular-nums" title={s}>
          <SeverityDot severity={s} />
          {counts[s] ?? 0}
        </span>
      ))}
    </span>
  );
}

/** Job-state pill with a status dot (animated when running). */
/** Warning badge for a degraded scan (0 live servers despite live assets — the
 *  probe was blocked, so a zero-finding result is inconclusive, not "clean"). */
export function DegradedBadge({ className, title }: { className?: string; title?: string }) {
  return (
    <span
      title={title ?? "Scan degraded — the target blocked the probe; results are inconclusive"}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium",
        "border-warning/40 bg-warning/10 text-warning",
        className
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-warning" />
      Blocked
    </span>
  );
}

export function StateBadge({ state, className }: { state: JobState; className?: string }) {
  const s = STATE_STYLES[state] ?? STATE_STYLES.queued;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium",
        s.className,
        className
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", s.dot)} />
      {s.label}
    </span>
  );
}
