import { cn } from "@/lib/utils";
import { SEVERITY_COLORS, STATE_STYLES } from "@/lib/constants";
import type { JobState, Severity } from "@/lib/types";

/** Severity pill — solid color dot + label, color from semantic constants. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const color = SEVERITY_COLORS[severity] ?? "#888";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
        className
      )}
      style={{ borderColor: `${color}66`, color, backgroundColor: `${color}1a` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {severity}
    </span>
  );
}

/** Job-state pill with a status dot (animated when running). */
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
