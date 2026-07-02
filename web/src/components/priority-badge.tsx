import { cn } from "@/lib/utils";

/** Manual business-priority badge (1–10). Brand-tinted by magnitude; "—" when unset. */
export function PriorityBadge({ p, className }: { p?: number | null; className?: string }) {
  if (p == null) return <span className={cn("text-xs text-muted-foreground", className)}>—</span>;
  const cls =
    p >= 9 ? "bg-brand text-white"
      : p >= 7 ? "border border-brand/40 bg-brand/15 text-brand"
        : p >= 4 ? "bg-overlay text-muted-foreground"
          : "border border-border text-muted-foreground";
  return (
    <span className={cn("inline-flex items-center rounded-md px-2 py-0.5 font-mono text-[11px] font-bold", cls, className)}>
      {p}<span className="font-medium opacity-60">/10</span>
    </span>
  );
}
