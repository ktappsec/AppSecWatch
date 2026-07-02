import type { LucideIcon } from "lucide-react";
import { TrendingUp, TrendingDown } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Sparkline } from "@/components/sparkline";
import { cn } from "@/lib/utils";

type Accent = "brand" | "critical" | "high" | "warning" | "success" | "muted";

const ACCENT_ICON: Record<Accent, string> = {
  brand: "bg-brand/10 text-brand",
  critical: "bg-sev-critical/12 text-sev-critical",
  high: "bg-sev-high/12 text-sev-high",
  warning: "bg-warning/15 text-warning",
  success: "bg-success/12 text-success",
  muted: "bg-muted text-muted-foreground",
};

interface StatCardProps {
  title: string;
  value: React.ReactNode;
  icon: LucideIcon;
  delay?: number;
  trend?: { value: string; positive?: boolean };
  hint?: string;
  accent?: Accent;
  spark?: number[];
  sparkTone?: string;
  iconClassName?: string;
}

/** KPI card — large value, top-right icon box, optional trend + embedded sparkline. */
export function StatCard({
  title,
  value,
  icon: Icon,
  delay = 0,
  trend,
  hint,
  accent = "brand",
  spark,
  sparkTone,
  iconClassName,
}: StatCardProps) {
  return (
    <Card
      className={cn(
        "relative gap-0 overflow-hidden p-5 transition-smooth animate-fade-in-up",
        "hover:border-brand/40 hover:shadow-pop"
      )}
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1.5">
          <p className="text-xs font-medium tracking-wide text-muted-foreground">{title}</p>
          <p className="text-3xl font-semibold leading-tight tracking-tight tabular-nums">
            {value}
          </p>
        </div>
        <div
          className={cn(
            "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg",
            ACCENT_ICON[accent],
            iconClassName
          )}
        >
          <Icon className="h-5 w-5" />
        </div>
      </div>
      {(trend || hint) && (
        <div className="mt-3 flex items-center gap-2 text-xs">
          {trend && (
            <span
              className={cn(
                "inline-flex items-center gap-1 font-medium",
                trend.positive ? "text-success" : "text-destructive"
              )}
            >
              {trend.positive ? (
                <TrendingUp className="h-3.5 w-3.5" />
              ) : (
                <TrendingDown className="h-3.5 w-3.5" />
              )}
              {trend.value}
            </span>
          )}
          {hint && <span className="text-muted-foreground">{hint}</span>}
        </div>
      )}
      {spark && spark.length > 1 && (
        <div className="pointer-events-none absolute inset-x-0 bottom-0 h-9 opacity-80">
          <Sparkline data={spark} tone={sparkTone ?? accent} filled />
        </div>
      )}
    </Card>
  );
}
