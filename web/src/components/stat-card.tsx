import type { LucideIcon } from "lucide-react";
import { TrendingUp, TrendingDown } from "lucide-react";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface StatCardProps {
  title: string;
  value: React.ReactNode;
  icon: LucideIcon;
  delay?: number;
  trend?: { value: string; positive?: boolean };
  hint?: string;
  iconClassName?: string;
}

/** KPI card — large value, top-right icon box, optional trend. */
export function StatCard({
  title,
  value,
  icon: Icon,
  delay = 0,
  trend,
  hint,
  iconClassName,
}: StatCardProps) {
  return (
    <Card
      className={cn(
        "relative gap-0 p-6 transition-smooth animate-fade-in-up",
        "hover:border-accent/50 hover:shadow-lg hover:shadow-accent/10"
      )}
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {title}
          </p>
          <p className="text-3xl font-bold leading-tight">{value}</p>
        </div>
        <div
          className={cn(
            "flex h-12 w-12 shrink-0 items-center justify-center rounded-lg bg-accent/15 text-accent",
            iconClassName
          )}
        >
          <Icon className="h-6 w-6" />
        </div>
      </div>
      {(trend || hint) && (
        <div className="mt-3 flex items-center gap-2 text-xs">
          {trend && (
            <span
              className={cn(
                "inline-flex items-center gap-1 font-medium",
                trend.positive ? "text-[#00c853]" : "text-destructive"
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
    </Card>
  );
}
