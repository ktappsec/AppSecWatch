import { Check, X, AlertTriangle, ShieldCheck } from "lucide-react";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { TLSHostReport } from "@/lib/types";

export function TLSScorecard({ reports }: { reports: TLSHostReport[] }) {
  if (!reports.length) {
    return (
      <div className="py-12 text-center text-sm text-muted-foreground">
        No TLS scans in this run.
      </div>
    );
  }

  const totalChecks = reports.reduce((s, r) => s + r.checks.length, 0);
  const passed = reports.reduce((s, r) => s + r.checks.filter((c) => c.passed).length, 0);

  return (
    <div className="space-y-4">
      <Card className="flex-row items-center justify-between gap-4 p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <p className="text-sm font-medium">Fleet TLS posture</p>
            <p className="text-xs text-muted-foreground">{reports.length} host(s) scanned</p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-2xl font-semibold tabular-nums">
            {passed}
            <span className="text-base font-normal text-muted-foreground">/{totalChecks}</span>
          </p>
          <p className="text-xs text-muted-foreground">checks passed</p>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {reports.map((r) => (
          <Card key={r.host} className="gap-3 p-4">
            <div className="flex items-center justify-between gap-2">
              <p className="truncate text-sm font-semibold">{r.host}</p>
              {r.error ? (
                <span className="inline-flex items-center gap-1 text-xs text-warning">
                  <AlertTriangle className="h-3.5 w-3.5" /> error
                </span>
              ) : (
                <span
                  className={cn(
                    "rounded-md px-2 py-0.5 text-xs font-medium",
                    r.checks.every((c) => c.passed)
                      ? "bg-success/15 text-success"
                      : "bg-destructive/15 text-destructive"
                  )}
                >
                  {r.checks.filter((c) => c.passed).length}/{r.checks.length}
                </span>
              )}
            </div>
            {r.error ? (
              <p className="text-xs text-muted-foreground">{r.error}</p>
            ) : (
              <ul className="space-y-1">
                {r.checks.map((c, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs">
                    {c.passed ? (
                      <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" />
                    ) : (
                      <X className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" />
                    )}
                    <span className={cn(!c.passed && "text-foreground")}>
                      {c.name}
                      {c.detail && <span className="text-muted-foreground"> — {c.detail}</span>}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        ))}
      </div>
    </div>
  );
}
