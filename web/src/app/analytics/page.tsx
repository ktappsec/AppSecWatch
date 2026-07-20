"use client";

import * as React from "react";
import { AlertCircle, CheckCircle2, EyeOff, Layers } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { ChartCard } from "@/components/chart-card";
import { SeverityTrend, SeverityBars, EmptyChart } from "@/components/charts";
import { SeverityBadge } from "@/components/badges";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiErrorState } from "@/components/api-error-state";
import { CATEGORY_LABEL } from "@/components/scan/findings-table";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import type { AnalyticsResponse, AssetGroup, TrendPoint } from "@/lib/types";

export default function AnalyticsPage() {
  const [group, setGroup] = React.useState<string>("");
  const g = group || undefined;
  const analytics = usePoll<AnalyticsResponse>(() => api.analytics(g ? { group: g } : {}),
    { intervalMs: 30000, deps: [group] });
  const trends = usePoll<TrendPoint[]>(() => api.trends({ group: g, limit: 30 }),
    { intervalMs: 30000, deps: [group] });
  const groups = usePoll<AssetGroup[]>(() => api.assetGroups(), { intervalMs: 60000 });

  const a = analytics.data;
  const t = trends.data ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Analytics</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Security-posture trends and the current cross-scan finding lifecycle.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <span className="text-muted-foreground">Group</span>
          <select
            value={group}
            onChange={(e) => setGroup(e.target.value)}
            className="rounded-lg border border-border bg-background px-3 py-1.5 text-sm"
          >
            <option value="">All groups</option>
            {(groups.data ?? []).filter((x) => x.group).map((x) => (
              <option key={x.group} value={x.group!}>{x.group} ({x.count})</option>
            ))}
          </select>
        </label>
      </div>

      {analytics.error ? (
        <ApiErrorState error={analytics.error} />
      ) : !a ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard title="Open findings" value={a.open_total} icon={AlertCircle} accent="high" />
            <StatCard title="Resolved" value={a.resolved_total} icon={CheckCircle2} accent="success"
              hint="absent 2 consecutive scans" />
            <StatCard title="Suppressed" value={a.suppressed_total} icon={EyeOff} accent="muted" />
            <StatCard title="Distinct issues" value={Object.values(a.by_category).reduce((s, n) => s + n, 0)}
              icon={Layers} accent="brand" />
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <ChartCard title="Risk & severity over time"
              description="Per-scan risk score and severity mix (this scope)">
              {t.length >= 2 ? <SeverityTrend data={t} /> : (
                <EmptyChart label={g
                  ? "No trend for this group yet — trends track scans launched for a specific group"
                  : "Not enough history yet — run more scans"} />
              )}
            </ChartCard>
            <ChartCard title="Open findings by severity">
              {a.open_total > 0 ? <SeverityBars totals={a.by_severity} /> : <EmptyChart label="No open findings" />}
            </ChartCard>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <ChartCard title="By category" description="Open findings grouped by taxonomy category">
              <CategoryBars data={a.by_category} />
            </ChartCard>
            <ChartCard title="Open findings by asset priority"
              description="Business-criticality (10 highest) vs open findings">
              <PriorityBars data={a.by_priority} />
            </ChartCard>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="p-6">
              <h3 className="mb-4 text-lg font-semibold">Most widespread issues</h3>
              {a.widespread.length ? (
                <ul className="space-y-2">
                  {a.widespread.map((w) => (
                    <li key={w.key} className="flex items-center justify-between gap-3 text-sm">
                      <span className="min-w-0 truncate">{w.title || w.key}</span>
                      <span className="shrink-0 rounded-full bg-secondary px-2 py-0.5 text-xs text-muted-foreground">
                        {w.host_count} host{w.host_count === 1 ? "" : "s"}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : <p className="text-sm text-muted-foreground">No open findings.</p>}
            </Card>

            <Card className="p-6">
              <h3 className="mb-4 text-lg font-semibold">Longest-open findings</h3>
              {a.longest_open.length ? (
                <ul className="space-y-2">
                  {a.longest_open.map((l, i) => (
                    <li key={i} className="flex items-center gap-3 text-sm">
                      {l.severity && <SeverityBadge severity={l.severity as never} />}
                      <span className="min-w-0 flex-1 truncate">{l.title}</span>
                      <span className="shrink-0 font-mono text-xs text-muted-foreground">{l.host}</span>
                    </li>
                  ))}
                </ul>
              ) : <p className="text-sm text-muted-foreground">No open findings.</p>}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}

function CategoryBars({ data }: { data: Record<string, number> }) {
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...rows.map(([, n]) => n));
  if (!rows.length) return <EmptyChart label="No open findings" />;
  return (
    <div className="space-y-2">
      {rows.map(([cat, n]) => (
        <div key={cat} className="flex items-center gap-3 text-sm">
          <span className="w-44 shrink-0 truncate text-muted-foreground">{CATEGORY_LABEL[cat] ?? cat}</span>
          <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-secondary">
            <div className={cn("h-full rounded-full bg-primary")} style={{ width: `${(n / max) * 100}%` }} />
          </div>
          <span className="w-8 shrink-0 text-right tabular-nums">{n}</span>
        </div>
      ))}
    </div>
  );
}

function PriorityBars({ data }: { data: Array<{ priority: number; open: number }> }) {
  const rows = [...data].sort((a, b) => b.priority - a.priority);
  const max = Math.max(1, ...rows.map((r) => r.open));
  if (!rows.length) return <EmptyChart label="No open findings" />;
  return (
    <div className="space-y-2">
      {rows.map((r) => (
        <div key={r.priority} className="flex items-center gap-3 text-sm">
          <span className="w-44 shrink-0 text-muted-foreground">
            {r.priority ? `Priority ${r.priority}` : "Unprioritized"}
          </span>
          <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-secondary">
            <div className="h-full rounded-full bg-warning" style={{ width: `${(r.open / max) * 100}%` }} />
          </div>
          <span className="w-8 shrink-0 text-right tabular-nums">{r.open}</span>
        </div>
      ))}
    </div>
  );
}
