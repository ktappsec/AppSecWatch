"use client";

import * as React from "react";
import Link from "next/link";
import { Radar, Activity, ShieldAlert, CheckCircle2, ArrowRight } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { ChartCard } from "@/components/chart-card";
import { SeverityPie, FindingsByScan } from "@/components/charts";
import { StateBadge } from "@/components/badges";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { relativeTime, shortId, rootsLabel } from "@/lib/format";
import type { JobStatus, ScanResult } from "@/lib/types";
import { ApiErrorState } from "@/components/api-error-state";

export default function DashboardPage() {
  const { data, error, loading } = usePoll<{ jobs: JobStatus[]; total: number }>(
    () => api.listScans({ limit: 100 }),
    { intervalMs: 6000 }
  );

  const jobs = data?.jobs ?? [];
  const completed = jobs.filter((j) => j.state === "completed");

  // Aggregate severities across the most recent completed scans.
  const [results, setResults] = React.useState<Record<string, ScanResult>>({});
  const recentCompletedIds = completed.slice(0, 6).map((j) => j.id).join(",");
  React.useEffect(() => {
    const ids = recentCompletedIds ? recentCompletedIds.split(",") : [];
    let cancelled = false;
    Promise.all(
      ids.map((id) => api.getResult(id).catch(() => null))
    ).then((rs) => {
      if (cancelled) return;
      const map: Record<string, ScanResult> = {};
      rs.forEach((r) => {
        if (r) map[r.id] = r;
      });
      setResults(map);
    });
    return () => {
      cancelled = true;
    };
  }, [recentCompletedIds]);

  const aggTotals: Record<string, number> = {};
  Object.values(results).forEach((r) => {
    Object.entries(r.histogram_totals || {}).forEach(([sev, n]) => {
      aggTotals[sev] = (aggTotals[sev] || 0) + (n || 0);
    });
  });

  const findingsByScan = completed.slice(0, 6).map((j) => ({
    name: shortId(j.id),
    findings: j.finding_count,
  }));

  const totalFindings = jobs.reduce((sum, j) => sum + (j.finding_count || 0), 0);
  const running = jobs.filter((j) => j.state === "running" || j.state === "queued").length;

  if (error) {
    return <ApiErrorState error={error} />;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            Fleet-wide view of your external AppSec audits.
          </p>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link href="/scans">
            All scans <ArrowRight className="h-4 w-4" />
          </Link>
        </Button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        {loading && jobs.length === 0 ? (
          Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28 rounded-xl" />)
        ) : (
          <>
            <StatCard title="Total scans" value={data?.total ?? 0} icon={Radar} delay={0} />
            <StatCard
              title="In progress"
              value={running}
              icon={Activity}
              delay={100}
              iconClassName={running ? "bg-primary/10 text-primary" : undefined}
              hint={running ? "running or queued" : "idle"}
            />
            <StatCard title="Completed" value={completed.length} icon={CheckCircle2} delay={200} />
            <StatCard
              title="Total findings"
              value={totalFindings}
              icon={ShieldAlert}
              delay={300}
              iconClassName="bg-destructive/10 text-destructive"
            />
          </>
        )}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ChartCard
          title="Severity distribution"
          description="Aggregated across recent completed scans"
        >
          <SeverityPie totals={aggTotals} />
        </ChartCard>
        <ChartCard title="Findings by scan" description="Most recent completed scans">
          <FindingsByScan data={findingsByScan} />
        </ChartCard>
      </div>

      {/* Recent activity */}
      <Card className="p-6">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold">Recent scans</h3>
          <Button asChild variant="ghost" size="sm">
            <Link href="/scans">View all</Link>
          </Button>
        </div>
        {jobs.length === 0 ? (
          <EmptyScans loading={loading} />
        ) : (
          <div className="space-y-1">
            {jobs.slice(0, 8).map((j, i) => (
              <Link
                key={j.id}
                href={`/scans/detail?id=${encodeURIComponent(j.id)}`}
                className="flex items-center justify-between gap-3 rounded-lg px-3 py-2.5 transition-smooth hover:bg-muted animate-fade-in-up"
                style={{ animationDelay: `${i * 50}ms` }}
              >
                <div className="flex min-w-0 items-center gap-3">
                  <StateBadge state={j.state} />
                  <span
                    className="truncate text-sm font-medium"
                    title={j.roots?.length ? j.roots.join(", ") : undefined}
                  >
                    {rootsLabel(j.roots)}
                  </span>
                </div>
                <div className="flex shrink-0 items-center gap-4 text-xs text-muted-foreground">
                  <span className="tabular-nums">{j.finding_count} findings</span>
                  <span className="hidden md:inline">{relativeTime(j.submitted_at)}</span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function EmptyScans({ loading }: { loading: boolean }) {
  if (loading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-12 rounded-lg" />
        ))}
      </div>
    );
  }
  return (
    <div className="flex flex-col items-center gap-3 py-10 text-center">
      <Radar className="h-10 w-10 text-muted-foreground" />
      <p className="text-sm text-muted-foreground">No scans yet.</p>
      <Button asChild size="sm">
        <Link href="/scans/new">Run your first scan</Link>
      </Button>
    </div>
  );
}
