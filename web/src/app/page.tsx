"use client";

import * as React from "react";
import Link from "next/link";
import {
  Globe, Radio, TriangleAlert, ShieldAlert, ArrowRight, ArrowUpRight,
} from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { RiskGauge } from "@/components/risk-gauge";
import { ScoreMeter } from "@/components/score-meter";
import { SeverityPie, SeverityTrend } from "@/components/charts";
import { PrioritizationMatrix, type MatrixRow } from "@/components/prioritization-matrix";
import { SeverityDot, SeverityCounts, StateBadge } from "@/components/badges";
import { PriorityBadge } from "@/components/priority-badge";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiErrorState } from "@/components/api-error-state";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { relativeTime, rootsLabel } from "@/lib/format";
import { cn } from "@/lib/utils";
import {
  SEV, aggregateExposure, dominantSeverity, exposureScore, posture,
  priorityBand, priorityWeightedScore, riskScore, sumCounts, worstExposureCol,
} from "@/lib/risk";
import type { Asset, JobStatus, TrendPoint } from "@/lib/types";

const BANDS = [
  { range: "9–10", label: "Critical" },
  { range: "7–8", label: "High" },
  { range: "4–6", label: "Medium" },
  { range: "1–3", label: "Low" },
];

export default function AttackSurfacePage() {
  const scans = usePoll<{ jobs: JobStatus[]; total: number }>(
    () => api.listScans({ limit: 30 }),
    { intervalMs: 6000 }
  );
  const assetsPoll = usePoll<Asset[]>(() => api.listAssets({}), { intervalMs: 30000 });
  const trendsPoll = usePoll<TrendPoint[]>(() => api.trends({ limit: 30 }), { intervalMs: 30000 });

  const assets = React.useMemo(() => assetsPoll.data ?? [], [assetsPoll.data]);
  const trends = trendsPoll.data ?? [];
  const jobs = scans.data?.jobs ?? [];

  const fleet = React.useMemo(() => aggregateExposure(assets), [assets]);
  const fleetRisk = riskScore(fleet);
  const fleetPosture = posture(fleet);

  const discovered = assets.length;
  const live = assets.filter((a) => a.status === "live").length;
  const takeover = assets.filter((a) => a.status === "dead").length;
  const openFindings = sumCounts(fleet);
  const exposedAssets = assets.filter((a) => sumCounts(a.finding_counts || {}) > 0).length;
  const findingSeries = trends.map((p) => p.finding_count);

  const matrixRows: MatrixRow[] = React.useMemo(() => {
    const cells = [
      [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0],
    ];
    for (const a of assets) cells[priorityBand(a.priority)][worstExposureCol(a.finding_counts || {})] += 1;
    return BANDS.map((b, i) => ({ ...b, cells: cells[i] }));
  }, [assets]);

  const prioritized = React.useMemo(() => {
    return assets
      .map((a) => ({
        a,
        w: priorityWeightedScore(a.finding_counts || {}, a.priority),
        exp: exposureScore(a.finding_counts || {}),
      }))
      .filter((x) => x.exp > 0 || (x.a.priority ?? 0) >= 7)
      .sort((x, y) => y.w - x.w)
      .slice(0, 8);
  }, [assets]);

  if (scans.error && assetsPoll.error) return <ApiErrorState error={scans.error} />;

  const loadingAll = assetsPoll.loading && assets.length === 0;

  return (
    <div className="space-y-4">
      {/* header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-brand">
            External attack surface
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Attack surface</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            {live} internet-facing across {discovered} discovered assets
          </p>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link href="/scans">All audits <ArrowRight className="h-4 w-4" /></Link>
        </Button>
      </div>

      {/* hero: fleet gauge + scale KPIs */}
      <div className="grid gap-4 lg:grid-cols-[minmax(300px,1fr)_2fr]">
        <Card variant="glow" className="gap-0 p-5">
          <div className="flex items-center gap-4">
            <RiskGauge score={fleetRisk} rating={fleetPosture} size={210} />
            <div className="min-w-0">
              <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
                Fleet posture
              </div>
              <PostureBadge posture={fleetPosture} className="mt-2" />
              <p className="mt-3 text-sm text-muted-foreground">
                {openFindings > 0
                  ? <>{fleet.critical || 0} critical · {fleet.high || 0} high across{" "}
                      <span className="font-medium text-foreground">{exposedAssets} exposed</span> assets.</>
                  : "No open exposures across your discovered assets."}
              </p>
            </div>
          </div>
        </Card>

        <div className="grid grid-cols-2 gap-4">
          <StatCard title="Assets discovered" value={discovered} icon={Globe} accent="brand" delay={0} />
          <StatCard title="Internet-facing" value={live} icon={Radio} accent="brand" delay={80} />
          <StatCard title="Takeover watch" value={takeover} icon={TriangleAlert} accent="critical"
            delay={160} hint={takeover ? "dangling / no A record" : "none"} />
          <StatCard title="Open findings" value={openFindings} icon={ShieldAlert} accent="high"
            delay={240} spark={findingSeries.length > 1 ? findingSeries : undefined} sparkTone="high" />
        </div>
      </div>

      {/* exposure trend */}
      <Card className="p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-semibold">Exposure over time</div>
            <div className="text-xs text-muted-foreground">Open findings by severity, recent audits</div>
          </div>
          <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
            {SEV.map((s) => (
              <span key={s} className="inline-flex items-center gap-1.5 capitalize">
                <SeverityDot severity={s} /> {s}
              </span>
            ))}
          </div>
        </div>
        <SeverityTrend data={trends} />
      </Card>

      {/* current exposure + prioritization matrix */}
      <div className="grid gap-4 lg:grid-cols-[minmax(300px,1fr)_1.35fr]">
        <Card className="p-5">
          <div className="mb-3 text-sm font-semibold">Current exposure</div>
          <div className="flex items-center gap-5">
            <div className="w-[150px] shrink-0">
              <SeverityPie totals={fleet} height={150} />
            </div>
            <div className="flex flex-1 flex-col gap-2">
              {SEV.map((s) => (
                <div key={s} className="flex items-center gap-2.5 text-sm">
                  <SeverityDot severity={s} />
                  <span className="capitalize text-muted-foreground">{s}</span>
                  <span className="ml-auto font-medium tabular-nums">{fleet[s] || 0}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        <Card className="p-5">
          <div className="mb-3">
            <div className="text-sm font-semibold">Prioritization matrix</div>
            <div className="text-xs text-muted-foreground">business priority (1–10) × worst exposure · assets</div>
          </div>
          <PrioritizationMatrix rows={matrixRows} />
          <div className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
            <span className="inline-block h-3.5 w-3.5 shrink-0 rounded-[4px]"
              style={{ outline: "2px solid var(--sev-high)", outlineOffset: "-1px" }} />
            Highlighted = top-priority assets carrying the worst exposure — start here.
          </div>
        </Card>
      </div>

      {/* prioritized assets */}
      <Card className="p-5">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-semibold">Prioritized assets</div>
            <div className="text-xs text-muted-foreground">ranked by exposure × business priority</div>
          </div>
          <Button asChild variant="ghost" size="sm"><Link href="/assets">Inventory →</Link></Button>
        </div>
        {loadingAll ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-11 rounded-lg" />)}
          </div>
        ) : prioritized.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">
            No exposed assets yet — run an audit to populate exposure.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wide text-muted-foreground">
                  <th className="pb-2 pr-3 font-medium">Asset</th>
                  <th className="pb-2 pr-3 font-medium">Business unit</th>
                  <th className="pb-2 pr-3 font-medium">Priority</th>
                  <th className="pb-2 pr-3 font-medium">Exposure</th>
                  <th className="pb-2 font-medium">Findings</th>
                </tr>
              </thead>
              <tbody>
                {prioritized.map(({ a, exp }) => {
                  const worst = dominantSeverity(a.finding_counts || {}) ?? "low";
                  return (
                    <tr key={a.fqdn} className="border-t border-border transition-smooth hover:bg-overlay/50">
                      <td className="py-2.5 pr-3">
                        <Link href={`/assets?q=${encodeURIComponent(a.fqdn)}`}
                          className="font-mono text-[12.5px] text-brand hover:underline">
                          {a.fqdn}
                        </Link>
                      </td>
                      <td className="py-2.5 pr-3">
                        <span className="rounded-md border border-border bg-card px-2 py-0.5 text-xs text-muted-foreground">
                          {a.group || "—"}
                        </span>
                      </td>
                      <td className="py-2.5 pr-3"><PriorityBadge p={a.priority} /></td>
                      <td className="w-[150px] py-2.5 pr-3">
                        <ScoreMeter value={exp} max={10} tone={worst} />
                      </td>
                      <td className="py-2.5">
                        <SeverityCounts counts={a.finding_counts || {}} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* recent audits */}
      <Card className="p-5">
        <div className="mb-3 flex items-center justify-between">
          <div className="text-sm font-semibold">Recent audits</div>
          <Button asChild variant="ghost" size="sm"><Link href="/scans">View all</Link></Button>
        </div>
        {jobs.length === 0 ? (
          <EmptyScans loading={scans.loading} />
        ) : (
          <div className="space-y-1">
            {jobs.slice(0, 6).map((j, i) => (
              <Link key={j.id} href={`/scans/detail?id=${encodeURIComponent(j.id)}`}
                className="flex items-center justify-between gap-3 rounded-lg px-3 py-2.5 transition-smooth hover:bg-overlay animate-fade-in-up"
                style={{ animationDelay: `${i * 40}ms` }}>
                <div className="flex min-w-0 items-center gap-3">
                  <StateBadge state={j.state} />
                  <span className="truncate text-sm font-medium">{rootsLabel(j.roots)}</span>
                </div>
                <div className="flex shrink-0 items-center gap-4 text-xs text-muted-foreground">
                  <span className="tabular-nums">{j.finding_count} findings</span>
                  <span className="hidden md:inline">{relativeTime(j.submitted_at)}</span>
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function PostureBadge({ posture, className }: { posture: string; className?: string }) {
  const sev = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", LOW: "low" }[posture] || "low";
  const c = `var(--sev-${sev})`;
  return (
    <span className={cn("inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-bold", className)}
      style={{ color: c, background: `color-mix(in srgb, ${c} 14%, transparent)`, border: `1px solid color-mix(in srgb, ${c} 40%, transparent)` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />
      {posture}
    </span>
  );
}

function EmptyScans({ loading }: { loading: boolean }) {
  if (loading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 rounded-lg" />)}
      </div>
    );
  }
  return (
    <div className="flex flex-col items-center gap-3 py-10 text-center">
      <Radio className="h-10 w-10 text-muted-foreground" />
      <p className="text-sm text-muted-foreground">No audits yet.</p>
      <Button asChild size="sm"><Link href="/scans/new">Run your first audit</Link></Button>
    </div>
  );
}
