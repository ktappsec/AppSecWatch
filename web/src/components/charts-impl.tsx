"use client";

import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip as RTooltip,
} from "recharts";
import { SEVERITY_COLORS, SEVERITY_ORDER } from "@/lib/constants";
import type { Severity } from "@/lib/types";
import { EmptyChart } from "./charts-empty";

const axisStyle = { fontSize: 11, fill: "var(--muted-foreground)" };

function tooltipStyle() {
  return {
    backgroundColor: "var(--popover)",
    border: "1px solid var(--border)",
    borderRadius: 8,
    color: "var(--popover-foreground)",
    fontSize: 12,
  };
}

/** Donut of severity totals with a center total. `data` = {severity: count}. */
export function SeverityPie({
  totals,
  height = 200,
}: {
  totals: Record<string, number>;
  height?: number;
}) {
  const data = SEVERITY_ORDER.map((s) => ({ name: s, value: totals[s] || 0 })).filter(
    (d) => d.value > 0
  );
  const total = data.reduce((a, d) => a + d.value, 0);

  if (data.length === 0) {
    return <EmptyChart label="No findings" />;
  }

  return (
    <div className="relative" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius="62%"
            outerRadius="92%"
            paddingAngle={2}
            stroke="var(--card)"
            strokeWidth={2}
          >
            {data.map((d) => (
              <Cell key={d.name} fill={SEVERITY_COLORS[d.name as Severity]} />
            ))}
          </Pie>
          <RTooltip contentStyle={tooltipStyle()} />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold tabular-nums">{total}</span>
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">findings</span>
      </div>
    </div>
  );
}

/** Vertical bars of severity totals. */
export function SeverityBars({ totals }: { totals: Record<string, number> }) {
  const data = SEVERITY_ORDER.map((s) => ({ name: s, count: totals[s] || 0 }));
  const hasAny = data.some((d) => d.count > 0);
  if (!hasAny) return <EmptyChart label="No findings" />;

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
        <XAxis dataKey="name" tick={axisStyle} axisLine={false} tickLine={false} className="capitalize" />
        <YAxis tick={axisStyle} axisLine={false} tickLine={false} allowDecimals={false} />
        <RTooltip contentStyle={tooltipStyle()} cursor={{ fill: "var(--primary)", opacity: 0.08 }} />
        <Bar dataKey="count" radius={[6, 6, 0, 0]}>
          {data.map((d) => (
            <Cell key={d.name} fill={SEVERITY_COLORS[d.name as Severity]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Horizontal mini bar chart of findings count per scan. */
export function FindingsByScan({
  data,
}: {
  data: { name: string; findings: number }[];
}) {
  if (!data.length) return <EmptyChart label="No completed scans" />;
  return (
    <ResponsiveContainer width="100%" height={Math.max(140, data.length * 40)}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 8 }}>
        <XAxis type="number" tick={axisStyle} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="name"
          tick={axisStyle}
          axisLine={false}
          tickLine={false}
          width={140}
        />
        <RTooltip contentStyle={tooltipStyle()} cursor={{ fill: "var(--primary)", opacity: 0.08 }} />
        <Bar dataKey="findings" fill="var(--chart-1)" radius={[0, 6, 6, 0]} barSize={18} />
      </BarChart>
    </ResponsiveContainer>
  );
}

/** One point of the exposure-over-time trend (findings by severity). */
export interface TrendPoint {
  label: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
function TrendTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((a: number, p: any) => a + (p.value || 0), 0);
  return (
    <div className="rounded-lg border border-border bg-popover px-3 py-2 text-xs shadow-pop">
      <div className="mb-1.5 font-medium text-foreground">{label}</div>
      {[...payload].reverse().map((p: any) => (
        <div key={p.dataKey} className="flex items-center gap-2 py-0.5">
          <span className="h-2 w-2 rounded-[3px]" style={{ background: p.color }} />
          <span className="capitalize text-muted-foreground">{p.dataKey}</span>
          <span className="ml-auto font-medium tabular-nums text-foreground">{p.value}</span>
        </div>
      ))}
      <div className="mt-1.5 flex items-center justify-between border-t border-border pt-1.5">
        <span className="text-muted-foreground">Total</span>
        <span className="font-semibold tabular-nums text-foreground">{total}</span>
      </div>
    </div>
  );
}
/* eslint-enable @typescript-eslint/no-explicit-any */

/** Stacked-area exposure trend over time (findings by severity). */
export function SeverityTrend({ data, height = 230 }: { data: TrendPoint[]; height?: number }) {
  if (!data.length) return <EmptyChart label="No history yet" />;
  const order: Severity[] = ["info", "low", "medium", "high", "critical"]; // stack bottom→top
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
        <defs>
          {order.map((s) => (
            <linearGradient key={s} id={`trend-${s}`} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stopColor={SEVERITY_COLORS[s]} stopOpacity={s === "info" ? 0.5 : 0.8} />
              <stop offset="1" stopColor={SEVERITY_COLORS[s]} stopOpacity={0.08} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid vertical={false} stroke="var(--grid-line)" />
        <XAxis dataKey="label" tick={axisStyle} axisLine={false} tickLine={false} minTickGap={20} />
        <YAxis tick={axisStyle} axisLine={false} tickLine={false} allowDecimals={false} width={30} />
        <RTooltip content={<TrendTooltip />} />
        {order.map((s) => (
          <Area
            key={s}
            type="monotone"
            dataKey={s}
            stackId="1"
            stroke={SEVERITY_COLORS[s]}
            strokeWidth={1.5}
            fill={`url(#trend-${s})`}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}
