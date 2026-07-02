"use client";

import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip as RTooltip,
  Legend,
} from "recharts";
import { SEVERITY_COLORS, SEVERITY_ORDER } from "@/lib/constants";
import type { Severity } from "@/lib/types";

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

/** Donut of severity totals. `data` = {severity: count}. */
export function SeverityPie({ totals }: { totals: Record<string, number> }) {
  const data = SEVERITY_ORDER.map((s) => ({ name: s, value: totals[s] || 0 })).filter(
    (d) => d.value > 0
  );

  if (data.length === 0) {
    return <EmptyChart label="No findings" />;
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={95}
          paddingAngle={2}
          stroke="var(--card)"
        >
          {data.map((d) => (
            <Cell key={d.name} fill={SEVERITY_COLORS[d.name as Severity]} />
          ))}
        </Pie>
        <RTooltip contentStyle={tooltipStyle()} />
        <Legend
          formatter={(v) => <span className="text-xs capitalize text-muted-foreground">{v}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
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

export function EmptyChart({ label }: { label: string }) {
  return (
    <div className="flex h-[260px] items-center justify-center text-sm text-muted-foreground">
      {label}
    </div>
  );
}
