"use client";

import dynamic from "next/dynamic";

// Recharts is a large bundle. Load it only when a chart actually renders (the
// dashboard, analytics, scan detail) via next/dynamic, so non-chart routes
// (settings, suppressions, nuclei, docs, …) don't ship it. EmptyChart stays a
// light static export (no Recharts) and is re-exported for existing importers.
export { EmptyChart } from "./charts-empty";
export type { TrendPoint } from "./charts-impl";

const ChartFallback = () => (
  <div className="h-[220px] animate-pulse rounded-lg bg-muted/40" />
);

export const SeverityPie = dynamic(
  () => import("./charts-impl").then((m) => m.SeverityPie),
  { ssr: false, loading: ChartFallback },
);
export const SeverityBars = dynamic(
  () => import("./charts-impl").then((m) => m.SeverityBars),
  { ssr: false, loading: ChartFallback },
);
export const FindingsByScan = dynamic(
  () => import("./charts-impl").then((m) => m.FindingsByScan),
  { ssr: false, loading: ChartFallback },
);
export const SeverityTrend = dynamic(
  () => import("./charts-impl").then((m) => m.SeverityTrend),
  { ssr: false, loading: ChartFallback },
);
