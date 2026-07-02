"use client";

import * as React from "react";
import Link from "next/link";
import { Plus, RefreshCw, Ban } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { StateBadge } from "@/components/badges";
import { ApiErrorState } from "@/components/api-error-state";
import { api, ApiError } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { relativeTime, formatDuration, rootsLabel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { toast } from "@/components/ui/sonner";
import type { JobStatus } from "@/lib/types";

const FILTERS: { value: string; label: string }[] = [
  { value: "", label: "All" },
  { value: "running", label: "Running" },
  { value: "queued", label: "Queued" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "cancelled", label: "Cancelled" },
];

export default function ScansPage() {
  const [filter, setFilter] = React.useState("");
  const { data, error, loading, refresh } = usePoll<{ jobs: JobStatus[]; total: number }>(
    () => api.listScans({ limit: 200, state: filter || undefined }),
    { intervalMs: 4000, deps: [filter] }
  );

  const cancel = async (id: string) => {
    try {
      await api.cancelScan(id);
      toast.success("Scan cancelled");
      refresh();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Cancel failed");
    }
  };

  if (error) return <ApiErrorState error={error} />;

  const jobs = data?.jobs ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Scans</h1>
          <p className="text-sm text-muted-foreground">
            {data ? `${data.total} total` : "Loading…"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon-sm" onClick={refresh} aria-label="Refresh">
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
          <Button asChild size="sm">
            <Link href="/scans/new">
              <Plus className="h-4 w-4" /> New Scan
            </Link>
          </Button>
        </div>
      </div>

      {/* Filter chips */}
      <div className="flex flex-wrap gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setFilter(f.value)}
            aria-pressed={filter === f.value}
            className={cn(
              "rounded-lg border px-3 py-1.5 text-xs font-medium transition-smooth",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
              filter === f.value
                ? "border-primary/40 bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:bg-muted"
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      <Card className="p-0 py-0">
        {loading && jobs.length === 0 ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-12 rounded-lg" />
            ))}
          </div>
        ) : jobs.length === 0 ? (
          <div className="py-16 text-center text-sm text-muted-foreground">
            No scans match this filter.
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Status</TableHead>
                <TableHead>Roots</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead className="hidden lg:table-cell">Stage</TableHead>
                <TableHead className="hidden sm:table-cell">Duration</TableHead>
                <TableHead className="hidden md:table-cell">Submitted</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {jobs.map((j) => (
                <TableRow key={j.id} className="group">
                  <TableCell>
                    <StateBadge state={j.state} />
                  </TableCell>
                  <TableCell className="max-w-[220px]">
                    <Link
                      href={`/scans/detail?id=${encodeURIComponent(j.id)}`}
                      className="block truncate font-medium hover:text-primary"
                      title={j.roots?.length ? j.roots.join(", ") : undefined}
                    >
                      {rootsLabel(j.roots)}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <span className={cn(j.finding_count > 0 && "font-semibold text-destructive")}>
                      {j.finding_count}
                    </span>
                  </TableCell>
                  <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">
                    {j.state === "running" ? j.current_stage ?? "…" : "—"}
                  </TableCell>
                  <TableCell className="hidden sm:table-cell text-xs text-muted-foreground tabular-nums">
                    {formatDuration(j.elapsed_s)}
                  </TableCell>
                  <TableCell className="hidden md:table-cell text-xs text-muted-foreground">
                    {relativeTime(j.submitted_at)}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      {(j.state === "running" || j.state === "queued") && (
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label="Cancel"
                          onClick={() => cancel(j.id)}
                          className="text-muted-foreground hover:text-destructive"
                        >
                          <Ban className="h-4 w-4" />
                        </Button>
                      )}
                      <Button asChild variant="ghost" size="sm">
                        <Link href={`/scans/detail?id=${encodeURIComponent(j.id)}`}>View</Link>
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>
    </div>
  );
}
