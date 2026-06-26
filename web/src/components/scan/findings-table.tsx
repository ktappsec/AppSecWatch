"use client";

import * as React from "react";
import Link from "next/link";
import { ShieldCheck, EyeOff, ChevronRight, ChevronDown } from "lucide-react";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/badges";
import { cn } from "@/lib/utils";
import { SEVERITY_ORDER } from "@/lib/constants";
import type { Finding, Severity } from "@/lib/types";

export const SOURCE_LABEL: Record<string, string> = {
  nuclei: "nuclei",
  takeover: "takeover",
  sslscan: "TLS",
  headers: "headers",
  csp: "csp",
  js_lib: "JS library",
  ai_headers: "AI headers",
  ai_supply_chain: "AI supply-chain",
};

/** The stable suppression key for a finding — mirrors the engine's finding_key. */
export function findingKey(f: Finding): string {
  if (f.check_id) return f.check_id;
  const ev = (f.evidence ?? {}) as Record<string, unknown>;
  if (f.source === "nuclei" || f.source === "takeover")
    return String(ev.template_id ?? f.title);
  if (f.source === "sslscan") return String(ev.check ?? f.title);
  if (f.source === "js_lib" && ev.library)
    return `${ev.library}@${ev.version ?? ""}`;
  return f.title;
}

function evidenceSummary(ev?: Record<string, unknown>): string {
  if (!ev) return "";
  return Object.entries(ev)
    .filter(([k, v]) => k !== "type" && v != null && v !== "")
    .map(([, v]) => String(v))
    .join(" · ")
    .slice(0, 160);
}

export function FindingsTable({
  findings,
  onSuppress,
}: {
  findings: Finding[];
  onSuppress?: (f: Finding, scope?: "host" | "global") => void;
}) {
  const [sev, setSev] = React.useState<Severity | "all">("all");
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());
  const toggle = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  // Soft-suppressed findings (AI-judged false-positives) are split out: hidden
  // from the main table + counts, shown in a collapsible section, never dropped.
  const visible = React.useMemo(
    () => findings.filter((f) => !f.ai_verdict?.suppressed),
    [findings]
  );
  const suppressed = React.useMemo(
    () => findings.filter((f) => f.ai_verdict?.suppressed),
    [findings]
  );

  const sorted = React.useMemo(() => {
    const order = (s: string) => SEVERITY_ORDER.indexOf(s as Severity);
    return [...visible].sort((a, b) => order(a.severity) - order(b.severity));
  }, [visible]);

  const filtered = sev === "all" ? sorted : sorted.filter((f) => f.severity === sev);

  // Collapse the same issue (source + key) across hosts into one row — the same
  // missing header on 66 hosts is one issue, not 66.
  const groups = React.useMemo(() => {
    const ord = (s: string) => SEVERITY_ORDER.indexOf(s as Severity);
    const m = new Map<
      string,
      { id: string; rep: Finding; hosts: string[]; items: Finding[]; count: number }
    >();
    for (const f of filtered) {
      const k = `${f.source}|${findingKey(f)}`;
      const host = f.host ?? "";
      const g = m.get(k);
      if (!g) m.set(k, { id: k, rep: f, hosts: host ? [host] : [], items: [f], count: 1 });
      else {
        g.count++;
        g.items.push(f);
        if (host && !g.hosts.includes(host)) g.hosts.push(host);
        if (ord(f.severity) < ord(g.rep.severity)) g.rep = f;
      }
    }
    return [...m.values()];
  }, [filtered]);

  if (visible.length === 0 && suppressed.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-center">
        <ShieldCheck className="h-10 w-10 text-[#00c853]" />
        <p className="text-sm text-muted-foreground">No findings recorded.</p>
      </div>
    );
  }

  const counts = SEVERITY_ORDER.reduce<Record<string, number>>((acc, s) => {
    acc[s] = visible.filter((f) => f.severity === s).length;
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <FilterChip active={sev === "all"} onClick={() => setSev("all")}>
          All ({visible.length})
        </FilterChip>
        {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
          <FilterChip key={s} active={sev === s} onClick={() => setSev(s)}>
            <span className="capitalize">{s}</span> ({counts[s]})
          </FilterChip>
        ))}
      </div>

      <p className="text-xs text-muted-foreground">
        {groups.length} unique issue{groups.length === 1 ? "" : "s"} across {visible.length}{" "}
        finding{visible.length === 1 ? "" : "s"} (collapsed by host). Expand a row to see the
        affected hosts and jump to each asset.
      </p>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-8" />
            <TableHead>Severity</TableHead>
            <TableHead>Source</TableHead>
            <TableHead>Hosts</TableHead>
            <TableHead>Title</TableHead>
            <TableHead className="hidden lg:table-cell">Evidence</TableHead>
            {onSuppress && <TableHead className="text-right">Suppress</TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {groups.map((g) => {
            const canExpand = g.hosts.length > 0;
            const isOpen = expanded.has(g.id);
            const cols = onSuppress ? 7 : 6;
            return (
              <React.Fragment key={g.id}>
                <TableRow
                  className={cn(canExpand && "cursor-pointer")}
                  onClick={canExpand ? () => toggle(g.id) : undefined}
                >
                  <TableCell className="w-8 text-muted-foreground">
                    {canExpand &&
                      (isOpen ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      ))}
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={g.rep.severity} />
                  </TableCell>
                  <TableCell>
                    <span className="rounded bg-secondary px-1.5 py-0.5 text-[11px] text-muted-foreground">
                      {SOURCE_LABEL[g.rep.source] ?? g.rep.source}
                    </span>
                  </TableCell>
                  <TableCell className="max-w-[180px] truncate text-sm" title={g.hosts.join(", ")}>
                    {g.hosts.length <= 1 ? (g.hosts[0] ?? "—") : `${g.hosts.length} hosts`}
                  </TableCell>
                  <TableCell className="max-w-[280px] text-sm font-medium">{g.rep.title}</TableCell>
                  <TableCell className="hidden lg:table-cell max-w-[300px] truncate text-xs text-muted-foreground">
                    {evidenceSummary(g.rep.evidence)}
                  </TableCell>
                  {onSuppress && (
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon-sm" aria-label="Suppress"
                        title={g.hosts.length > 1 ? "Suppress everywhere (all hosts)" : "Suppress this finding (future scans)"}
                        onClick={(e) => {
                          e.stopPropagation();
                          onSuppress(g.rep, g.hosts.length > 1 ? "global" : "host");
                        }}>
                        <EyeOff className="h-3.5 w-3.5" />
                      </Button>
                    </TableCell>
                  )}
                </TableRow>
                {isOpen && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={cols} className="bg-secondary/20 p-0">
                      <div className="space-y-1 px-4 py-2">
                        <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                          Affected hosts ({g.hosts.length})
                        </p>
                        {g.items.map((item, j) => (
                          <div key={j} className="flex items-center gap-2 text-xs">
                            {item.host ? (
                              <Link
                                href={`/assets?q=${encodeURIComponent(item.host)}`}
                                onClick={(e) => e.stopPropagation()}
                                className="shrink-0 font-mono text-accent hover:underline"
                                title="Open this asset"
                              >
                                {item.host}
                              </Link>
                            ) : (
                              <span className="shrink-0 font-mono text-muted-foreground">—</span>
                            )}
                            <span className="truncate text-muted-foreground">
                              {evidenceSummary(item.evidence) || item.title}
                            </span>
                            {onSuppress && item.host && (
                              <Button variant="ghost" size="icon-sm" className="ml-auto shrink-0"
                                aria-label="Suppress on this host"
                                title="Suppress on this host only (future scans)"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onSuppress(item, "host");
                                }}>
                                <EyeOff className="h-3.5 w-3.5" />
                              </Button>
                            )}
                          </div>
                        ))}
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </React.Fragment>
            );
          })}
        </TableBody>
      </Table>

      {suppressed.length > 0 && <SuppressedSection findings={suppressed} />}
    </div>
  );
}

function SuppressedSection({ findings }: { findings: Finding[] }) {
  return (
    <details className="rounded-lg border border-border bg-secondary/30">
      <summary className="cursor-pointer select-none px-4 py-2 text-xs font-medium text-muted-foreground">
        Suppressed — AI judged likely false-positive ({findings.length}) · excluded from counts
      </summary>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Severity</TableHead>
            <TableHead>Source</TableHead>
            <TableHead>Host</TableHead>
            <TableHead>Title</TableHead>
            <TableHead className="hidden lg:table-cell">Why suppressed (AI)</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.map((f, i) => (
            <TableRow key={i} className="opacity-60">
              <TableCell>
                <SeverityBadge severity={f.severity} />
              </TableCell>
              <TableCell>
                <span className="rounded bg-secondary px-1.5 py-0.5 text-[11px] text-muted-foreground">
                  {SOURCE_LABEL[f.source] ?? f.source}
                </span>
              </TableCell>
              <TableCell className="max-w-[180px] truncate text-sm">{f.host ?? "—"}</TableCell>
              <TableCell className="max-w-[280px] text-sm font-medium">{f.title}</TableCell>
              <TableCell className="hidden lg:table-cell max-w-[300px] text-xs text-muted-foreground">
                {f.ai_verdict ? (
                  <>
                    <span className="mr-1 rounded bg-secondary px-1 py-0.5 text-[10px]">
                      conf: {f.ai_verdict.confidence}
                    </span>
                    {f.ai_verdict.reason}
                  </>
                ) : null}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </details>
  );
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-lg border px-3 py-1.5 text-xs font-medium transition-smooth",
        active
          ? "border-accent/40 bg-accent/15 text-accent"
          : "border-border text-muted-foreground hover:bg-accent/5"
      )}
    >
      {children}
    </button>
  );
}
