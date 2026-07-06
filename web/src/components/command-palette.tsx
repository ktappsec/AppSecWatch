"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Search, CornerDownLeft } from "lucide-react";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { StateBadge } from "@/components/badges";
import { api } from "@/lib/api";
import { useHotkey } from "@/lib/hooks";
import { rootsLabel } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { JobStatus, SearchResults } from "@/lib/types";

const ROUTES = [
  { label: "Attack surface", href: "/", kw: "dashboard home overview" },
  { label: "Analytics", href: "/analytics", kw: "trends charts posture" },
  { label: "Inventory", href: "/assets", kw: "assets hosts" },
  { label: "Audits", href: "/scans", kw: "scans" },
  { label: "New audit", href: "/scans/new", kw: "scan run" },
  { label: "Schedules", href: "/schedules", kw: "recurring" },
  { label: "Nuclei", href: "/nuclei", kw: "templates cve" },
  { label: "AI tuning", href: "/ai", kw: "prompts" },
  { label: "Suppressions", href: "/suppressions", kw: "" },
  { label: "Settings", href: "/settings", kw: "config api" },
  { label: "Docs", href: "/docs", kw: "help" },
];

type Row = { key: string; label: React.ReactNode; href: string; hint?: React.ReactNode };

export function CommandPalette() {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [q, setQ] = React.useState("");
  const [results, setResults] = React.useState<SearchResults>({ assets: [], findings: [] });
  const [scans, setScans] = React.useState<JobStatus[]>([]);

  useHotkey("k", () => setOpen((o) => !o));

  React.useEffect(() => {
    if (!open) return;
    setQ("");
    setResults({ assets: [], findings: [] });
    api.listScans({ limit: 20 }).then((r) => setScans(r.jobs)).catch(() => {});
  }, [open]);

  // Server-side all-in-one search (FTS5): assets by fqdn/tech/endpoint/profile +
  // findings by title/host/category. Debounced.
  React.useEffect(() => {
    const ql = q.trim();
    if (!ql) { setResults({ assets: [], findings: [] }); return; }
    const h = setTimeout(() => {
      api.search(ql, { limit: 8 }).then(setResults).catch(() => {});
    }, 160);
    return () => clearTimeout(h);
  }, [q]);

  const go = (href: string) => { setOpen(false); router.push(href); };

  const ql = q.trim().toLowerCase();
  const routeRows: Row[] = ROUTES
    .filter((r) => !ql || r.label.toLowerCase().includes(ql) || r.kw.includes(ql))
    .map((r) => ({ key: `r:${r.href}`, label: r.label, href: r.href }));

  const assetRows: Row[] = results.assets.map((a) => ({
    key: `a:${a.fqdn}`,
    label: <span className="font-mono text-[13px]">{a.fqdn}</span>,
    href: `/assets?q=${encodeURIComponent(a.fqdn)}`,
    hint: a.group || undefined,
  }));

  const findingRows: Row[] = results.findings.map((f) => ({
    key: `f:${f.fingerprint}`,
    label: <span className="text-[13px]">{f.title}</span>,
    href: `/assets?q=${encodeURIComponent(f.host)}`,
    hint: <span className="font-mono text-[11px]">{f.host}</span>,
  }));

  const scanRows: Row[] = (ql
    ? scans.filter((s) => (s.roots || []).join(" ").toLowerCase().includes(ql) || s.id.toLowerCase().includes(ql)).slice(0, 5)
    : scans.slice(0, 5)
  ).map((s) => ({
    key: `s:${s.id}`,
    label: rootsLabel(s.roots),
    href: `/scans/detail?id=${encodeURIComponent(s.id)}`,
    hint: <StateBadge state={s.state} />,
  }));

  const groups: { title: string; rows: Row[] }[] = [
    { title: "Go to", rows: routeRows },
    { title: "Assets", rows: assetRows },
    { title: "Findings", rows: findingRows },
    { title: ql ? "Matching audits" : "Recent audits", rows: scanRows },
  ].filter((g) => g.rows.length);

  const flat = groups.flatMap((g) => g.rows);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="top-[12%] max-w-xl translate-y-0 gap-0 overflow-hidden p-0">
        <DialogTitle className="sr-only">Command palette</DialogTitle>
        <div className="flex items-center gap-2.5 border-b border-border px-4 pr-11">
          <Search className="h-4 w-4 shrink-0 text-muted-foreground" />
          <input
            autoFocus
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && flat[0]) go(flat[0].href); }}
            placeholder="Search assets, audits, pages…"
            className="h-12 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
        </div>
        <div className="max-h-[55vh] overflow-y-auto p-2">
          {flat.length === 0 ? (
            <p className="px-3 py-8 text-center text-sm text-muted-foreground">No matches.</p>
          ) : (
            groups.map((g) => (
              <div key={g.title} className="mb-1">
                <p className="px-3 pb-1 pt-2 text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground/70">{g.title}</p>
                {g.rows.map((row, i) => (
                  <button
                    key={row.key}
                    onClick={() => go(row.href)}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm transition-smooth hover:bg-overlay",
                      i === 0 && g.title === groups[0].title && "bg-overlay/60"
                    )}
                  >
                    <span className="min-w-0 flex-1 truncate">{row.label}</span>
                    {row.hint && <span className="shrink-0 text-xs text-muted-foreground">{row.hint}</span>}
                    <CornerDownLeft className="h-3.5 w-3.5 shrink-0 text-muted-foreground opacity-0 group-hover:opacity-100" />
                  </button>
                ))}
              </div>
            ))
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
