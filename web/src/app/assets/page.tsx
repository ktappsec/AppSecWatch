"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import {
  Upload, Plus, Trash2, Play, ChevronDown, ChevronRight, RefreshCw, Network, Info, Search, X,
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useVirtualizer } from "@tanstack/react-virtual";
import { SeverityBadge, SeverityCounts } from "@/components/badges";
import { ScoreMeter } from "@/components/score-meter";
import { PriorityBadge } from "@/components/priority-badge";
import { AssetDrawer } from "@/components/asset-drawer";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from "@/components/ui/select";
import { ListSkeleton } from "@/components/ui/skeleton";
import { InlineError } from "@/components/api-error-state";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from "@/components/ui/dialog";
import {
  AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle,
  AlertDialogDescription, AlertDialogFooter, AlertDialogCancel, AlertDialogAction,
} from "@/components/ui/alert-dialog";
import { toast } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import { api, ApiError } from "@/lib/api";
import { useMounted, useDebouncedValue, useScrollParent, useIsomorphicLayoutEffect } from "@/lib/hooks";
import { relativeTime } from "@/lib/format";
import { dominantSeverity, exposureScore, sumCounts } from "@/lib/risk";
import type { Asset, Finding } from "@/lib/types";
import { STATUS_STYLE } from "@/lib/constants";

function FindingCounts({ counts }: { counts?: Record<string, number> }) {
  const total = Object.values(counts ?? {}).reduce((a, b) => a + b, 0);
  if (!total) return <span className="text-xs text-muted-foreground">—</span>;
  return <SeverityCounts counts={counts ?? {}} />;
}

// The grouped inventory is flattened into ONE list of virtual rows (group
// header · column header · asset rows) so the whole ~468-asset table can be
// window-virtualized — only the rows in view live in the DOM.
type FlatItem =
  | { kind: "group"; key: string; group: string; rows: Asset[]; open: boolean }
  | { kind: "colhead"; key: string }
  | { kind: "asset"; key: string; asset: Asset };

// Fixed per-kind heights (px). Kept EXACT (each row renders `h-full` inside a
// fixed-size wrapper) so the virtualizer's estimates never drift → no
// measureElement, no scroll jumpiness.
const ROW_SIZE: Record<FlatItem["kind"], number> = { group: 52, colhead: 40, asset: 44 };

// Shared column layout — one flex track set reused by the column header and
// every asset row so columns stay aligned. Optional columns hide at the same
// breakpoints on every row, so they vanish cleanly (no empty grid tracks).
const COL = {
  cb: "w-8 shrink-0",
  fqdn: "min-w-0 flex-[1.4] truncate",
  source: "w-[84px] shrink-0",
  status: "w-[64px] shrink-0",
  priority: "w-[64px] shrink-0",
  exposure: "hidden w-[130px] shrink-0 sm:block",
  findings: "min-w-0 flex-1",
  arec: "hidden w-[130px] shrink-0 xl:block",
  lastseen: "hidden w-[92px] shrink-0 lg:block",
  actions: "flex w-[112px] shrink-0 items-center justify-end",
} as const;

export default function AssetsPage() {
  const mounted = useMounted();
  const router = useRouter();
  const fileRef = React.useRef<HTMLInputElement>(null);

  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);
  const [q, setQ] = React.useState("");
  const [status, setStatus] = React.useState("");
  // Debounce the values that drive the SERVER refetch so typing in the search
  // box fires one request after a quiet gap, not one per keystroke. The input
  // stays bound to the instant `q`/`status`, so it feels immediate.
  const dq = useDebouncedValue(q, 250);
  const dStatus = useDebouncedValue(status, 250);
  // Client-side facets (the list is fully loaded — instant, no server round-trip).
  const [priorityMin, setPriorityMin] = React.useState("any");   // any | 9|7|5|3 | none
  const [findings, setFindings] = React.useState("any");         // any | critical|high|medium | clean
  const [source, setSource] = React.useState("all");             // all | imported | discovered
  const [sort, setSort] = React.useState("group");               // group | priority|exposure|findings|name|lastseen
  const [collapsed, setCollapsed] = React.useState<Set<string>>(new Set());
  const [newFqdn, setNewFqdn] = React.useState("");
  const [newGroup, setNewGroup] = React.useState("");
  const [newPriority, setNewPriority] = React.useState("");

  const load = React.useCallback(async () => {
    setErr(null);
    try {
      setAssets(await api.listAssets({ q: dq || undefined, status: dStatus || undefined }));
      setLoaded(true);
    } catch (e) {
      setLoaded(false);
      setErr(e instanceof ApiError ? `${e.code}: ${e.message}` : "Failed to load assets");
    }
  }, [dq, dStatus]);

  // Seed the search box + status filter from the URL (?q=…&status=…) so a
  // finding → asset cross-link lands pre-filtered. Runs once on mount;
  // window.location keeps this static-export-safe (no useSearchParams Suspense).
  React.useEffect(() => {
    if (!mounted) return;
    const sp = new URLSearchParams(window.location.search);
    const qp = sp.get("q");
    const st = sp.get("status");
    if (qp) setQ(qp);
    if (st) setStatus(st);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mounted]);

  React.useEffect(() => {
    if (mounted) load();
  }, [mounted, load]);

  // "New since last scan": assets first discovered in their most recent scan
  // (first_seen_scan set + equal to last_scan_id) — the new-domain view.
  const [newOnly, setNewOnly] = React.useState(false);
  const shownAssets = React.useMemo(() => assets.filter((a) => {
    if (newOnly && !(a.first_seen_scan && a.first_seen_scan === a.last_scan_id)) return false;
    if (source !== "all" && a.source !== source) return false;
    if (priorityMin === "none") { if (a.priority != null) return false; }
    else if (priorityMin !== "any") { if ((a.priority ?? 0) < Number(priorityMin)) return false; }
    if (findings !== "any") {
      const c = a.finding_counts || {};
      const tot = sumCounts(c);
      if (findings === "clean") return tot === 0;
      if (findings === "critical") return (c.critical ?? 0) > 0;
      if (findings === "high") return (c.critical ?? 0) + (c.high ?? 0) > 0;
      if (findings === "medium") return (c.critical ?? 0) + (c.high ?? 0) + (c.medium ?? 0) > 0;
    }
    return true;
  }), [assets, newOnly, source, priorityMin, findings]);

  // Sort applied WITHIN each iştirak group (the view stays grouped by design).
  const cmp = React.useCallback((a: Asset, b: Asset) => {
    const byName = a.fqdn.localeCompare(b.fqdn);
    switch (sort) {
      case "priority": return (b.priority ?? -1) - (a.priority ?? -1) || byName;
      case "exposure": return exposureScore(b.finding_counts || {}) - exposureScore(a.finding_counts || {}) || byName;
      case "findings": return sumCounts(b.finding_counts || {}) - sumCounts(a.finding_counts || {}) || byName;
      case "lastseen": return (b.last_seen ? Date.parse(b.last_seen) : 0) - (a.last_seen ? Date.parse(a.last_seen) : 0) || byName;
      case "name": return byName;
      default: return byName; // group: fqdn asc
    }
  }, [sort]);

  // group by iştirak (null → "Ungrouped"); sort rows within each group
  const groups = React.useMemo(() => {
    const m = new Map<string, Asset[]>();
    for (const a of shownAssets) {
      const g = a.group || "Ungrouped";
      (m.get(g) ?? m.set(g, []).get(g)!).push(a);
    }
    for (const rows of m.values()) rows.sort(cmp);
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [shownAssets, cmp]);

  // Defer the (potentially large) grouped list so a facet change / refetch
  // re-render stays off the interaction's critical path — the input and other
  // controls keep responding while the heavy list catches up.
  const deferredGroups = React.useDeferredValue(groups);

  // Active-filter chips (non-default facets), for the removable chip row.
  const FINDINGS_LABEL: Record<string, string> = {
    critical: "Has critical", high: "High+", medium: "Medium+", clean: "Clean",
  };
  const activeChips = React.useMemo(() => {
    const chips: { key: string; label: string; clear: () => void }[] = [];
    if (q) chips.push({ key: "q", label: `“${q}”`, clear: () => setQ("") });
    if (status) chips.push({ key: "status", label: `Status: ${status}`, clear: () => setStatus("") });
    if (newOnly) chips.push({ key: "new", label: "New since last scan", clear: () => setNewOnly(false) });
    if (source !== "all") chips.push({ key: "source", label: `Source: ${source}`, clear: () => setSource("all") });
    if (priorityMin !== "any") chips.push({
      key: "prio",
      label: priorityMin === "none" ? "Unprioritized" : `Priority ≥ ${priorityMin}`,
      clear: () => setPriorityMin("any"),
    });
    if (findings !== "any") chips.push({ key: "find", label: FINDINGS_LABEL[findings], clear: () => setFindings("any") });
    return chips;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, status, newOnly, source, priorityMin, findings]);

  const clearAll = () => {
    setQ(""); setStatus(""); setNewOnly(false); setSource("all");
    setPriorityMin("any"); setFindings("any"); setSort("group");
  };

  const addAsset = async () => {
    if (!newFqdn.trim()) return;
    try {
      await api.addAsset({
        fqdn: newFqdn.trim(),
        group: newGroup.trim() || null,
        priority: newPriority ? Number(newPriority) : null,
      });
      setNewFqdn(""); setNewGroup(""); setNewPriority("");
      toast.success("Asset added");
      load();
    } catch (e) {
      toast.error(e instanceof ApiError ? `${e.code}: ${e.message}` : "Add failed");
    }
  };

  const onImport = async (file: File) => {
    try {
      const res = await api.importAssets(await file.text());
      toast.success(`Imported: +${res.added} added, ${res.updated} updated, ${res.skipped} skipped`);
      load();
    } catch (e) {
      toast.error(e instanceof ApiError ? `${e.code}: ${e.message}` : "Import failed");
    }
  };

  // Row callbacks are memoized so the `AssetRow` React.memo can bail out when
  // the page re-renders (e.g. a keystroke in the search box) — otherwise all
  // ~468 rows reconcile on every render.
  const del = React.useCallback(async (fqdn: string) => {
    try { await api.deleteAsset(fqdn); load(); }
    catch (e) { toast.error(e instanceof ApiError ? e.message : "Delete failed"); }
  }, [load]);

  // Manual business priority (1..10). Optimistic; reload on error.
  const setPriority = React.useCallback(async (fqdn: string, p: number | null) => {
    setAssets((as) => as.map((a) => (a.fqdn === fqdn ? { ...a, priority: p } : a)));
    try { await api.updateAsset(fqdn, { priority: p }); }
    catch (e) { toast.error(e instanceof ApiError ? e.message : "Update failed"); load(); }
  }, [load]);

  // Deep-link into the New-Scan form (prefilled) so you get the full controls.
  const scan = React.useCallback((req: { group?: string; assets?: string[] }) => {
    const qs = req.group ? `?group=${encodeURIComponent(req.group)}`
      : req.assets?.length ? `?assets=${encodeURIComponent(req.assets.join(","))}` : "";
    router.push(`/scans/new${qs}`);
  }, [router]);
  const scanAsset = React.useCallback((fqdn: string) => scan({ assets: [fqdn] }), [scan]);

  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const toggleSel = React.useCallback((fqdn: string) =>
    setSelected((s) => { const n = new Set(s); n.has(fqdn) ? n.delete(fqdn) : n.add(fqdn); return n; }), []);
  const selectMany = React.useCallback((fqdns: string[], on: boolean) =>
    setSelected((s) => { const n = new Set(s); fqdns.forEach((f) => (on ? n.add(f) : n.delete(f))); return n; }), []);

  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [groupOpen, setGroupOpen] = React.useState(false);
  const [groupValue, setGroupValue] = React.useState("");
  const [prioOpen, setPrioOpen] = React.useState(false);
  const [prioValue, setPrioValue] = React.useState("");

  const bulkDelete = async () => {
    setDeleteOpen(false);
    if (!selected.size) return;
    try {
      const r = await api.bulkAssets({ action: "delete", fqdns: [...selected] });
      toast.success(`Deleted ${r.affected}`); setSelected(new Set()); load();
    } catch (e) { toast.error(e instanceof ApiError ? e.message : "Bulk delete failed"); }
  };
  const bulkSetGroup = async () => {
    setGroupOpen(false);
    try {
      const r = await api.bulkAssets({
        action: "set_group", fqdns: [...selected], group: groupValue.trim() || null,
      });
      toast.success(`Regrouped ${r.affected}`); setSelected(new Set()); load();
    } catch (e) { toast.error(e instanceof ApiError ? e.message : "Bulk set-group failed"); }
  };
  const bulkSetPriority = async () => {
    setPrioOpen(false);
    const p = prioValue === "" ? null : Number(prioValue);
    const fqdns = [...selected];
    try {
      await Promise.all(fqdns.map((f) => api.updateAsset(f, { priority: p })));
      toast.success(`Priority set on ${fqdns.length}`); setSelected(new Set()); load();
    } catch (e) { toast.error(e instanceof ApiError ? e.message : "Bulk priority failed"); }
  };
  const toggle = React.useCallback((g: string) =>
    setCollapsed((s) => { const n = new Set(s); n.has(g) ? n.delete(g) : n.add(g); return n; }), []);

  const summary = React.useMemo(() => ({
    total: assets.length,
    live: assets.filter((a) => a.status === "live").length,
    dead: assets.filter((a) => a.status === "dead").length,
    exposed: assets.filter((a) => sumCounts(a.finding_counts || {}) > 0).length,
  }), [assets]);

  // Per-asset detail is a right-side slide-over drawer (one asset at a time).
  const [detailAsset, setDetailAsset] = React.useState<Asset | null>(null);
  // Keep the open drawer's data fresh after a priority edit / reload.
  React.useEffect(() => {
    if (detailAsset) {
      const fresh = assets.find((a) => a.fqdn === detailAsset.fqdn);
      if (fresh && fresh !== detailAsset) setDetailAsset(fresh);
    }
  }, [assets]); // eslint-disable-line react-hooks/exhaustive-deps

  // Flatten the grouped/filtered/sorted assets into one list of virtual rows.
  // Collapsed groups contribute only their header, so toggling a group just
  // adds/removes items — the virtualizer re-lays-out instantly.
  const flatItems = React.useMemo<FlatItem[]>(() => {
    const items: FlatItem[] = [];
    for (const [group, rows] of deferredGroups) {
      const open = !collapsed.has(group);
      items.push({ kind: "group", key: `g:${group}`, group, rows, open });
      if (open) {
        items.push({ kind: "colhead", key: `h:${group}` });
        for (const a of rows) items.push({ kind: "asset", key: `a:${a.fqdn}`, asset: a });
      }
    }
    return items;
  }, [deferredGroups, collapsed]);

  // Virtualize against the app's real scroll container (the nested <main>), not
  // the window. The list starts partway down that container (below the header,
  // summary tiles, add-asset + filter cards), so the virtualizer needs that
  // offset as `scrollMargin`; recompute it whenever anything above the list
  // changes height (load, bulk bar, filter chips, viewport resize).
  const { ref: listRef, scrollEl, nodeRef: listNodeRef } = useScrollParent();
  const [scrollMargin, setScrollMargin] = React.useState(0);
  const bulkOpen = selected.size > 0;
  const chipCount = activeChips.length;
  useIsomorphicLayoutEffect(() => {
    const listNode = listNodeRef.current;
    if (!scrollEl || !listNode) return;
    const compute = () => {
      const top = listNode.getBoundingClientRect().top
        - scrollEl.getBoundingClientRect().top + scrollEl.scrollTop;
      setScrollMargin((m) => (Math.abs(m - top) > 1 ? top : m));
    };
    compute();
    window.addEventListener("resize", compute);
    return () => window.removeEventListener("resize", compute);
  }, [scrollEl, loaded, bulkOpen, chipCount, assets.length, listNodeRef]);

  const virtualizer = useVirtualizer({
    count: flatItems.length,
    getScrollElement: () => scrollEl,
    estimateSize: (i) => ROW_SIZE[flatItems[i].kind],
    overscan: 10,
    scrollMargin,
    getItemKey: (i) => flatItems[i].key,
  });
  const virtualRows = virtualizer.getVirtualItems();

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-brand">
            External attack surface
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Inventory</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Assets grouped by iştirak — imported roots + subdomains discovered by recon. Set a
            business priority (1–10) to drive the dashboard&apos;s prioritization.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input ref={fileRef} type="file" accept=".csv,text/csv" className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) onImport(f); e.target.value = ""; }} />
          <Button variant="outline" className="gap-1.5" onClick={() => fileRef.current?.click()}>
            <Upload className="h-4 w-4" /> Import CSV
          </Button>
          <Button variant="outline" size="icon-sm" onClick={load} aria-label="Reload">
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Summary */}
      {loaded && assets.length > 0 && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <SummaryTile n={summary.total} l="Assets" />
          <SummaryTile n={summary.live} l="Internet-facing" tone="success" />
          <SummaryTile n={summary.dead} l="Takeover-watch" tone={summary.dead ? "critical" : undefined} />
          <SummaryTile n={summary.exposed} l="With findings" tone={summary.exposed ? "high" : undefined} />
        </div>
      )}

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <Card className="flex flex-row flex-wrap items-center gap-2 p-3">
          <span className="text-sm font-medium">{selected.size} selected</span>
          <Button variant="outline" size="sm" className="gap-1.5"
            onClick={() => scan({ assets: [...selected] })}>
            <Play className="h-3.5 w-3.5" /> Scan
          </Button>
          <Button variant="outline" size="sm" onClick={() => { setGroupValue(""); setGroupOpen(true); }}>
            Set group…
          </Button>
          <Button variant="outline" size="sm" onClick={() => { setPrioValue(""); setPrioOpen(true); }}>
            Set priority…
          </Button>
          <Button variant="outline" size="sm" className="gap-1.5 text-destructive"
            onClick={() => setDeleteOpen(true)}>
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </Button>
          <Button variant="ghost" size="sm" className="ml-auto" onClick={() => setSelected(new Set())}>
            Clear
          </Button>
        </Card>
      )}

      {/* Add asset */}
      <Card className="gap-3 p-4">
        <div className="flex flex-wrap items-end gap-2">
          <Input value={newFqdn} onChange={(e) => setNewFqdn(e.target.value)}
            placeholder="domain (e.g. kuveytturk.com.tr)" className="max-w-xs" />
          <Input value={newGroup} onChange={(e) => setNewGroup(e.target.value)}
            placeholder="iştirak / group" className="max-w-[200px]" />
          <Select value={newPriority || "none"} onValueChange={(v) => setNewPriority(v === "none" ? "" : v)}>
            <SelectTrigger className="w-32" aria-label="Priority"><SelectValue placeholder="priority" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="none">no priority</SelectItem>
              {[10, 9, 8, 7, 6, 5, 4, 3, 2, 1].map((n) => (
                <SelectItem key={n} value={String(n)}>priority {n}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button className="gap-1.5" onClick={addAsset}><Plus className="h-4 w-4" /> Add</Button>
          <p className="ml-auto self-center text-xs text-muted-foreground">
            CSV: <code>domain,group,priority</code>
          </p>
        </div>
      </Card>

      {/* Filter bar */}
      <Card className="gap-3 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input value={q} onChange={(e) => setQ(e.target.value)}
              placeholder="search fqdn, tech, endpoint…" className="w-[260px] pl-8" />
          </div>
          <FacetSelect value={status || "all"} onChange={(v) => setStatus(v === "all" ? "" : v)}
            options={[["all", "Any status"], ["live", "Live"], ["dead", "Dead"]]} />
          <FacetSelect value={findings} onChange={setFindings}
            options={[["any", "Any findings"], ["critical", "Has critical"], ["high", "High+"],
              ["medium", "Medium+"], ["clean", "Clean"]]} />
          <FacetSelect value={priorityMin} onChange={setPriorityMin}
            options={[["any", "Any priority"], ["9", "Priority ≥ 9"], ["7", "Priority ≥ 7"],
              ["5", "Priority ≥ 5"], ["3", "Priority ≥ 3"], ["none", "Unprioritized"]]} />
          <FacetSelect value={source} onChange={setSource}
            options={[["all", "Any source"], ["imported", "Imported"], ["discovered", "Discovered"]]} />
          <div className="ml-auto flex items-center gap-2">
            <span className="text-xs text-muted-foreground">Sort</span>
            <FacetSelect value={sort} onChange={setSort} width="w-36"
              options={[["group", "Group order"], ["priority", "Priority"], ["exposure", "Exposure"],
                ["findings", "Findings"], ["name", "Name"], ["lastseen", "Last seen"]]} />
            <Button variant={newOnly ? "default" : "outline"} size="sm" onClick={() => setNewOnly((v) => !v)}
              title="Assets first discovered in their most recent scan">New</Button>
          </div>
        </div>
        {activeChips.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            {activeChips.map((c) => (
              <button key={c.key} onClick={c.clear}
                className="inline-flex items-center gap-1 rounded-full border border-border bg-muted/60 px-2 py-0.5 text-xs text-muted-foreground transition-smooth hover:bg-muted hover:text-foreground">
                {c.label}<X className="h-3 w-3" />
              </button>
            ))}
            <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={clearAll}>Clear all</Button>
          </div>
        )}
      </Card>

      {!loaded ? (
        err ? <InlineError message={`${err}. Check the API connection in Settings.`} onRetry={load} /> : <ListSkeleton rows={5} />
      ) : assets.length === 0 ? (
        <Card className="flex flex-col items-center gap-2 p-12 text-center">
          <Network className="h-10 w-10 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">No assets yet — import a CSV or add one above.</p>
        </Card>
      ) : flatItems.length === 0 ? (
        <Card className="p-8 text-center text-sm text-muted-foreground">
          No assets match the current filters.
        </Card>
      ) : (
        <Card className="overflow-hidden p-0">
          <div ref={listRef} className="relative w-full" style={{ height: virtualizer.getTotalSize() }}>
            {virtualRows.map((vr) => {
              const item = flatItems[vr.index];
              return (
                <div
                  key={vr.key}
                  className="absolute left-0 top-0 w-full"
                  style={{ height: vr.size, transform: `translateY(${vr.start - scrollMargin}px)` }}
                >
                  {item.kind === "group" ? (
                    <GroupHeaderRow item={item} selected={selected}
                      onToggle={toggle} onSelectMany={selectMany} onScan={scan} />
                  ) : item.kind === "colhead" ? (
                    <ColHeaderRow />
                  ) : (
                    <AssetRow asset={item.asset} selected={selected.has(item.asset.fqdn)}
                      onToggleSel={toggleSel} onSetPriority={setPriority}
                      onScan={scanAsset} onDetails={setDetailAsset} onDelete={del} />
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* Asset detail slide-over */}
      <AssetDrawer
        asset={detailAsset}
        onClose={() => setDetailAsset(null)}
        onScan={(f) => scan({ assets: [f] })}
        onSetPriority={setPriority}
      />

      {/* Bulk delete confirmation */}
      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {selected.size} asset{selected.size === 1 ? "" : "s"}?</AlertDialogTitle>
            <AlertDialogDescription>
              This removes the selected asset{selected.size === 1 ? "" : "s"} from the inventory.
              Scan history and run artifacts are not affected.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={bulkDelete}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Bulk set-group */}
      <Dialog open={groupOpen} onOpenChange={setGroupOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Set group</DialogTitle>
            <DialogDescription>
              Assign {selected.size} selected asset{selected.size === 1 ? "" : "s"} to an iştirak / group.
              Leave blank to clear.
            </DialogDescription>
          </DialogHeader>
          <Input
            autoFocus
            value={groupValue}
            onChange={(e) => setGroupValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && bulkSetGroup()}
            placeholder="iştirak / group"
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setGroupOpen(false)}>Cancel</Button>
            <Button onClick={bulkSetGroup}>Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk set-priority */}
      <Dialog open={prioOpen} onOpenChange={setPrioOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Set priority</DialogTitle>
            <DialogDescription>
              Business criticality (1 lowest → 10 highest) for {selected.size} selected asset
              {selected.size === 1 ? "" : "s"}. Leave blank to clear.
            </DialogDescription>
          </DialogHeader>
          <Select value={prioValue || "none"} onValueChange={(v) => setPrioValue(v === "none" ? "" : v)}>
            <SelectTrigger aria-label="Priority"><SelectValue placeholder="Priority" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="none">— (clear)</SelectItem>
              {Array.from({ length: 10 }, (_, i) => 10 - i).map((n) => (
                <SelectItem key={n} value={String(n)}>{n}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPrioOpen(false)}>Cancel</Button>
            <Button onClick={bulkSetPriority}>Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/** Compact self-describing filter select — the option text carries the facet
 *  name (e.g. "Any findings" / "High+"), so no separate label is needed. */
function FacetSelect({ value, onChange, options, width = "w-[150px]" }: {
  value: string; onChange: (v: string) => void; options: [string, string][]; width?: string;
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className={cn("h-9", width)}><SelectValue /></SelectTrigger>
      <SelectContent>
        {options.map(([v, label]) => <SelectItem key={v} value={v}>{label}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}

/** Summary KPI tile for the inventory header. */
function SummaryTile({ n, l, tone }: { n: number; l: string; tone?: string }) {
  const color = tone === "success" ? "var(--success)"
    : tone === "critical" ? "var(--sev-critical)"
      : tone === "high" ? "var(--sev-high)" : undefined;
  return (
    <Card className="gap-0.5 p-3">
      <span className="text-2xl font-bold tabular-nums" style={color ? { color } : undefined}>{n}</span>
      <span className="text-xs text-muted-foreground">{l}</span>
    </Card>
  );
}

/** Inline priority editor — click the badge to pick 1–10 (or clear). */
function PriorityCell({ asset, onSet }: { asset: Asset; onSet: (fqdn: string, p: number | null) => void }) {
  const [editing, setEditing] = React.useState(false);
  if (editing) {
    return (
      <select
        autoFocus
        defaultValue={asset.priority?.toString() ?? ""}
        onChange={(e) => { const v = e.target.value; onSet(asset.fqdn, v === "" ? null : Number(v)); setEditing(false); }}
        onBlur={() => setEditing(false)}
        className="h-7 rounded-md border border-border bg-input px-1 text-xs"
      >
        <option value="">—</option>
        {Array.from({ length: 10 }, (_, i) => 10 - i).map((n) => <option key={n} value={n}>{n}</option>)}
      </select>
    );
  }
  return (
    <button onClick={() => setEditing(true)} aria-label="Edit priority"
      className="rounded transition-smooth hover:opacity-80">
      <PriorityBadge p={asset.priority} />
    </button>
  );
}

/** Weighted exposure meter from an asset's last-scan finding counts. */
function ExposureCell({ counts }: { counts?: Record<string, number> }) {
  const total = sumCounts(counts || {});
  if (!total) return <span className="text-xs text-muted-foreground">—</span>;
  const worst = dominantSeverity(counts || {}) ?? "low";
  return <ScoreMeter value={exposureScore(counts || {})} max={10} tone={worst} className="w-[120px]" />;
}

/** Group divider row — select-all + collapse + "Scan group". Rendered inside
 *  the virtualized list (only when the header is on screen). */
function GroupHeaderRow({ item, selected, onToggle, onSelectMany, onScan }: {
  item: Extract<FlatItem, { kind: "group" }>;
  selected: Set<string>;
  onToggle: (g: string) => void;
  onSelectMany: (fqdns: string[], on: boolean) => void;
  onScan: (req: { group?: string; assets?: string[] }) => void;
}) {
  const { group, rows, open } = item;
  const scannable = group !== "Ungrouped";
  const allSel = rows.length > 0 && rows.every((r) => selected.has(r.fqdn));
  return (
    <div className="flex h-full items-center justify-between gap-2 border-b border-border bg-muted/30 px-4">
      <div className="flex items-center gap-2">
        <Checkbox aria-label={`select ${group}`} checked={allSel}
          onCheckedChange={(c) => onSelectMany(rows.map((r) => r.fqdn), c === true)} />
        <button onClick={() => onToggle(group)} className="flex items-center gap-2 text-left">
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <span className="font-semibold">{group}</span>
          <span className="text-xs text-muted-foreground">({rows.length})</span>
        </button>
      </div>
      {scannable && (
        <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onScan({ group })}>
          <Play className="h-3.5 w-3.5" /> Scan group
        </Button>
      )}
    </div>
  );
}

/** Column-label row — repeated once per open group; shares `COL` with AssetRow. */
function ColHeaderRow() {
  return (
    <div className="flex h-full items-center gap-3 border-b border-border bg-card px-4 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
      <div className={COL.cb} />
      <div className={COL.fqdn}>FQDN</div>
      <div className={COL.source}>Source</div>
      <div className={COL.status}>Status</div>
      <div className={COL.priority}>Priority</div>
      <div className={COL.exposure}>Exposure</div>
      <div className={COL.findings}>Findings</div>
      <div className={COL.arec}>A records</div>
      <div className={COL.lastseen}>Last seen</div>
      <div className={COL.actions}>Actions</div>
    </div>
  );
}

/** One inventory row (flex, not <tr> — the list is a virtualized div stack).
 *  Memoized so a page re-render (e.g. toggling another row's checkbox) skips
 *  rows whose asset + selected state are unchanged; parent callbacks are stable. */
const AssetRow = React.memo(function AssetRow({
  asset: a, selected, onToggleSel, onSetPriority, onScan, onDetails, onDelete,
}: {
  asset: Asset;
  selected: boolean;
  onToggleSel: (fqdn: string) => void;
  onSetPriority: (fqdn: string, p: number | null) => void;
  onScan: (fqdn: string) => void;
  onDetails: (a: Asset) => void;
  onDelete: (fqdn: string) => void;
}) {
  return (
    <div className="flex h-full items-center gap-3 border-b border-border/60 px-4 transition-smooth hover:bg-overlay/40">
      <div className={COL.cb}>
        <Checkbox aria-label={`select ${a.fqdn}`} checked={selected} onCheckedChange={() => onToggleSel(a.fqdn)} />
      </div>
      <div className={cn(COL.fqdn, "font-mono text-xs")} title={a.fqdn}>{a.fqdn}</div>
      <div className={COL.source}>
        <span className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">{a.source}</span>
      </div>
      <div className={COL.status}>
        {a.status && (
          <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", STATUS_STYLE[a.status] ?? "")}>{a.status}</span>
        )}
      </div>
      <div className={COL.priority}><PriorityCell asset={a} onSet={onSetPriority} /></div>
      <div className={COL.exposure}><ExposureCell counts={a.finding_counts} /></div>
      <div className={COL.findings}><FindingCounts counts={a.finding_counts} /></div>
      <div className={cn(COL.arec, "truncate text-xs text-muted-foreground")}>{a.a_records.slice(0, 3).join(", ")}</div>
      <div className={cn(COL.lastseen, "text-xs text-muted-foreground")}>{a.last_seen ? relativeTime(a.last_seen) : "—"}</div>
      <div className={COL.actions}>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon-sm" aria-label="Details" onClick={() => onDetails(a)}>
            <Info className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="icon-sm" aria-label="Scan" onClick={() => onScan(a.fqdn)}>
            <Play className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="icon-sm" aria-label="Delete" onClick={() => onDelete(a.fqdn)}>
            <Trash2 className="h-3.5 w-3.5 text-destructive" />
          </Button>
        </div>
      </div>
    </div>
  );
});

