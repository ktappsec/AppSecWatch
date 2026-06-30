"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import {
  Upload, Plus, Trash2, Play, ChevronDown, ChevronRight, RefreshCw, Network, Info,
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/badges";
import { toast } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import { api, ApiError } from "@/lib/api";
import { useMounted } from "@/lib/hooks";
import { relativeTime } from "@/lib/format";
import type { Asset, Finding } from "@/lib/types";

const STATUS_STYLE: Record<string, string> = {
  live: "text-[#00c853] border-[#00c853]/40",
  dead: "text-muted-foreground border-border",
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-[#d11a2a]", high: "bg-[#ff4d4f]", medium: "bg-[#ff8a3d]",
  low: "bg-[#facc15]", info: "bg-[#5b9bd5]",
};

function FindingCounts({ counts }: { counts?: Record<string, number> }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const present = order.filter((s) => (counts?.[s] ?? 0) > 0);
  if (!present.length) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <span className="flex flex-wrap items-center gap-1">
      {present.map((s) => (
        <span key={s} title={s} className="inline-flex items-center gap-1 text-[11px]">
          <span className={cn("h-2 w-2 rounded-full", SEV_DOT[s])} />{counts![s]}
        </span>
      ))}
    </span>
  );
}

export default function AssetsPage() {
  const mounted = useMounted();
  const router = useRouter();
  const fileRef = React.useRef<HTMLInputElement>(null);

  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);
  const [q, setQ] = React.useState("");
  const [status, setStatus] = React.useState("");
  const [collapsed, setCollapsed] = React.useState<Set<string>>(new Set());
  const [newFqdn, setNewFqdn] = React.useState("");
  const [newGroup, setNewGroup] = React.useState("");

  const load = React.useCallback(async () => {
    setErr(null);
    try {
      setAssets(await api.listAssets({ q: q || undefined, status: status || undefined }));
      setLoaded(true);
    } catch (e) {
      setLoaded(false);
      setErr(e instanceof ApiError ? `${e.code}: ${e.message}` : "Failed to load assets");
    }
  }, [q, status]);

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

  // group by iştirak (null → "Ungrouped")
  const groups = React.useMemo(() => {
    const m = new Map<string, Asset[]>();
    for (const a of assets) {
      const g = a.group || "Ungrouped";
      (m.get(g) ?? m.set(g, []).get(g)!).push(a);
    }
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [assets]);

  const addAsset = async () => {
    if (!newFqdn.trim()) return;
    try {
      await api.addAsset({ fqdn: newFqdn.trim(), group: newGroup.trim() || null });
      setNewFqdn(""); setNewGroup("");
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

  const del = async (fqdn: string) => {
    try { await api.deleteAsset(fqdn); load(); }
    catch (e) { toast.error(e instanceof ApiError ? e.message : "Delete failed"); }
  };

  // Deep-link into the New-Scan form (prefilled) so you get the full controls.
  const scan = (req: { group?: string; assets?: string[] }) => {
    const qs = req.group ? `?group=${encodeURIComponent(req.group)}`
      : req.assets?.length ? `?assets=${encodeURIComponent(req.assets.join(","))}` : "";
    router.push(`/scans/new${qs}`);
  };

  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const toggleSel = (fqdn: string) =>
    setSelected((s) => { const n = new Set(s); n.has(fqdn) ? n.delete(fqdn) : n.add(fqdn); return n; });
  const selectMany = (fqdns: string[], on: boolean) =>
    setSelected((s) => { const n = new Set(s); fqdns.forEach((f) => (on ? n.add(f) : n.delete(f))); return n; });

  const bulkDelete = async () => {
    if (!selected.size || !window.confirm(`Delete ${selected.size} asset(s)?`)) return;
    try {
      const r = await api.bulkAssets({ action: "delete", fqdns: [...selected] });
      toast.success(`Deleted ${r.affected}`); setSelected(new Set()); load();
    } catch (e) { toast.error(e instanceof ApiError ? e.message : "Bulk delete failed"); }
  };
  const bulkSetGroup = async () => {
    const g = window.prompt("Set group (iştirak) for selected assets:");
    if (g === null) return;
    try {
      const r = await api.bulkAssets({ action: "set_group", fqdns: [...selected], group: g.trim() || null });
      toast.success(`Regrouped ${r.affected}`); setSelected(new Set()); load();
    } catch (e) { toast.error(e instanceof ApiError ? e.message : "Bulk set-group failed"); }
  };
  const toggle = (g: string) =>
    setCollapsed((s) => { const n = new Set(s); n.has(g) ? n.delete(g) : n.add(g); return n; });

  // Per-asset detail (profile + tech + findings + surface + screenshot) — inline row.
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());
  // fqdn -> findings (undefined = not fetched, null = loading, [] / list = loaded)
  const [findingsCache, setFindingsCache] = React.useState<Record<string, Finding[] | null>>({});
  // fqdn -> screenshot object URL (undefined = not fetched, null = loading, "" = none, url = shown)
  const [shotCache, setShotCache] = React.useState<Record<string, string | null>>({});
  const createdUrls = React.useRef<string[]>([]);
  // Revoke all object URLs on unmount so blobs don't leak.
  React.useEffect(() => () => { createdUrls.current.forEach((u) => URL.revokeObjectURL(u)); }, []);
  const toggleDetail = async (a: Asset) => {
    setExpanded((s) => { const n = new Set(s); n.has(a.fqdn) ? n.delete(a.fqdn) : n.add(a.fqdn); return n; });
    if (!(a.fqdn in findingsCache)) {
      setFindingsCache((c) => ({ ...c, [a.fqdn]: null }));
      try { const f = await api.assetFindings(a.fqdn); setFindingsCache((c) => ({ ...c, [a.fqdn]: f })); }
      catch { setFindingsCache((c) => ({ ...c, [a.fqdn]: [] })); }
    }
    if (!(a.fqdn in shotCache)) {
      setShotCache((c) => ({ ...c, [a.fqdn]: null }));
      const url = await api.assetScreenshot(a.fqdn);
      if (url) createdUrls.current.push(url);
      setShotCache((c) => ({ ...c, [a.fqdn]: url ?? "" }));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Assets</h1>
          <p className="text-sm text-muted-foreground">
            Inventory grouped by iştirak. Imported roots + subdomains discovered by recon.
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

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <Card className="flex flex-row flex-wrap items-center gap-2 p-3">
          <span className="text-sm font-medium">{selected.size} selected</span>
          <Button variant="outline" size="sm" className="gap-1.5"
            onClick={() => scan({ assets: [...selected] })}>
            <Play className="h-3.5 w-3.5" /> Scan
          </Button>
          <Button variant="outline" size="sm" onClick={bulkSetGroup}>Set group…</Button>
          <Button variant="outline" size="sm" className="gap-1.5 text-destructive" onClick={bulkDelete}>
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </Button>
          <Button variant="ghost" size="sm" className="ml-auto" onClick={() => setSelected(new Set())}>
            Clear
          </Button>
        </Card>
      )}

      {/* Add + filters */}
      <Card className="gap-3 p-4">
        <div className="flex flex-wrap items-end gap-2">
          <Input value={newFqdn} onChange={(e) => setNewFqdn(e.target.value)}
            placeholder="domain (e.g. kuveytturk.com.tr)" className="max-w-xs" />
          <Input value={newGroup} onChange={(e) => setNewGroup(e.target.value)}
            placeholder="iştirak / group" className="max-w-[200px]" />
          <Button className="gap-1.5" onClick={addAsset}><Plus className="h-4 w-4" /> Add</Button>
          <div className="ml-auto flex items-center gap-2">
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="search fqdn…"
              className="max-w-[220px]" />
            <select value={status} onChange={(e) => setStatus(e.target.value)}
              className="h-9 rounded-md border border-border bg-input px-2 text-sm">
              <option value="">all</option>
              <option value="live">live</option>
              <option value="dead">dead</option>
            </select>
          </div>
        </div>
        <p className="text-xs text-muted-foreground">CSV format: <code>domain,group</code> (header optional).</p>
      </Card>

      {!loaded ? (
        <Card className="p-6 text-sm text-muted-foreground">
          {err ? <>Couldn&apos;t load — <span className="text-destructive">{err}</span>. Check the API connection in Settings.</> : "Loading…"}
        </Card>
      ) : assets.length === 0 ? (
        <Card className="flex flex-col items-center gap-2 p-12 text-center">
          <Network className="h-10 w-10 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">No assets yet — import a CSV or add one above.</p>
        </Card>
      ) : (
        <div className="space-y-3">
          {groups.map(([group, rows]) => {
            const open = !collapsed.has(group);
            const scannable = group !== "Ungrouped";
            return (
              <Card key={group} className="overflow-hidden p-0">
                <div className="flex items-center justify-between gap-2 px-4 py-3">
                  <div className="flex items-center gap-2">
                    <input type="checkbox" aria-label={`select ${group}`}
                      checked={rows.length > 0 && rows.every((r) => selected.has(r.fqdn))}
                      onChange={(e) => selectMany(rows.map((r) => r.fqdn), e.target.checked)}
                      className="h-4 w-4 accent-[var(--primary)]" />
                    <button onClick={() => toggle(group)} className="flex items-center gap-2 text-left">
                      {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                      <span className="font-semibold">{group}</span>
                      <span className="text-xs text-muted-foreground">({rows.length})</span>
                    </button>
                  </div>
                  {scannable && (
                    <Button variant="outline" size="sm" className="gap-1.5"
                      onClick={() => scan({ group })}>
                      <Play className="h-3.5 w-3.5" /> Scan group
                    </Button>
                  )}
                </div>
                {open && (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-8"></TableHead>
                        <TableHead>FQDN</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Findings</TableHead>
                        <TableHead className="hidden lg:table-cell">A records</TableHead>
                        <TableHead className="hidden md:table-cell">Last seen</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {rows.map((a) => (
                        <React.Fragment key={a.fqdn}>
                        <TableRow className={cn(expanded.has(a.fqdn) && "border-b-0")}>
                          <TableCell>
                            <input type="checkbox" aria-label={`select ${a.fqdn}`}
                              checked={selected.has(a.fqdn)} onChange={() => toggleSel(a.fqdn)}
                              className="h-4 w-4 accent-[var(--primary)]" />
                          </TableCell>
                          <TableCell className="max-w-[260px] truncate font-mono text-xs" title={a.fqdn}>{a.fqdn}</TableCell>
                          <TableCell>
                            <span className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">{a.source}</span>
                          </TableCell>
                          <TableCell>
                            {a.status && (
                              <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", STATUS_STYLE[a.status] ?? "")}>
                                {a.status}
                              </span>
                            )}
                          </TableCell>
                          <TableCell><FindingCounts counts={a.finding_counts} /></TableCell>
                          <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">
                            {a.a_records.slice(0, 3).join(", ")}
                          </TableCell>
                          <TableCell className="hidden md:table-cell text-xs text-muted-foreground">
                            {a.last_seen ? relativeTime(a.last_seen) : "—"}
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex items-center justify-end gap-1">
                              <Button variant="ghost" size="icon-sm" aria-label="Details"
                                onClick={() => toggleDetail(a)}>
                                {expanded.has(a.fqdn)
                                  ? <ChevronDown className="h-3.5 w-3.5 text-accent" />
                                  : <Info className="h-3.5 w-3.5" />}
                              </Button>
                              <Button variant="ghost" size="icon-sm" aria-label="Scan"
                                onClick={() => scan({ assets: [a.fqdn] })}>
                                <Play className="h-3.5 w-3.5" />
                              </Button>
                              <Button variant="ghost" size="icon-sm" aria-label="Delete"
                                onClick={() => del(a.fqdn)}>
                                <Trash2 className="h-3.5 w-3.5 text-destructive" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                        {expanded.has(a.fqdn) && (
                          <TableRow className="hover:bg-transparent">
                            <TableCell colSpan={8} className="bg-secondary/30 p-4">
                              <AssetDetailPanel asset={a} findings={findingsCache[a.fqdn]} screenshot={shotCache[a.fqdn]} />
                            </TableCell>
                          </TableRow>
                        )}
                        </React.Fragment>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

/** Inline detail panel shown under an expanded asset row. */
function AssetDetailPanel(
  { asset, findings, screenshot }:
  { asset: Asset; findings: Finding[] | null | undefined; screenshot: string | null | undefined },
) {
  const p = (asset.profile ?? {}) as Record<string, unknown>;
  const flags = ["handles_auth", "handles_pii", "handles_payments", "has_file_upload", "is_api"]
    .filter((k) => p[k]);
  const s = asset.surface ?? null;
  const hasSurface = !!s && [s.third_party_domains, s.endpoints, s.cookie_keys, s.storage_keys]
    .some((x) => x && x.length);
  return (
    <div className="space-y-4">
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      {/* Profile */}
      <section className="space-y-1.5">
        <h4 className="text-xs font-semibold uppercase text-muted-foreground">AI profile</h4>
        {asset.profile ? (
          <div className="space-y-1 text-xs">
            <p><span className="text-muted-foreground">Type:</span> {String(p.app_type ?? "—")}</p>
            <p><span className="text-muted-foreground">Audience:</span> {String(p.audience ?? "—")} · {String(p.confidence ?? "—")} conf.</p>
            {flags.length > 0 && (
              <p className="flex flex-wrap gap-1">
                {flags.map((k) => (
                  <span key={k} className="rounded bg-secondary px-1.5 py-0.5 text-[10px]">
                    {k.replace("handles_", "").replace("has_file_upload", "file-upload").replace("is_api", "API")}
                  </span>
                ))}
              </p>
            )}
            {p.reasoning ? <p className="text-muted-foreground">{String(p.reasoning)}</p> : null}
          </div>
        ) : <p className="text-xs text-muted-foreground">No profile (run an AI scan).</p>}
      </section>

      {/* Tech */}
      <section className="space-y-1.5">
        <h4 className="text-xs font-semibold uppercase text-muted-foreground">Detected tech</h4>
        {asset.tech.length ? (
          <div className="flex flex-wrap gap-1">
            {asset.tech.map((t, i) => (
              <span key={i} className="rounded border border-border px-1.5 py-0.5 text-[10px]">
                {t.name}{t.source ? <span className="text-muted-foreground"> · {t.source}</span> : null}
              </span>
            ))}
          </div>
        ) : <p className="text-xs text-muted-foreground">None detected.</p>}
      </section>

      {/* Findings (last scan) */}
      <section className="space-y-1.5">
        <h4 className="text-xs font-semibold uppercase text-muted-foreground">Findings (last scan)</h4>
        {findings === undefined || findings === null ? (
          <p className="text-xs text-muted-foreground">Loading…</p>
        ) : findings.length === 0 ? (
          <p className="text-xs text-muted-foreground">No findings.</p>
        ) : (
          <div className="space-y-1">
            {findings.map((f, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <SeverityBadge severity={f.severity} />
                <span className="truncate">{f.title}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>

    {/* Surface (EASM) + screenshot */}
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      <section className="space-y-2 md:col-span-2">
        <h4 className="text-xs font-semibold uppercase text-muted-foreground">Surface / connections</h4>
        {hasSurface ? (
          <div className="space-y-2 text-xs">
            <SurfaceList label="3rd-party domains" items={s?.third_party_domains} />
            <SurfaceList label="Endpoints" items={s?.endpoints} mono />
            <SurfaceList label="Cookie keys" items={s?.cookie_keys} mono />
            <SurfaceList label="Storage keys" items={s?.storage_keys} mono />
          </div>
        ) : <p className="text-xs text-muted-foreground">No surface data (run a scan that renders the page).</p>}
      </section>

      <section className="space-y-1.5">
        <h4 className="text-xs font-semibold uppercase text-muted-foreground">Screenshot</h4>
        {screenshot === null || screenshot === undefined ? (
          <p className="text-xs text-muted-foreground">Loading…</p>
        ) : screenshot === "" ? (
          <p className="text-xs text-muted-foreground">No screenshot.</p>
        ) : (
          <a href={screenshot} target="_blank" rel="noreferrer">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={screenshot} alt={`${asset.fqdn} screenshot`}
              className="max-h-44 rounded border border-border transition-smooth hover:opacity-90" />
          </a>
        )}
      </section>
    </div>
    </div>
  );
}

/** A labelled, wrapped chip list for one facet of an asset's surface. */
function SurfaceList({ label, items, mono }: { label: string; items?: string[]; mono?: boolean }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="space-y-1">
      <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <div className="flex flex-wrap gap-1">
        {items.map((it, i) => (
          <span key={i} className={cn(
            "rounded border border-border px-1.5 py-0.5 text-[10px]",
            mono && "font-mono",
          )}>{it}</span>
        ))}
      </div>
    </div>
  );
}
