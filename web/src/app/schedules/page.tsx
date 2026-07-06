"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import {
  CalendarClock, Plus, Trash2, Power, RefreshCw, Play, Pencil, Check, X, SlidersHorizontal,
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ListSkeleton } from "@/components/ui/skeleton";
import { InlineError } from "@/components/api-error-state";
import { toast } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import { api, ApiError } from "@/lib/api";
import { useMounted } from "@/lib/hooks";
import { relativeTime } from "@/lib/format";
import {
  CadenceFields, cadenceLabel, atTimeForPayload, type Cadence,
} from "@/components/schedule/cadence-fields";
import type { Schedule, ScheduleTarget, ScheduleUpsert, ScanRequest } from "@/lib/types";

/** A schedule's target selector as a short human label. */
const targetLabel = (t: ScheduleTarget): string =>
  t.all_assets ? "all assets"
    : t.group ? `group ${t.group}`
      : t.assets?.length ? `${t.assets.length} asset${t.assets.length === 1 ? "" : "s"}`
        : t.roots?.length ? (t.roots.length === 1 ? t.roots[0] : `${t.roots.length} roots`)
          : "—";

/** A schedule's capability selection as a short label. */
const capsLabel = (s: Schedule): string =>
  s.only?.length ? `only ${s.only.join(", ")}`
    : s.skip?.length ? `skip ${s.skip.join(", ")}`
      : "full audit";

/** Build a COMPLETE ScheduleUpsert from a schedule (+ overrides). Sending the full
 *  body on every update preserves only/skip/throttle/compress — the PUT resets any
 *  field the body omits. */
const toUpsert = (s: Schedule, o: Partial<ScheduleUpsert> = {}): ScheduleUpsert => ({
  name: s.name ?? undefined,
  target: s.target,
  only: s.only ?? null,
  skip: s.skip ?? null,
  throttle: s.throttle ?? null,
  compress: s.compress,
  cadence: s.cadence as Cadence,
  at_time: s.at_time ?? null,
  weekday: s.weekday ?? null,
  enabled: s.enabled,
  ...o,
});

export default function SchedulesPage() {
  const mounted = useMounted();
  const router = useRouter();
  const [items, setItems] = React.useState<Schedule[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);

  // Inline cadence editor (light fields only; config edits go to the builder).
  const [editId, setEditId] = React.useState<string | null>(null);
  const [editName, setEditName] = React.useState("");
  const [editCadence, setEditCadence] = React.useState<Cadence>("daily");
  const [editAtTime, setEditAtTime] = React.useState("02:00");
  const [editWeekday, setEditWeekday] = React.useState(0);

  const load = React.useCallback(async () => {
    setErr(null);
    try {
      setItems(await api.listSchedules());
      setLoaded(true);
    } catch (e) {
      setLoaded(false);
      setErr(e instanceof ApiError ? `${e.code}: ${e.message}` : "Failed to load schedules");
    }
  }, []);

  React.useEffect(() => { if (mounted) load(); }, [mounted, load]);

  const beginEdit = (s: Schedule) => {
    setEditId(s.id);
    setEditName(s.name || "");
    setEditCadence((s.cadence as Cadence) || "daily");
    setEditAtTime(s.at_time || "02:00");
    setEditWeekday(s.weekday ?? 0);
  };

  const saveEdit = async (s: Schedule) => {
    try {
      await api.updateSchedule(s.id, toUpsert(s, {
        name: editName.trim() || undefined,
        cadence: editCadence,
        at_time: atTimeForPayload(editCadence, editAtTime),
        weekday: editCadence === "weekly" ? editWeekday : null,
      }));
      setEditId(null); toast.success("Schedule updated"); load();
    } catch (e) { toast.error(e instanceof ApiError ? e.message : "Update failed"); }
  };

  const toggle = async (s: Schedule) => {
    try {
      await api.updateSchedule(s.id, toUpsert(s, { enabled: !s.enabled }));
      load();
    } catch (e) { toast.error(e instanceof ApiError ? e.message : "Update failed"); }
  };

  const del = async (id: string) => {
    try { await api.deleteSchedule(id); load(); }
    catch (e) { toast.error(e instanceof ApiError ? e.message : "Delete failed"); }
  };

  // Fire the schedule's exact config as a one-off scan now.
  const runNow = async (s: Schedule) => {
    const t = s.target || {};
    const req: ScanRequest = { compress: s.compress };
    if (t.all_assets) req.all_assets = true;
    else if (t.group) req.group = t.group;
    else if (t.assets?.length) req.assets = t.assets;
    else if (t.roots?.length) req.roots = t.roots;
    if (s.only?.length) req.only = s.only;
    if (s.skip?.length) req.skip = s.skip;
    if (s.throttle) req.throttle = s.throttle as ScanRequest["throttle"];
    try {
      const job = await api.submitScan(req);
      toast.success("Scan started", { description: job.id });
      router.push(`/scans/detail?id=${encodeURIComponent(job.id)}`);
    } catch (e) {
      toast.error(e instanceof ApiError ? `${e.code}: ${e.message}` : "Run failed");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Schedules</h1>
          <p className="text-sm text-muted-foreground">
            Recurring audits (times are UTC). Build the scan config in New audit, then choose
            Schedule.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button className="gap-1.5" onClick={() => router.push("/scans/new")}>
            <Plus className="h-4 w-4" /> New schedule
          </Button>
          <Button variant="outline" size="icon-sm" onClick={load} aria-label="Reload">
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {!loaded ? (
        err ? <InlineError message={err} onRetry={load} /> : <ListSkeleton />
      ) : items.length === 0 ? (
        <Card className="flex flex-col items-center gap-3 p-12 text-center">
          <CalendarClock className="h-10 w-10 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">No schedules yet.</p>
          <Button className="gap-1.5" onClick={() => router.push("/scans/new")}>
            <Plus className="h-4 w-4" /> Create one in New audit
          </Button>
        </Card>
      ) : (
        <div className="space-y-2">
          {items.map((s) => (
            <Card key={s.id} className={cn("gap-3 p-4", !s.enabled && "opacity-60")}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold">{s.name || s.id}</span>
                    <span className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">
                      {targetLabel(s.target)}
                    </span>
                    <span className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">
                      {capsLabel(s)}{s.throttle ? ` · ${s.throttle}` : ""}
                    </span>
                    {!s.enabled && <span className="text-[10px] text-muted-foreground">(disabled)</span>}
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {cadenceLabel(s)} · next {s.next_run_at ? relativeTime(s.next_run_at) : "—"}
                    {s.last_run_at && <> · last {relativeTime(s.last_run_at)}</>}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <Button variant="outline" size="sm" className="gap-1.5" onClick={() => runNow(s)}>
                    <Play className="h-3.5 w-3.5" /> Run now
                  </Button>
                  <Button variant="ghost" size="sm" className="gap-1.5"
                    onClick={() => router.push(`/scans/new?schedule=${encodeURIComponent(s.id)}`)}
                    title="Edit the scan config in the builder">
                    <SlidersHorizontal className="h-3.5 w-3.5" /> Edit config
                  </Button>
                  <Button variant="ghost" size="icon-sm" aria-label="Edit cadence"
                    onClick={() => (editId === s.id ? setEditId(null) : beginEdit(s))}>
                    <Pencil className={cn("h-4 w-4", editId === s.id && "text-primary")} />
                  </Button>
                  <Button variant="ghost" size="icon-sm" aria-label="Toggle" onClick={() => toggle(s)}>
                    <Power className={cn("h-4 w-4", s.enabled ? "text-success" : "text-muted-foreground")} />
                  </Button>
                  <Button variant="ghost" size="icon-sm" aria-label="Delete" onClick={() => del(s.id)}>
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              </div>

              {/* Inline cadence editor (name + cadence/time/weekday) */}
              {editId === s.id && (
                <div className="flex flex-wrap items-end gap-3 border-t border-border pt-3">
                  <div className="space-y-1.5">
                    <Label>Name</Label>
                    <Input value={editName} onChange={(e) => setEditName(e.target.value)}
                      className="w-44" placeholder="schedule name" />
                  </div>
                  <CadenceFields
                    cadence={editCadence} onCadence={setEditCadence}
                    atTime={editAtTime} onAtTime={setEditAtTime}
                    weekday={editWeekday} onWeekday={setEditWeekday}
                  />
                  <div className="flex items-center gap-1.5 pb-0.5">
                    <Button size="sm" className="gap-1.5" onClick={() => saveEdit(s)}>
                      <Check className="h-3.5 w-3.5" /> Save
                    </Button>
                    <Button size="sm" variant="ghost" className="gap-1.5" onClick={() => setEditId(null)}>
                      <X className="h-3.5 w-3.5" /> Cancel
                    </Button>
                  </div>
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
