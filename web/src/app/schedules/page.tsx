"use client";

import * as React from "react";
import { CalendarClock, Plus, Trash2, Power, RefreshCw } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import { api, ApiError } from "@/lib/api";
import { useMounted } from "@/lib/hooks";
import { relativeTime } from "@/lib/format";
import type { Schedule, AssetGroup } from "@/lib/types";

const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export default function SchedulesPage() {
  const mounted = useMounted();
  const [items, setItems] = React.useState<Schedule[]>([]);
  const [groups, setGroups] = React.useState<AssetGroup[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);

  // create form
  const [name, setName] = React.useState("");
  const [group, setGroup] = React.useState("");
  const [cadence, setCadence] = React.useState<"hourly" | "daily" | "weekly">("daily");
  const [atTime, setAtTime] = React.useState("02:00");
  const [weekday, setWeekday] = React.useState(0);

  const load = React.useCallback(async () => {
    setErr(null);
    try {
      const [s, g] = await Promise.all([api.listSchedules(), api.assetGroups()]);
      setItems(s); setGroups(g.filter((x) => x.group)); setLoaded(true);
    } catch (e) {
      setLoaded(false);
      setErr(e instanceof ApiError ? `${e.code}: ${e.message}` : "Failed to load schedules");
    }
  }, []);

  React.useEffect(() => { if (mounted) load(); }, [mounted, load]);

  const create = async () => {
    if (!group) { toast.error("Pick a target group"); return; }
    try {
      await api.createSchedule({
        name: name.trim() || undefined,
        target: { group },
        cadence,
        at_time: cadence === "hourly" ? `00:${atTime.split(":")[1] ?? "00"}` : atTime,
        weekday: cadence === "weekly" ? weekday : null,
      });
      setName(""); toast.success("Schedule created"); load();
    } catch (e) {
      toast.error(e instanceof ApiError ? `${e.code}: ${e.message}` : "Create failed");
    }
  };

  const toggle = async (s: Schedule) => {
    try {
      await api.updateSchedule(s.id, {
        target: s.target, cadence: s.cadence, at_time: s.at_time, weekday: s.weekday,
        enabled: !s.enabled,
      });
      load();
    } catch (e) { toast.error(e instanceof ApiError ? e.message : "Update failed"); }
  };

  const del = async (id: string) => {
    try { await api.deleteSchedule(id); load(); }
    catch (e) { toast.error(e instanceof ApiError ? e.message : "Delete failed"); }
  };

  const cadenceLabel = (s: Schedule) =>
    s.cadence === "hourly" ? `hourly @ :${(s.at_time ?? "00:00").split(":")[1]}`
    : s.cadence === "weekly" ? `${WEEKDAYS[s.weekday ?? 0]} @ ${s.at_time} UTC`
    : `daily @ ${s.at_time} UTC`;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Schedules</h1>
          <p className="text-sm text-muted-foreground">Recurring scans of an iştirak (times are UTC).</p>
        </div>
        <Button variant="outline" size="icon-sm" onClick={load} aria-label="Reload">
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>

      {/* create */}
      <Card className="gap-3 p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="space-y-1.5">
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="weekly bank" className="w-44" />
          </div>
          <div className="space-y-1.5">
            <Label>Target group</Label>
            <select value={group} onChange={(e) => setGroup(e.target.value)}
              className="h-9 w-44 rounded-md border border-border bg-input px-2 text-sm">
              <option value="">select iştirak…</option>
              {groups.map((g) => <option key={g.group} value={g.group ?? ""}>{g.group} ({g.count})</option>)}
            </select>
          </div>
          <div className="space-y-1.5">
            <Label>Cadence</Label>
            <select value={cadence} onChange={(e) => setCadence(e.target.value as typeof cadence)}
              className="h-9 w-32 rounded-md border border-border bg-input px-2 text-sm">
              <option value="hourly">hourly</option>
              <option value="daily">daily</option>
              <option value="weekly">weekly</option>
            </select>
          </div>
          {cadence === "weekly" && (
            <div className="space-y-1.5">
              <Label>Weekday</Label>
              <select value={weekday} onChange={(e) => setWeekday(Number(e.target.value))}
                className="h-9 w-28 rounded-md border border-border bg-input px-2 text-sm">
                {WEEKDAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
              </select>
            </div>
          )}
          <div className="space-y-1.5">
            <Label>{cadence === "hourly" ? "Minute (MM)" : "Time (HH:MM)"}</Label>
            <Input value={atTime} onChange={(e) => setAtTime(e.target.value)} className="w-28" placeholder="02:00" />
          </div>
          <Button className="gap-1.5" onClick={create}><Plus className="h-4 w-4" /> Create</Button>
        </div>
      </Card>

      {!loaded ? (
        <Card className="p-6 text-sm text-muted-foreground">
          {err ? <>Couldn&apos;t load — <span className="text-destructive">{err}</span>.</> : "Loading…"}
        </Card>
      ) : items.length === 0 ? (
        <Card className="flex flex-col items-center gap-2 p-12 text-center">
          <CalendarClock className="h-10 w-10 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">No schedules yet.</p>
        </Card>
      ) : (
        <div className="space-y-2">
          {items.map((s) => (
            <Card key={s.id} className={cn("flex items-center justify-between gap-3 p-4", !s.enabled && "opacity-60")}>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-semibold">{s.name || s.id}</span>
                  <span className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">
                    {s.target.group ?? "—"}
                  </span>
                  {!s.enabled && <span className="text-[10px] text-muted-foreground">(disabled)</span>}
                </div>
                <p className="text-xs text-muted-foreground">
                  {cadenceLabel(s)} · next {s.next_run_at ? relativeTime(s.next_run_at) : "—"}
                  {s.last_run_at && <> · last {relativeTime(s.last_run_at)}</>}
                </p>
              </div>
              <div className="flex items-center gap-1">
                <Button variant="ghost" size="icon-sm" aria-label="Toggle" onClick={() => toggle(s)}>
                  <Power className={cn("h-4 w-4", s.enabled ? "text-[#00c853]" : "text-muted-foreground")} />
                </Button>
                <Button variant="ghost" size="icon-sm" aria-label="Delete" onClick={() => del(s.id)}>
                  <Trash2 className="h-4 w-4 text-destructive" />
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
