"use client";

import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from "@/components/ui/select";

export const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
export type Cadence = "hourly" | "daily" | "weekly";

/**
 * The light cadence controls (cadence · weekday · time) shared by the New-Scan
 * schedule dialog and the Schedules inline editor. Renders bare labelled field
 * blocks — the caller supplies the flex/grid wrapper so it composes in both a
 * stacked dialog and a horizontal row.
 */
export function CadenceFields({
  cadence, onCadence, atTime, onAtTime, weekday, onWeekday,
}: {
  cadence: Cadence;
  onCadence: (c: Cadence) => void;
  atTime: string;
  onAtTime: (v: string) => void;
  weekday: number;
  onWeekday: (n: number) => void;
}) {
  return (
    <>
      <div className="space-y-1.5">
        <Label>Cadence</Label>
        <Select value={cadence} onValueChange={(v) => onCadence(v as Cadence)}>
          <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="hourly">hourly</SelectItem>
            <SelectItem value="daily">daily</SelectItem>
            <SelectItem value="weekly">weekly</SelectItem>
          </SelectContent>
        </Select>
      </div>
      {cadence === "weekly" && (
        <div className="space-y-1.5">
          <Label>Weekday</Label>
          <Select value={String(weekday)} onValueChange={(v) => onWeekday(Number(v))}>
            <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
            <SelectContent>
              {WEEKDAYS.map((d, i) => <SelectItem key={d} value={String(i)}>{d}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
      )}
      <div className="space-y-1.5">
        <Label>{cadence === "hourly" ? "Minute (MM)" : "Time (HH:MM) UTC"}</Label>
        <Input value={atTime} onChange={(e) => onAtTime(e.target.value)} className="w-28"
          placeholder={cadence === "hourly" ? "30" : "02:00"} />
      </div>
    </>
  );
}

/** Human-readable cadence summary for a schedule row. */
export const cadenceLabel = (s: { cadence: string; at_time?: string | null; weekday?: number | null }) =>
  s.cadence === "hourly" ? `hourly @ :${(s.at_time ?? "00:00").split(":")[1] ?? "00"}`
    : s.cadence === "weekly" ? `${WEEKDAYS[s.weekday ?? 0]} @ ${s.at_time ?? "00:00"} UTC`
      : `daily @ ${s.at_time ?? "00:00"} UTC`;

/** Normalize the time field for the API payload (hourly stores minute-of-hour). */
export const atTimeForPayload = (cadence: Cadence, atTime: string): string => {
  if (cadence !== "hourly") return atTime;
  const mm = (atTime.includes(":") ? atTime.split(":")[1] : atTime) || "00";
  return `00:${mm.padStart(2, "0").slice(0, 2)}`;
};
