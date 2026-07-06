"use client";

import * as React from "react";
import { Wifi, WifiOff, Loader2 } from "lucide-react";
import { api, getApiBase } from "@/lib/api";
import { useMounted, usePoll } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

/** Pings /healthz periodically; shows a colored connectivity chip. */
export function ApiStatus() {
  const mounted = useMounted();
  // usePoll gives us tab-visibility gating for free (no pings while backgrounded).
  const { data, error } = usePoll<{ status: string; version: string }>(
    () => api.health(), { intervalMs: 15000 });
  const status: "loading" | "up" | "down" = error ? "down" : data ? "up" : "loading";
  const version = data?.version ?? null;

  if (!mounted) return null;

  const map = {
    loading: { icon: Loader2, cls: "text-muted-foreground", label: "Connecting…", spin: true },
    up: { icon: Wifi, cls: "text-success", label: `API online · v${version ?? "?"}`, spin: false },
    down: { icon: WifiOff, cls: "text-destructive", label: "API unreachable", spin: false },
  }[status];
  const Icon = map.icon;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div
          className={cn(
            "flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs",
            map.cls
          )}
        >
          <Icon className={cn("h-3.5 w-3.5", map.spin && "animate-spin")} />
          <span className="hidden sm:inline">{status === "up" ? "Online" : status === "down" ? "Offline" : "…"}</span>
        </div>
      </TooltipTrigger>
      <TooltipContent>
        {map.label}
        <span className="block text-muted-foreground">{getApiBase()}</span>
      </TooltipContent>
    </Tooltip>
  );
}
