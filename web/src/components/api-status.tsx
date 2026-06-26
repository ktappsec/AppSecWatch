"use client";

import * as React from "react";
import { Wifi, WifiOff, Loader2 } from "lucide-react";
import { api, getApiBase } from "@/lib/api";
import { useMounted } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

/** Pings /healthz periodically; shows a colored connectivity chip. */
export function ApiStatus() {
  const mounted = useMounted();
  const [status, setStatus] = React.useState<"loading" | "up" | "down">("loading");
  const [version, setVersion] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    const check = async () => {
      try {
        const h = await api.health();
        if (!cancelled) {
          setStatus("up");
          setVersion(h.version);
        }
      } catch {
        if (!cancelled) setStatus("down");
      }
    };
    check();
    const t = setInterval(check, 15000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  if (!mounted) return null;

  const map = {
    loading: { icon: Loader2, cls: "text-muted-foreground", label: "Connecting…", spin: true },
    up: { icon: Wifi, cls: "text-[#00c853]", label: `API online · v${version ?? "?"}`, spin: false },
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
