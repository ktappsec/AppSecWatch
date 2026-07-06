"use client";

// Topbar notifications bell — surfaces the in-app channel of the pluggable
// notifier (new-domain alerts today). Unread badge + dropdown + mark-all-read.
import * as React from "react";
import Link from "next/link";
import { Bell, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Notification } from "@/lib/types";

export function NotificationsBell() {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);
  const { data, refresh } = usePoll<Notification[]>(
    () => api.notifications({ limit: 20 }), { intervalMs: 30000 }
  );
  const items = data ?? [];
  const unread = items.filter((n) => !n.read).length;

  React.useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const markAll = async () => { await api.markNotificationsRead().catch(() => {}); refresh(); };

  return (
    <div className="relative" ref={ref}>
      <Button variant="ghost" size="icon" aria-label="Notifications" onClick={() => setOpen((o) => !o)}>
        <Bell className="h-5 w-5" />
        {unread > 0 && (
          <span className="absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-sev-high px-1 text-[9px] font-bold text-white">
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </Button>
      {open && (
        <div className="absolute right-0 top-11 z-50 w-80 overflow-hidden rounded-xl border border-border bg-card shadow-xl">
          <div className="flex items-center justify-between border-b border-border px-3 py-2">
            <span className="text-xs font-semibold">Notifications</span>
            {unread > 0 && (
              <button onClick={markAll} className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground">
                <Check className="h-3 w-3" /> Mark all read
              </button>
            )}
          </div>
          <div className="max-h-80 overflow-y-auto">
            {items.length === 0 ? (
              <p className="px-3 py-8 text-center text-xs text-muted-foreground">No notifications.</p>
            ) : (
              items.map((n) => {
                const fqdns = (n.payload?.fqdns as string[] | undefined) ?? [];
                const href = fqdns.length ? `/assets?q=${encodeURIComponent(fqdns[0])}` : "/assets";
                return (
                  <Link
                    key={n.id}
                    href={href}
                    onClick={() => setOpen(false)}
                    className={cn(
                      "block border-b border-border/60 px-3 py-2 transition-smooth hover:bg-overlay",
                      !n.read && "bg-primary/[0.04]"
                    )}
                  >
                    <div className="flex items-start gap-2">
                      {!n.read && <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />}
                      <div className="min-w-0">
                        <p className="text-xs font-medium">{n.title}</p>
                        {n.body && <p className="truncate text-[11px] text-muted-foreground">{n.body}</p>}
                        {n.created_at && <p className="text-[10px] text-muted-foreground/70">{relativeTime(n.created_at)}</p>}
                      </div>
                    </div>
                  </Link>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
