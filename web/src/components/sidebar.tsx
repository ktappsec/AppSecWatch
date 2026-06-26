"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Radar,
  PlusCircle,
  Network,
  CalendarClock,
  EyeOff,
  FileCode,
  Sparkles,
  Settings,
  ShieldCheck,
  BookOpen,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/assets", label: "Assets", icon: Network },
  { href: "/scans", label: "Scans", icon: Radar },
  { href: "/scans/new", label: "New Scan", icon: PlusCircle },
  { href: "/schedules", label: "Schedules", icon: CalendarClock },
  { href: "/nuclei", label: "Nuclei", icon: FileCode },
];

const ADMIN = [
  { href: "/ai", label: "AI Tuning", icon: Sparkles },
  { href: "/suppressions", label: "Suppressions", icon: EyeOff },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();

  // Longest-prefix-wins so /scans/new highlights only "New Scan", not also "Scans".
  const allHrefs = [...NAV, ...ADMIN].map((e) => e.href);
  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    const matches = allHrefs.filter(
      (h) => h !== "/" && (pathname === h || pathname.startsWith(h + "/"))
    );
    const best = matches.sort((a, b) => b.length - a.length)[0];
    return href === best;
  };

  const item = (entry: { href: string; label: string; icon: typeof Settings }) => {
    const active = isActive(entry.href);
    const Icon = entry.icon;
    return (
      <Link
        key={entry.href}
        href={entry.href}
        onClick={onNavigate}
        className={cn(
          "flex items-center gap-3 rounded-lg px-4 py-2.5 text-sm transition-smooth",
          active
            ? "bg-accent/20 text-accent font-medium"
            : "text-muted-foreground hover:bg-accent/10 hover:text-foreground"
        )}
      >
        <Icon className="h-5 w-5 shrink-0" />
        <span>{entry.label}</span>
      </Link>
    );
  };

  return (
    <aside className="flex h-full w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-accent text-primary-foreground shadow-md">
          <ShieldCheck className="h-6 w-6" />
        </div>
        <div className="leading-tight">
          <p className="text-lg font-bold">WatchTower</p>
          <p className="text-[11px] text-muted-foreground">AppSec Orchestrator</p>
        </div>
      </div>

      {/* Main nav */}
      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-2">
        {NAV.map(item)}
      </nav>

      {/* Admin + footer */}
      <div className="space-y-1 border-t border-sidebar-border px-3 py-3">
        {ADMIN.map(item)}
        {item({ href: "/docs", label: "Docs", icon: BookOpen })}
      </div>
    </aside>
  );
}
