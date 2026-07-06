"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Radar, Network, ScanLine, CalendarClock, EyeOff, FileCode, Sparkles,
  Settings, ShieldCheck, BookOpen, LineChart,
} from "lucide-react";
import { cn } from "@/lib/utils";

const MONITOR = [
  { href: "/", label: "Attack surface", icon: Radar },
  { href: "/analytics", label: "Analytics", icon: LineChart },
  { href: "/assets", label: "Inventory", icon: Network },
  { href: "/scans", label: "Audits", icon: ScanLine },
  { href: "/schedules", label: "Schedules", icon: CalendarClock },
];
const CONFIGURE = [
  { href: "/nuclei", label: "Nuclei", icon: FileCode },
  { href: "/ai", label: "AI tuning", icon: Sparkles },
  { href: "/suppressions", label: "Suppressions", icon: EyeOff },
  { href: "/settings", label: "Settings", icon: Settings },
  { href: "/docs", label: "Docs", icon: BookOpen },
];
const ALL = [...MONITOR, ...CONFIGURE];

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();

  // Longest-prefix-wins so /scans/new highlights only "Audits" once, etc.
  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    const matches = ALL.map((e) => e.href).filter(
      (h) => h !== "/" && (pathname === h || pathname.startsWith(h + "/"))
    );
    return href === matches.sort((a, b) => b.length - a.length)[0];
  };

  const item = (entry: { href: string; label: string; icon: typeof Settings }) => {
    const active = isActive(entry.href);
    const Icon = entry.icon;
    return (
      <Link
        key={entry.href}
        href={entry.href}
        prefetch={false}
        onClick={onNavigate}
        aria-current={active ? "page" : undefined}
        className={cn(
          "relative flex items-center gap-3 rounded-lg px-3.5 py-2 text-sm transition-smooth",
          active
            ? "bg-primary/10 font-medium text-primary before:absolute before:inset-y-1.5 before:left-0 before:w-[3px] before:rounded-full before:bg-[linear-gradient(180deg,var(--brand-from),var(--brand-to))]"
            : "text-muted-foreground hover:bg-overlay hover:text-foreground"
        )}
      >
        <Icon className={cn("h-[18px] w-[18px] shrink-0", active ? "text-primary" : "")} />
        <span>{entry.label}</span>
      </Link>
    );
  };

  return (
    <aside className="flex h-full w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar/70 backdrop-blur-md">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl text-white shadow-glow gradient-brand">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div className="leading-tight">
          <p className="text-[15px] font-bold tracking-tight">AppSecWatch</p>
          <p className="text-[11px] text-muted-foreground">External ASM</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 pb-3">
        <SectionLabel>Monitor</SectionLabel>
        {MONITOR.map(item)}
        <SectionLabel className="pt-4">Configure</SectionLabel>
        {CONFIGURE.map(item)}
      </nav>
    </aside>
  );
}

function SectionLabel({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <p className={cn("px-3.5 pb-1.5 pt-2 text-[10.5px] font-semibold uppercase tracking-[0.13em] text-faint text-muted-foreground/70", className)}>
      {children}
    </p>
  );
}
