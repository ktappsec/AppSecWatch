"use client";

import Link from "next/link";
import { Menu, Moon, Sun, Plus, Settings as SettingsIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiStatus } from "@/components/api-status";
import { useTheme } from "@/components/theme-provider";
import { useMounted } from "@/lib/hooks";

export function TopBar({ onOpenSidebar }: { onOpenSidebar?: () => void }) {
  const { resolvedTheme, setTheme } = useTheme();
  const mounted = useMounted();

  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-border bg-background/80 px-4 backdrop-blur-md md:px-6">
      <Button
        variant="ghost"
        size="icon"
        className="md:hidden"
        onClick={onOpenSidebar}
        aria-label="Open menu"
      >
        <Menu className="h-5 w-5" />
      </Button>

      <div className="flex-1" />

      <ApiStatus />

      <Button asChild size="sm" className="gap-1.5">
        <Link href="/scans/new">
          <Plus className="h-4 w-4" />
          <span className="hidden sm:inline">New Scan</span>
        </Link>
      </Button>

      <Button
        variant="ghost"
        size="icon"
        aria-label="Toggle theme"
        onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
      >
        {mounted && resolvedTheme === "dark" ? (
          <Sun className="h-5 w-5" />
        ) : (
          <Moon className="h-5 w-5" />
        )}
      </Button>

      <Button asChild variant="ghost" size="icon" aria-label="Settings">
        <Link href="/settings">
          <SettingsIcon className="h-5 w-5" />
        </Link>
      </Button>

      <div className="ml-1 flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-accent text-sm font-semibold text-primary-foreground">
        SS
      </div>
    </header>
  );
}
