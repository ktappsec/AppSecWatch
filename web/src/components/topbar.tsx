"use client";

import Link from "next/link";
import { Menu, Moon, Sun, Plus, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiStatus } from "@/components/api-status";
import { CommandPalette } from "@/components/command-palette";
import { useTheme } from "@/components/theme-provider";
import { useMounted } from "@/lib/hooks";

export function TopBar({ onOpenSidebar }: { onOpenSidebar?: () => void }) {
  const { resolvedTheme, setTheme } = useTheme();
  const mounted = useMounted();

  // Dispatch a synthetic ⌘K so the (self-contained) palette opens from the button too.
  const openPalette = () =>
    window.dispatchEvent(
      new KeyboardEvent("keydown", { key: "k", metaKey: true, bubbles: true })
    );

  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-border bg-background/70 px-4 backdrop-blur-md md:px-6">
      <Button variant="ghost" size="icon" className="md:hidden" onClick={onOpenSidebar} aria-label="Open menu">
        <Menu className="h-5 w-5" />
      </Button>

      {/* Search / command palette trigger */}
      <button
        onClick={openPalette}
        className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-sm text-muted-foreground transition-smooth hover:border-border-strong hover:text-foreground"
      >
        <Search className="h-4 w-4" />
        <span className="hidden sm:inline">Search…</span>
        <kbd className="ml-2 hidden rounded border border-border px-1.5 py-0.5 text-[10px] sm:inline">⌘K</kbd>
      </button>

      <div className="flex-1" />

      <ApiStatus />

      <Button asChild size="sm" className="gap-1.5 gradient-brand text-white shadow-glow hover:brightness-105">
        <Link href="/scans/new">
          <Plus className="h-4 w-4" />
          <span className="hidden sm:inline">New audit</span>
        </Link>
      </Button>

      <Button
        variant="ghost"
        size="icon"
        aria-label="Toggle theme"
        onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
      >
        {mounted && resolvedTheme === "dark" ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
      </Button>

      <CommandPalette />
    </header>
  );
}
