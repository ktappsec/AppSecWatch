"use client";

/** Minimal theme provider — next-themes-compatible API, no dependency.
 * Sets `<html class="dark|light">` + colorScheme, persists to localStorage. */
import * as React from "react";

type Theme = "dark" | "light" | "system";

type ThemeContextValue = {
  theme: Theme;
  resolvedTheme: "dark" | "light";
  setTheme: (t: Theme) => void;
};

const ThemeContext = React.createContext<ThemeContextValue | null>(null);

const STORAGE_KEY = "theme";

function systemPrefersDark(): boolean {
  if (typeof window === "undefined") return true;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function applyTheme(resolved: "dark" | "light") {
  const root = document.documentElement;
  root.classList.remove("dark", "light");
  root.classList.add(resolved);
  root.style.colorScheme = resolved;
}

export function ThemeProvider({
  children,
  defaultTheme = "light",
  enableSystem = true,
}: {
  children: React.ReactNode;
  attribute?: string;
  defaultTheme?: Theme;
  enableSystem?: boolean;
}) {
  const [theme, setThemeState] = React.useState<Theme>(defaultTheme);
  const [resolvedTheme, setResolvedTheme] = React.useState<"dark" | "light">(
    defaultTheme === "light" ? "light" : "dark"
  );

  // Hydrate from storage / system on mount.
  React.useEffect(() => {
    const stored = (typeof window !== "undefined"
      ? (localStorage.getItem(STORAGE_KEY) as Theme | null)
      : null);
    // Light is the product default; "system" only applies when explicitly chosen.
    const initial: Theme = stored ?? defaultTheme;
    setThemeState(initial);
    const resolved =
      initial === "system" ? (systemPrefersDark() ? "dark" : "light") : initial;
    setResolvedTheme(resolved);
    applyTheme(resolved);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const setTheme = React.useCallback((t: Theme) => {
    setThemeState(t);
    const resolved = t === "system" ? (systemPrefersDark() ? "dark" : "light") : t;
    setResolvedTheme(resolved);
    applyTheme(resolved);
    try {
      localStorage.setItem(STORAGE_KEY, t);
    } catch {
      /* ignore */
    }
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, resolvedTheme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = React.useContext(ThemeContext);
  // Safe default outside a provider (test safety): pretend light.
  return (
    ctx ?? {
      theme: "light",
      resolvedTheme: "light",
      setTheme: () => {},
    }
  );
}
