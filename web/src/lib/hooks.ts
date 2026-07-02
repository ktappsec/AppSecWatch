"use client";

import * as React from "react";

type Fetcher<T> = () => Promise<T>;

interface PollState<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  refresh: () => void;
}

/** Poll an async fetcher on an interval. `intervalMs <= 0` disables auto-refresh
 * (one-shot). `enabled=false` skips fetching entirely. */
export function usePoll<T>(
  fetcher: Fetcher<T>,
  { intervalMs = 0, enabled = true, deps = [] as React.DependencyList } = {}
): PollState<T> {
  const [data, setData] = React.useState<T | null>(null);
  const [error, setError] = React.useState<Error | null>(null);
  const [loading, setLoading] = React.useState<boolean>(enabled);
  const [tick, setTick] = React.useState(0);
  const fetcherRef = React.useRef(fetcher);
  fetcherRef.current = fetcher;

  const refresh = React.useCallback(() => setTick((t) => t + 1), []);

  React.useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    setLoading((prev) => prev && data === null ? true : prev);

    const run = async () => {
      try {
        const result = await fetcherRef.current();
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e as Error);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    run();

    if (intervalMs > 0) {
      const h = setInterval(run, intervalMs);
      return () => {
        cancelled = true;
        clearInterval(h);
      };
    }
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, intervalMs, tick, ...deps]);

  return { data, error, loading, refresh };
}

/** Read-only mount guard to avoid SSR/CSR localStorage mismatch. */
export function useMounted(): boolean {
  const [m, setM] = React.useState(false);
  React.useEffect(() => setM(true), []);
  return m;
}

/** Animated count-up to `target` (rAF, cubic ease-out). Respects reduced motion. */
export function useCountUp(target: number, duration = 700): number {
  const [val, setVal] = React.useState(target);
  React.useEffect(() => {
    if (
      typeof window === "undefined" ||
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
    ) {
      setVal(target);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setVal(target * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
      else setVal(target);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);
  return val;
}

/** Fire `handler` on a ⌘/Ctrl + `key` chord (or plain key when meta=false). */
export function useHotkey(key: string, handler: () => void, meta = true) {
  const ref = React.useRef(handler);
  ref.current = handler;
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const chord = meta ? e.metaKey || e.ctrlKey : true;
      if (chord && e.key.toLowerCase() === key.toLowerCase()) {
        e.preventDefault();
        ref.current();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [key, meta]);
}

/** localStorage-backed state, SSR-safe (returns `initial` until mounted). */
export function useLocalStorage<T extends string>(storageKey: string, initial: T) {
  const [value, setValue] = React.useState<T>(initial);
  React.useEffect(() => {
    try {
      const v = localStorage.getItem(storageKey);
      if (v !== null) setValue(v as T);
    } catch {
      /* ignore */
    }
  }, [storageKey]);
  const set = React.useCallback(
    (v: T) => {
      setValue(v);
      try {
        localStorage.setItem(storageKey, v);
      } catch {
        /* ignore */
      }
    },
    [storageKey]
  );
  return [value, set] as const;
}
