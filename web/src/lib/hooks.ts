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
    run(); // always fetch once so the first paint has data, even if hidden

    if (intervalMs <= 0) {
      return () => { cancelled = true; }; // one-shot
    }

    // Gate the interval on tab visibility: pause polling while the tab is
    // backgrounded (don't re-download/re-render for an unseen page), and fire
    // one immediate refresh when it becomes visible again.
    let timer: ReturnType<typeof setInterval> | null = null;
    const start = () => { if (timer === null) timer = setInterval(run, intervalMs); };
    const stop = () => { if (timer !== null) { clearInterval(timer); timer = null; } };
    const onVisibility = () => {
      if (document.hidden) stop();
      else { run(); start(); }
    };

    if (typeof document === "undefined" || !document.hidden) start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      cancelled = true;
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
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

/** Debounce a rapidly-changing value; returns the latest value after `delayMs`
 * of quiet. Used to throttle server refetches driven by a text input so a
 * keystroke doesn't fire a request (and a full re-render) per character. */
export function useDebouncedValue<T>(value: T, delayMs = 250): T {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const h = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(h);
  }, [value, delayMs]);
  return debounced;
}

/** `useLayoutEffect` on the client, `useEffect` on the server — avoids the
 *  "useLayoutEffect does nothing on the server" warning during static export
 *  prerender while still running before paint in the browser. */
export const useIsomorphicLayoutEffect =
  typeof window !== "undefined" ? React.useLayoutEffect : React.useEffect;

/** Resolve the nearest scrollable ancestor (overflow-y auto|scroll) of the
 *  element the returned `ref` is attached to — used to point a virtualizer at
 *  the app's real scroll container (the nested `<main>`, not the window).
 *
 *  Uses a CALLBACK ref, not a plain ref + mount effect: the virtualized list
 *  often mounts LATE (after async data load), so a mount-time effect would run
 *  while the element is still absent and wrongly fall back to the document
 *  scroller. A callback ref fires exactly when the node attaches (or re-attaches
 *  after a filter empties/refills the list), so detection always sees the node.
 *  `nodeRef` exposes the attached element for layout reads (e.g. scrollMargin). */
export function useScrollParent(): {
  ref: (node: HTMLElement | null) => void;
  scrollEl: HTMLElement | null;
  nodeRef: React.RefObject<HTMLElement | null>;
} {
  const [scrollEl, setScrollEl] = React.useState<HTMLElement | null>(null);
  const nodeRef = React.useRef<HTMLElement | null>(null);
  const ref = React.useCallback((node: HTMLElement | null) => {
    nodeRef.current = node;
    if (!node) return;
    let n: HTMLElement | null = node.parentElement;
    while (n) {
      const oy = getComputedStyle(n).overflowY;
      if (oy === "auto" || oy === "scroll") {
        setScrollEl((prev) => (prev === n ? prev : n));
        return;
      }
      n = n.parentElement;
    }
    const doc = (document.scrollingElement as HTMLElement) ?? null;
    setScrollEl((prev) => (prev === doc ? prev : doc));
  }, []);
  return { ref, scrollEl, nodeRef };
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
