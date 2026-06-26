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
