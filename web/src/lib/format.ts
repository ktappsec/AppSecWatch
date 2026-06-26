import { formatDistanceToNow } from "date-fns";

export function relativeTime(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return formatDistanceToNow(new Date(iso), { addSuffix: true });
  } catch {
    return iso;
  }
}

export function formatDuration(seconds?: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function shortId(id: string): string {
  // Run ids look like 2026-06-04T09-30-00Z-example_com — keep the tail.
  const parts = id.split("Z-");
  return parts.length > 1 ? parts[1] : id;
}

export function rootsLabel(roots?: string[] | null): string {
  return roots && roots.length ? roots.join(", ") : "—";
}
