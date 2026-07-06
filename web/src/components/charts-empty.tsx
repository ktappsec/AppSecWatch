/** Light empty-state placeholder for charts. Kept in its own module (no Recharts
 *  import) so consumers that only need EmptyChart — or the dynamic charts.tsx
 *  boundary — don't pull the heavy charting bundle. */
export function EmptyChart({ label }: { label: string }) {
  return (
    <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
      {label}
    </div>
  );
}
