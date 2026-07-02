import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";

function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("animate-pulse rounded-md bg-muted/60", className)} {...props} />;
}

/** A card of shimmer rows — the shared loading shape for list/table pages. */
function ListSkeleton({ rows = 4, className }: { rows?: number; className?: string }) {
  return (
    <Card className={cn("gap-3 p-5", className)}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3">
          <Skeleton className="h-4 w-4 rounded-full" />
          <Skeleton className="h-4 flex-1" style={{ maxWidth: `${70 - i * 6}%` }} />
          <Skeleton className="h-4 w-16" />
        </div>
      ))}
    </Card>
  );
}

export { Skeleton, ListSkeleton };
