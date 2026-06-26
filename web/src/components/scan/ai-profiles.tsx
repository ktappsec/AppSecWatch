import { Brain, ShieldQuestion } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { AppProfile } from "@/lib/types";

const CONFIDENCE_CLS: Record<string, string> = {
  high: "text-[#00c853] border-[#00c853]/40",
  medium: "text-[#ffd600] border-[#ffd600]/40",
  low: "text-muted-foreground border-border",
};

export function AIProfiles({ profiles }: { profiles: Record<string, AppProfile> }) {
  const entries = Object.entries(profiles);
  if (!entries.length) {
    return (
      <div className="py-12 text-center text-sm text-muted-foreground">
        No AI profiling in this run.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {entries.map(([host, p]) => {
        const caps = [
          p.handles_auth && "Auth",
          p.handles_pii && "PII",
          p.handles_payments && "Payments",
          p.has_file_upload && "Upload",
          p.is_api && "API",
        ].filter(Boolean) as string[];

        return (
          <Card key={host} className="gap-3 p-5">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/15 text-accent">
                  <Brain className="h-4.5 w-4.5" />
                </div>
                <div>
                  <p className="truncate text-sm font-semibold">{host}</p>
                  <p className="text-xs text-muted-foreground">{p.app_type ?? "unknown"}</p>
                </div>
              </div>
              {p.error ? (
                <Badge variant="outline" className="text-destructive border-destructive/40">
                  degraded
                </Badge>
              ) : (
                <span
                  className={cn(
                    "rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
                    CONFIDENCE_CLS[p.confidence ?? "low"]
                  )}
                >
                  {p.confidence ?? "low"}
                </span>
              )}
            </div>

            <div className="flex flex-wrap gap-1.5">
              <Badge variant="secondary" className="capitalize">
                {p.audience ?? "unknown"}
              </Badge>
              {caps.map((c) => (
                <Badge key={c} variant="outline">
                  {c}
                </Badge>
              ))}
            </div>

            {p.reasoning && (
              <p className="text-xs leading-relaxed text-muted-foreground">{p.reasoning}</p>
            )}

            {p.expected_controls && p.expected_controls.length > 0 && (
              <div>
                <p className="mb-1 flex items-center gap-1 text-xs font-medium">
                  <ShieldQuestion className="h-3.5 w-3.5" /> Expected controls
                </p>
                <div className="flex flex-wrap gap-1">
                  {p.expected_controls.map((c) => (
                    <span key={c} className="rounded bg-secondary px-1.5 py-0.5 text-[11px]">
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
}
