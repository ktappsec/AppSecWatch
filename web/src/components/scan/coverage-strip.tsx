import { Check, Minus, CircleDashed } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { CoverageEntry } from "@/lib/types";

const ORDER = ["recon", "takeovers", "tls", "nuclei", "headers", "supply-chain", "ai"];
const LABELS: Record<string, string> = {
  recon: "Recon",
  takeovers: "Takeovers",
  tls: "TLS",
  nuclei: "Web CVEs",
  headers: "Headers",
  "supply-chain": "Supply chain",
  ai: "AI",
};

function subLeaf(token: string): string {
  return token.includes(".") ? token.split(".").slice(1).join(".") : token;
}

export function CoverageStrip({
  coverage,
}: {
  coverage: Record<string, CoverageEntry>;
}) {
  const tokens = ORDER.filter((t) => coverage[t]);
  if (!tokens.length) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {tokens.map((t) => {
        const c = coverage[t];
        const partial = c.ran && c.partial;
        const subEntries = c.sub ? Object.entries(c.sub) : [];
        return (
          <Tooltip key={t}>
            <TooltipTrigger asChild>
              <span
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium",
                  partial
                    ? "border-[#ffd600]/40 bg-[#ffd600]/10 text-[#d9b400]"
                    : c.ran
                      ? "border-[#00c853]/40 bg-[#00c853]/10 text-[#00c853]"
                      : "border-border text-muted-foreground"
                )}
              >
                {partial ? (
                  <CircleDashed className="h-3 w-3" />
                ) : c.ran ? (
                  <Check className="h-3 w-3" />
                ) : (
                  <Minus className="h-3 w-3" />
                )}
                {LABELS[t] ?? t}
                {partial && <span className="opacity-70">partial</span>}
              </span>
            </TooltipTrigger>
            <TooltipContent>
              <div>{c.reason}</div>
              {subEntries.length > 0 && (
                <div className="mt-1 space-y-0.5">
                  {subEntries.map(([k, v]) => (
                    <div key={k} className="flex items-center gap-1.5">
                      <span className={v.ran ? "text-[#00c853]" : "text-muted-foreground"}>
                        {v.ran ? "✓" : "✗"}
                      </span>
                      <span>{subLeaf(k)}</span>
                    </div>
                  ))}
                </div>
              )}
            </TooltipContent>
          </Tooltip>
        );
      })}
    </div>
  );
}
