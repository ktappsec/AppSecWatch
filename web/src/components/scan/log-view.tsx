"use client";

import * as React from "react";
import { RefreshCw, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface LogLine {
  ts?: string;
  level?: string;
  event?: string;
  msg?: string;
  message?: string;
  [k: string]: unknown;
}

const LEVEL_CLS: Record<string, string> = {
  error: "text-destructive",
  warn: "text-[#ffd600]",
  info: "text-foreground",
  debug: "text-muted-foreground",
};

export function LogView({ id, live }: { id: string; live: boolean }) {
  const [lines, setLines] = React.useState<LogLine[]>([]);
  const [raw, setRaw] = React.useState(false);
  const [rawText, setRawText] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      const text = await api.getLog(id, 500);
      setRawText(text);
      const parsed = text
        .split("\n")
        .filter(Boolean)
        .map((l) => {
          try {
            return JSON.parse(l) as LogLine;
          } catch {
            return { msg: l } as LogLine;
          }
        });
      setLines(parsed);
    } catch {
      /* ignore */
    }
  }, [id]);

  React.useEffect(() => {
    load();
    if (live) {
      const t = setInterval(load, 3000);
      return () => clearInterval(t);
    }
  }, [load, live]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setRaw((r) => !r)}>
            {raw ? "Structured" : "Raw"}
          </Button>
        </div>
        <Button asChild variant="ghost" size="sm">
          <a href={api.reportUrl(id)} target="_blank" rel="noreferrer">
            Open full report <ExternalLink className="h-4 w-4" />
          </a>
        </Button>
      </div>

      <div className="max-h-[480px] overflow-auto rounded-lg border border-border bg-[var(--card)] p-3 font-mono text-xs">
        {lines.length === 0 ? (
          <p className="py-8 text-center text-muted-foreground">No log output yet.</p>
        ) : raw ? (
          <pre className="whitespace-pre-wrap break-all text-muted-foreground">{rawText}</pre>
        ) : (
          <div className="space-y-0.5">
            {lines.map((l, i) => (
              <div key={i} className="flex gap-2">
                <span className="shrink-0 text-muted-foreground/60">
                  {l.ts ? new Date(l.ts).toLocaleTimeString() : ""}
                </span>
                {l.level && (
                  <span className={cn("shrink-0 uppercase", LEVEL_CLS[l.level] ?? "")}>
                    {l.level}
                  </span>
                )}
                <span className="break-all">
                  {l.event && <span className="text-accent">[{l.event}] </span>}
                  {l.msg ?? l.message ?? ""}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
