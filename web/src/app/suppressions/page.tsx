"use client";

import * as React from "react";
import Link from "next/link";
import { EyeOff, Trash2, RefreshCw, Info, Globe, Server } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/table";
import { toast } from "@/components/ui/sonner";
import { api, ApiError } from "@/lib/api";
import { useMounted } from "@/lib/hooks";
import { relativeTime } from "@/lib/format";
import { SOURCE_LABEL } from "@/components/scan/findings-table";
import type { Suppression } from "@/lib/types";

export default function SuppressionsPage() {
  const mounted = useMounted();
  const [items, setItems] = React.useState<Suppression[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setErr(null);
    try { setItems(await api.listSuppressions()); setLoaded(true); }
    catch (e) {
      setLoaded(false);
      setErr(e instanceof ApiError ? `${e.code}: ${e.message}` : "Failed to load suppressions");
    }
  }, []);

  React.useEffect(() => { if (mounted) load(); }, [mounted, load]);

  const remove = async (fp: string) => {
    try { await api.deleteSuppression(fp); toast.success("Un-suppressed"); load(); }
    catch (e) { toast.error(e instanceof ApiError ? e.message : "Delete failed"); }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Suppressions</h1>
          <p className="text-sm text-muted-foreground">
            Manually-suppressed findings. Hidden + uncounted on every scan until removed here.
          </p>
        </div>
        <Button variant="outline" size="icon-sm" onClick={load} aria-label="Reload">
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>

      <Card className="flex gap-3 border-accent/30 bg-accent/5 p-4 text-sm">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
        <div className="space-y-1 text-muted-foreground">
          <p>
            These are <span className="font-medium text-foreground">manual</span> suppressions —
            cross-run rules you created with the eye-off button on a finding. A finding is matched
            by <span className="font-mono text-xs">source · host · key</span>; it is hidden and
            excluded from severity counts but never deleted (it stays in{" "}
            <span className="font-mono text-xs">findings.json</span>).
          </p>
          <p>
            Distinct from <span className="font-medium text-foreground">AI false-positive</span>{" "}
            suppression, which is judged fresh each scan and shown inline in the findings table.{" "}
            <Link href="/docs#suppression" className="text-accent hover:underline">
              Learn more
            </Link>
            .
          </p>
        </div>
      </Card>

      {!loaded ? (
        <Card className="p-6 text-sm text-muted-foreground">
          {err ? <>Couldn&apos;t load — <span className="text-destructive">{err}</span>.</> : "Loading…"}
        </Card>
      ) : items.length === 0 ? (
        <Card className="flex flex-col items-center gap-2 p-12 text-center">
          <EyeOff className="h-10 w-10 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">
            No suppressions. Use the eye-off button on a finding to suppress it.
          </p>
        </Card>
      ) : (
        <Card className="overflow-hidden p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Host / scope</TableHead>
                <TableHead>Key</TableHead>
                <TableHead className="hidden md:table-cell">Reason</TableHead>
                <TableHead className="hidden md:table-cell">Since</TableHead>
                <TableHead className="text-right">Remove</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((s) => {
                const isGlobal = s.scope === "global" || s.host === "*";
                return (
                <TableRow key={s.fingerprint}>
                  <TableCell>
                    <span
                      className="rounded bg-secondary px-1.5 py-0.5 text-[11px] text-muted-foreground"
                      title={`finding source: ${s.source}`}
                    >
                      {SOURCE_LABEL[s.source] ?? s.source}
                    </span>
                  </TableCell>
                  <TableCell className="text-sm">
                    <span className="inline-flex items-center gap-1.5">
                      {isGlobal ? (
                        <>
                          <Globe className="h-3.5 w-3.5 text-[#ff8a3d]" />
                          <span>Everywhere</span>
                        </>
                      ) : (
                        <>
                          <Server className="h-3.5 w-3.5 text-muted-foreground" />
                          <span className="font-mono text-xs">{s.host}</span>
                        </>
                      )}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{s.key}</TableCell>
                  <TableCell className="hidden md:table-cell text-xs text-muted-foreground">{s.reason}</TableCell>
                  <TableCell className="hidden md:table-cell text-xs text-muted-foreground">
                    {s.created_at ? relativeTime(s.created_at) : "—"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon-sm" aria-label="Un-suppress"
                      onClick={() => remove(s.fingerprint)}>
                      <Trash2 className="h-3.5 w-3.5 text-destructive" />
                    </Button>
                  </TableCell>
                </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Card>
      )}
    </div>
  );
}
