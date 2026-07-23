"use client";

import * as React from "react";
import { ShieldCheck, RefreshCw, Download } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "@/components/ui/sonner";
import { api, ApiError } from "@/lib/api";
import type { SignatureStatus } from "@/lib/types";

/** Vulnerable-JS-library signature pack (the retire.js repository).
 *
 * Refresh is deliberately manual here: a scan never fetches, so an air-gapped
 * deployment keeps running on the seed shipped in the image. Auto-refresh is a
 * server-side opt-in (`signatures.auto_update`), surfaced read-only. */
export function SignaturesCard() {
  const [st, setSt] = React.useState<SignatureStatus | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [updating, setUpdating] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      setSt(await api.signatureStatus());
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Couldn't load signature status");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const update = async () => {
    setUpdating(true);
    try {
      const next = await api.updateSignatures();
      setSt(next);
      toast.success(`Signatures updated — ${next.entry_count} libraries, ${next.vuln_count} advisories`);
    } catch (e) {
      // A failed fetch leaves the current pack in place; say so explicitly.
      toast.error(
        e instanceof ApiError ? `Update failed: ${e.message}` : "Update failed",
        { description: "The current signature pack is unchanged — scans are unaffected." },
      );
    } finally {
      setUpdating(false);
    }
  };

  return (
    <Card className="gap-5 p-6">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-primary" />
          <h3 className="text-lg font-semibold">JS library signatures</h3>
        </div>
        <Button variant="outline" size="icon-sm" onClick={load} aria-label="Reload" disabled={loading}>
          <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        Vulnerable-JS-library detection uses the{" "}
        <a
          href="https://github.com/RetireJS/retire.js"
          target="_blank"
          rel="noreferrer noopener"
          className="underline underline-offset-2 hover:text-foreground transition-smooth"
        >
          retire.js
        </a>{" "}
        signature repository. A copy ships with the image, so scans work offline; refreshing pulls
        the latest advisories.
      </p>

      {error ? (
        <p className="text-sm text-destructive">{error}</p>
      ) : !st ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={st.origin === "store" ? "default" : "secondary"}>
              {st.origin === "store" ? "Updated" : "Bundled"}
            </Badge>
            <span className="text-sm text-muted-foreground">
              {st.entry_count} libraries · {st.vuln_count} advisories
            </span>
            {st.auto_update && <Badge variant="outline">Auto-refresh on</Badge>}
          </div>

          <p className="rounded-md border border-border bg-secondary/30 px-3 py-2 text-[11px] text-muted-foreground">
            {st.fetched_at
              ? <>Last updated {new Date(st.fetched_at).toLocaleString()}.</>
              : <>Running the version bundled with this image — never refreshed.</>}{" "}
            Stored in <span className="font-mono">{st.store_dir}</span>. Mount this path so updates
            survive a rebuild.
          </p>
        </>
      )}

      <div className="flex justify-end">
        <Button onClick={update} disabled={updating || !st} className="gap-1.5">
          <Download className={updating ? "h-4 w-4 animate-pulse" : "h-4 w-4"} />
          {updating ? "Updating…" : "Update now"}
        </Button>
      </div>
    </Card>
  );
}
