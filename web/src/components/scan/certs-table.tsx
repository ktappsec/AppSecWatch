"use client";

import { ShieldCheck } from "lucide-react";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import type { CertInfo } from "@/lib/types";

/** Recon cert inventory (tlsx) — captured from the same handshake that harvests
 * SANs; inventory only (no findings). Expiry + self-signed flagged. */
export function CertsTable({ certs }: { certs: CertInfo[] }) {
  if (certs.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-center">
        <ShieldCheck className="h-10 w-10 text-muted-foreground" />
        <p className="text-sm text-muted-foreground">
          No certificates captured (tlsx skipped or no in-scope IPs).
        </p>
      </div>
    );
  }
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Captured from the recon cert-grab — one handshake per in-scope IP, no extra requests.
        Rows are keyed by <span className="font-medium">IP</span>: “Serving” is which scanned
        host actually resolves there. Inventory only; the TLS scorecard is the{" "}
        <span className="font-mono">tls</span> capability.
      </p>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>IP</TableHead>
            <TableHead>Subject CN</TableHead>
            <TableHead>Serving (resolves here)</TableHead>
            <TableHead className="hidden md:table-cell">Issuer</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead>Flags</TableHead>
            <TableHead className="hidden lg:table-cell">SANs</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {certs.map((c, i) => {
            const soon = c.days_remaining != null && (c.expired || c.days_remaining < 30);
            return (
              <TableRow key={i}>
                <TableCell className="font-mono text-xs">{c.ip}</TableCell>
                <TableCell className="max-w-[200px] truncate text-sm">{c.subject_cn ?? "—"}</TableCell>
                <TableCell className="max-w-[220px] text-xs">{servingCell(c)}</TableCell>
                <TableCell className="hidden md:table-cell max-w-[220px] truncate text-xs text-muted-foreground">
                  {c.issuer ?? "—"}
                </TableCell>
                <TableCell>
                  {c.days_remaining != null ? (
                    <span className={cn("text-sm", soon ? "font-semibold text-destructive" : "text-success")}>
                      {c.days_remaining}d
                    </span>
                  ) : (
                    "—"
                  )}
                </TableCell>
                <TableCell className="space-x-1">
                  {c.expired && <Flag className="text-destructive border-destructive/40">expired</Flag>}
                  {c.self_signed && <Flag className="text-destructive border-destructive/40">self-signed</Flag>}
                  {c.wildcard && <Flag className="text-muted-foreground border-border">wildcard</Flag>}
                  {cnMismatch(c) && (
                    <Flag className="text-warning border-warning/40">
                      CN resolves elsewhere → {c.subject_cn_ips.join(", ")}
                    </Flag>
                  )}
                </TableCell>
                <TableCell className="hidden lg:table-cell text-xs text-muted-foreground tabular-nums">
                  {c.sans.length}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

function Flag({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={cn("inline-block rounded border px-1.5 py-0.5 text-[10px]", className)}>
      {children}
    </span>
  );
}

/** The scanned host(s) whose DNS actually resolves to this cert's IP. Empty is
 * possible only for out-of-scope certs; normal rows always have ≥1. */
function servingCell(c: CertInfo) {
  const names = c.resolving_names ?? [];
  if (names.length === 0) return <span className="text-muted-foreground">—</span>;
  const [first, ...rest] = names;
  return (
    <span className="font-mono">
      <span className="truncate">{first}</span>
      {rest.length > 0 && <span className="text-muted-foreground"> +{rest.length}</span>}
    </span>
  );
}

/** True when the cert's Subject CN is NOT among the hosts that resolve to this IP,
 * yet the CN demonstrably resolves elsewhere — i.e. this cert sits on an IP the CN
 * doesn't point at (a stale/co-hosted endpoint). Wildcard CNs are never a mismatch. */
function cnMismatch(c: CertInfo): boolean {
  const cn = (c.subject_cn ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (!cn || c.wildcard) return false;
  const serving = (c.resolving_names ?? []).map((n) => n.toLowerCase());
  const elsewhere = (c.subject_cn_ips ?? []).filter((ip) => ip !== c.ip);
  return !serving.includes(cn) && elsewhere.length > 0;
}
