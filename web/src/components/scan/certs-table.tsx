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
        Inventory only; the TLS scorecard is the <span className="font-mono">tls</span> capability.
      </p>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>IP</TableHead>
            <TableHead>Subject CN</TableHead>
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
                <TableCell className="hidden md:table-cell max-w-[220px] truncate text-xs text-muted-foreground">
                  {c.issuer ?? "—"}
                </TableCell>
                <TableCell>
                  {c.days_remaining != null ? (
                    <span className={cn("text-sm", soon ? "font-semibold text-destructive" : "text-[#00c853]")}>
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
                </TableCell>
                <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">
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
