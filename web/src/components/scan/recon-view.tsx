import { Globe2, ServerCog, Skull } from "lucide-react";
import { Card } from "@/components/ui/card";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import type { AssetStatus, LiveWebServer, TriagedAsset } from "@/lib/types";

const STATUS_META = {
  live: { label: "Live (scanned)", icon: Globe2, cls: "text-success" },
  dead: { label: "Dead / dangling", icon: Skull, cls: "text-muted-foreground" },
} as const;

export function ReconView({
  assets,
  liveServers,
  wildcards,
}: {
  assets: TriagedAsset[];
  liveServers: LiveWebServer[];
  wildcards: string[];
}) {
  const statuses: AssetStatus[] = ["live", "dead"];
  const grouped = Object.fromEntries(
    statuses.map((s) => [s, assets.filter((a) => a.status === s)])
  ) as Record<AssetStatus, TriagedAsset[]>;

  if (!assets.length && !liveServers.length) {
    return (
      <div className="py-12 text-center text-sm text-muted-foreground">
        No recon data yet.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Liveness counts */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
        {statuses.map((s) => {
          const meta = STATUS_META[s];
          const Icon = meta.icon;
          return (
            <Card key={s} className="flex-row items-center gap-3 p-4">
              <Icon className={cn("h-5 w-5", meta.cls)} />
              <div>
                <p className="text-xl font-semibold tabular-nums">{grouped[s].length}</p>
                <p className="text-xs text-muted-foreground">{meta.label}</p>
              </div>
            </Card>
          );
        })}
        <Card className="flex-row items-center gap-3 p-4">
          <ServerCog className="h-5 w-5 text-primary" />
          <div>
            <p className="text-xl font-semibold tabular-nums">{liveServers.length}</p>
            <p className="text-xs text-muted-foreground">Live web servers</p>
          </div>
        </Card>
      </div>

      {/* Live servers */}
      {liveServers.length > 0 && (
        <Card className="p-6">
          <h3 className="mb-4 text-lg font-semibold">Live web servers</h3>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>URL</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="hidden md:table-cell">Title</TableHead>
                <TableHead className="hidden lg:table-cell">Tech</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {liveServers.map((s) => (
                <TableRow key={s.url}>
                  <TableCell className="max-w-[260px] truncate font-medium">{s.url}</TableCell>
                  <TableCell>
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.5 text-xs",
                        (s.status_code ?? 0) < 400
                          ? "bg-success/15 text-success"
                          : "bg-destructive/15 text-destructive"
                      )}
                    >
                      {s.status_code ?? "—"}
                    </span>
                  </TableCell>
                  <TableCell className="hidden md:table-cell max-w-[220px] truncate text-sm text-muted-foreground">
                    {s.title ?? "—"}
                  </TableCell>
                  <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">
                    {s.tech?.slice(0, 4).join(", ") || "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Assets by liveness */}
      {statuses
        .filter((s) => grouped[s].length > 0)
        .map((s) => (
          <Card key={s} className="p-6">
            <h3 className="mb-4 flex items-center gap-2 text-lg font-semibold">
              {STATUS_META[s].label}
              <span className="text-sm font-normal text-muted-foreground">
                ({grouped[s].length})
              </span>
            </h3>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>FQDN</TableHead>
                  <TableHead className="hidden sm:table-cell">A records</TableHead>
                  <TableHead className="hidden lg:table-cell">ASN / org</TableHead>
                  <TableHead className="hidden md:table-cell">CNAME chain</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {grouped[s].map((a) => (
                  <TableRow key={a.fqdn}>
                    <TableCell className="max-w-[220px] truncate font-medium">{a.fqdn}</TableCell>
                    <TableCell className="hidden sm:table-cell text-xs text-muted-foreground">
                      {a.a_records.join(", ") || "—"}
                    </TableCell>
                    <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">
                      {a.asn ? `AS${a.asn} ${a.as_org ?? ""}` : "—"}
                    </TableCell>
                    <TableCell className="hidden md:table-cell max-w-[260px] truncate text-xs text-muted-foreground">
                      {a.cname_chain?.join(" → ") || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        ))}

      {wildcards.length > 0 && (
        <Card className="p-6">
          <h3 className="mb-2 text-lg font-semibold">Wildcards</h3>
          <div className="flex flex-wrap gap-2">
            {wildcards.map((w) => (
              <span key={w} className="rounded bg-secondary px-2 py-1 font-mono text-xs">
                {w}
              </span>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
