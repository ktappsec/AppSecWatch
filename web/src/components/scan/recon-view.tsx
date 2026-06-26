import { Globe2, ServerCog, Ghost, Skull } from "lucide-react";
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
import type { LiveWebServer, TriagedAsset } from "@/lib/types";

const BUCKET_META = {
  in_scope: { label: "In-Scope", icon: Globe2, cls: "text-[#00c853]" },
  shadow_it: { label: "Shadow IT", icon: Ghost, cls: "text-[#ffd600]" },
  dead: { label: "Dead", icon: Skull, cls: "text-muted-foreground" },
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
  const buckets: Array<keyof typeof BUCKET_META> = ["in_scope", "shadow_it", "dead"];
  const grouped = Object.fromEntries(
    buckets.map((b) => [b, assets.filter((a) => a.bucket === b)])
  ) as Record<keyof typeof BUCKET_META, TriagedAsset[]>;

  if (!assets.length && !liveServers.length) {
    return (
      <div className="py-12 text-center text-sm text-muted-foreground">
        No recon data yet.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Bucket counts */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {buckets.map((b) => {
          const meta = BUCKET_META[b];
          const Icon = meta.icon;
          return (
            <Card key={b} className="flex-row items-center gap-3 p-4">
              <Icon className={cn("h-5 w-5", meta.cls)} />
              <div>
                <p className="text-xl font-bold">{grouped[b].length}</p>
                <p className="text-xs text-muted-foreground">{meta.label}</p>
              </div>
            </Card>
          );
        })}
        <Card className="flex-row items-center gap-3 p-4">
          <ServerCog className="h-5 w-5 text-accent" />
          <div>
            <p className="text-xl font-bold">{liveServers.length}</p>
            <p className="text-xs text-muted-foreground">Live servers</p>
          </div>
        </Card>
      </div>

      {/* Live servers */}
      {liveServers.length > 0 && (
        <Card className="p-6">
          <h3 className="mb-4 text-lg font-bold">Live web servers</h3>
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
                          ? "bg-[#00c853]/15 text-[#00c853]"
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

      {/* Asset buckets */}
      {buckets
        .filter((b) => grouped[b].length > 0)
        .map((b) => (
          <Card key={b} className="p-6">
            <h3 className="mb-4 flex items-center gap-2 text-lg font-bold">
              {BUCKET_META[b].label}
              <span className="text-sm font-normal text-muted-foreground">
                ({grouped[b].length})
              </span>
            </h3>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>FQDN</TableHead>
                  <TableHead className="hidden sm:table-cell">A records</TableHead>
                  <TableHead className="hidden lg:table-cell">ASN</TableHead>
                  <TableHead>Reason</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {grouped[b].map((a) => (
                  <TableRow key={a.fqdn}>
                    <TableCell className="max-w-[220px] truncate font-medium">{a.fqdn}</TableCell>
                    <TableCell className="hidden sm:table-cell text-xs text-muted-foreground">
                      {a.a_records.join(", ") || "—"}
                    </TableCell>
                    <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">
                      {a.asn ? `AS${a.asn} ${a.as_org ?? ""}` : "—"}
                    </TableCell>
                    <TableCell className="max-w-[260px] truncate text-xs text-muted-foreground">
                      {a.reason}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        ))}

      {wildcards.length > 0 && (
        <Card className="p-6">
          <h3 className="mb-2 text-lg font-bold">Wildcards</h3>
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
