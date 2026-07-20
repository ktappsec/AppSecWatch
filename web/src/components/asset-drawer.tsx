"use client";

// Right-side asset detail slide-over. Replaces the old inline expand row: a
// seamless drawer with a sticky identity header (fqdn/status/priority/group) and
// clean sections — Overview (AI profile + tech + screenshot), Findings (collapsed
// by category, each with cross-scan status + freeform tags like "sent-to-dev"),
// and Connections (contacted domains only). Fetches its own data on open.
import * as React from "react";
import Link from "next/link";
import { Play, Plus, X, Globe } from "lucide-react";
import {
  Sheet, SheetContent, SheetHeader, SheetBody, SheetTitle,
} from "@/components/ui/sheet";
import { SeverityBadge } from "@/components/badges";
import { PriorityBadge } from "@/components/priority-badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { CATEGORY_LABEL, findingKey } from "@/components/scan/findings-table";
import { api } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { SEVERITY_ORDER, STATUS_STYLE } from "@/lib/constants";
import type { Asset, CertInfo, Finding, FindingStateRow, Severity } from "@/lib/types";

const STATUS_TONE: Record<string, string> = {
  open: "text-sev-high",
  resolved: "text-success",
  suppressed: "text-muted-foreground",
  accepted: "text-warning",
};

export function AssetDrawer({
  asset, onClose, onScan, onSetPriority,
}: {
  asset: Asset | null;
  onClose: () => void;
  onScan: (fqdn: string) => void;
  onSetPriority: (fqdn: string, p: number | null) => void;
}) {
  const [findings, setFindings] = React.useState<Finding[] | null>(null);
  const [states, setStates] = React.useState<Record<string, FindingStateRow>>({});
  const [certs, setCerts] = React.useState<CertInfo[] | null>(null);
  const [shot, setShot] = React.useState<string | null | undefined>(undefined);
  const shotUrl = React.useRef<string | null>(null);
  const fqdn = asset?.fqdn ?? null;

  React.useEffect(() => {
    if (!fqdn) return;
    setFindings(null); setStates({}); setCerts(null); setShot(undefined);
    let live = true;
    api.assetFindings(fqdn).then((f) => live && setFindings(f)).catch(() => live && setFindings([]));
    api.assetCerts(fqdn).then((c) => live && setCerts(c)).catch(() => live && setCerts([]));
    api.findingState({ host: fqdn, limit: 500 })
      .then((rows) => { if (live) setStates(Object.fromEntries(rows.map((r) => [r.fingerprint, r]))); })
      .catch(() => {});
    api.assetScreenshot(fqdn).then((u) => {
      if (!live) { if (u) URL.revokeObjectURL(u); return; }
      if (shotUrl.current) URL.revokeObjectURL(shotUrl.current);
      shotUrl.current = u; setShot(u ?? "");
    });
    return () => { live = false; };
  }, [fqdn]);

  React.useEffect(() => () => { if (shotUrl.current) URL.revokeObjectURL(shotUrl.current); }, []);

  const patch = React.useCallback((fp: string, patch: { tags?: string[]; status?: FindingStateRow["status"] }) => {
    api.patchFindingState(fp, patch)
      .then((row) => setStates((s) => ({ ...s, [fp]: row })))
      .catch(() => {});
  }, []);

  const p = (asset?.profile ?? {}) as Record<string, unknown>;
  const flags = ["handles_auth", "handles_pii", "handles_payments", "has_file_upload", "is_api"].filter((k) => p[k]);
  const domains = React.useMemo(() => {
    const s = asset?.surface;
    return Array.from(new Set([...(s?.third_party_domains ?? []), ...(s?.script_domains ?? [])])).sort();
  }, [asset]);

  return (
    <Sheet open={!!asset} onOpenChange={(o) => !o && onClose()}>
      <SheetContent>
        {asset && (
          <>
            <SheetHeader>
              <div className="flex items-start justify-between gap-3 pr-8">
                <div className="min-w-0">
                  <SheetTitle className="truncate font-mono text-[15px]">{asset.fqdn}</SheetTitle>
                  <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                    {asset.status && (
                      <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", STATUS_STYLE[asset.status] ?? "")}>
                        {asset.status}
                      </span>
                    )}
                    <span className="rounded bg-secondary px-1.5 py-0.5 text-[10px]">{asset.source}</span>
                    {asset.group && <span>· {asset.group}</span>}
                    {asset.last_seen && <span>· seen {relativeTime(asset.last_seen)}</span>}
                  </div>
                </div>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <select
                  value={asset.priority?.toString() ?? ""}
                  onChange={(e) => onSetPriority(asset.fqdn, e.target.value ? Number(e.target.value) : null)}
                  className="rounded-md border border-border bg-background px-2 py-1 text-xs"
                  aria-label="Priority"
                >
                  <option value="">no priority</option>
                  {[10, 9, 8, 7, 6, 5, 4, 3, 2, 1].map((n) => <option key={n} value={n}>priority {n}</option>)}
                </select>
                {asset.priority ? <PriorityBadge p={asset.priority} /> : null}
                <Button size="sm" variant="outline" className="ml-auto gap-1.5" onClick={() => onScan(asset.fqdn)}>
                  <Play className="h-3.5 w-3.5" /> Scan
                </Button>
              </div>
            </SheetHeader>

            <SheetBody className="space-y-6">
              {/* Overview */}
              <Section title="Overview">
                <div className="grid gap-4 sm:grid-cols-[1fr_140px]">
                  <div className="min-w-0 space-y-2 text-sm">
                    {asset.profile ? (
                      <>
                        <p><span className="text-muted-foreground">Type:</span> {String(p.app_type ?? "—")}</p>
                        <p className="text-xs text-muted-foreground">
                          {String(p.audience ?? "—")} · {String(p.confidence ?? "—")} confidence
                        </p>
                        {flags.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {flags.map((k) => (
                              <span key={k} className="rounded bg-secondary px-1.5 py-0.5 text-[10px]">
                                {k.replace("handles_", "").replace("has_file_upload", "file-upload").replace("is_api", "API")}
                              </span>
                            ))}
                          </div>
                        )}
                        {p.reasoning ? <p className="text-xs text-muted-foreground">{String(p.reasoning)}</p> : null}
                      </>
                    ) : <p className="text-xs text-muted-foreground">No AI profile (run a scan with AI profiling).</p>}
                  </div>
                  {shot === undefined ? (
                    <Skeleton className="h-24 w-full rounded-md" />
                  ) : shot ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img src={shot} alt="screenshot" className="h-24 w-full rounded-md border border-border object-cover object-top" />
                  ) : (
                    <div className="flex h-24 items-center justify-center rounded-md border border-dashed border-border text-[10px] text-muted-foreground">
                      no screenshot
                    </div>
                  )}
                </div>
                {asset.tech.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1">
                    {asset.tech.map((t, i) => (
                      <span key={i} className="rounded bg-secondary px-1.5 py-0.5 text-[11px]"
                        title={t.source ? `via ${t.source}` : undefined}>{t.name}</span>
                    ))}
                  </div>
                )}
              </Section>

              {/* Findings — collapsed by category, with cross-scan status + tags */}
              <Section title="Findings">
                {findings === null ? (
                  <Skeleton className="h-16 w-full" />
                ) : findings.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No open findings on this asset.</p>
                ) : (
                  <FindingsByCategory findings={findings} states={states} onPatch={patch} />
                )}
              </Section>

              {/* Certificates — matched to this host by IP (cert.ip ∈ a_records), so it
                  shows the cert on the IP this host actually resolves to, not every cert
                  that merely names it in a SAN. */}
              <Section title="Certificates">
                {certs === null ? (
                  <Skeleton className="h-12 w-full" />
                ) : certs.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No certs captured for this host&apos;s IP (tlsx skipped or not HTTPS).</p>
                ) : (
                  <div className="space-y-1.5">
                    {certs.map((c, i) => <CertRow key={i} c={c} host={asset.fqdn} />)}
                  </div>
                )}
              </Section>

              {/* Connections — contacted domains only (no cookie/storage keys or endpoint paths) */}
              <Section title="Connections">
                {domains.length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {domains.map((d) => (
                      <span key={d} className="inline-flex items-center gap-1 rounded-full border border-border bg-secondary/40 px-2 py-0.5 text-[11px] text-muted-foreground">
                        <Globe className="h-3 w-3" /> {d}
                      </span>
                    ))}
                  </div>
                ) : <p className="text-xs text-muted-foreground">No connection data (run a scan that renders the page).</p>}
              </Section>
            </SheetBody>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

/** One cert served on an IP this host resolves to. `host` is the asset we're viewing;
 * when the cert's Subject CN is a different host that resolves elsewhere, we say so —
 * the cert on this IP was issued primarily for another name. */
function CertRow({ c, host }: { c: CertInfo; host: string }) {
  const soon = c.days_remaining != null && (c.expired || c.days_remaining < 30);
  const cnName = (c.subject_cn ?? "").trim().toLowerCase().replace(/\.$/, "");
  const elsewhere = (c.subject_cn_ips ?? []).filter((ip) => ip !== c.ip);
  const primaryElsewhere =
    !!cnName && !c.wildcard && cnName !== host.toLowerCase().replace(/\.$/, "") && elsewhere.length > 0;
  return (
    <div className="rounded-md border border-border bg-secondary/20 px-2.5 py-1.5 text-xs">
      <div className="flex items-center gap-2">
        <span className="font-mono text-muted-foreground">{c.ip}</span>
        <span className="min-w-0 flex-1 truncate">{c.subject_cn ?? "—"}</span>
        {c.days_remaining != null && (
          <span className={cn("font-medium", soon ? "text-destructive" : "text-success")}>
            {c.days_remaining}d
          </span>
        )}
      </div>
      <div className="mt-1 flex flex-wrap gap-1">
        {c.expired && <CertFlag className="text-destructive border-destructive/40">expired</CertFlag>}
        {c.self_signed && <CertFlag className="text-destructive border-destructive/40">self-signed</CertFlag>}
        {c.wildcard && <CertFlag className="text-muted-foreground border-border">wildcard</CertFlag>}
        {primaryElsewhere && (
          <CertFlag className="text-warning border-warning/40">
            issued for {c.subject_cn} → {elsewhere.join(", ")}
          </CertFlag>
        )}
      </div>
    </div>
  );
}

function CertFlag({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={cn("inline-block rounded border px-1.5 py-0.5 text-[10px]", className)}>
      {children}
    </span>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <h4 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">{title}</h4>
      {children}
    </section>
  );
}

function FindingsByCategory({
  findings, states, onPatch,
}: {
  findings: Finding[];
  states: Record<string, FindingStateRow>;
  onPatch: (fp: string, patch: { tags?: string[]; status?: FindingStateRow["status"] }) => void;
}) {
  const cats = React.useMemo(() => {
    const ord = (s: string) => SEVERITY_ORDER.indexOf(s as Severity);
    const m = new Map<string, { id: string; label: string; items: Finding[]; worst: number }>();
    for (const f of findings) {
      const cat = (f.category as string) || "other";
      const e = m.get(cat) ?? { id: cat, label: CATEGORY_LABEL[cat] ?? cat, items: [], worst: 99 };
      e.items.push(f); e.worst = Math.min(e.worst, ord(f.severity));
      m.set(cat, e);
    }
    return [...m.values()].sort((a, b) => a.worst - b.worst);
  }, [findings]);

  return (
    <div className="space-y-3">
      {cats.map((c) => (
        <div key={c.id}>
          <div className="mb-1 text-xs font-semibold">{c.label} <span className="font-normal text-muted-foreground">· {c.items.length}</span></div>
          <div className="space-y-1.5">
            {c.items.map((f, i) => {
              const fp = `${f.source}|${f.host ?? ""}|${findingKey(f)}`;
              const st = states[fp];
              return (
                <div key={i} className="rounded-md border border-border bg-secondary/20 px-2.5 py-1.5">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="min-w-0 flex-1 truncate text-xs">{f.title}</span>
                    {st && (
                      <span className={cn("text-[10px] font-medium capitalize", STATUS_TONE[st.status])}>{st.status}</span>
                    )}
                  </div>
                  {st && <TagRow row={st} onPatch={onPatch} />}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

function TagRow({
  row, onPatch,
}: {
  row: FindingStateRow;
  onPatch: (fp: string, patch: { tags?: string[] }) => void;
}) {
  const [adding, setAdding] = React.useState(false);
  const [val, setVal] = React.useState("");
  const add = () => {
    const t = val.trim();
    if (t && !row.tags.includes(t)) onPatch(row.fingerprint, { tags: [...row.tags, t] });
    setVal(""); setAdding(false);
  };
  const remove = (t: string) => onPatch(row.fingerprint, { tags: row.tags.filter((x) => x !== t) });
  return (
    <div className="mt-1 flex flex-wrap items-center gap-1">
      {row.tags.map((t) => (
        <span key={t} className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-1.5 py-0.5 text-[10px] text-primary">
          {t}
          <button onClick={() => remove(t)} aria-label={`remove ${t}`} className="opacity-60 hover:opacity-100">
            <X className="h-2.5 w-2.5" />
          </button>
        </span>
      ))}
      {adding ? (
        <input
          autoFocus value={val} onChange={(e) => setVal(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") add(); if (e.key === "Escape") { setVal(""); setAdding(false); } }}
          onBlur={add} placeholder="tag…"
          className="w-24 rounded border border-border bg-background px-1.5 py-0.5 text-[10px] outline-none"
        />
      ) : (
        <button onClick={() => setAdding(true)}
          className="inline-flex items-center gap-0.5 rounded-full border border-dashed border-border px-1.5 py-0.5 text-[10px] text-muted-foreground hover:text-foreground">
          <Plus className="h-2.5 w-2.5" /> tag
        </button>
      )}
    </div>
  );
}
