"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowLeft, Ban, ExternalLink, RefreshCw, Copy, Clock, Loader2, AlertCircle,
  FileText, Download, Check, ChevronRight, ShieldCheck, Globe, Radio, TriangleAlert,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { StateBadge, SeverityDot, SeverityCounts, DegradedBadge } from "@/components/badges";
import { RiskGauge, type Rating } from "@/components/risk-gauge";
import { SeverityPie } from "@/components/charts";
import { ApiErrorState } from "@/components/api-error-state";
import { CoverageStrip } from "@/components/scan/coverage-strip";
import { FindingsTable, findingKey, SOURCE_LABEL } from "@/components/scan/findings-table";
import { CertsTable } from "@/components/scan/certs-table";
import { TLSScorecard } from "@/components/scan/tls-scorecard";
import { ReconView } from "@/components/scan/recon-view";
import { AIProfiles } from "@/components/scan/ai-profiles";
import { LogView } from "@/components/scan/log-view";
import { api, ApiError } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { relativeTime, formatDuration, rootsLabel } from "@/lib/format";
import { TERMINAL_STATES } from "@/lib/constants";
import { posture as clientPosture, riskScore as clientRisk } from "@/lib/risk";
import { toast } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import type { Finding, JobStatus, Posture, ScanResult, TLSHostReport, CertInfo } from "@/lib/types";

const STAGE_FLOW = [
  "recon.subfinder", "recon.dnsx-triage", "recon.tlsx-loop", "recon.httpx",
  "ai.profile", "audit.takeovers", "audit.parallel", "audit.zap", "ai.analyze",
  "report", "compress",
];
const STAGE_LABEL: Record<string, string> = {
  "recon.subfinder": "Subdomains", "recon.dnsx-triage": "DNS triage",
  "recon.tlsx-loop": "Cert SANs", "recon.httpx": "Live probe", "ai.profile": "Profiling",
  "audit.takeovers": "Takeovers", "audit.parallel": "Audit fan-out", "audit.zap": "Active scan",
  "ai.analyze": "AI analysis", report: "Report", compress: "Compress",
};
const RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// Static-export-safe: the run id comes from ?id= (no dynamic route segment).
export default function ScanDetailPage() {
  return (
    <React.Suspense fallback={<DetailSkeleton />}>
      <ScanDetail />
    </React.Suspense>
  );
}

function ScanDetail() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const [terminal, setTerminal] = React.useState(false);

  const { data: job, error, refresh } = usePoll<JobStatus>(() => api.getScan(id), {
    enabled: !!id, intervalMs: terminal ? 0 : 3000, deps: [id, terminal],
  });
  React.useEffect(() => {
    if (job && TERMINAL_STATES.includes(job.state)) setTerminal(true);
  }, [job]);
  const { data: result } = usePoll<ScanResult>(() => api.getResult(id), {
    enabled: !!id && terminal, intervalMs: 0, deps: [id, terminal],
  });

  const cancel = async () => {
    try { await api.cancelScan(id); toast.success("Audit cancelled"); refresh(); }
    catch (e) { toast.error(e instanceof ApiError ? e.message : "Cancel failed"); }
  };
  const copyId = () => { navigator.clipboard?.writeText(id); toast.success("Run ID copied"); };

  if (!id) return <NotFound message="No run id given." />;
  if (error && !job) {
    if (error instanceof ApiError && error.status === 404) return <NotFound />;
    return <ApiErrorState error={error} />;
  }
  if (!job) return <DetailSkeleton />;

  const isLive = job.state === "running" || job.state === "queued";
  const totals = result?.histogram_totals ?? {};
  const findingTotal = result
    ? result.findings.filter((f) => !f.ai_verdict?.suppressed).length
    : job.finding_count;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <Link href="/scans" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" /> Audits
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="max-w-[60ch] truncate text-xl font-bold tracking-tight"
              title={job.roots?.length ? job.roots.join(", ") : undefined}>
              {rootsLabel(job.roots)} <span className="font-normal text-muted-foreground">— audit</span>
            </h1>
            <StateBadge state={job.state} />
            {(job.degraded || result?.degraded) && <DegradedBadge />}
          </div>
          <button onClick={copyId} className="inline-flex items-center gap-1.5 font-mono text-xs text-muted-foreground hover:text-foreground">
            {id} <Copy className="h-3 w-3" />
          </button>
        </div>
        <div className="flex items-center gap-2">
          {!terminal && (
            <Button variant="outline" size="icon-sm" onClick={refresh} aria-label="Refresh">
              <RefreshCw className="h-4 w-4" />
            </Button>
          )}
          {isLive && (
            <Button variant="outline" size="sm" onClick={cancel} className="gap-1.5 text-destructive">
              <Ban className="h-4 w-4" /> Cancel
            </Button>
          )}
          {terminal && (
            <Button asChild size="sm" variant="outline">
              <a href={api.executiveUrl(id)} target="_blank" rel="noreferrer">
                <FileText className="h-4 w-4" /> Executive <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </Button>
          )}
          {terminal && result?.executive_pdf_url && (
            <Button asChild size="sm" variant="outline">
              <a href={api.executivePdfUrl(id)} target="_blank" rel="noreferrer">
                <Download className="h-4 w-4" /> PDF
              </a>
            </Button>
          )}
          {terminal && (
            <Button asChild size="sm" variant="outline">
              <a href={api.reportUrl(id)} target="_blank" rel="noreferrer">
                Report <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </Button>
          )}
        </div>
      </div>

      {isLive && <LiveProgress job={job} />}

      {job.error && (
        <Card className="flex-row items-start gap-3 border-destructive/40 bg-destructive/5 p-4">
          <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-destructive" />
          <div>
            <p className="text-sm font-medium text-destructive">Audit {job.state}</p>
            <p className="text-xs text-muted-foreground">{job.error}</p>
          </div>
        </Card>
      )}

      {(job.degraded || result?.degraded) && (
        <Card className="flex-row items-start gap-3 border-warning/40 bg-warning/10 p-4">
          <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-warning" />
          <div>
            <p className="text-sm font-medium text-warning">Scan degraded — results are inconclusive</p>
            <p className="text-xs text-muted-foreground">
              {result?.degraded_reason ??
                "The target edge blocked the probe: 0 live web servers were reached despite resolvable assets. A low finding count here does NOT mean the estate is clean — re-run with a gentler throttle."}
            </p>
          </div>
        </Card>
      )}

      {!result?.degraded && !!result?.not_assessed && (
        <Card className="flex-row items-start gap-3 border-warning/30 bg-warning/5 p-3">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
          <p className="text-xs text-muted-foreground">
            <span className="font-medium text-foreground">{result.not_assessed}</span> host
            {result.not_assessed === 1 ? "" : "s"} returned a blocked/error response and could
            not be assessed — their findings are suppressed and excluded from the counts (see
            the report&apos;s &ldquo;Not assessed&rdquo; section). Not the same as clean.
          </p>
        </Card>
      )}

      <Tabs defaultValue="overview">
        <TabsList className="flex-wrap">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="findings">Findings{findingTotal ? ` (${findingTotal})` : ""}</TabsTrigger>
          <TabsTrigger value="recon">Recon</TabsTrigger>
          <TabsTrigger value="tls">TLS{result?.tls.length ? ` (${result.tls.length})` : ""}</TabsTrigger>
          <TabsTrigger value="certs">Certs{result?.tls_certs.length ? ` (${result.tls_certs.length})` : ""}</TabsTrigger>
          <TabsTrigger value="ai">AI{result ? ` (${Object.keys(result.app_profiles).length})` : ""}</TabsTrigger>
          <TabsTrigger value="log">Log</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          {result ? (
            <OverviewTab job={job} result={result} totals={totals} findingTotal={findingTotal} />
          ) : (
            <Card className="p-6"><PendingResult live={isLive} /></Card>
          )}
        </TabsContent>

        <TabsContent value="findings">
          <Card className="p-6">
            {result ? (
              <FindingsTable
                findings={result.findings}
                onSuppress={async (f, scope = "host") => {
                  try {
                    await api.addSuppression({
                      source: f.source, host: scope === "global" ? undefined : (f.host ?? undefined),
                      key: findingKey(f), scope, reason: "manual",
                    });
                    toast.success(
                      scope === "global" ? "Suppressed everywhere (all hosts)" : "Suppressed — hidden on future audits",
                      { description: `${f.source} · ${scope === "global" ? "*" : (f.host ?? "*")}` },
                    );
                  } catch (e) {
                    toast.error(e instanceof ApiError ? e.message : "Suppress failed");
                  }
                }}
              />
            ) : <PendingResult live={isLive} />}
          </Card>
        </TabsContent>

        <TabsContent value="recon">
          {result ? (
            <ReconView assets={result.assets} liveServers={result.live_servers} wildcards={result.wildcards} />
          ) : <Card className="p-6"><PendingResult live={isLive} /></Card>}
        </TabsContent>

        <TabsContent value="tls">
          {result ? <TLSScorecard reports={result.tls} /> : <Card className="p-6"><PendingResult live={isLive} /></Card>}
        </TabsContent>

        <TabsContent value="certs">
          <Card className="p-6">{result ? <CertsTable certs={result.tls_certs} /> : <PendingResult live={isLive} />}</Card>
        </TabsContent>

        <TabsContent value="ai">
          {result ? <AIProfiles profiles={result.app_profiles} /> : <Card className="p-6"><PendingResult live={isLive} /></Card>}
        </TabsContent>

        <TabsContent value="log">
          <Card className="p-6"><LogView id={id} live={isLive} /></Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Overview landing
// --------------------------------------------------------------------------- //
function DiffStat({ n, label, tone }: { n: number; label: string; tone: string }) {
  return (
    <div className="rounded-lg border border-border bg-secondary/30 p-3 text-center">
      <div className={cn("text-2xl font-bold tabular-nums", tone)}>{n}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}

function OverviewTab({
  job, result, totals, findingTotal,
}: { job: JobStatus; result: ScanResult; totals: Record<string, number>; findingTotal: number }) {
  const score = result.risk_score ?? clientRisk(totals);
  const post = (result.posture as Posture) ?? clientPosture(totals);
  const exposures = topExposures(result.findings);
  const tls = tlsPosture(result.tls, result.tls_certs);
  const s = result.summary?.assets as Record<string, number> | undefined;
  const scale = {
    live: s?.live ?? result.assets.filter((a) => a.status === "live").length,
    dead: s?.dead ?? result.assets.filter((a) => a.status === "dead").length,
    live_servers: s?.live_servers ?? result.live_servers.length,
    wildcards: s?.wildcards ?? result.wildcards.length,
  };

  return (
    <div className="space-y-4">
      {/* posture hero + top exposures */}
      <div className="grid gap-4 lg:grid-cols-[minmax(300px,1fr)_1.7fr]">
        <Card variant="glow" className="gap-0 p-5">
          <div className="flex items-center gap-4">
            <RiskGauge score={score} rating={post as Rating} size={200} />
            <div className="min-w-0">
              <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Audit posture</div>
              <PostureBadge posture={post} className="mt-2" />
              <p className="mt-3 text-sm text-muted-foreground">
                {findingTotal > 0
                  ? "Rating reflects the highest severity present across this audit."
                  : "No open findings in this audit."}
              </p>
              <div className="mt-3 flex gap-5 border-t border-border pt-3">
                <Mini n={String(findingTotal)} l="Findings" />
                <Mini n={formatDuration(job.elapsed_s)} l="Elapsed" />
                <Mini n={String(scale.live_servers)} l="Live servers" />
              </div>
            </div>
          </div>
        </Card>

        <Card className="p-5">
          <div className="mb-1 text-sm font-semibold">Top exposures</div>
          <div className="mb-2 text-xs text-muted-foreground">grouped across hosts, worst first</div>
          {exposures.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">No exposures found.</p>
          ) : (
            <div>{exposures.map((e) => <ExposureRow key={e.key} e={e} />)}</div>
          )}
        </Card>
      </div>

      {result.diff && (
        <Card className="p-5">
          <div className="mb-3 text-sm font-semibold">Changes since last scan</div>
          <div className="grid grid-cols-3 gap-4">
            <DiffStat n={result.diff.new} label="New" tone="text-sev-high" />
            <DiffStat n={result.diff.recurring} label="Recurring" tone="text-sev-medium" />
            <DiffStat n={result.diff.resolved} label="Resolved" tone="text-success" />
          </div>
        </Card>
      )}

      {/* coverage + severity */}
      <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
        <Card className="p-5">
          <div className="mb-3 text-sm font-semibold">Coverage</div>
          <CoverageStrip coverage={result.coverage ?? job.coverage} />
        </Card>
        <Card className="p-5">
          <div className="mb-3 text-sm font-semibold">Severity</div>
          <div className="flex items-center gap-4">
            <div className="w-[120px] shrink-0"><SeverityPie totals={totals} height={120} /></div>
            <div className="flex flex-1 flex-col gap-1.5">
              {(["critical", "high", "medium", "low", "info"] as const).map((k) => (
                <div key={k} className="flex items-center gap-2 text-sm">
                  <SeverityDot severity={k} />
                  <span className="capitalize text-muted-foreground">{k}</span>
                  <span className="ml-auto font-medium tabular-nums">{totals[k] || 0}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* TLS + surface */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
            <ShieldCheck className="h-4 w-4 text-muted-foreground" /> TLS &amp; certificate hygiene
          </div>
          <div className="flex flex-wrap gap-x-8 gap-y-3">
            <Mini n={<><span style={{ color: "var(--success)" }}>{tls.pass}</span><span className="text-sm text-muted-foreground">/{tls.total}</span></>} l="Hosts passing" />
            <Mini n={<span style={{ color: tls.expiring ? "var(--warning)" : undefined }}>{tls.expiring}</span>} l="Certs ≤30d" />
            <Mini n={<span style={{ color: tls.expired ? "var(--sev-critical)" : undefined }}>{tls.expired}</span>} l="Expired" />
            <Mini n={String(tls.selfSigned)} l="Self-signed" />
          </div>
        </Card>
        <Card className="p-5">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
            <Globe className="h-4 w-4 text-muted-foreground" /> Surface discovered
          </div>
          <div className="grid grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-4">
            <Mini n={String(scale.live_servers)} l="Live web servers" icon={Radio} />
            <Mini n={String(scale.live)} l="Live assets" />
            <Mini n={String(scale.dead)} l="Takeover-watch" icon={scale.dead ? TriangleAlert : undefined} />
            <Mini n={String(scale.wildcards)} l="Wildcards" />
          </div>
        </Card>
      </div>
    </div>
  );
}

type Exposure = { key: string; title: string; source: string; severity: string; hosts: Set<string> };

function topExposures(findings: Finding[], limit = 5): Exposure[] {
  const groups = new Map<string, Exposure>();
  for (const f of findings) {
    if (f.ai_verdict?.suppressed) continue;
    const key = `${f.source}|${f.check_id || f.title}`;
    let g = groups.get(key);
    if (!g) { g = { key, title: f.title, source: f.source, severity: f.severity, hosts: new Set() }; groups.set(key, g); }
    else if ((RANK[f.severity] ?? 0) > (RANK[g.severity] ?? 0)) g.severity = f.severity;
    if (f.host) g.hosts.add(f.host);
  }
  return [...groups.values()].sort(
    (a, b) => (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0) || b.hosts.size - a.hosts.size || a.key.localeCompare(b.key)
  ).slice(0, limit);
}

function ExposureRow({ e }: { e: Exposure }) {
  const c = `var(--sev-${e.severity})`;
  const n = e.hosts.size;
  return (
    <div className="flex items-center gap-3 border-t border-border py-3 first:border-t-0">
      <span className="self-stretch w-[3px] shrink-0 rounded-full" style={{ background: c }} />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium" title={e.title}>{e.title}</div>
        <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-medium capitalize"
            style={{ color: c, borderColor: `color-mix(in srgb, ${c} 45%, transparent)` }}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />{e.severity}
          </span>
          <span className="rounded border border-border bg-card px-1.5 py-0.5">{SOURCE_LABEL[e.source] ?? e.source}</span>
          <span className="font-mono">{n === 1 ? [...e.hosts][0] : `${n} host${n === 1 ? "" : "s"}`}</span>
        </div>
      </div>
      <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
    </div>
  );
}

function tlsPosture(reports: TLSHostReport[], certs: CertInfo[]) {
  const total = reports.length;
  const pass = reports.filter((r) => !r.error && r.checks.length > 0 && r.checks.every((c) => c.passed)).length;
  const expiring = certs.filter((c) => c.days_remaining != null && c.days_remaining <= 30 && !c.expired).length;
  const expired = certs.filter((c) => c.expired).length;
  const selfSigned = certs.filter((c) => c.self_signed).length;
  return { total, pass, expiring, expired, selfSigned };
}

// --------------------------------------------------------------------------- //
// Live progress — stage stepper (real state, no fake %)
// --------------------------------------------------------------------------- //
function LiveProgress({ job }: { job: JobStatus }) {
  const done = new Set(job.completed_stages);
  return (
    <Card className="gap-3 p-5">
      <div className="flex items-center gap-2 text-sm font-medium">
        <Loader2 className="h-4 w-4 animate-spin text-brand" />
        {job.state === "queued" ? "Queued — waiting for a slot" : "Audit in progress"}
        <span className="ml-auto text-xs font-normal text-muted-foreground">
          {job.current_stage ? STAGE_LABEL[job.current_stage] ?? job.current_stage : `${done.size} stages done`}
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {STAGE_FLOW.map((st) => {
          const isDone = done.has(st);
          const isCurrent = job.current_stage === st;
          return (
            <span key={st}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-medium transition-smooth",
                isDone ? "border-success/40 bg-success/10 text-success"
                  : isCurrent ? "border-brand/40 bg-brand/10 text-brand"
                    : "border-border text-muted-foreground opacity-60"
              )}>
              {isDone ? <Check className="h-3 w-3" /> : isCurrent ? <Loader2 className="h-3 w-3 animate-spin" /> : <span className="h-1.5 w-1.5 rounded-full bg-current opacity-50" />}
              {STAGE_LABEL[st] ?? st}
            </span>
          );
        })}
      </div>
    </Card>
  );
}

function PostureBadge({ posture, className }: { posture: string; className?: string }) {
  const sev = ({ CRITICAL: "critical", HIGH: "high", MODERATE: "medium", LOW: "low" } as Record<string, string>)[posture] || "low";
  const c = `var(--sev-${sev})`;
  return (
    <span className={cn("inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-bold", className)}
      style={{ color: c, background: `color-mix(in srgb, ${c} 14%, transparent)`, border: `1px solid color-mix(in srgb, ${c} 40%, transparent)` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />{posture}
    </span>
  );
}

function Mini({ n, l, icon: Icon }: { n: React.ReactNode; l: string; icon?: typeof Clock }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xl font-bold tabular-nums leading-none">{n}</span>
      <span className="flex items-center gap-1 text-[11.5px] text-muted-foreground">
        {Icon && <Icon className="h-3 w-3" />}{l}
      </span>
    </div>
  );
}

function PendingResult({ live }: { live: boolean }) {
  return (
    <div className="flex flex-col items-center gap-2 py-12 text-center text-sm text-muted-foreground">
      {live ? (<><Loader2 className="h-6 w-6 animate-spin text-brand" /> Results appear when the audit completes.</>)
        : "No result available for this run."}
    </div>
  );
}

function DetailSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-10 w-64" />
      <Skeleton className="h-24 rounded-xl" />
      <Skeleton className="h-64 rounded-xl" />
    </div>
  );
}

function NotFound({ message }: { message?: string }) {
  return (
    <Card className="mx-auto mt-10 max-w-md items-center gap-3 p-10 text-center">
      <AlertCircle className="h-10 w-10 text-muted-foreground" />
      <h2 className="text-lg font-semibold">Audit not found</h2>
      <p className="text-sm text-muted-foreground">{message ?? "This run id doesn't exist on the server."}</p>
      <Button asChild size="sm"><Link href="/scans">Back to audits</Link></Button>
    </Card>
  );
}
