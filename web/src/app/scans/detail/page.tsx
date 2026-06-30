"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowLeft,
  Ban,
  ExternalLink,
  RefreshCw,
  Copy,
  Clock,
  Loader2,
  AlertCircle,
  FileText,
  Download,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { StateBadge } from "@/components/badges";
import { ApiErrorState } from "@/components/api-error-state";
import { CoverageStrip } from "@/components/scan/coverage-strip";
import { FindingsTable, findingKey } from "@/components/scan/findings-table";
import { CertsTable } from "@/components/scan/certs-table";
import { TLSScorecard } from "@/components/scan/tls-scorecard";
import { ReconView } from "@/components/scan/recon-view";
import { AIProfiles } from "@/components/scan/ai-profiles";
import { LogView } from "@/components/scan/log-view";
import { api, ApiError } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { relativeTime, formatDuration, rootsLabel } from "@/lib/format";
import { SEVERITY_ORDER, SEVERITY_COLORS, TERMINAL_STATES } from "@/lib/constants";
import { toast } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import type { JobStatus, ScanResult } from "@/lib/types";

// Stage order for the live progress bar (recon spine + audit + report).
const STAGE_FLOW = [
  "recon.subfinder",
  "recon.dnsx-triage",
  "recon.tlsx-loop",
  "recon.httpx",
  "ai.profile",
  "audit.takeovers",
  "audit.parallel",
  "ai.analyze",
  "report",
  "compress",
];

// Static-export-safe: the run id comes from ?id= (no dynamic route segment), so
// the whole UI exports to plain HTML and FastAPI can serve it from one image.
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
    enabled: !!id,
    intervalMs: terminal ? 0 : 3000,
    deps: [id, terminal],
  });

  React.useEffect(() => {
    if (job && TERMINAL_STATES.includes(job.state)) setTerminal(true);
  }, [job]);

  const { data: result } = usePoll<ScanResult>(() => api.getResult(id), {
    enabled: !!id && terminal,
    intervalMs: 0,
    deps: [id, terminal],
  });

  const cancel = async () => {
    try {
      await api.cancelScan(id);
      toast.success("Scan cancelled");
      refresh();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Cancel failed");
    }
  };

  const copyId = () => {
    navigator.clipboard?.writeText(id);
    toast.success("Run ID copied");
  };

  if (!id) return <NotFound message="No run id given." />;

  if (error && !job) {
    if (error instanceof ApiError && error.status === 404) return <NotFound />;
    return <ApiErrorState error={error} />;
  }

  if (!job) return <DetailSkeleton />;

  const isLive = job.state === "running" || job.state === "queued";
  const totals = result?.histogram_totals ?? {};
  // Count visible findings only — soft-suppressed ones are excluded (they live in
  // a collapsible section), matching the API finding_count + severity histogram.
  const findingTotal = result
    ? result.findings.filter((f) => !f.ai_verdict?.suppressed).length
    : job.finding_count;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <Link
            href="/scans"
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> All scans
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold">{rootsLabel(job.roots)}</h1>
            <StateBadge state={job.state} />
          </div>
          <button
            onClick={copyId}
            className="inline-flex items-center gap-1.5 font-mono text-xs text-muted-foreground hover:text-foreground"
          >
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
                <FileText className="h-4 w-4" /> Executive <ExternalLink className="h-4 w-4" />
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
                Report <ExternalLink className="h-4 w-4" />
              </a>
            </Button>
          )}
        </div>
      </div>

      {/* Meta row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Meta label="Findings" value={String(findingTotal)} accent={findingTotal > 0} />
        <Meta label="Elapsed" value={formatDuration(job.elapsed_s)} icon={Clock} />
        <Meta label="Submitted" value={relativeTime(job.submitted_at)} />
      </div>

      {/* Live progress */}
      {isLive && <LiveProgress job={job} />}

      {/* Failure banner */}
      {job.error && (
        <Card className="flex-row items-start gap-3 border-destructive/40 bg-destructive/5 p-4">
          <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-destructive" />
          <div>
            <p className="text-sm font-medium text-destructive">Scan {job.state}</p>
            <p className="text-xs text-muted-foreground">{job.error}</p>
          </div>
        </Card>
      )}

      {/* Coverage + severity summary */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <CoverageStrip coverage={result?.coverage ?? job.coverage} />
        <SeveritySummary totals={totals} />
      </div>

      {/* Tabs */}
      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">Findings{findingTotal ? ` (${findingTotal})` : ""}</TabsTrigger>
          <TabsTrigger value="recon">Recon</TabsTrigger>
          <TabsTrigger value="tls">TLS{result?.tls.length ? ` (${result.tls.length})` : ""}</TabsTrigger>
          <TabsTrigger value="certs">Certs{result?.tls_certs.length ? ` (${result.tls_certs.length})` : ""}</TabsTrigger>
          <TabsTrigger value="ai">
            AI{result ? ` (${Object.keys(result.app_profiles).length})` : ""}
          </TabsTrigger>
          <TabsTrigger value="log">Log</TabsTrigger>
          {terminal && <TabsTrigger value="executive">Executive</TabsTrigger>}
          {terminal && <TabsTrigger value="report">Report</TabsTrigger>}
        </TabsList>

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
                      scope === "global" ? "Suppressed everywhere (all hosts)" : "Suppressed — hidden on future scans",
                      { description: `${f.source} · ${scope === "global" ? "*" : (f.host ?? "*")}` },
                    );
                  } catch (e) {
                    toast.error(e instanceof ApiError ? e.message : "Suppress failed");
                  }
                }}
              />
            ) : (
              <PendingResult live={isLive} />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="recon">
          {result ? (
            <ReconView
              assets={result.assets}
              liveServers={result.live_servers}
              wildcards={result.wildcards}
            />
          ) : (
            <Card className="p-6">
              <PendingResult live={isLive} />
            </Card>
          )}
        </TabsContent>

        <TabsContent value="tls">
          {result ? (
            <TLSScorecard reports={result.tls} />
          ) : (
            <Card className="p-6">
              <PendingResult live={isLive} />
            </Card>
          )}
        </TabsContent>

        <TabsContent value="certs">
          <Card className="p-6">
            {result ? <CertsTable certs={result.tls_certs} /> : <PendingResult live={isLive} />}
          </Card>
        </TabsContent>

        <TabsContent value="ai">
          {result ? (
            <AIProfiles profiles={result.app_profiles} />
          ) : (
            <Card className="p-6">
              <PendingResult live={isLive} />
            </Card>
          )}
        </TabsContent>

        <TabsContent value="log">
          <Card className="p-6">
            <LogView id={id} live={isLive} />
          </Card>
        </TabsContent>

        {terminal && (
          <TabsContent value="executive">
            <Card className="overflow-hidden p-0 py-0">
              <iframe
                src={api.executiveUrl(id)}
                title="Executive summary"
                className="h-[75vh] w-full border-0 bg-white"
              />
            </Card>
          </TabsContent>
        )}

        {terminal && (
          <TabsContent value="report">
            <Card className="overflow-hidden p-0 py-0">
              <iframe
                src={api.reportUrl(id)}
                title="Scan report"
                className="h-[75vh] w-full border-0 bg-white"
              />
            </Card>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}

function LiveProgress({ job }: { job: JobStatus }) {
  const completed = new Set(job.completed_stages);
  const idx = job.current_stage ? STAGE_FLOW.indexOf(job.current_stage) : completed.size;
  const pct = Math.min(100, Math.round(((idx + 1) / STAGE_FLOW.length) * 100));

  return (
    <Card className="gap-3 p-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Loader2 className="h-4 w-4 animate-spin text-accent" />
          {job.state === "queued" ? "Queued — waiting for a slot" : "Scan in progress"}
        </div>
        <span className="text-xs text-muted-foreground">
          {job.current_stage ? `Stage: ${job.current_stage}` : `${completed.size} stages done`}
        </span>
      </div>
      <Progress value={pct} indicatorClassName="bg-gradient-to-r from-primary to-accent" />
      {job.completed_stages.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {job.completed_stages.map((s) => (
            <span key={s} className="rounded bg-secondary px-1.5 py-0.5 text-[11px] text-muted-foreground">
              {s}
            </span>
          ))}
        </div>
      )}
    </Card>
  );
}

function SeveritySummary({ totals }: { totals: Record<string, number> }) {
  const any = SEVERITY_ORDER.some((s) => totals[s] > 0);
  if (!any) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {SEVERITY_ORDER.filter((s) => totals[s] > 0).map((s) => (
        <span
          key={s}
          className="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium capitalize"
          style={{
            borderColor: `${SEVERITY_COLORS[s]}66`,
            color: SEVERITY_COLORS[s],
            backgroundColor: `${SEVERITY_COLORS[s]}1a`,
          }}
        >
          {totals[s]} {s}
        </span>
      ))}
    </div>
  );
}

function Meta({
  label,
  value,
  accent,
  icon: Icon,
}: {
  label: string;
  value: React.ReactNode;
  accent?: boolean;
  icon?: typeof Clock;
}) {
  return (
    <Card className="gap-1 p-4">
      <p className="flex items-center gap-1 text-xs uppercase tracking-wide text-muted-foreground">
        {Icon && <Icon className="h-3 w-3" />} {label}
      </p>
      <p className={cn("text-lg font-semibold", accent && "text-destructive")}>{value}</p>
    </Card>
  );
}

function PendingResult({ live }: { live: boolean }) {
  return (
    <div className="flex flex-col items-center gap-2 py-12 text-center text-sm text-muted-foreground">
      {live ? (
        <>
          <Loader2 className="h-6 w-6 animate-spin text-accent" />
          Results appear when the scan completes.
        </>
      ) : (
        "No result available for this run."
      )}
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
      <h2 className="text-lg font-bold">Scan not found</h2>
      <p className="text-sm text-muted-foreground">
        {message ?? "This run id doesn't exist on the server."}
      </p>
      <Button asChild size="sm">
        <Link href="/scans">Back to scans</Link>
      </Button>
    </Card>
  );
}
