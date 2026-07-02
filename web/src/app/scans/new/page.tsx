"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Rocket, Info } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from "@/components/ui/select";
import { toast } from "@/components/ui/sonner";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useMounted } from "@/lib/hooks";
import { CAPABILITY_TOKENS, THROTTLE_PROFILES } from "@/lib/constants";
import type { AssetGroup, Capabilities, ScanRequest, ScanTemplate } from "@/lib/types";

type TargetMode = "roots" | "group" | "assets" | "all";
const split = (s: string) => s.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);

// Built-in presets → capability selections. "Custom" is implicit (shown when the
// current selection matches none of these). Quick mirrors the roots-only shortcut.
type Selection = "all" | "only" | "skip";
const SCAN_PRESETS: {
  id: string;
  label: string;
  hint: string;
  selection: Selection;
  tokens: string[];
}[] = [
  { id: "full", label: "Full audit", hint: "Every capability — deepest coverage", selection: "all", tokens: [] },
  { id: "quick", label: "Quick (roots only)", hint: "Skip subdomain enumeration; scan exactly your targets", selection: "skip", tokens: ["recon.subfinder"] },
  { id: "recon", label: "Recon only", hint: "Discover + resolve assets; no active audit", selection: "only", tokens: ["recon"] },
  { id: "tls-headers", label: "TLS + headers", hint: "Passive transport + header hygiene only", selection: "only", tokens: ["tls", "headers"] },
];
const sameSet = (a: string[], b: string[]) =>
  a.length === b.length && a.every((x) => b.includes(x));

export default function NewScanPage() {
  const router = useRouter();
  const mounted = useMounted();

  const [target, setTarget] = React.useState<TargetMode>("roots");
  const [roots, setRoots] = React.useState("");
  const [group, setGroup] = React.useState("");
  const [assetsText, setAssetsText] = React.useState("");
  const [groups, setGroups] = React.useState<AssetGroup[]>([]);

  const [selection, setSelection] = React.useState<"all" | "only" | "skip">("all");
  const [tokens, setTokens] = React.useState<string[]>([]);

  const [throttle, setThrottle] = React.useState("");
  const [renderMode, setRenderMode] = React.useState("");   // blank = server default
  const [caps, setCaps] = React.useState<Capabilities | null>(null);
  const [compress, setCompress] = React.useState(true);
  const [callbackUrl, setCallbackUrl] = React.useState("");
  const [zapTargets, setZapTargets] = React.useState("");
  const [zapAjax, setZapAjax] = React.useState(false);
  const [templates, setTemplates] = React.useState<ScanTemplate[]>([]);
  const [submitting, setSubmitting] = React.useState(false);

  // Prefill the target from the Assets-page deep-link (?group= / ?assets= / ?roots=).
  React.useEffect(() => {
    if (!mounted) return;
    api.assetGroups().then(setGroups).catch(() => {});
    api.capabilities().then(setCaps).catch(() => {});
    api.listScanTemplates().then(setTemplates).catch(() => {});
    const q = new URLSearchParams(window.location.search);
    if (q.get("group")) { setTarget("group"); setGroup(q.get("group")!); }
    else if (q.get("assets")) { setTarget("assets"); setAssetsText(q.get("assets")!.split(",").join("\n")); }
    else if (q.get("roots")) { setTarget("roots"); setRoots(q.get("roots")!); }
  }, [mounted]);

  const toggleToken = (tok: string) =>
    setTokens((p) => (p.includes(tok) ? p.filter((t) => t !== tok) : [...p, tok]));

  // One-click quick scan: skip subfinder → scan exactly the targets given.
  const quickScan = () => { setSelection("skip"); setTokens(["recon.subfinder"]); };

  const applyPreset = (p: (typeof SCAN_PRESETS)[number]) => {
    setSelection(p.selection);
    setTokens(p.tokens);
  };
  const activePreset =
    SCAN_PRESETS.find((p) => p.selection === selection && sameSet(p.tokens, tokens))?.id ?? "custom";

  const applyTemplate = (id: string) => {
    const t = templates.find((x) => x.id === id);
    if (!t) return;
    if (t.only?.length) { setSelection("only"); setTokens(t.only); }
    else if (t.skip?.length) { setSelection("skip"); setTokens(t.skip); }
    else { setSelection("all"); setTokens([]); }
    setThrottle(t.throttle ?? "");
    setCompress(t.compress);
  };

  const saveTemplate = async () => {
    const name = window.prompt("Template name:");
    if (!name?.trim()) return;
    try {
      await api.createScanTemplate({
        name: name.trim(),
        only: selection === "only" ? tokens : null,
        skip: selection === "skip" ? tokens : null,
        throttle: (throttle || null) as ScanTemplate["throttle"],
        compress,
      });
      setTemplates(await api.listScanTemplates());
      toast.success("Template saved");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Save failed");
    }
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const req: ScanRequest = { compress };
    if (target === "roots") {
      const r = split(roots);
      if (!r.length) return toast.error("Enter at least one root domain");
      req.roots = r;
    } else if (target === "group") {
      if (!group) return toast.error("Pick a group");
      req.group = group;
    } else if (target === "assets") {
      const a = split(assetsText);
      if (!a.length) return toast.error("Enter at least one asset FQDN");
      req.assets = a;
    } else {
      req.all_assets = true;
    }
    if (throttle) req.throttle = throttle as ScanRequest["throttle"];
    if (renderMode) req.profile_render = renderMode as ScanRequest["profile_render"];
    if (callbackUrl.trim()) req.callback_url = callbackUrl.trim();

    if (selection === "only" && tokens.length) req.only = tokens;
    else if (selection === "skip" && tokens.length) req.skip = tokens;

    // ZAP active scan (opt-in) only runs via `only` + explicit in-scope targets.
    if (selection === "only" && tokens.includes("zap")) {
      const zt = split(zapTargets);
      if (!zt.length) return toast.error("ZAP active scan needs at least one in-scope target");
      req.zap_targets = zt;
      if (zapAjax) req.zap_ajax_spider = true;   // null/unchecked = server default
    }

    setSubmitting(true);
    try {
      const job = await api.submitScan(req);
      toast.success("Scan submitted", { description: job.id });
      router.push(`/scans/detail?id=${encodeURIComponent(job.id)}`);
    } catch (err) {
      toast.error(err instanceof ApiError ? `${err.code}: ${err.message}` : "Submit failed");
      setSubmitting(false);
    }
  };

  const details = caps?.throttle_details?.[throttle];
  // The opt-in `zap` capability is only offered when the server advertises it
  // (daemon enabled + configured) via /capabilities.
  const advertised = new Set(caps?.capabilities ?? []);
  const visibleTokens = CAPABILITY_TOKENS.filter(
    (t) => t.token !== "zap" || advertised.has("zap"),
  );

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">New Scan</h1>
        <p className="text-sm text-muted-foreground">
          Submit an external AppSec audit. Secrets live server-side.
        </p>
      </div>

      <form onSubmit={onSubmit} className="space-y-6">
        {/* Target */}
        <Card className="gap-4 p-6">
          <h3 className="text-lg font-bold">Target</h3>
          <div className="flex flex-wrap gap-2">
            {([["roots", "Ad-hoc roots"], ["group", "İştirak group"], ["assets", "Specific assets"], ["all", "All assets"]] as const).map(
              ([m, label]) => (
                <Chip key={m} active={target === m} onClick={() => setTarget(m)}>{label}</Chip>
              ),
            )}
          </div>
          {target === "roots" && (
            <Field label="Root domains" hint="comma/space separated">
              <Input value={roots} onChange={(e) => setRoots(e.target.value)}
                placeholder="example.com, sub.example.com" />
            </Field>
          )}
          {target === "group" && (
            <Field label="Group (iştirak)">
              <Select value={group} onValueChange={setGroup}>
                <SelectTrigger><SelectValue placeholder="select group…" /></SelectTrigger>
                <SelectContent>
                  {groups.filter((g) => g.group).map((g) => (
                    <SelectItem key={g.group} value={g.group!}>{g.group} ({g.count})</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          )}
          {target === "assets" && (
            <Field label="Asset FQDNs" hint="one per line / comma separated">
              <Textarea value={assetsText} onChange={(e) => setAssetsText(e.target.value)}
                className="min-h-[80px] font-mono text-xs" placeholder="app.example.com" />
            </Field>
          )}
          {target === "all" && (
            <p className="text-sm text-muted-foreground">Scans every imported asset (all groups).</p>
          )}
        </Card>

        {/* Preset */}
        <Card className="gap-4 p-6">
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-bold">Preset</h3>
            <InfoHint href="/docs#capabilities" label="What each capability does" />
          </div>
          <p className="text-xs text-muted-foreground">
            Pick a starting point — it sets the capabilities below, which you can then fine-tune.
          </p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {SCAN_PRESETS.map((p) => (
              <button key={p.id} type="button" onClick={() => applyPreset(p)}
                className={cn("rounded-lg border p-3 text-left transition-smooth",
                  activePreset === p.id
                    ? "border-accent/50 bg-accent/10"
                    : "border-border hover:bg-accent/5")}>
                <span className="block text-sm font-medium">{p.label}</span>
                <span className="block text-xs text-muted-foreground">{p.hint}</span>
              </button>
            ))}
            <div className={cn("rounded-lg border p-3",
              activePreset === "custom" ? "border-accent/50 bg-accent/10" : "border-dashed border-border")}>
              <span className="block text-sm font-medium">Custom</span>
              <span className="block text-xs text-muted-foreground">
                {activePreset === "custom" ? "Hand-picked below" : "Edit the capabilities below"}
              </span>
            </div>
          </div>
        </Card>

        {/* Capabilities */}
        <Card className="gap-4 p-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="flex items-center gap-2 text-lg font-bold">
              Capabilities
              <InfoHint href="/docs#capabilities" label="Capability tokens & sub-tokens" />
            </h3>
            <div className="flex flex-row flex-wrap items-center gap-2">
              <Button type="button" variant="outline" size="sm" onClick={quickScan}
                title="Skip subfinder — scan exactly the targets above">
                Quick scan (roots only)
              </Button>
              {templates.length > 0 && (
                <Select onValueChange={applyTemplate}>
                  <SelectTrigger className="h-8 w-[150px]"><SelectValue placeholder="Load template…" /></SelectTrigger>
                  <SelectContent>
                    {templates.map((t) => <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>)}
                  </SelectContent>
                </Select>
              )}
              <Button type="button" variant="outline" size="sm" onClick={saveTemplate}>
                Save as template
              </Button>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {(["all", "only", "skip"] as const).map((s) => (
              <Chip key={s} active={selection === s} onClick={() => setSelection(s)}>
                {s === "all" ? "Run all" : s}
              </Chip>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            Subfinder &amp; tlsx are skippable here (recon.subfinder / recon.tlsx) — skip subfinder for a quick scan of just your targets.
          </p>
          {selection !== "all" && (
            <div className="space-y-2">
              {visibleTokens.map((t) => (
                <div key={t.token} className="rounded-lg border border-border p-3">
                  <button type="button" onClick={() => toggleToken(t.token)}
                    className="flex w-full items-start gap-3 text-left">
                    <span className={cn("mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border",
                      tokens.includes(t.token) ? "border-accent bg-accent text-accent-foreground" : "border-border")}>
                      {tokens.includes(t.token) && <span className="h-2 w-2 rounded-sm bg-current" />}
                    </span>
                    <span>
                      <span className="block text-sm font-medium">{t.label}</span>
                      <span className="block text-xs text-muted-foreground">{t.description}</span>
                    </span>
                  </button>
                  {t.children && (
                    <div className="mt-2 flex flex-wrap gap-1.5 pl-7">
                      {t.children.map((c) => (
                        <button key={c.token} type="button" title={c.description}
                          onClick={() => toggleToken(c.token)}
                          className={cn("rounded-md border px-2 py-1 text-xs transition-smooth",
                            tokens.includes(c.token) ? "border-accent/50 bg-accent/15 text-accent"
                              : "border-border text-muted-foreground hover:bg-accent/5")}>
                          {c.label}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          {selection === "only" && tokens.includes("zap") && (
            <div className="space-y-1.5 rounded-lg border border-amber-500/40 bg-amber-500/5 p-3">
              <Label>ZAP active-scan targets</Label>
              <p className="text-xs text-muted-foreground">
                Intrusive active scan — sends live payloads (SQLi/XSS/…). One host or URL per
                line; each must be in scope (under a scan root) or the scan is rejected.
              </p>
              <Textarea value={zapTargets} onChange={(e) => setZapTargets(e.target.value)}
                className="min-h-[70px] font-mono text-xs"
                placeholder={"app.example.com\nhttps://api.example.com/v2"} />
              <label className="flex cursor-pointer items-center gap-3 pt-1">
                <input type="checkbox" checked={zapAjax} onChange={(e) => setZapAjax(e.target.checked)}
                  className="h-4 w-4 accent-[var(--primary)]" />
                <span className="text-sm">
                  Run AJAX spider{" "}
                  <span className="text-muted-foreground">(SPA discovery — overrides the server default for this scan)</span>
                </span>
              </label>
            </div>
          )}
        </Card>

        {/* Options */}
        <Card className="gap-4 p-6">
          <h3 className="text-lg font-bold">Options</h3>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="Throttle" hint="Blank = server default" info="/docs#throttle">
              <Select value={throttle} onValueChange={setThrottle}>
                <SelectTrigger><SelectValue placeholder="Server default" /></SelectTrigger>
                <SelectContent>
                  {THROTTLE_PROFILES.map((p) => (
                    <SelectItem key={p} value={p} className="capitalize">{p}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field label="Profile render" hint="Blank = server default" info="/docs#capabilities">
              <Select value={renderMode} onValueChange={setRenderMode}>
                <SelectTrigger><SelectValue placeholder="Server default" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">Auto</SelectItem>
                  <SelectItem value="always">Always</SelectItem>
                  <SelectItem value="never">Never</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label="Webhook callback (optional)">
              <Input value={callbackUrl} onChange={(e) => setCallbackUrl(e.target.value)}
                placeholder="https://svc.internal/ingest" />
            </Field>
          </div>
          <p className="text-xs text-muted-foreground">
            Profiling reads the root page. <span className="font-medium">Auto</span> renders it in a headless
            browser when supply-chain runs and captures resource / endpoint / cookie / storage{" "}
            <span className="font-medium">names — never values</span>.{" "}
            <span className="font-medium">Always</span> forces a browser per host (slower, more thorough).{" "}
            <span className="font-medium">Never</span> uses the fast HTTP fetch only.
          </p>
          {details && (
            <p className="text-xs text-muted-foreground">
              <span className="capitalize font-medium">{throttle}</span>: httpx {String(details.httpx_threads)} threads / {String(details.httpx_rl)} rps ·
              nuclei {String(details.nuclei_rl)} rps · tlsx conc {String(details.tlsx_conc)} · dnsx {String(details.dnsx_rl)} rps
            </p>
          )}
          <label className="flex cursor-pointer items-center gap-3">
            <input type="checkbox" checked={compress} onChange={(e) => setCompress(e.target.checked)}
              className="h-4 w-4 accent-[var(--primary)]" />
            <span className="text-sm">Compress artifact directories at end of run</span>
          </label>
        </Card>

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={() => router.back()}>Cancel</Button>
          <Button type="submit" disabled={submitting} className="gap-1.5">
            <Rocket className="h-4 w-4" />
            {submitting ? "Submitting…" : "Launch scan"}
          </Button>
        </div>
      </form>
    </div>
  );
}

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button type="button" onClick={onClick}
      className={cn("rounded-lg border px-3 py-1.5 text-xs font-medium capitalize transition-smooth",
        active ? "border-accent/40 bg-accent/15 text-accent" : "border-border text-muted-foreground hover:bg-accent/5")}>
      {children}
    </button>
  );
}

function InfoHint({ href, label }: { href: string; label?: string }) {
  return (
    <Link href={href} title={label ?? "Learn more"} aria-label={label ?? "Learn more"}
      className="text-muted-foreground transition-smooth hover:text-accent">
      <Info className="h-3.5 w-3.5" />
    </Link>
  );
}

function Field({ label, hint, info, children }: { label: string; hint?: string; info?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-1.5">
          <Label>{label}</Label>
          {info && <InfoHint href={info} />}
        </span>
        {hint && <span className="text-xs text-muted-foreground">{hint}</span>}
      </div>
      {children}
    </div>
  );
}
