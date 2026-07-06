"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Rocket, Info, ChevronDown, CalendarClock } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from "@/components/ui/dialog";
import {
  DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from "@/components/ui/select";
import { toast } from "@/components/ui/sonner";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useMounted } from "@/lib/hooks";
import { CAPABILITY_TOKENS, THROTTLE_PROFILES } from "@/lib/constants";
import { ChipInput } from "@/components/chip-input";
import {
  CadenceFields, atTimeForPayload, type Cadence,
} from "@/components/schedule/cadence-fields";
import type {
  AssetGroup, Capabilities, ScanRequest, ScanTemplate, ScheduleTarget, ScheduleUpsert,
} from "@/lib/types";

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

  // Scheduling: this same builder can create/update a schedule instead of running.
  // `?schedule=<id>` loads a schedule into the form for editing (round-trip).
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [editingName, setEditingName] = React.useState("");
  // The cadence dialog. `schedMode` null = closed; otherwise the write it performs.
  const [schedMode, setSchedMode] = React.useState<"create" | "update" | "saveAsNew" | null>(null);
  const [savingSched, setSavingSched] = React.useState(false);
  const [schedName, setSchedName] = React.useState("");
  const [schedCadence, setSchedCadence] = React.useState<Cadence>("daily");
  const [schedAtTime, setSchedAtTime] = React.useState("02:00");
  const [schedWeekday, setSchedWeekday] = React.useState(0);

  // Prefill the target from the Assets-page deep-link (?group= / ?assets= / ?roots=).
  React.useEffect(() => {
    if (!mounted) return;
    api.assetGroups().then(setGroups).catch(() => {});
    api.capabilities().then(setCaps).catch(() => {});
    api.listScanTemplates().then(setTemplates).catch(() => {});
    const q = new URLSearchParams(window.location.search);
    const sid = q.get("schedule");
    if (sid) {
      // Edit an existing schedule: load its full config into the form (round-trip).
      api.listSchedules().then((list) => {
        const s = list.find((x) => x.id === sid);
        if (!s) { toast.error("Schedule not found"); return; }
        setEditingId(s.id);
        setEditingName(s.name || s.id);
        const t = s.target || {};
        if (t.all_assets) setTarget("all");
        else if (t.group) { setTarget("group"); setGroup(t.group); }
        else if (t.assets?.length) { setTarget("assets"); setAssetsText(t.assets.join("\n")); }
        else if (t.roots?.length) { setTarget("roots"); setRoots(t.roots.join(", ")); }
        if (s.only?.length) { setSelection("only"); setTokens(s.only); }
        else if (s.skip?.length) { setSelection("skip"); setTokens(s.skip); }
        else { setSelection("all"); setTokens([]); }
        if (s.throttle) setThrottle(s.throttle);
        setCompress(s.compress);
        setSchedName(s.name || "");
        setSchedCadence((s.cadence as Cadence) || "daily");
        setSchedAtTime(s.at_time || "02:00");
        setSchedWeekday(s.weekday ?? 0);
      }).catch(() => {});
    } else if (q.get("group")) { setTarget("group"); setGroup(q.get("group")!); }
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

  const [templateOpen, setTemplateOpen] = React.useState(false);
  const [templateName, setTemplateName] = React.useState("");

  const saveTemplate = async () => {
    const name = templateName.trim();
    if (!name) return;
    setTemplateOpen(false);
    try {
      await api.createScanTemplate({
        name,
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

  // --- Scheduling: reuse this builder's config as a recurring schedule -------- #
  const targetValid = () =>
    target === "roots" ? split(roots).length > 0
      : target === "group" ? !!group
        : target === "assets" ? split(assetsText).length > 0
          : true; // all

  const buildTarget = (): ScheduleTarget =>
    target === "roots" ? { roots: split(roots) }
      : target === "group" ? { group }
        : target === "assets" ? { assets: split(assetsText) }
          : { all_assets: true };

  const buildScheduleUpsert = (): ScheduleUpsert => ({
    name: schedName.trim() || undefined,
    target: buildTarget(),
    only: selection === "only" && tokens.length ? tokens : null,
    skip: selection === "skip" && tokens.length ? tokens : null,
    throttle: (throttle || null) as ScheduleUpsert["throttle"],
    compress,
    cadence: schedCadence,
    at_time: atTimeForPayload(schedCadence, schedAtTime),
    weekday: schedCadence === "weekly" ? schedWeekday : null,
    enabled: true,
  });

  const openSchedule = (mode: "create" | "update" | "saveAsNew") => {
    if (!targetValid()) { toast.error("Pick a target first"); return; }
    if (mode === "saveAsNew") setSchedName("");   // fresh name for a copy
    setSchedMode(mode);
  };

  const saveSchedule = async () => {
    setSavingSched(true);
    try {
      const body = buildScheduleUpsert();
      if (schedMode === "update" && editingId) await api.updateSchedule(editingId, body);
      else await api.createSchedule(body);
      toast.success(schedMode === "update" ? "Schedule updated" : "Schedule created");
      router.push("/schedules");
    } catch (err) {
      toast.error(err instanceof ApiError ? `${err.code}: ${err.message}` : "Save failed");
      setSavingSched(false);
    }
  };

  // Run the scan once immediately (reuses onSubmit's validation + submit path).
  const runNow = () => onSubmit({ preventDefault() {} } as unknown as React.FormEvent);

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
        <h1 className="text-2xl font-bold tracking-tight">
          {editingId ? "Edit schedule" : "New audit"}
        </h1>
        <p className="text-sm text-muted-foreground">
          {editingId
            ? "Adjust the scan config, then update the schedule — or run it once now."
            : "Launch a point-in-time external AppSec audit. Secrets live server-side."}
        </p>
      </div>

      {editingId && (
        <div className="flex items-center gap-2 rounded-lg border border-primary/40 bg-primary/10 px-3 py-2 text-sm">
          <CalendarClock className="h-4 w-4 text-primary" />
          <span>Editing schedule <span className="font-semibold">{editingName}</span></span>
          <Link href="/schedules" className="ml-auto text-xs text-primary hover:underline">
            Back to schedules
          </Link>
        </div>
      )}

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
            <Field label="Asset FQDNs" hint="type or paste — one per line / comma separated">
              <ChipInput value={assetsText} onChange={setAssetsText} />
              {split(assetsText).length > 8 && (
                <p className="mt-2 text-xs text-muted-foreground">
                  Targeting {split(assetsText).length} assets individually —{" "}
                  <button type="button" onClick={() => setTarget("group")}
                    className="text-primary hover:underline">scan a whole group instead?</button>
                </p>
              )}
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
                aria-pressed={activePreset === p.id}
                className={cn("rounded-lg border p-3 text-left transition-smooth",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
                  activePreset === p.id
                    ? "border-primary/50 bg-primary/10"
                    : "border-border hover:bg-muted")}>
                <span className="block text-sm font-medium">{p.label}</span>
                <span className="block text-xs text-muted-foreground">{p.hint}</span>
              </button>
            ))}
            <div className={cn("rounded-lg border p-3",
              activePreset === "custom" ? "border-primary/50 bg-primary/10" : "border-dashed border-border")}>
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
              <Button type="button" variant="outline" size="sm"
                onClick={() => { setTemplateName(""); setTemplateOpen(true); }}>
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
                    aria-pressed={tokens.includes(t.token)}
                    className="flex w-full items-start gap-3 rounded-md text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background">
                    <span className={cn("mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border",
                      tokens.includes(t.token) ? "border-primary bg-primary text-primary-foreground" : "border-border")}>
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
                          aria-pressed={tokens.includes(c.token)}
                          className={cn("rounded-md border px-2 py-1 text-xs transition-smooth",
                            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
                            tokens.includes(c.token) ? "border-primary/50 bg-primary/10 text-primary"
                              : "border-border text-muted-foreground hover:bg-muted")}>
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
              <div className="flex items-center gap-3 pt-1">
                <Checkbox id="zap-ajax" checked={zapAjax}
                  onCheckedChange={(c) => setZapAjax(c === true)} />
                <Label htmlFor="zap-ajax" className="cursor-pointer text-sm font-normal">
                  Run AJAX spider{" "}
                  <span className="text-muted-foreground">(SPA discovery — overrides the server default for this scan)</span>
                </Label>
              </div>
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
          <div className="flex items-center gap-3">
            <Checkbox id="compress" checked={compress}
              onCheckedChange={(c) => setCompress(c === true)} />
            <Label htmlFor="compress" className="cursor-pointer text-sm font-normal">
              Compress artifact directories at end of run
            </Label>
          </div>
        </Card>

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={() => router.back()}>Cancel</Button>
          {editingId ? (
            // Edit-a-schedule mode: primary updates the schedule; menu offers run-once + copy.
            <div className="flex">
              <Button type="button" onClick={() => openSchedule("update")}
                className="gap-1.5 rounded-r-none">
                <CalendarClock className="h-4 w-4" /> Update schedule
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button type="button" aria-label="More actions"
                    className="rounded-l-none border-l border-primary-foreground/25 px-2">
                    <ChevronDown className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={runNow} disabled={submitting}>
                    <Rocket className="h-4 w-4" /> Run once now
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => openSchedule("saveAsNew")}>
                    <CalendarClock className="h-4 w-4" /> Save as new schedule
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          ) : (
            // New-scan mode: primary runs now; menu offers scheduling.
            <div className="flex">
              <Button type="submit" disabled={submitting} className="gap-1.5 rounded-r-none">
                <Rocket className="h-4 w-4" />
                {submitting ? "Submitting…" : "Launch scan"}
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button type="button" aria-label="More actions"
                    className="rounded-l-none border-l border-primary-foreground/25 px-2">
                    <ChevronDown className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={() => openSchedule("create")}>
                    <CalendarClock className="h-4 w-4" /> Schedule…
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          )}
        </div>
      </form>

      <Dialog open={templateOpen} onOpenChange={setTemplateOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Save as template</DialogTitle>
            <DialogDescription>
              Save the current capability selection, throttle, and compress options as a reusable preset.
            </DialogDescription>
          </DialogHeader>
          <Input
            autoFocus
            value={templateName}
            onChange={(e) => setTemplateName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && saveTemplate()}
            placeholder="template name"
          />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setTemplateOpen(false)}>Cancel</Button>
            <Button type="button" onClick={saveTemplate} disabled={!templateName.trim()}>Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Schedule dialog — captures cadence for the config assembled above. */}
      <Dialog open={schedMode !== null} onOpenChange={(o) => !o && setSchedMode(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{schedMode === "update" ? "Update schedule" : "Schedule this audit"}</DialogTitle>
            <DialogDescription>
              Runs the config from this page on a recurring cadence. Times are UTC.
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-lg border border-border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
            <span className="font-medium text-foreground">Scanning:</span>{" "}
            {target === "roots" ? `${split(roots).length} root(s)`
              : target === "group" ? `group “${group || "—"}”`
                : target === "assets" ? `${split(assetsText).length} asset(s)`
                  : "all assets"}{" "}·{" "}
            {selection === "all" ? "Full audit"
              : selection === "only" ? `only ${tokens.join(", ") || "—"}`
                : `skip ${tokens.join(", ") || "—"}`}{" "}
            {throttle && <>· {throttle}</>}
          </div>
          <div className="space-y-1.5">
            <Label>Name</Label>
            <Input value={schedName} onChange={(e) => setSchedName(e.target.value)}
              placeholder="e.g. weekly bank" />
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <CadenceFields
              cadence={schedCadence} onCadence={setSchedCadence}
              atTime={schedAtTime} onAtTime={setSchedAtTime}
              weekday={schedWeekday} onWeekday={setSchedWeekday}
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setSchedMode(null)}>Cancel</Button>
            <Button type="button" onClick={saveSchedule} disabled={savingSched} className="gap-1.5">
              <CalendarClock className="h-4 w-4" />
              {savingSched ? "Saving…" : schedMode === "update" ? "Update schedule" : "Create schedule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active}
      className={cn("rounded-lg border px-3 py-1.5 text-xs font-medium capitalize transition-smooth",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
        active ? "border-primary/40 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:bg-muted")}>
      {children}
    </button>
  );
}

function InfoHint({ href, label }: { href: string; label?: string }) {
  return (
    <Link href={href} title={label ?? "Learn more"} aria-label={label ?? "Learn more"}
      className="text-muted-foreground transition-smooth hover:text-primary">
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
