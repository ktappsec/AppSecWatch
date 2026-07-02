"use client";

import * as React from "react";
import { Save, SlidersHorizontal, RefreshCw } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { toast } from "@/components/ui/sonner";
import { api, ApiError } from "@/lib/api";
import { useMounted } from "@/lib/hooks";
import { THROTTLE_PROFILES } from "@/lib/constants";
import type { ServerConfigView } from "@/lib/types";

type LlmShape = {
  base_url?: string;
  model?: string;
  api_key?: string;
  timeout_seconds?: number;
  max_retries?: number;
  app_title?: string;
  app_url?: string;
  tag_requests?: boolean;
  models?: Record<string, string>;
};

// Per-call-type model override slots (LLMConfig.models keys = call purpose).
const MODEL_SLOTS: { key: string; label: string }[] = [
  { key: "profile", label: "profile" },
  { key: "triage", label: "triage" },
  { key: "supply", label: "supply-chain" },
  { key: "summary", label: "summary" },
  { key: "nuclei-gen", label: "nuclei-gen" },
];
type Dict = Record<string, unknown>;

type ReportShape = {
  org_name?: string;
  classification?: string;
  logo_path?: string;
  executive_pdf?: boolean;
};

// Keys surfaced as friendly fields → stripped from the JSON editor (which keeps
// only the long tail: tools, concurrency, anything unrecognized).
const PROMOTED = [
  "llm", "mmdb_path", "throttle", "ai", "headers", "identity",
  "paths_per_host", "report", "zap",
];

const IDENTITY_PRESETS = ["off", "chrome-win", "chrome-mac", "firefox"];

const splitList = (s: string) => s.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);

const parseHeaders = (s: string): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const line of s.split("\n")) {
    const t = line.trim();
    const i = t.indexOf(":");
    if (i > 0) out[t.slice(0, i).trim()] = t.slice(i + 1).trim();
  }
  return out;
};
const headersToText = (h: Record<string, string>) =>
  Object.entries(h || {}).map(([k, v]) => `${k}: ${v}`).join("\n");

/** UI-managed scan configuration (GET/PUT /config). Common knobs are real form
 * fields; the JSON editor is only for the long tail. The store is primary;
 * server.yaml only seeds first boot. */
export function ScanConfigCard() {
  const mounted = useMounted();
  const [loaded, setLoaded] = React.useState(false);
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  const [llm, setLlm] = React.useState<LlmShape>({});
  const [apiKey, setApiKey] = React.useState("");
  const [mmdbPath, setMmdbPath] = React.useState("");
  const [throttle, setThrottle] = React.useState("normal");
  const [pathsPerHost, setPathsPerHost] = React.useState("");
  // Stealth identity (UA + decoy headers, applied to httpx/nuclei/crawler).
  const [idPreset, setIdPreset] = React.useState("off");
  const [idUA, setIdUA] = React.useState("");
  const [idHeaders, setIdHeaders] = React.useState("");
  const [idLocale, setIdLocale] = React.useState("");
  // Preserve any non-surfaced sub-keys (e.g. headers.severity_overrides) on round-trip.
  const [aiBlock, setAiBlock] = React.useState<Dict>({});
  const [headersBlock, setHeadersBlock] = React.useState<Dict>({});
  const [idBlock, setIdBlock] = React.useState<Dict>({});
  // Executive-report branding + PDF toggle (cfg.report).
  const [report, setReport] = React.useState<ReportShape>({});
  // ZAP active-scan config (opt-in). Whole block kept so un-exposed sub-keys
  // (auth_headers, poll/timeout/alert_cap) survive a round-trip; api_key is a
  // separate write-only field (never prefilled from the masked value).
  const [zap, setZap] = React.useState<Dict>({});
  const [zapApiKey, setZapApiKey] = React.useState("");
  const [restJson, setRestJson] = React.useState("");
  const [jsonError, setJsonError] = React.useState<string | null>(null);
  const [paths, setPaths] = React.useState<{ config_store: string; db: string } | null>(null);

  const load = React.useCallback(async () => {
    setLoadError(null);
    try {
      hydrate(await api.getConfig());
      api.capabilities().then((c) => c.paths && setPaths(c.paths)).catch(() => {});
      setLoaded(true);
    } catch (e) {
      setLoaded(false);
      setLoadError(e instanceof ApiError ? `${e.code}: ${e.message}` : "Failed to load config");
    }
  }, []);

  function hydrate(cfg: ServerConfigView) {
    const base = { ...(cfg.base_config || {}) } as Dict;
    setLlm((base.llm as LlmShape) || {});
    setApiKey(""); // never prefill the masked secret
    setMmdbPath((base.mmdb_path as string) ?? "");
    setThrottle((base.throttle as string) || "normal");
    const ai = (base.ai as Dict) || {};
    setAiBlock(ai);                       // AI behavior (profiling/suppression/prompts) lives on the AI Tuning page
    const h = (base.headers as Dict) || {};
    setHeadersBlock(h);
    setPathsPerHost(((base.paths_per_host as string[]) || []).join(", "));
    const id = (base.identity as Dict) || {};
    setIdBlock(id);
    setIdPreset((id.preset as string) || "off");
    setIdUA((id.user_agent as string) || "");
    setIdLocale((id.locale as string) || "");
    setIdHeaders(headersToText((id.headers as Record<string, string>) || {}));
    setReport((base.report as ReportShape) || {});
    setZap((base.zap as Dict) || {});
    setZapApiKey(""); // never prefill the masked secret
    for (const k of PROMOTED) delete base[k];
    setRestJson(Object.keys(base).length ? JSON.stringify(base, null, 2) : "");
  }

  React.useEffect(() => {
    if (mounted) load();
  }, [mounted, load]);

  const save = async () => {
    let rest: Dict;
    try {
      rest = restJson.trim() ? JSON.parse(restJson) : {};
      if (typeof rest !== "object" || Array.isArray(rest)) throw new Error("must be an object");
      setJsonError(null);
    } catch (e) {
      setJsonError(`Invalid JSON: ${String(e)}`);
      return;
    }

    const llmOut: LlmShape = { base_url: llm.base_url, model: llm.model };
    if (llm.timeout_seconds !== undefined && Number.isFinite(Number(llm.timeout_seconds)))
      llmOut.timeout_seconds = Number(llm.timeout_seconds);
    if (llm.max_retries !== undefined && Number.isFinite(Number(llm.max_retries)))
      llmOut.max_retries = Number(llm.max_retries);
    if (apiKey.trim()) llmOut.api_key = apiKey.trim(); // write-only secret
    if (llm.app_title?.trim()) llmOut.app_title = llm.app_title.trim();
    if (llm.app_url?.trim()) llmOut.app_url = llm.app_url.trim();
    llmOut.tag_requests = llm.tag_requests !== false; // default on
    const models: Record<string, string> = {};
    for (const [k, v] of Object.entries(llm.models || {}))
      if (typeof v === "string" && v.trim()) models[k] = v.trim();
    if (Object.keys(models).length) llmOut.models = models;

    const reportOut: ReportShape = { executive_pdf: report.executive_pdf !== false };
    if (report.org_name?.trim()) reportOut.org_name = report.org_name.trim();
    if (report.classification?.trim()) reportOut.classification = report.classification.trim();
    if (report.logo_path?.trim()) reportOut.logo_path = report.logo_path.trim();

    // ZAP: spread the loaded block first so un-exposed knobs survive; api_key only
    // when re-typed (else the stored/masked key is preserved by the backend).
    const zapOut: Dict = { ...zap };
    if (zapApiKey.trim()) zapOut.api_key = zapApiKey.trim();

    const paths = splitList(pathsPerHost);
    const body: ServerConfigView = {
      base_config: {
        ...rest,
        llm: llmOut,
        mmdb_path: mmdbPath.trim(),
        throttle,
        ai: aiBlock,           // preserved as-is; edited on the AI Tuning page
        headers: headersBlock,
        identity: {
          ...idBlock,
          preset: idPreset,
          user_agent: idUA.trim() || null,
          headers: parseHeaders(idHeaders),
          locale: idLocale.trim() || null,
        },
        paths_per_host: paths.length ? paths : ["/"],
        report: reportOut,
        zap: zapOut,
      },
    };

    setSaving(true);
    try {
      hydrate(await api.updateConfig(body));
      toast.success("Scan configuration saved");
    } catch (e) {
      toast.error(e instanceof ApiError ? `${e.code}: ${e.message}` : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card className="gap-5 p-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SlidersHorizontal className="h-5 w-5 text-accent" />
          <h3 className="text-lg font-bold">Scan configuration</h3>
        </div>
        <Button variant="outline" size="icon-sm" onClick={load} aria-label="Reload">
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">
        Server-side defaults for every scan. Persisted in the API&apos;s config store (the primary
        source of truth); <span className="font-mono">server.yaml</span> only seeds first boot.
      </p>
      {paths && (
        <p className="rounded-md border border-border bg-secondary/30 px-3 py-2 text-[11px] text-muted-foreground">
          Stored at <span className="font-mono">{paths.config_store}</span> · DB{" "}
          <span className="font-mono">{paths.db}</span>. Mount this path (e.g. a Docker volume)
          so settings + assets survive a rebuild.
        </p>
      )}

      {!loaded ? (
        <p className="text-sm text-muted-foreground">
          {loadError ? (
            <>
              Couldn&apos;t load config — <span className="text-destructive">{loadError}</span>. Set
              the API connection above, then reload.
            </>
          ) : (
            "Loading…"
          )}
        </p>
      ) : (
        <>
          {/* LLM */}
          <Section title="LLM endpoint">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Base URL">
                <Input value={llm.base_url ?? ""} onChange={(e) => setLlm({ ...llm, base_url: e.target.value })}
                  placeholder="https://openrouter.ai/api/v1" />
              </Field>
              <Field label="Model">
                <Input value={llm.model ?? ""} onChange={(e) => setLlm({ ...llm, model: e.target.value })}
                  placeholder="minimax/minimax-m3" />
              </Field>
              <Field label="API key">
                <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
                  placeholder="•••••• (leave blank to keep current)" />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Timeout (s)">
                  <Input type="number" value={llm.timeout_seconds ?? ""}
                    onChange={(e) => setLlm({ ...llm, timeout_seconds: e.target.value === "" ? undefined : Number(e.target.value) })}
                    placeholder="120" />
                </Field>
                <Field label="Max retries">
                  <Input type="number" value={llm.max_retries ?? ""}
                    onChange={(e) => setLlm({ ...llm, max_retries: e.target.value === "" ? undefined : Number(e.target.value) })}
                    placeholder="1" />
                </Field>
              </div>
              <Field label="App title" hint="X-Title — the request name in OpenRouter's logs">
                <Input value={llm.app_title ?? ""} onChange={(e) => setLlm({ ...llm, app_title: e.target.value })}
                  placeholder="WatchTower" />
              </Field>
              <Field label="App URL" hint="optional HTTP-Referer">
                <Input value={llm.app_url ?? ""} onChange={(e) => setLlm({ ...llm, app_url: e.target.value })}
                  placeholder="https://watchtower.internal" />
              </Field>
              <Field label="Per-call attribution" hint="append the call purpose (profile/triage/…) so OpenRouter spend breaks down by call type">
                <label className="flex items-center gap-2 text-sm text-muted-foreground">
                  <input type="checkbox" className="h-4 w-4 accent-accent"
                    checked={llm.tag_requests !== false}
                    onChange={(e) => setLlm({ ...llm, tag_requests: e.target.checked })} />
                  Tag requests by purpose
                </label>
              </Field>
            </div>
            <p className="mt-3 text-xs text-muted-foreground">
              Per-call models <span className="opacity-70">— optional; blank uses Model above. Profiling tolerates a cheap/fast model; keep triage capable (it can suppress findings).</span>
            </p>
            <div className="mt-2 grid grid-cols-1 gap-3 sm:grid-cols-2">
              {MODEL_SLOTS.map((slot) => (
                <Field key={slot.key} label={`Model · ${slot.label}`}>
                  <Input value={llm.models?.[slot.key] ?? ""}
                    onChange={(e) => {
                      const m = { ...(llm.models || {}) };
                      if (e.target.value) m[slot.key] = e.target.value; else delete m[slot.key];
                      setLlm({ ...llm, models: m });
                    }}
                    placeholder="(uses Model above)" className="font-mono text-xs" />
                </Field>
              ))}
            </div>
          </Section>

          <Separator />

          {/* Engine */}
          <Section title="Engine">
            <Field label="MMDB path" hint="optional — GeoLite2-ASN.mmdb enables ASN/org enrichment">
              <Input value={mmdbPath} onChange={(e) => setMmdbPath(e.target.value)}
                placeholder="/data/mmdb/GeoLite2-ASN.mmdb" className="font-mono text-xs" />
            </Field>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Throttle" hint="Global politeness tier">
                <Select value={throttle} onValueChange={setThrottle}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {THROTTLE_PROFILES.map((p) => (
                      <SelectItem key={p} value={p} className="capitalize">{p}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Paths per host" hint="Crawler paths, comma/space separated">
                <Input value={pathsPerHost} onChange={(e) => setPathsPerHost(e.target.value)} placeholder="/" />
              </Field>
            </div>
          </Section>

          <Separator />

          {/* Executive report branding */}
          <Section title="Executive report">
            <p className="text-xs text-muted-foreground">
              Branding for the executive one-pager (executive.html). All optional —
              an unset org name falls back to the scanned root.
            </p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Organization name" hint="letterhead — blank = scanned root">
                <Input value={report.org_name ?? ""}
                  onChange={(e) => setReport({ ...report, org_name: e.target.value })}
                  placeholder="Kuveyt Türk" />
              </Field>
              <Field label="Classification" hint="banner label">
                <Input value={report.classification ?? ""}
                  onChange={(e) => setReport({ ...report, classification: e.target.value })}
                  placeholder="Confidential" />
              </Field>
            </div>
            <Field label="Logo path" hint="optional — embedded (base64) so the report stays self-contained">
              <Input value={report.logo_path ?? ""}
                onChange={(e) => setReport({ ...report, logo_path: e.target.value })}
                placeholder="/etc/watchtower/logo.png" className="font-mono text-xs" />
            </Field>
            <Field label="PDF" hint="also render executive.pdf via the bundled Chromium (best-effort)">
              <label className="flex items-center gap-2 text-sm text-muted-foreground">
                <input type="checkbox" className="h-4 w-4 accent-accent"
                  checked={report.executive_pdf !== false}
                  onChange={(e) => setReport({ ...report, executive_pdf: e.target.checked })} />
                Auto-render executive.pdf
              </label>
            </Field>
          </Section>

          <Separator />

          {/* Stealth identity */}
          <Section title="Stealth / identity">
            <p className="text-xs text-muted-foreground">
              Applied to httpx, nuclei &amp; the crawler. A browser preset sets a coherent
              UA + headers. Note: this defeats UA/header WAF rules, not TLS/JA3 fingerprinting
              or IP-reputation — use only for authorized testing of your own assets.
            </p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Browser preset">
                <Select value={idPreset} onValueChange={setIdPreset}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {IDENTITY_PRESETS.map((p) => (
                      <SelectItem key={p} value={p}>{p}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Locale" hint="overrides preset (e.g. tr-TR)">
                <Input value={idLocale} onChange={(e) => setIdLocale(e.target.value)} placeholder="tr-TR" />
              </Field>
            </div>
            <Field label="User-Agent override" hint="blank = use the preset's UA">
              <Input value={idUA} onChange={(e) => setIdUA(e.target.value)}
                placeholder="Mozilla/5.0 …" className="font-mono text-xs" />
            </Field>
            <Field label="Extra / decoy headers" hint="one per line, Key: Value (merged over the preset)">
              <Textarea value={idHeaders} onChange={(e) => setIdHeaders(e.target.value)}
                placeholder={"X-Forwarded-For: 203.0.113.7\nReferer: https://www.google.com/"}
                className="min-h-[72px] font-mono text-xs" />
            </Field>
          </Section>

          <Separator />

          {/* ZAP active scan (opt-in) */}
          <Section title="ZAP active scan">
            <p className="text-xs text-muted-foreground">
              The opt-in active scanner (OWASP ZAP sidecar). <span className="font-medium">Intrusive</span> —
              it fires live payloads, so it runs only via the New Scan form&apos;s{" "}
              <span className="font-mono">zap</span> capability with explicit, in-scope targets. Enable it
              and point it at the daemon here.
            </p>
            <Field label="Enabled" hint="advertise + allow the zap capability">
              <label className="flex items-center gap-2 text-sm text-muted-foreground">
                <input type="checkbox" className="h-4 w-4 accent-accent"
                  checked={zap.enabled === true}
                  onChange={(e) => setZap({ ...zap, enabled: e.target.checked })} />
                Allow active scans
              </label>
            </Field>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Daemon base URL" hint="the ZAP sidecar">
                <Input value={(zap.base_url as string) ?? ""}
                  onChange={(e) => setZap({ ...zap, base_url: e.target.value })}
                  placeholder="http://zap:8090" className="font-mono text-xs" />
              </Field>
              <Field label="API key">
                <Input type="password" value={zapApiKey} onChange={(e) => setZapApiKey(e.target.value)}
                  placeholder="•••••• (leave blank to keep current)" />
              </Field>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Scan policy" hint="ZAP scan-policy name">
                <Input value={(zap.scan_policy as string) ?? ""}
                  onChange={(e) => setZap({ ...zap, scan_policy: e.target.value })}
                  placeholder="Default Policy" />
              </Field>
              <Field label="AJAX spider" hint="default for SPAs (slower); per-scan overridable on New Scan">
                <label className="flex items-center gap-2 text-sm text-muted-foreground">
                  <input type="checkbox" className="h-4 w-4 accent-accent"
                    checked={zap.ajax_spider === true}
                    onChange={(e) => setZap({ ...zap, ajax_spider: e.target.checked })} />
                  Run the AJAX spider
                </label>
              </Field>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <Field label="Max min · total">
                <Input type="number" value={(zap.max_minutes_total as number) ?? ""}
                  onChange={(e) => setZap({ ...zap, max_minutes_total: e.target.value === "" ? undefined : Number(e.target.value) })}
                  placeholder="60" />
              </Field>
              <Field label="Max min · per host">
                <Input type="number" value={(zap.max_minutes_per_host as number) ?? ""}
                  onChange={(e) => setZap({ ...zap, max_minutes_per_host: e.target.value === "" ? undefined : Number(e.target.value) })}
                  placeholder="20" />
              </Field>
              <Field label="Max min · spider">
                <Input type="number" value={(zap.spider_max_minutes as number) ?? ""}
                  onChange={(e) => setZap({ ...zap, spider_max_minutes: e.target.value === "" ? undefined : Number(e.target.value) })}
                  placeholder="5" />
              </Field>
            </div>
          </Section>

          <Separator />

          {/* Long tail — raw JSON */}
          <div className="space-y-1.5">
            <Label>Advanced — tools &amp; other config (JSON)</Label>
            <Textarea value={restJson} onChange={(e) => setRestJson(e.target.value)} spellCheck={false}
              className="min-h-[160px] font-mono text-xs" placeholder="{}" />
            <p className="text-xs text-muted-foreground">
              Everything not surfaced above (per-tool tuning under <span className="font-mono">tools</span>,{" "}
              <span className="font-mono">concurrency</span>, …). Mirrors <span className="font-mono">WatchTowerConfig</span>.
            </p>
            {jsonError && <p className="text-xs text-destructive">{jsonError}</p>}
          </div>

          <Separator />

          <div className="flex justify-end">
            <Button onClick={save} disabled={saving} className="gap-1.5">
              <Save className="h-4 w-4" />
              {saving ? "Saving…" : "Save configuration"}
            </Button>
          </div>
        </>
      )}
    </Card>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold">{title}</h4>
      {children}
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <Label>{label}</Label>
        {hint && <span className="text-right text-[11px] text-muted-foreground">{hint}</span>}
      </div>
      {children}
    </div>
  );
}

