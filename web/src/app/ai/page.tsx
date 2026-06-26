"use client";

import * as React from "react";
import { Sparkles, RotateCcw, Eye, Save, RefreshCw } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from "@/components/ui/dialog";
import { toast } from "@/components/ui/sonner";
import { api, ApiError } from "@/lib/api";
import { useMounted } from "@/lib/hooks";
import type {
  PromptPreview, PromptSlot, ServerConfigView, SuppressionConfig,
} from "@/lib/types";

type Dict = Record<string, unknown>;

const DEFAULT_SUPP: SuppressionConfig = {
  enabled: true, min_confidence: "medium", max_severity: "medium", require_profile: false,
};

export default function AITuningPage() {
  const mounted = useMounted();

  // ----- suppression / behavior knobs (base_config.ai) ------------------- //
  const [cfgBase, setCfgBase] = React.useState<Dict | null>(null);
  const [profiling, setProfiling] = React.useState(true);
  const [supp, setSupp] = React.useState<SuppressionConfig>(DEFAULT_SUPP);
  const [savingCfg, setSavingCfg] = React.useState(false);
  const [cfgErr, setCfgErr] = React.useState<string | null>(null);

  // ----- prompt registry ------------------------------------------------- //
  const [slots, setSlots] = React.useState<PromptSlot[]>([]);
  const [drafts, setDrafts] = React.useState<Record<string, string>>({});
  const [busy, setBusy] = React.useState<string | null>(null);
  const [loaded, setLoaded] = React.useState(false);

  // ----- preview dialog -------------------------------------------------- //
  const [preview, setPreview] = React.useState<{ slot: PromptSlot; data: PromptPreview } | null>(null);

  const hydratePrompts = React.useCallback((view: { slots: PromptSlot[] }) => {
    setSlots(view.slots);
    setDrafts(Object.fromEntries(view.slots.map((s) => [s.id, s.effective])));
  }, []);

  const load = React.useCallback(async () => {
    setCfgErr(null);
    try {
      const cfg = await api.getConfig();
      const base = { ...(cfg.base_config || {}) } as Dict;
      const ai = (base.ai as Dict) || {};
      setCfgBase(base);
      setProfiling(ai.profiling !== false);
      const s = (ai.suppression as Partial<SuppressionConfig>) || {};
      setSupp({
        enabled: s.enabled !== false,
        min_confidence: s.min_confidence || "medium",
        max_severity: s.max_severity || "medium",
        require_profile: !!s.require_profile,
      });
      hydratePrompts(await api.listPrompts());
      setLoaded(true);
    } catch (e) {
      setLoaded(false);
      setCfgErr(e instanceof ApiError ? `${e.code}: ${e.message}` : "Failed to load");
    }
  }, [hydratePrompts]);

  React.useEffect(() => { if (mounted) load(); }, [mounted, load]);

  const saveCfg = async () => {
    if (!cfgBase) return;
    setSavingCfg(true);
    try {
      const ai = { ...((cfgBase.ai as Dict) || {}), profiling, suppression: supp };
      // Round-trip the full base (masked llm.api_key is kept server-side).
      const body: ServerConfigView = { base_config: { ...cfgBase, ai } };
      await api.updateConfig(body);
      toast.success("AI behavior saved");
      await load();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Save failed");
    } finally {
      setSavingCfg(false);
    }
  };

  const saveSlot = async (slot: PromptSlot) => {
    const draft = drafts[slot.id] ?? "";
    // A draft equal to the built-in default (or blank) clears the override.
    const text = draft.trim() && draft.trim() !== slot.default_text.trim() ? draft : null;
    setBusy(slot.id);
    try {
      hydratePrompts(await api.updatePrompt(slot.id, text));
      toast.success(text ? `Override saved — ${slot.label}` : `Reset to default — ${slot.label}`);
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Save failed");
    } finally {
      setBusy(null);
    }
  };

  const resetSlot = async (slot: PromptSlot) => {
    setBusy(slot.id);
    try {
      hydratePrompts(await api.updatePrompt(slot.id, null));
      toast.success(`Reset to default — ${slot.label}`);
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Reset failed");
    } finally {
      setBusy(null);
    }
  };

  const showPreview = async (slot: PromptSlot) => {
    setBusy(slot.id);
    try {
      const data = await api.previewPrompt(slot.id, drafts[slot.id] ?? "");
      setPreview({ slot, data });
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Preview failed");
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Sparkles className="h-6 w-6 text-accent" />
          <div>
            <h1 className="text-2xl font-bold">AI Tuning</h1>
            <p className="text-sm text-muted-foreground">
              Profiling, cross-source false-positive suppression (the <code>ai.triage</code> pass),
              and the editable AI system prompts.
            </p>
          </div>
        </div>
        <Button variant="outline" size="icon-sm" onClick={load} aria-label="Reload">
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>

      {!loaded ? (
        <Card className="p-6 text-sm text-muted-foreground">
          {cfgErr ? <>Couldn&apos;t load — <span className="text-destructive">{cfgErr}</span>.</> : "Loading…"}
        </Card>
      ) : (
        <>
          {/* Behavior + suppression */}
          <Card className="space-y-5 p-6">
            <div>
              <h2 className="text-lg font-semibold">Behavior</h2>
              <p className="text-sm text-muted-foreground">
                Soft-suppression hides + uncounts a finding but keeps it in <code>findings.json</code>;
                an AI degrade suppresses nothing.
              </p>
            </div>

            <label className="flex cursor-pointer items-center gap-3">
              <input type="checkbox" checked={profiling}
                onChange={(e) => setProfiling(e.target.checked)}
                className="h-4 w-4 accent-[var(--primary)]" />
              <span className="text-sm">Context-aware AI profiling (one extra LLM call/host)</span>
            </label>

            <label className="flex cursor-pointer items-center gap-3">
              <input type="checkbox" checked={supp.enabled}
                onChange={(e) => setSupp({ ...supp, enabled: e.target.checked })}
                className="h-4 w-4 accent-[var(--primary)]" />
              <span className="text-sm">Let the AI soft-suppress false-positive findings (all sources)</span>
            </label>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label="Min suppression confidence"
                hint="AI verdict confidence required to hide a finding">
                <Select value={supp.min_confidence}
                  onValueChange={(v) => setSupp({ ...supp, min_confidence: v as SuppressionConfig["min_confidence"] })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["low", "medium", "high"].map((c) => (
                      <SelectItem key={c} value={c} className="capitalize">{c}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>

              <Field label="Severity ceiling"
                hint="Above this, the AI verdict is advisory only — the finding stays visible">
                <Select value={supp.max_severity}
                  onValueChange={(v) => setSupp({ ...supp, max_severity: v as SuppressionConfig["max_severity"] })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["info", "low", "medium", "high", "critical"].map((c) => (
                      <SelectItem key={c} value={c} className="capitalize">{c}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
            </div>

            <label className="flex cursor-pointer items-center gap-3">
              <input type="checkbox" checked={supp.require_profile}
                onChange={(e) => setSupp({ ...supp, require_profile: e.target.checked })}
                className="h-4 w-4 accent-[var(--primary)]" />
              <span className="text-sm">
                Require a usable, non-low-confidence profile before suppressing (legacy gate)
              </span>
            </label>

            <div className="flex justify-end">
              <Button onClick={saveCfg} disabled={savingCfg}>
                <Save className="h-4 w-4" /> {savingCfg ? "Saving…" : "Save behavior"}
              </Button>
            </div>
          </Card>

          {/* Prompt editors */}
          <div className="space-y-1">
            <h2 className="text-lg font-semibold">System prompts</h2>
            <p className="text-sm text-muted-foreground">
              Override the built-in AI system prompts. A blank field (or text equal to the default)
              reverts to the built-in default. Shape-hints stay in code, so edits can&apos;t break JSON output.
            </p>
          </div>

          {slots.map((slot) => {
            const draft = drafts[slot.id] ?? "";
            const dirty = draft.trim() !== slot.effective.trim();
            return (
              <Card key={slot.id} className="space-y-3 p-5">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{slot.label}</span>
                      {slot.modified && <Badge variant="default">Modified</Badge>}
                      {dirty && <Badge variant="outline">Unsaved</Badge>}
                    </div>
                    <p className="text-xs text-muted-foreground">{slot.description}</p>
                  </div>
                  <code className="shrink-0 rounded bg-secondary px-1.5 py-0.5 text-[11px] text-muted-foreground">
                    {slot.id}
                  </code>
                </div>

                <Textarea
                  value={draft}
                  onChange={(e) => setDrafts({ ...drafts, [slot.id]: e.target.value })}
                  className="min-h-[160px] font-mono text-xs"
                  spellCheck={false}
                />

                <div className="flex flex-wrap items-center justify-end gap-2">
                  <Button variant="ghost" size="sm" disabled={busy === slot.id}
                    onClick={() => showPreview(slot)}>
                    <Eye className="h-4 w-4" /> Preview
                  </Button>
                  <Button variant="outline" size="sm"
                    disabled={busy === slot.id || !slot.modified}
                    onClick={() => resetSlot(slot)}>
                    <RotateCcw className="h-4 w-4" /> Reset to default
                  </Button>
                  <Button size="sm" disabled={busy === slot.id || !dirty}
                    onClick={() => saveSlot(slot)}>
                    <Save className="h-4 w-4" /> Save
                  </Button>
                </div>
              </Card>
            );
          })}
        </>
      )}

      <Dialog open={!!preview} onOpenChange={(o) => !o && setPreview(null)}>
        <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Preview — {preview?.slot.label}</DialogTitle>
            <DialogDescription>
              The exact system + user message the engine would send, using your edited text and a
              representative sample payload. No LLM call.
            </DialogDescription>
          </DialogHeader>
          {preview && (
            <div className="space-y-4">
              <PreviewBlock title="System" text={preview.data.system} />
              <PreviewBlock title="User" text={preview.data.user} />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}

function PreviewBlock({ title, text }: { title: string; text: string }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-medium text-muted-foreground">{title}</p>
      <pre className="max-h-[40vh] overflow-auto whitespace-pre-wrap rounded-md bg-secondary p-3 font-mono text-[11px] leading-relaxed">
        {text}
      </pre>
    </div>
  );
}
