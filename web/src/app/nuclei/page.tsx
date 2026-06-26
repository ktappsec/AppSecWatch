"use client";

import * as React from "react";
import { FileCode, Sparkles, Save, Trash2, Power, RefreshCw, Search } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/table";
import { toast } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import { api, ApiError } from "@/lib/api";
import { useMounted } from "@/lib/hooks";
import type { CustomTemplate, NucleiTemplate } from "@/lib/types";

export default function NucleiPage() {
  const mounted = useMounted();

  // catalog
  const [q, setQ] = React.useState("");
  const [severity, setSeverity] = React.useState("");
  const [templates, setTemplates] = React.useState<NucleiTemplate[]>([]);
  // custom
  const [custom, setCustom] = React.useState<CustomTemplate[]>([]);
  const [name, setName] = React.useState("");
  const [yamlText, setYamlText] = React.useState("");
  const [desc, setDesc] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const searchCatalog = React.useCallback(async () => {
    try {
      setTemplates(await api.nucleiTemplates({ q: q || undefined, severity: severity || undefined, limit: 100 }));
    } catch (e) {
      toast.error(e instanceof ApiError ? `${e.code}: ${e.message}` : "Search failed");
    }
  }, [q, severity]);

  const loadCustom = React.useCallback(async () => {
    try { setCustom(await api.listCustomTemplates()); }
    catch { /* surfaced elsewhere */ }
  }, []);

  React.useEffect(() => { if (mounted) { searchCatalog(); loadCustom(); } }, [mounted, searchCatalog, loadCustom]);

  const reindex = async () => {
    try { const r = await api.nucleiReindex(); toast.success(`Indexed ${r.indexed} templates`); searchCatalog(); }
    catch (e) { toast.error(e instanceof ApiError ? `${e.code}: ${e.message}` : "Reindex failed"); }
  };

  const save = async () => {
    if (!yamlText.trim()) { toast.error("Template YAML is empty"); return; }
    try {
      const t = await api.createCustomTemplate({ name: name.trim() || undefined, yaml: yamlText });
      toast[t.valid ? "success" : "error"](t.valid ? "Saved (valid)" : `Saved but invalid: ${t.error ?? ""}`);
      setName(""); setYamlText(""); loadCustom();
    } catch (e) { toast.error(e instanceof ApiError ? `${e.code}: ${e.message}` : "Save failed"); }
  };

  const generate = async () => {
    if (!desc.trim()) { toast.error("Describe the check first"); return; }
    setBusy(true);
    try {
      const g = await api.generateTemplate(desc.trim());
      setYamlText(g.yaml);
      toast[g.valid ? "success" : "error"](g.valid ? "Generated + validated" : `Generated but invalid: ${g.error}`);
    } catch (e) { toast.error(e instanceof ApiError ? `${e.code}: ${e.message}` : "Generate failed"); }
    finally { setBusy(false); }
  };

  const toggle = async (t: CustomTemplate) => {
    try { await api.updateCustomTemplate(t.id, { yaml: t.yaml, name: t.name ?? undefined, enabled: !t.enabled }); loadCustom(); }
    catch (e) { toast.error(e instanceof ApiError ? e.message : "Update failed"); }
  };
  const del = async (id: string) => {
    try { await api.deleteCustomTemplate(id); loadCustom(); }
    catch (e) { toast.error(e instanceof ApiError ? e.message : "Delete failed"); }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Nuclei templates</h1>
        <p className="text-sm text-muted-foreground">
          Browse the bundled catalog, author custom templates, or generate one with AI.
        </p>
      </div>

      {/* Custom + generator */}
      <Card className="gap-4 p-6">
        <h3 className="flex items-center gap-2 text-lg font-bold"><FileCode className="h-5 w-5 text-accent" /> Custom templates</h3>
        <div className="flex flex-wrap items-end gap-2">
          <div className="flex-1 space-y-1.5">
            <Label>Generate from a description (AI)</Label>
            <div className="flex gap-2">
              <Input value={desc} onChange={(e) => setDesc(e.target.value)}
                placeholder="e.g. detect exposed .git/config" />
              <Button variant="outline" className="gap-1.5" onClick={generate} disabled={busy}>
                <Sparkles className="h-4 w-4" /> {busy ? "Generating…" : "Generate"}
              </Button>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[200px_1fr]">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="template name" />
          <Textarea value={yamlText} onChange={(e) => setYamlText(e.target.value)} spellCheck={false}
            className="min-h-[180px] font-mono text-xs" placeholder="id: my-check&#10;info:&#10;  name: …&#10;  severity: info" />
        </div>
        <div className="flex justify-end">
          <Button className="gap-1.5" onClick={save}><Save className="h-4 w-4" /> Validate & save</Button>
        </div>

        {custom.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead><TableHead>Valid</TableHead>
                <TableHead className="hidden md:table-cell">Error</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {custom.map((t) => (
                <TableRow key={t.id} className={cn(!t.enabled && "opacity-60")}>
                  <TableCell className="text-sm font-medium">{t.name || t.id}</TableCell>
                  <TableCell>
                    <span className={cn("rounded border px-1.5 py-0.5 text-[10px]",
                      t.valid ? "border-[#00c853]/40 text-[#00c853]" : "border-destructive/40 text-destructive")}>
                      {t.valid ? "valid" : "invalid"}
                    </span>
                  </TableCell>
                  <TableCell className="hidden md:table-cell max-w-[280px] truncate text-xs text-muted-foreground">{t.error}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button variant="ghost" size="icon-sm" aria-label="Toggle" onClick={() => toggle(t)}>
                        <Power className={cn("h-4 w-4", t.enabled ? "text-[#00c853]" : "text-muted-foreground")} />
                      </Button>
                      <Button variant="ghost" size="icon-sm" aria-label="Delete" onClick={() => del(t.id)}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      {/* Catalog */}
      <Card className="gap-4 p-6">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-bold">Template catalog</h3>
          <Button variant="outline" size="sm" className="gap-1.5" onClick={reindex}>
            <RefreshCw className="h-3.5 w-3.5" /> Reindex
          </Button>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input value={q} onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && searchCatalog()}
              placeholder="search id / name…" className="pl-8" />
          </div>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}
            className="h-9 rounded-md border border-border bg-input px-2 text-sm">
            <option value="">all severities</option>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <Button variant="outline" onClick={searchCatalog}>Search</Button>
        </div>
        {templates.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No templates indexed. Click <span className="font-medium">Reindex</span> to scan the nuclei-templates dir.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead><TableHead>Severity</TableHead>
                <TableHead>Category</TableHead>
                <TableHead className="hidden md:table-cell">Tags</TableHead>
                <TableHead>Source</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {templates.map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="font-mono text-xs">{t.id}</TableCell>
                  <TableCell className="text-xs">{t.severity ?? "—"}</TableCell>
                  <TableCell className="text-xs">{t.category ?? "—"}</TableCell>
                  <TableCell className="hidden md:table-cell text-xs text-muted-foreground">{t.tags.slice(0, 4).join(", ")}</TableCell>
                  <TableCell>
                    <span className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">{t.source}</span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>
    </div>
  );
}
