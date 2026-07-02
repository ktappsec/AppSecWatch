"use client";

/** Typed client for the AppSecWatch FastAPI backend.
 *
 * Base URL + API key resolve from localStorage first (set via Settings), then
 * from NEXT_PUBLIC_* env vars. Every error is normalized to ApiError carrying
 * the backend's `{error:{code,message}}` envelope. */
import type {
  Asset,
  AssetBulkRequest,
  AssetGroup,
  AssetImportResult,
  Capabilities,
  CustomTemplate,
  CustomTemplateUpsert,
  Finding,
  GenerateResponse,
  JobList,
  ScanTemplate,
  ScanTemplateUpsert,
  JobStatus,
  NucleiCategory,
  NucleiTemplate,
  PromptPreview,
  PromptsView,
  ScanHistoryEntry,
  ScanRequest,
  ScanResult,
  Schedule,
  ScheduleUpsert,
  ServerConfigView,
  Suppression,
  SuppressionCreate,
  TrendPoint,
} from "./types";

const LS_BASE = "appsecwatch.apiBase";
const LS_KEY = "appsecwatch.apiKey";

export function getApiBase(): string {
  if (typeof window !== "undefined") {
    const v = localStorage.getItem(LS_BASE);
    if (v) return v.replace(/\/$/, "");
  }
  return (process.env.NEXT_PUBLIC_API_BASE || "http://127.0.0.1:8099").replace(/\/$/, "");
}

export function getApiKey(): string {
  if (typeof window !== "undefined") {
    const v = localStorage.getItem(LS_KEY);
    if (v !== null) return v;
  }
  return process.env.NEXT_PUBLIC_API_KEY || "";
}

export function setApiConfig(base: string, key: string) {
  if (typeof window === "undefined") return;
  localStorage.setItem(LS_BASE, base.replace(/\/$/, ""));
  localStorage.setItem(LS_KEY, key);
}

export class ApiError extends Error {
  code: string;
  status: number;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  extraHeaders: Record<string, string> = {}
): Promise<T> {
  const base = getApiBase();
  const key = getApiKey();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...extraHeaders,
  };
  if (key) headers["Authorization"] = `Bearer ${key}`;

  let resp: Response;
  try {
    resp = await fetch(`${base}${path}`, { ...init, headers });
  } catch (e) {
    throw new ApiError(0, "network_error", `Cannot reach API at ${base} (${String(e)})`);
  }

  const contentType = resp.headers.get("content-type") || "";
  if (!resp.ok) {
    let code = "error";
    let message = `${resp.status} ${resp.statusText}`;
    if (contentType.includes("application/json")) {
      try {
        const body = await resp.json();
        if (body?.error) {
          code = body.error.code ?? code;
          message = body.error.message ?? message;
        }
      } catch {
        /* keep defaults */
      }
    }
    throw new ApiError(resp.status, code, message);
  }

  if (contentType.includes("application/json")) return (await resp.json()) as T;
  return (await resp.text()) as unknown as T;
}

// --- endpoints ----------------------------------------------------------- //
export const api = {
  capabilities: () => request<Capabilities>("/capabilities"),

  health: () => request<{ status: string; version: string }>("/healthz"),

  listScans: (opts: { state?: string; limit?: number; offset?: number } = {}) => {
    const qs = new URLSearchParams();
    if (opts.state) qs.set("state", opts.state);
    if (opts.limit != null) qs.set("limit", String(opts.limit));
    if (opts.offset != null) qs.set("offset", String(opts.offset));
    const q = qs.toString();
    return request<JobList>(`/scans${q ? `?${q}` : ""}`);
  },

  // Chronological exposure/risk trend points (durable SQLite scans index).
  trends: (opts: { group?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (opts.group) qs.set("group", opts.group);
    if (opts.limit != null) qs.set("limit", String(opts.limit));
    const q = qs.toString();
    return request<TrendPoint[]>(`/trends${q ? `?${q}` : ""}`);
  },

  // Durable cross-run terminal-scan history index.
  history: (opts: { group?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (opts.group) qs.set("group", opts.group);
    if (opts.limit != null) qs.set("limit", String(opts.limit));
    const q = qs.toString();
    return request<ScanHistoryEntry[]>(`/history${q ? `?${q}` : ""}`);
  },

  getScan: (id: string) => request<JobStatus>(`/scans/${encodeURIComponent(id)}`),

  getResult: (id: string) => request<ScanResult>(`/scans/${encodeURIComponent(id)}/result`),

  getLog: (id: string, tail = 200) =>
    request<string>(`/scans/${encodeURIComponent(id)}/log?tail=${tail}`),

  // Browser-facing URL (used in <iframe>/<a>). Appends ?api_key= because those
  // elements can't carry an Authorization header.
  reportUrl: (id: string) => {
    const key = getApiKey();
    const base = `${getApiBase()}/scans/${encodeURIComponent(id)}/report`;
    return key ? `${base}?api_key=${encodeURIComponent(key)}` : base;
  },

  // Executive one-pager (HTML) — iframe/link target, so ?api_key= like reportUrl.
  executiveUrl: (id: string) => {
    const key = getApiKey();
    const base = `${getApiBase()}/scans/${encodeURIComponent(id)}/executive`;
    return key ? `${base}?api_key=${encodeURIComponent(key)}` : base;
  },

  // Executive PDF download link (best-effort artifact; the server 404s when absent).
  executivePdfUrl: (id: string) => {
    const key = getApiKey();
    const base = `${getApiBase()}/scans/${encodeURIComponent(id)}/executive.pdf`;
    return key ? `${base}?api_key=${encodeURIComponent(key)}` : base;
  },

  submitScan: (req: ScanRequest, idempotencyKey?: string) =>
    request<JobStatus>(
      "/scans",
      { method: "POST", body: JSON.stringify(req) },
      idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}
    ),

  cancelScan: (id: string) =>
    request<JobStatus>(`/scans/${encodeURIComponent(id)}/cancel`, { method: "POST" }),

  getConfig: () => request<ServerConfigView>("/config"),

  updateConfig: (cfg: ServerConfigView) =>
    request<ServerConfigView>("/config", { method: "PUT", body: JSON.stringify(cfg) }),

  // --- AI prompts (editable system-prompt registry) ---
  listPrompts: () => request<PromptsView>("/prompts"),

  updatePrompt: (id: string, text: string | null) =>
    request<PromptsView>(`/prompts/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify({ text }),
    }),

  previewPrompt: (id: string, text: string) =>
    request<PromptPreview>(`/prompts/${encodeURIComponent(id)}/preview`, {
      method: "POST",
      body: JSON.stringify({ text }),
    }),

  // --- assets inventory ---
  listAssets: (opts: { group?: string; status?: string; source?: string; q?: string } = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(opts)) if (v) qs.set(k, v);
    const q = qs.toString();
    return request<Asset[]>(`/assets${q ? `?${q}` : ""}`);
  },

  assetGroups: () => request<AssetGroup[]>("/assets/groups"),

  addAsset: (a: { fqdn: string; group?: string | null; notes?: string | null; priority?: number | null }) =>
    request<Asset>("/assets", { method: "POST", body: JSON.stringify(a) }),

  // Partial edit of an existing asset (group/notes/priority); never changes source.
  updateAsset: (fqdn: string, patch: { group?: string | null; notes?: string | null; priority?: number | null }) =>
    request<Asset>(`/assets/${encodeURIComponent(fqdn)}`, { method: "PUT", body: JSON.stringify(patch) }),

  deleteAsset: (fqdn: string) =>
    request<{ deleted: string }>(`/assets/${encodeURIComponent(fqdn)}`, { method: "DELETE" }),

  importAssets: (csv: string) =>
    request<AssetImportResult>("/assets/import", { method: "POST", body: JSON.stringify({ csv }) }),

  bulkAssets: (req: AssetBulkRequest) =>
    request<{ affected: number }>("/assets/bulk", { method: "POST", body: JSON.stringify(req) }),

  assetFindings: (fqdn: string) =>
    request<Finding[]>(`/assets/${encodeURIComponent(fqdn)}/findings`),

  // Per-host crawler screenshot. Binary + auth'd, so it can't be a plain <img src>
  // (that can't send the Bearer header) — fetch as a blob → object URL. Returns
  // null when there is no screenshot (disabled / not crawled / older scan).
  assetScreenshot: async (fqdn: string): Promise<string | null> => {
    const base = getApiBase();
    const key = getApiKey();
    const headers: Record<string, string> = {};
    if (key) headers["Authorization"] = `Bearer ${key}`;
    try {
      const resp = await fetch(`${base}/assets/${encodeURIComponent(fqdn)}/screenshot`, { headers });
      if (!resp.ok) return null;
      return URL.createObjectURL(await resp.blob());
    } catch {
      return null;
    }
  },

  // --- scan templates (option presets) ---
  listScanTemplates: () => request<ScanTemplate[]>("/scan-templates"),
  createScanTemplate: (t: ScanTemplateUpsert) =>
    request<ScanTemplate>("/scan-templates", { method: "POST", body: JSON.stringify(t) }),
  deleteScanTemplate: (id: string) =>
    request<{ deleted: string }>(`/scan-templates/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // --- schedules ---
  listSchedules: () => request<Schedule[]>("/schedules"),

  createSchedule: (s: ScheduleUpsert) =>
    request<Schedule>("/schedules", { method: "POST", body: JSON.stringify(s) }),

  updateSchedule: (id: string, s: ScheduleUpsert) =>
    request<Schedule>(`/schedules/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(s) }),

  deleteSchedule: (id: string) =>
    request<{ deleted: string }>(`/schedules/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // --- suppressions ---
  listSuppressions: () => request<Suppression[]>("/suppressions"),

  addSuppression: (s: SuppressionCreate) =>
    request<Suppression>("/suppressions", { method: "POST", body: JSON.stringify(s) }),

  deleteSuppression: (fingerprint: string) =>
    request<{ deleted: string }>(`/suppressions/${encodeURIComponent(fingerprint)}`, { method: "DELETE" }),

  // --- nuclei catalog + custom templates ---
  nucleiTemplates: (opts: { q?: string; category?: string; tag?: string; severity?: string; source?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(opts)) if (v != null && v !== "") qs.set(k, String(v));
    const q = qs.toString();
    return request<NucleiTemplate[]>(`/nuclei/templates${q ? `?${q}` : ""}`);
  },
  nucleiCategories: () => request<NucleiCategory[]>("/nuclei/categories"),
  nucleiReindex: () => request<{ indexed: number; root: string }>("/nuclei/reindex", { method: "POST" }),
  listCustomTemplates: () => request<CustomTemplate[]>("/nuclei/custom"),
  createCustomTemplate: (t: CustomTemplateUpsert) =>
    request<CustomTemplate>("/nuclei/custom", { method: "POST", body: JSON.stringify(t) }),
  updateCustomTemplate: (id: string, t: CustomTemplateUpsert) =>
    request<CustomTemplate>(`/nuclei/custom/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(t) }),
  deleteCustomTemplate: (id: string) =>
    request<{ deleted: string }>(`/nuclei/custom/${encodeURIComponent(id)}`, { method: "DELETE" }),
  generateTemplate: (description: string) =>
    request<GenerateResponse>("/nuclei/custom/generate", { method: "POST", body: JSON.stringify({ description }) }),
};
