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
  CertInfo,
  CustomTemplate,
  CustomTemplateUpsert,
  Finding,
  GenerateResponse,
  JobList,
  ScanTemplate,
  ScanTemplateUpsert,
  JobStatus,
  NucleiCategory,
  SignatureStatus,
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
  FindingStateRow,
  FindingStatePatch,
  AnalyticsResponse,
  SearchResults,
  Notification,
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

const inflightGets = new Map<string, Promise<unknown>>();

/** Dedupe concurrent identical GETs: a page and a global poller (or two
 * components mounting together) that hit the same endpoint share one in-flight
 * response instead of each firing its own request. Mutating / header-bearing
 * calls always go straight through. */
async function request<T>(
  path: string,
  init: RequestInit = {},
  extraHeaders: Record<string, string> = {}
): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  if (method !== "GET" || Object.keys(extraHeaders).length > 0) {
    return doFetch<T>(path, init, extraHeaders);
  }
  const cacheKey = `${getApiBase()}${path}`;
  const existing = inflightGets.get(cacheKey) as Promise<T> | undefined;
  if (existing) return existing;
  const p = doFetch<T>(path, init, extraHeaders);
  inflightGets.set(cacheKey, p);
  p.finally(() => { if (inflightGets.get(cacheKey) === p) inflightGets.delete(cacheKey); });
  return p;
}

async function doFetch<T>(
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
  listAssets: (opts: { group?: string; status?: string; source?: string; q?: string;
                       new_since_scan?: string; sort?: string; summary?: boolean } = {}) => {
    const { summary, ...rest } = opts;
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(rest)) if (v) qs.set(k, v as string);
    if (summary) qs.set("summary", "1");   // slim projection: dashboard-needed columns only
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

  // TLS certs served to this asset from its last scan, matched by IP intersection
  // (cert.ip ∈ asset.a_records) — so a host shows the cert on the IP it resolves to.
  assetCerts: (fqdn: string) =>
    request<CertInfo[]>(`/assets/${encodeURIComponent(fqdn)}/certs`),

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

  // --- cross-scan finding state (lifecycle + tags) ---
  findingState: (opts: { status?: string; group?: string; finding_class?: string;
                         host?: string; sort?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(opts)) if (v != null && v !== "") qs.set(k, String(v));
    const q = qs.toString();
    return request<FindingStateRow[]>(`/finding-state${q ? `?${q}` : ""}`);
  },
  patchFindingState: (fingerprint: string, patch: FindingStatePatch) =>
    request<FindingStateRow>(`/finding-state/${encodeURIComponent(fingerprint)}`,
      { method: "PATCH", body: JSON.stringify(patch) }),

  // --- analytics ---
  analytics: (opts: { group?: string } = {}) => {
    const qs = new URLSearchParams();
    if (opts.group) qs.set("group", opts.group);
    const q = qs.toString();
    return request<AnalyticsResponse>(`/analytics${q ? `?${q}` : ""}`);
  },

  // --- all-in-one search ---
  search: (q: string, opts: { kind?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams({ q });
    if (opts.kind) qs.set("kind", opts.kind);
    if (opts.limit) qs.set("limit", String(opts.limit));
    return request<SearchResults>(`/search?${qs.toString()}`);
  },

  // --- notifications ---
  notifications: (opts: { unread_only?: boolean; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (opts.unread_only) qs.set("unread_only", "true");
    if (opts.limit) qs.set("limit", String(opts.limit));
    const q = qs.toString();
    return request<Notification[]>(`/notifications${q ? `?${q}` : ""}`);
  },
  markNotificationsRead: (id?: string) => {
    const q = id ? `?id=${encodeURIComponent(id)}` : "";
    return request<{ marked: number }>(`/notifications/read${q}`, { method: "POST" });
  },

  // --- nuclei catalog + custom templates ---
  nucleiTemplates: (opts: { q?: string; category?: string; tag?: string; severity?: string; source?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(opts)) if (v != null && v !== "") qs.set(k, String(v));
    const q = qs.toString();
    return request<NucleiTemplate[]>(`/nuclei/templates${q ? `?${q}` : ""}`);
  },
  nucleiCategories: () => request<NucleiCategory[]>("/nuclei/categories"),

  // --- signature packs (retire.js js-lib DB) ---
  signatureStatus: () => request<SignatureStatus>("/signatures"),
  updateSignatures: () => request<SignatureStatus>("/signatures/js-libs/update", { method: "POST" }),

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
