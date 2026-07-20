/** TypeScript mirror of the AppSecWatch FastAPI contract (appsecwatch/api/models.py).
 * Keep in sync with the Pydantic models. */

export type JobState =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "interrupted";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ThrottleProfile = "paranoid" | "gentle" | "normal" | "aggressive" | "insane";
export type AssetStatus = "live" | "dead";
export type FindingSource =
  | "nuclei"
  | "takeover"
  | "sslscan"
  | "headers"
  | "csp"
  | "js_lib"
  | "secret"
  | "zap"
  | "ai_headers"
  | "ai_supply_chain";

/** Verdict attached to a finding (AI soft-suppression or a manual suppression). */
export interface AIFindingVerdict {
  suppressed: boolean;
  confidence: "low" | "medium" | "high";
  reason: string;
  source?: "ai_headers" | "manual";
}

export interface Suppression {
  fingerprint: string;
  source: string;
  host?: string | null;
  key: string;
  scope: "host" | "global";
  reason?: string;
  created_at?: string | null;
}

export interface SuppressionCreate {
  source: string;
  host?: string | null;
  key: string;
  scope?: "host" | "global";
  reason?: string;
}

export interface Asset {
  fqdn: string;
  group?: string | null;
  source: "imported" | "discovered";
  root?: string | null;
  status?: AssetStatus | null;
  a_records: string[];
  cname_chain?: string[];
  asn?: number | null;
  as_org?: string | null;
  tech: { name: string; source?: string }[];
  profile?: Record<string, unknown> | null;
  finding_counts?: Record<string, number>;
  surface?: {
    third_party_domains?: string[];
    script_domains?: string[];
    endpoints?: string[];
    cookie_keys?: string[];
    storage_keys?: string[];
  } | null;
  priority?: number | null;   // manual business criticality 1..10 (10 highest)
  notes?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  last_scan_id?: string | null;
  first_seen_scan?: string | null;  // scan id that first discovered this asset (new-domain alert)
}

export interface AssetGroup {
  group: string | null;
  count: number;
  last_scan_id?: string | null;
}

export interface AssetImportResult {
  added: number;
  updated: number;
  skipped: number;
}

export interface ScheduleTarget {
  roots?: string[] | null;
  group?: string | null;
  assets?: string[] | null;
  all_assets?: boolean;
}

export interface Schedule {
  id: string;
  name?: string | null;
  target: ScheduleTarget;
  only?: string[] | null;
  skip?: string[] | null;
  throttle?: string | null;
  compress: boolean;
  cadence: "hourly" | "daily" | "weekly";
  at_time?: string | null;
  weekday?: number | null;
  enabled: boolean;
  next_run_at?: string | null;
  last_run_at?: string | null;
  last_job_id?: string | null;
  created_at?: string | null;
}

export interface ScheduleUpsert {
  name?: string;
  target: ScheduleTarget;
  only?: string[] | null;
  skip?: string[] | null;
  throttle?: string | null;
  compress?: boolean;
  cadence: "hourly" | "daily" | "weekly";
  at_time?: string | null;
  weekday?: number | null;
  enabled?: boolean;
}

export interface NucleiTemplate {
  id: string;
  name?: string | null;
  severity?: string | null;
  tags: string[];
  category?: string | null;
  path?: string | null;
  source: string;
}

export interface NucleiCategory {
  category: string | null;
  count: number;
}

export interface CustomTemplate {
  id: string;
  name?: string | null;
  yaml: string;
  enabled: boolean;
  valid: boolean;
  error?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface CustomTemplateUpsert {
  name?: string;
  yaml: string;
  enabled?: boolean;
}

export interface GenerateResponse {
  yaml: string;
  valid: boolean;
  error: string;
}

export interface ScanRequest {
  roots?: string[] | null;
  group?: string | null;
  assets?: string[] | null;
  all_assets?: boolean;
  only?: string[] | null;
  skip?: string[] | null;
  throttle?: ThrottleProfile | null;
  profile_render?: "auto" | "always" | "never" | null;
  /** Scope-locked targets for the opt-in `zap` active scan (required when zap is selected). */
  zap_targets?: string[] | null;
  /** Per-scan override of zap.ajax_spider (null = server-config default). */
  zap_ajax_spider?: boolean | null;
  compress?: boolean;
  callback_url?: string | null;
}

export interface CoverageEntry {
  ran: boolean;
  reason: string;
  partial?: boolean;
  sub?: Record<string, { ran: boolean; reason: string }>;
}

export interface JobLinks {
  self: string;
  result: string;
  report: string;
  log: string;
  cancel: string;
}

export interface JobStatus {
  id: string;
  state: JobState;
  roots?: string[] | null;
  group?: string | null;
  only?: string[] | null;
  skip?: string[] | null;
  throttle?: ThrottleProfile | null;
  submitted_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  current_stage?: string | null;
  completed_stages: string[];
  elapsed_s: number;
  finding_count: number;
  coverage: Record<string, CoverageEntry>;
  degraded: boolean;   // httpx probed 0 live servers despite live assets — not a clean scan
  error?: string | null;
  links: JobLinks;
}

export interface JobList {
  jobs: JobStatus[];
  total: number;
}

export interface Finding {
  source: FindingSource;
  host?: string | null;
  severity: Severity;
  title: string;
  description?: string;
  evidence?: Record<string, unknown>;
  check_id?: string | null;
  ai_verdict?: AIFindingVerdict | null;
  finding_class?: string | null;   // controlled taxonomy, e.g. "headers.hsts-missing"
  category?: string | null;        // e.g. "headers"
}

/** A cross-scan diff summary vs the previous scan of this scope. */
export interface ScanDiff {
  new: number;
  recurring: number;
  resolved: number;
  reopened?: number;
}

export interface TLSCheck {
  name: string;
  // Problem-phrased label shown when the check FAILS ("TLS 1.0 enabled").
  // `name` states the secure condition tested for ("TLS 1.0 disabled") and is
  // shown for a passing row; surfacing it on a failure reads backwards.
  fail_title?: string;
  passed: boolean;
  detail?: string;
  severity?: Severity;
}

export interface TLSHostReport {
  host: string;
  checks: TLSCheck[];
  error?: string | null;
}

export interface AppProfile {
  host?: string;
  app_type?: string;
  audience?: "public" | "internal" | "partner" | "unknown";
  confidence?: "low" | "medium" | "high";
  reasoning?: string;
  handles_auth?: boolean;
  handles_pii?: boolean;
  handles_payments?: boolean;
  has_file_upload?: boolean;
  is_api?: boolean;
  expected_controls?: string[];
  error?: string | null;
}

export interface TriagedAsset {
  fqdn: string;
  a_records: string[];
  cname_chain: string[];
  asn?: number | null;
  as_org?: string | null;
  status: AssetStatus;
  reason: string;
}

export interface LiveWebServer {
  url: string;
  host: string;
  status_code?: number | null;
  title?: string | null;
  tech: string[];
  assessed?: boolean;              // false = blocked/error response, not a real app surface
  not_assessed_reason?: string | null;
}

export interface CertInfo {
  ip: string;
  subject_cn?: string | null;
  sans: string[];
  issuer?: string | null;
  serial?: string | null;
  sha256?: string | null;
  not_before?: string | null;
  not_after?: string | null;
  days_remaining?: number | null;
  expired: boolean;
  self_signed: boolean;
  wildcard: boolean;
  // DNS attribution (filled server-side; the dossier is IP-keyed). resolving_names =
  // scanned FQDNs whose DNS points at this cert's IP; subject_cn_ips = where the
  // cert's own CN actually resolves (empty = unknown/wildcard).
  resolving_names: string[];
  subject_cn_ips: string[];
}

export type Posture = "CRITICAL" | "HIGH" | "MODERATE" | "LOW";

export interface ScanResult {
  id: string;
  state: JobState;
  coverage: Record<string, CoverageEntry>;
  histogram: Record<string, Record<string, number>>;
  histogram_totals: Record<string, number>;
  risk_score: number;          // derived 0..100
  posture: Posture;            // highest severity present
  findings: Finding[];
  tls: TLSHostReport[];
  tls_certs: CertInfo[];
  app_profiles: Record<string, AppProfile>;
  assets: TriagedAsset[];
  live_servers: LiveWebServer[];
  wildcards: string[];
  summary?: RunSummary | null;
  report_url: string;
  executive_url?: string | null;
  executive_pdf_url?: string | null;
  diff?: ScanDiff | null;          // cross-scan new/recurring/resolved vs previous scan
  degraded?: boolean;              // 0 live servers despite live assets — inconclusive scan
  degraded_reason?: string | null;
  not_assessed?: number;           // hosts probed but blocked/error (findings suppressed)
}

/** A row of the unified finding_state table (GET /finding-state). */
export interface FindingStateRow {
  fingerprint: string;
  source?: string | null;
  host?: string | null;
  group_key?: string | null;
  finding_class?: string | null;
  category?: string | null;
  severity?: string | null;
  title?: string | null;
  status: "open" | "resolved" | "suppressed" | "accepted";
  tags: string[];
  reason?: string;
  consecutive_absent?: number;
  first_seen_scan?: string | null;
  last_seen_scan?: string | null;
  group?: string | null;
}

export interface FindingStatePatch {
  tags?: string[];
  status?: "open" | "resolved" | "suppressed" | "accepted";
}

/** In-app notification (GET /notifications). */
export interface Notification {
  id: string;
  type: string;
  title: string;
  body?: string;
  payload?: Record<string, unknown>;
  group?: string | null;
  scan_id?: string | null;
  read: number;
  created_at?: string | null;
}

/** All-in-one search results (GET /search). */
export interface SearchResults {
  assets: Array<{ fqdn: string; group?: string | null }>;
  findings: Array<{
    title: string; host: string; category: string; source: string;
    fingerprint: string; scan_id?: string | null;
  }>;
}

/** Posture-over-time analytics (GET /analytics). */
export interface AnalyticsResponse {
  by_status: Record<string, number>;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  open_total: number;
  resolved_total: number;
  suppressed_total: number;
  widespread: Array<{ key: string; title?: string | null; category?: string | null; host_count: number }>;
  longest_open: Array<{ title?: string | null; host?: string | null; category?: string | null; severity?: string | null; first_seen_scan?: string | null }>;
  by_priority: Array<{ priority: number; open: number }>;
}

/** Durable cross-run terminal-scan record (GET /history). */
export interface ScanHistoryEntry {
  id: string;
  state?: string | null;
  roots: string[];
  group?: string | null;
  submitted_at?: string | null;
  finished_at?: string | null;
  finding_count: number;
  by_severity: Record<string, number>;
  risk_score?: number | null;
  source: string;
  schedule_id?: string | null;
}

/** One chronological point for the exposure/risk trend charts (GET /trends). */
export interface TrendPoint {
  id: string;
  label: string;
  finished_at?: string | null;
  finding_count: number;
  risk_score?: number | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface RunSummary {
  duration_s?: number;
  findings_total?: number;
  findings_by_severity?: Record<string, number>;
  assets?: Record<string, number>;
  errors_total?: number;
  errors_by_stage?: Record<string, number>;
  ai?: Record<string, number>;
  tls?: Record<string, number>;
  events?: Record<string, number>;
}

export interface Capabilities {
  version: string;
  capabilities: string[];
  subtokens?: Record<string, string[]>;
  throttle_profiles: ThrottleProfile[];
  throttle_details?: Record<string, Record<string, number | boolean>>;
  paths?: { output_root: string; config_store: string; db: string };
}

export interface AssetBulkRequest {
  action: "delete" | "set_group";
  fqdns?: string[] | null;
  filter?: { group?: string | null; status?: string | null; source?: string | null } | null;
  group?: string | null;
}

export interface ScanTemplate {
  id: string;
  name: string;
  only?: string[] | null;
  skip?: string[] | null;
  throttle?: ThrottleProfile | null;
  compress: boolean;
  created_at?: string | null;
}

export interface ScanTemplateUpsert {
  name: string;
  only?: string[] | null;
  skip?: string[] | null;
  throttle?: ThrottleProfile | null;
  compress?: boolean;
}

/** Effective server config (GET /config). `base_config` mirrors AppSecWatchConfig
 * minus per-request `roots`; `llm.api_key` is masked ("********"). The same shape
 * is sent to PUT /config (full replacement; a blank/masked api_key is kept).
 * There is no scan-target allowlist — the per-scan roots is the only scope. */
export interface ServerConfigView {
  base_config: Record<string, unknown>;
}

// AI prompts — the editable system-prompt registry (AI Tuning page). Mirrors
// appsecwatch/api/models.py PromptSlot / PromptsView / PromptPreview.
export interface PromptSlot {
  id: string;
  label: string;
  description: string;
  default_text: string;
  override: string | null;
  modified: boolean;
  effective: string;
}

export interface PromptsView {
  slots: PromptSlot[];
}

export interface PromptPreview {
  system: string;
  user: string;
}

// AI suppression knobs (base_config.ai.suppression). Mirrors SuppressionConfig.
export interface SuppressionConfig {
  enabled: boolean;
  min_confidence: "low" | "medium" | "high";
  max_severity: "info" | "low" | "medium" | "high" | "critical";
  require_profile: boolean;
}

export interface ApiErrorBody {
  error: { code: string; message: string };
}
