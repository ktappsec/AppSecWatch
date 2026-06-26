/** TypeScript mirror of the WatchTower FastAPI contract (watchtower/api/models.py).
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
export type Bucket = "in_scope" | "shadow_it" | "dead";
export type FindingSource =
  | "nuclei"
  | "takeover"
  | "sslyze"
  | "headers"
  | "csp"
  | "js_lib"
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
  bucket?: "in_scope" | "shadow_it" | "dead" | null;
  a_records: string[];
  cname_chain?: string[];
  asn?: number | null;
  as_org?: string | null;
  tech: { name: string; source?: string }[];
  profile?: Record<string, unknown> | null;
  finding_counts?: Record<string, number>;
  notes?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  last_scan_id?: string | null;
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
}

export interface TLSCheck {
  name: string;
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
  bucket: Bucket;
  reason: string;
}

export interface LiveWebServer {
  url: string;
  host: string;
  status_code?: number | null;
  title?: string | null;
  tech: string[];
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
}

export interface ScanResult {
  id: string;
  state: JobState;
  coverage: Record<string, CoverageEntry>;
  histogram: Record<string, Record<string, number>>;
  histogram_totals: Record<string, number>;
  findings: Finding[];
  tls: TLSHostReport[];
  tls_certs: CertInfo[];
  app_profiles: Record<string, AppProfile>;
  assets: TriagedAsset[];
  live_servers: LiveWebServer[];
  wildcards: string[];
  summary?: RunSummary | null;
  report_url: string;
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
  filter?: { group?: string | null; bucket?: string | null; source?: string | null } | null;
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

/** Effective server config (GET /config). `base_config` mirrors WatchTowerConfig
 * minus per-request `roots`; `llm.api_key` is masked ("********"). The same shape
 * is sent to PUT /config (full replacement; a blank/masked api_key is kept).
 * There is no scan-target allowlist — the per-scan roots is the only scope. */
export interface ServerConfigView {
  base_config: Record<string, unknown>;
}

// AI prompts — the editable system-prompt registry (AI Tuning page). Mirrors
// watchtower/api/models.py PromptSlot / PromptsView / PromptPreview.
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
