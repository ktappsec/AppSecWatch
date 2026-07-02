import type { Severity, JobState } from "./types";

/** Severity colors — CSS-var references to the `--sev-*` tokens in globals.css.
 * Theme-aware (light/dark) and safe as recharts fills / inline styles. */
export const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

/** Severity → Tailwind utility classes (literal strings so v4 can scan them).
 * `badge` keeps the label text neutral (foreground) and carries the vivid severity
 * color in the dot + border + tint, so the palette reads on the light surface too.
 * `text` is the raw colored-text variant — use only on dark/contrasting surfaces. */
export const SEVERITY_CLASSES: Record<
  string,
  { text: string; badge: string; dot: string }
> = {
  critical: {
    text: "text-sev-critical",
    badge: "border-sev-critical/50 bg-sev-critical/10",
    dot: "bg-sev-critical",
  },
  high: {
    text: "text-sev-high",
    badge: "border-sev-high/50 bg-sev-high/10",
    dot: "bg-sev-high",
  },
  medium: {
    text: "text-sev-medium",
    badge: "border-sev-medium/60 bg-sev-medium/15",
    dot: "bg-sev-medium",
  },
  low: {
    text: "text-sev-low",
    badge: "border-sev-low/50 bg-sev-low/10",
    dot: "bg-sev-low",
  },
  info: {
    text: "text-sev-info",
    badge: "border-sev-info/50 bg-sev-info/10",
    dot: "bg-sev-info",
  },
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const CHART_COLORS = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
  purple: "var(--chart-1)",
  pink: "var(--chart-5)",
  blue: "var(--chart-3)",
  cyan: "var(--chart-3)",
  teal: "var(--chart-4)",
} as const;

/** state → token-driven text/bg classes for status badges. */
export const STATE_STYLES: Record<JobState, { label: string; className: string; dot: string }> = {
  queued: { label: "Queued", className: "text-muted-foreground border-border", dot: "bg-muted-foreground" },
  running: { label: "Running", className: "text-primary border-primary/40", dot: "bg-primary animate-pulse" },
  completed: { label: "Completed", className: "text-success border-success/40", dot: "bg-success" },
  failed: { label: "Failed", className: "text-destructive border-destructive/40", dot: "bg-destructive" },
  cancelled: { label: "Cancelled", className: "text-warning border-warning/40", dot: "bg-warning" },
  interrupted: { label: "Interrupted", className: "text-sev-medium border-sev-medium/40", dot: "bg-sev-medium" },
};

export const TERMINAL_STATES: JobState[] = ["completed", "failed", "cancelled", "interrupted"];

export interface CapabilityChild {
  token: string;
  label: string;
  description: string;
}

export interface CapabilityToken {
  token: string;
  label: string;
  description: string;
  children?: CapabilityChild[];
}

export const CAPABILITY_TOKENS: CapabilityToken[] = [
  {
    token: "recon",
    label: "Recon",
    description: "Subdomain discovery + triage spine (always runs as a prerequisite)",
    children: [
      { token: "recon.subfinder", label: "subfinder", description: "passive subdomains" },
      { token: "recon.dns", label: "dns", description: "resolve + triage" },
      { token: "recon.tlsx", label: "tlsx", description: "cert-SAN re-feed (optional)" },
      { token: "recon.httpx", label: "httpx", description: "live-server probe (required by audit)" },
    ],
  },
  { token: "takeovers", label: "Takeovers", description: "Subdomain takeover — dangling CNAMEs + unclaimed third-party pages" },
  { token: "tls", label: "TLS", description: "sslscan per-host pass/fail scorecard" },
  {
    token: "nuclei",
    label: "Web CVEs",
    description: "nuclei auto-scan vs live web servers",
    children: [
      { token: "nuclei.critical", label: "critical", description: "-severity critical" },
      { token: "nuclei.high", label: "high", description: "-severity high" },
      { token: "nuclei.medium", label: "medium", description: "-severity medium" },
      { token: "nuclei.low", label: "low", description: "-severity low" },
      { token: "nuclei.info", label: "info", description: "noisy — opt-in" },
    ],
  },
  {
    token: "headers",
    label: "Security headers",
    description: "Deterministic OWASP header + CSP analysis (passive)",
    children: [
      { token: "headers.csp", label: "csp", description: "Content-Security-Policy weaknesses" },
      { token: "headers.best-practice", label: "best-practice", description: "HSTS, clickjacking, cookies, info-disclosure…" },
    ],
  },
  { token: "supply-chain", label: "Supply chain", description: "Playwright crawler — scripts + headers" },
  { token: "zap", label: "Active scan (ZAP)", description: "OWASP ZAP active scan of explicit in-scope targets — intrusive, opt-in" },
  {
    token: "ai",
    label: "AI analysis",
    description: "Profiling + cross-source triage + supply-chain reasoning",
    children: [
      { token: "ai.profile", label: "profile", description: "per-app profiling" },
      { token: "ai.triage", label: "triage", description: "cross-source FP suppression + header gaps" },
      { token: "ai.supply-chain", label: "supply-chain", description: "script risk (needs crawler)" },
      { token: "ai.summary", label: "summary", description: "executive-summary narrative (1 call/run)" },
    ],
  },
];

export const THROTTLE_PROFILES = ["paranoid", "gentle", "normal", "aggressive", "insane"] as const;
