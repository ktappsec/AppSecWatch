import type { Severity, JobState } from "./types";

/** Severity colors — semantic constants used in dashboard charts + badges. */
export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff1744",
  high: "#ff6d00",
  medium: "#ffd600",
  low: "#00c853",
  info: "#0ea5e9",
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const CHART_COLORS = {
  critical: "#ff1744",
  high: "#ff6d00",
  medium: "#ffd600",
  low: "#00c853",
  info: "#0ea5e9",
  purple: "#d946ef",
  pink: "#ec4899",
  blue: "#0ea5e9",
  cyan: "#06b6d4",
  teal: "#14b8a6",
} as const;

/** state → tailwind-ish text/bg classes for status badges. */
export const STATE_STYLES: Record<JobState, { label: string; className: string; dot: string }> = {
  queued: { label: "Queued", className: "text-muted-foreground border-border", dot: "bg-muted-foreground" },
  running: { label: "Running", className: "text-accent border-accent/40", dot: "bg-accent animate-pulse" },
  completed: { label: "Completed", className: "text-[#00c853] border-[#00c853]/40", dot: "bg-[#00c853]" },
  failed: { label: "Failed", className: "text-destructive border-destructive/40", dot: "bg-destructive" },
  cancelled: { label: "Cancelled", className: "text-[#ff6d00] border-[#ff6d00]/40", dot: "bg-[#ff6d00]" },
  interrupted: { label: "Interrupted", className: "text-[#ffd600] border-[#ffd600]/40", dot: "bg-[#ffd600]" },
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
