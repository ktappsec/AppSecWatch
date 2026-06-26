import type { Metadata } from "next";
import { Card } from "@/components/ui/card";
import { CAPABILITY_TOKENS, THROTTLE_PROFILES } from "@/lib/constants";

export const metadata: Metadata = {
  title: "Docs · WatchTower",
  description: "How WatchTower scans, classifies, and reports.",
};

const TOC: { id: string; label: string }[] = [
  { id: "overview", label: "How it works" },
  { id: "liveness", label: "Live vs dead assets" },
  { id: "capabilities", label: "Capabilities" },
  { id: "throttle", label: "Throttle tiers" },
  { id: "tls", label: "TLS scorecard" },
  { id: "suppression", label: "Suppression" },
  { id: "first-scan", label: "Your first scan" },
  { id: "scheduling", label: "Scheduling" },
];

const THROTTLE_NOTES: Record<string, string> = {
  paranoid: "~serial, tiny rates, long waits — maximum stealth vs hardened / WAF'd targets (httpx threads 1).",
  gentle: "Low rates, httpx threads 2–3 — the safe default for hardened targets that block bursts.",
  normal: "The default — balanced rates equal to the per-tool defaults (httpx threads 10).",
  aggressive: "High concurrency for targets you fully control (httpx threads 50).",
  insane: "Fastest and loudest (httpx threads 200) — WILL trip WAFs.",
};

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <header className="space-y-2">
        <h1 className="text-3xl font-bold">WatchTower documentation</h1>
        <p className="text-sm text-muted-foreground">
          WatchTower is a point-in-time external <span className="font-medium">Layer-7 AppSec</span>{" "}
          audit orchestrator. Each scan writes a complete, standalone artifact set — there is no
          database and no state carried across runs.
        </p>
      </header>

      {/* TOC */}
      <Card className="p-4">
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          On this page
        </p>
        <nav className="flex flex-wrap gap-2">
          {TOC.map((t) => (
            <a key={t.id} href={`#${t.id}`}
              className="rounded-lg border border-border px-3 py-1.5 text-xs text-muted-foreground transition-smooth hover:border-accent/40 hover:text-accent">
              {t.label}
            </a>
          ))}
        </nav>
      </Card>

      <Section id="overview" title="How it works">
        <p>
          A scan runs a modular async pipeline: <Mono>recon → triage → audit fan-out → AI analysis →
          aggregate → report.html</Mono>. You give it one or more <strong>root domains</strong> (or a
          saved asset group). The configured roots are the <strong>only</strong> scope — every name
          that resolves under a root is scanned, regardless of where it is hosted.
        </p>
        <p>
          Everything a scan produces lands under <Mono>runs/&lt;id&gt;/</Mono>: the raw tool output,
          the aggregated <Mono>result.json</Mono>, and a single self-contained{" "}
          <Mono>report.html</Mono>. The web UI is a thin layer over the same engine and adds a
          cross-run relational layer (assets, schedules, suppressions) in SQLite.
        </p>
      </Section>

      <Section id="liveness" title="Live vs dead assets">
        <p>
          WatchTower classifies every discovered name on a single <strong>liveness</strong> axis —
          there is no ownership / “in-scope vs shadow-IT” bucketing. What matters for an L7 audit is
          whether a host answers, not which network hosts its IP.
        </p>
        <ul className="ml-4 list-disc space-y-1.5">
          <li>
            <Badge tone="good">live</Badge> — resolves to one or more A records. Fully scanned, and
            its certificate SANs feed back into the DNS → TLS re-discovery loop to widen coverage.
          </li>
          <li>
            <Badge tone="muted">dead</Badge> — NXDOMAIN or no A records (e.g. a dangling{" "}
            <Mono>CNAME</Mono>). Not actively scanned, but watched for{" "}
            <a href="#capabilities" className="text-accent hover:underline">subdomain takeover</a>.
          </li>
        </ul>
        <p>
          ASN / organisation is <strong>display-only enrichment</strong>. It needs an optional MaxMind
          GeoLite2-ASN MMDB (configured in Settings); without it, scans run exactly the same, just
          without the ASN column.
        </p>
      </Section>

      <Section id="capabilities" title="Capabilities">
        <p>
          A scan is composed of capability <em>tokens</em>. By default every capability runs; use{" "}
          <Mono>only</Mono> to run a subset or <Mono>skip</Mono> to drop specific ones. The recon
          spine always runs as a prerequisite. Four capabilities split into dotted sub-tokens for
          finer control (e.g. <Mono>recon.subfinder</Mono>, <Mono>nuclei.critical</Mono>).
        </p>
        <div className="space-y-2">
          {CAPABILITY_TOKENS.map((t) => (
            <div key={t.token} className="rounded-lg border border-border p-3">
              <div className="flex items-baseline gap-2">
                <Mono>{t.token}</Mono>
                <span className="text-sm font-medium">{t.label}</span>
              </div>
              <p className="mt-0.5 text-xs text-muted-foreground">{t.description}</p>
              {t.children && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {t.children.map((c) => (
                    <span key={c.token} title={c.description}
                      className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                      {c.token}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          The New-Scan page exposes built-in presets (Full audit, Quick, Recon only, TLS + headers)
          that map onto these tokens — a fast starting point you can then fine-tune.
        </p>
      </Section>

      <Section id="throttle" title="Throttle tiers">
        <p>
          A single nmap-style politeness tier is applied across every tool at once. httpx concurrency
          is the main trigger for source-blocking against WAF&apos;d targets — if a hardened target
          returns 0 live servers, drop to <Mono>gentle</Mono>.
        </p>
        <div className="space-y-1.5">
          {THROTTLE_PROFILES.map((p) => (
            <div key={p} className="flex flex-col gap-0.5 rounded-lg border border-border p-3 sm:flex-row sm:items-baseline sm:gap-3">
              <Mono>{p}</Mono>
              <span className="text-xs text-muted-foreground">{THROTTLE_NOTES[p]}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section id="tls" title="TLS scorecard">
        <p>
          The <Mono>tls</Mono> capability runs <strong>sslscan</strong> against every live web server
          and turns the result into a pass/fail scorecard. It is passive — no attack-signature probes
          — so it does not trip the WAFs that get a noisier scanner blocked. Checks include:
        </p>
        <ul className="ml-4 list-disc space-y-1">
          <li>Insecure protocols disabled (SSLv2 / SSLv3 / TLS 1.0 / TLS 1.1)</li>
          <li>No weak ciphers (RC4 / 3DES / DES / EXPORT / NULL / MD5 / anonymous / &lt; 112-bit)</li>
          <li>Certificate valid and &gt; 30 days from expiry</li>
          <li>Key strength (RSA ≥ 2048 / EC ≥ 256) and signature algorithm not SHA-1 / MD5</li>
          <li>Secure renegotiation supported</li>
        </ul>
        <p>
          Separately, the recon stage harvests a passive <strong>certificate dossier</strong> (issuer,
          expiry, serial, SHA-256, self-signed / wildcard) via tlsx — inventory only, shown on the
          Certs tab. HSTS lives under the <Mono>headers</Mono> capability, not here.
        </p>
      </Section>

      <Section id="suppression" title="Suppression">
        <p>There are two distinct ways a finding can be hidden. Neither ever deletes it — every
          finding is preserved in <Mono>findings.json</Mono>; suppression only removes it from the
          report view and the severity counts.</p>
        <ul className="ml-4 list-disc space-y-1.5">
          <li>
            <strong>AI false-positive</strong> — the <Mono>ai.triage</Mono> pass judges deterministic
            findings per host and soft-suppresses likely false-positives. Re-judged fresh on every
            scan; shown inline in a collapsible section of the findings table. Gated by confidence /
            severity ceilings so high-severity findings are never auto-hidden.
          </li>
          <li>
            <strong>Manual</strong> — a cross-run rule you create with the eye-off button on a
            finding. Matched by <Mono>source · host · key</Mono>; a host of <Mono>*</Mono> means
            “everywhere”. Managed on the Suppressions page.
          </li>
        </ul>
        <p>
          In the findings table, suppressing a multi-host issue from the row suppresses it{" "}
          <em>everywhere</em>; expand the row and use the per-host button to suppress on{" "}
          <em>one host only</em>.
        </p>
      </Section>

      <Section id="first-scan" title="Your first scan">
        <ol className="ml-4 list-decimal space-y-1.5">
          <li>
            In <strong>Settings → Scan configuration</strong>, set the LLM endpoint + API key. (MMDB
            is optional.) A scan is gated only on a valid LLM config.
          </li>
          <li>
            Either enter ad-hoc roots on the New-Scan page, or import assets (CSV{" "}
            <Mono>domain,group</Mono>) on the Assets page and scan a group.
          </li>
          <li>Open <strong>New Scan</strong>, pick a preset, choose a throttle, and launch.</li>
          <li>
            On the scan detail page, the <strong>Findings</strong> tab collapses each issue by host —
            expand a row to see exactly which hosts are affected and jump straight to that asset.
          </li>
          <li>Suppress noise as you triage; the counts update on the next scan.</li>
        </ol>
      </Section>

      <Section id="scheduling" title="Scheduling">
        <p>
          Schedules run a normal scan on a friendly cadence (hourly / daily / weekly, with an
          optional time-of-day and weekday, in UTC). A schedule skips itself if a scan is already
          running, and runs once on boot if it was overdue while the server was down. Targets use the
          same selector as a manual scan (roots / group / specific assets / all assets).
        </p>
      </Section>
    </div>
  );
}

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="scroll-mt-20 space-y-3">
      <h2 className="border-b border-border pb-2 text-xl font-bold">{title}</h2>
      <div className="space-y-3 text-sm leading-relaxed text-muted-foreground [&_strong]:text-foreground">
        {children}
      </div>
    </section>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[0.85em] text-foreground">{children}</code>;
}

function Badge({ tone, children }: { tone: "good" | "muted"; children: React.ReactNode }) {
  return (
    <span className={
      tone === "good"
        ? "rounded border border-[#00c853]/40 px-1.5 py-0.5 font-mono text-[11px] text-[#00c853]"
        : "rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground"
    }>
      {children}
    </span>
  );
}
