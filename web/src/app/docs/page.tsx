import { Fragment } from "react";
import type { Metadata } from "next";
import { Card } from "@/components/ui/card";
import { CAPABILITY_TOKENS, THROTTLE_PROFILES } from "@/lib/constants";
import { Arrow, Badge, Callout, DocsLangToggle, Figure, FlowNode, Mono, Section } from "@/components/docs/ui";

export const metadata: Metadata = {
  title: "Docs · WatchTower",
  description: "How WatchTower scans, classifies, and reports.",
};

const TOC: { id: string; label: string }[] = [
  { id: "overview", label: "How it works" },
  { id: "recon", label: "Recon & re-feed loop" },
  { id: "liveness", label: "Live vs dead assets" },
  { id: "audit", label: "Audit fan-out" },
  { id: "ai", label: "AI analysis" },
  { id: "profiling", label: "Profiling & capture" },
  { id: "throttle", label: "Throttle tiers" },
  { id: "identity", label: "Stealth identity" },
  { id: "tls", label: "TLS scorecard" },
  { id: "suppression", label: "Suppression" },
  { id: "first-scan", label: "Your first scan" },
  { id: "scheduling", label: "Scheduling" },
  { id: "capabilities", label: "Capability reference" },
];

const THROTTLE_NOTES: Record<string, string> = {
  paranoid: "~serial, tiny rates, long waits — maximum stealth vs hardened / WAF'd targets (httpx threads 1).",
  gentle: "Low rates, httpx threads 2 — the safe default for hardened targets that block bursts.",
  normal: "The default — balanced rates equal to the per-tool defaults (httpx threads 10).",
  aggressive: "High concurrency for targets you fully control (httpx threads 50).",
  insane: "Fastest and loudest (httpx threads 200) — WILL trip WAFs.",
};

// Exact per-tier knob values — mirrors watchtower/config.py `_PROFILES`.
const THROTTLE_DETAIL: {
  tier: string; httpx: string; nuclei: number; takeovers: number; dnsx: number; tlsx: number; tls: string; conc: string;
}[] = [
  { tier: "paranoid", httpx: "2 / 1", nuclei: 2, takeovers: 2, dnsx: 50, tlsx: 5, tls: "900 s", conc: "1 / 1 / 1" },
  { tier: "gentle", httpx: "10 / 2", nuclei: 10, takeovers: 10, dnsx: 100, tlsx: 20, tls: "600 s", conc: "3 / 2 / 2" },
  { tier: "normal", httpx: "100 / 10", nuclei: 100, takeovers: 50, dnsx: 1000, tlsx: 100, tls: "300 s", conc: "10 / 5 / 5" },
  { tier: "aggressive", httpx: "500 / 50", nuclei: 500, takeovers: 150, dnsx: 5000, tlsx: 300, tls: "180 s", conc: "20 / 10 / 8" },
  { tier: "insane", httpx: "1000 / 200", nuclei: 1000, takeovers: 300, dnsx: 10000, tlsx: 500, tls: "120 s", conc: "40 / 20 / 15" },
];

// Stealth identity presets — mirrors watchtower/config.py `IDENTITY_PRESETS`.
const IDENTITY_PRESETS: { name: string; ua: string; platform: string; hints: string; isDefault?: boolean }[] = [
  { name: "chrome-win", ua: "Chrome/149 · Windows NT 10.0", platform: '"Windows"', hints: "low-entropy only", isDefault: true },
  { name: "chrome-mac", ua: "Chrome/149 · Intel Mac OS X 10_15_7", platform: '"macOS"', hints: "low-entropy only" },
  { name: "firefox", ua: "Firefox/140 · Windows", platform: "—", hints: "none (Firefox has no UA-CH)" },
  { name: "off", ua: "each tool's own default", platform: "—", hints: "no injected headers / referrer" },
];

const REFERER_POOL = [
  "google.com", "google.com.tr", "bing.com", "duckduckgo.com", "search.yahoo.com",
  "yandex.com.tr", "facebook.com", "linkedin.com", "t.co", "reddit.com",
];

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <header className="space-y-2">
        <div className="flex items-start justify-between gap-4">
          <h1 className="text-3xl font-bold">WatchTower documentation</h1>
          <DocsLangToggle active="en" />
        </div>
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
          A scan runs a modular async pipeline. You give it one or more{" "}
          <strong>root domains</strong> (or a saved asset group). The configured roots are the{" "}
          <strong>only</strong> scope — every name that resolves under a root is scanned,
          regardless of where it is hosted.
        </p>
        <Figure caption="The five phases of a scan. Recon always runs first; the audit nodes fan out in parallel; the AI layer runs after the audit so it can read the crawler's rendered capture.">
          <PipelineDiagram />
        </Figure>
        <p>
          Everything a scan produces lands under <Mono>runs/&lt;id&gt;/</Mono>: the raw tool output
          (<Mono>01_recon/</Mono>, <Mono>02_audit/</Mono>, <Mono>03_ai/</Mono>), the aggregated{" "}
          <Mono>result.json</Mono>, an <Mono>errors.json</Mono> / <Mono>summary.json</Mono> rollup,
          and two self-contained docs (CSS/JS inlined — they survive email): the full technical{" "}
          <Mono>report.html</Mono> and a leadership one-pager <Mono>executive.html</Mono> (plus an
          optional <Mono>executive.pdf</Mono>), both with a light/dark theme toggle.
          The web UI is a thin layer over the same engine and adds a cross-run relational layer
          (assets, schedules, suppressions, history) in SQLite. A completed scan exits{" "}
          <Mono>0</Mono> even with recorded errors; <Mono>--strict</Mono> turns any failure into a
          non-zero exit for CI.
        </p>
      </Section>

      <Section id="recon" title="Recon &amp; the re-feed loop">
        <p>
          The discovery <strong>spine</strong> runs sequentially and is always a prerequisite for
          every other capability. It establishes what exists and what is alive, then feeds every
          downstream node.
        </p>
        <Figure caption="The recon spine. Live certs harvest Subject-Alternative-Name hostnames that, filtered to your roots, loop back through dnsx — widening coverage up to 3 iterations.">
          <ReconFlow />
        </Figure>
        <ul className="ml-4 list-disc space-y-1.5">
          <li><strong>subfinder</strong> — passive subdomain discovery. <em>Optional</em>: skip it for a quick audit of exactly the roots/assets you gave (the required floor is <Mono>dns</Mono> + <Mono>httpx</Mono>).</li>
          <li><strong>dnsx</strong> — resolves every candidate (A + CNAME, IPv4). The roots are always seeded, so a no-subfinder scan still resolves them.</li>
          <li><strong>tlsx re-feed</strong> — one handshake does double duty: harvest cert SANs (re-fed to dnsx, bounded to 3 iterations; <Mono>*.</Mono> wildcards recorded but not iterated) <em>and</em> capture a passive <strong>certificate dossier</strong> (issuer, expiry, serial, SHA-256, self-signed / wildcard) — inventory only, shown on the Certs tab.</li>
          <li><strong>httpx</strong> — isolates live web servers and, with <Mono>-include-response</Mono>, yields per-host <strong>PageSignals</strong> (title, meta / OpenGraph, a pre-JS body snippet, form signals, detected tech) used by the profiler when no richer crawl is available.</li>
        </ul>
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
            <a href="#audit" className="text-accent hover:underline">subdomain takeover</a> via the
            offline provider-fingerprint DB.
          </li>
        </ul>
        <p>
          ASN / organisation is <strong>display-only enrichment</strong>. It needs an optional MaxMind
          GeoLite2-ASN MMDB (configured in Settings); without it, scans run exactly the same, just
          without the ASN column. It never gates a scan.
        </p>
      </Section>

      <Section id="audit" title="Audit fan-out">
        <p>
          Five independent capabilities run in parallel against the live set (the dead set only
          feeds the offline takeover check). Each is bounded by the concurrency caps and the
          chosen <a href="#throttle" className="text-accent hover:underline">throttle tier</a>.
        </p>
        <Figure caption="The audit phase. Five nodes run concurrently; none depends on another.">
          <AuditFanout />
        </Figure>
        <ul className="ml-4 list-disc space-y-1.5">
          <li><strong>Takeovers</strong> — two halves: live hosts whose CNAME chain leaves the roots are checked with <Mono>nuclei -t http/takeovers/</Mono>; the dead / dangling class is matched <strong>offline</strong> against a bundled provider-fingerprint DB (can-i-take-over-xyz) — a class nuclei structurally can&apos;t reach.</li>
          <li><strong>TLS</strong> — <Mono>sslscan</Mono> → a per-host pass/fail <a href="#tls" className="text-accent hover:underline">scorecard</a>. Passive, so it doesn&apos;t trip WAFs.</li>
          <li><strong>Web CVEs</strong> — <Mono>nuclei</Mono> auto-scan (templates limited to detected tech) against live web servers.</li>
          <li><strong>Security headers</strong> — deterministic, passive analysis of the response headers httpx already captured: the OWASP best-practice catalog plus a structured CSP weakness pass. No new requests.</li>
          <li><strong>Supply chain</strong> — the Playwright/Chromium <a href="#profiling" className="text-accent hover:underline">crawler</a> (structure-only capture).</li>
        </ul>
      </Section>

      <Section id="ai" title="AI analysis">
        <p>
          The AI layer&apos;s distinguishing value is <strong>per-application context awareness</strong>.
          It runs after the audit fan-out — the profiler at the head, so it can read the crawler&apos;s
          rendered capture before the two analysis passes that consume it.
        </p>
        <Figure caption="The AI phase. The profile is produced first and feeds both downstream passes.">
          <AiFlow />
        </Figure>
        <ul className="ml-4 list-disc space-y-1.5">
          <li><strong>ai.profile</strong> — infers what each app is (login portal, API, marketing site…) and the controls it ought to have. Input is set by <a href="#profiling" className="text-accent hover:underline"><Mono>ai.profile.render</Mono></a>.</li>
          <li><strong>ai.triage</strong> — reviews <em>all</em> deterministic findings (nuclei / TLS / js_lib / headers / takeover) per host, soft-suppresses likely false-positives, and adds header issues the rules miss. See <a href="#suppression" className="text-accent hover:underline">Suppression</a>.</li>
          <li><strong>ai.supply-chain</strong> — risk reasoning over the crawler&apos;s scripts, each pre-labeled 1st/3rd-party <strong>in Python</strong> (the LLM never decides party-ness), weighted by the profile.</li>
        </ul>
        <Callout>
          <strong>The LLM never gates a scanner.</strong> Every AI response is validated with one
          retry, then degrades gracefully: a failed profile falls back to context-light prompts, a
          degraded call is recorded as an <em>error</em> (not a crash), and an AI degrade{" "}
          <strong>suppresses nothing</strong>. If the LLM is unreachable or out of credits, you still
          get the complete deterministic finding set — only the AI annotations are missing.
        </Callout>
      </Section>

      <Section id="profiling" title="Profiling &amp; page capture">
        <p>
          The profiler&apos;s input depends on <Mono>ai.profile.render</Mono> (set in Settings, or
          per scan on the New-Scan form):
        </p>
        <ul className="ml-4 list-disc space-y-1.5">
          <li>
            <Badge tone="good">auto</Badge> (default) — when the supply-chain crawler runs
            for a host, the profiler uses the <strong>browser-rendered</strong> text plus a
            curated manifest of what the page actually loaded. Otherwise it falls back to the
            fast pre-JavaScript HTTP fetch. A browser is never spun up just to profile.
          </li>
          <li>
            <Badge tone="muted">always</Badge> — render every profiled host in a headless
            browser even when supply-chain is off (slower; a browser per host).
          </li>
          <li>
            <Badge tone="muted">never</Badge> — pre-JS HTTP signals only.
          </li>
        </ul>
        <p>
          When a page is rendered, the crawler captures a <strong>structure-only</strong>{" "}
          manifest — never any value, cookie content, or response body. A scan artifact is built to
          be shared and emailed, so it must never carry the target&apos;s secrets:
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-2 py-1.5 font-medium">Captured</th>
                <th className="px-2 py-1.5 font-medium">What it holds</th>
              </tr>
            </thead>
            <tbody className="[&_td]:px-2 [&_td]:py-1.5 [&_td]:align-top">
              <tr className="border-b border-border/50"><td><Mono>resources</Mono></td><td>every response: url / type / status / method (deduped, ≤ 500)</td></tr>
              <tr className="border-b border-border/50"><td><Mono>scripts</Mono></td><td>script-response URLs (feed js_libs + supply-chain)</td></tr>
              <tr className="border-b border-border/50"><td><Mono>cookies</Mono></td><td>name + flags (secure / httpOnly / sameSite / domain / path) — <strong>no value</strong></td></tr>
              <tr className="border-b border-border/50"><td><Mono>storage keys</Mono></td><td>localStorage / sessionStorage <strong>key names only</strong></td></tr>
              <tr className="border-b border-border/50"><td><Mono>rendered_text</Mono></td><td><Mono>body.innerText</Mono>, whitespace-normalized, ≤ 2 KB</td></tr>
              <tr><td><Mono>screenshot</Mono></td><td>optional per-host PNG (viewport) — dashboard only</td></tr>
            </tbody>
          </table>
        </div>
        <p>
          That curated, names-only surface is also persisted per asset (Assets → a row&apos;s
          Details → <em>Surface / connections</em>) so you can answer &ldquo;what does this host
          call?&rdquo; — a lightweight EASM view. Screenshots show in that same panel and are{" "}
          <strong>never</strong> embedded in the portable <Mono>report.html</Mono> or sent to the LLM.
        </p>
      </Section>

      <Section id="throttle" title="Throttle tiers">
        <p>
          A single nmap-style politeness tier is applied across every tool at once; any explicit
          per-tool value overrides it. <strong>httpx threads</strong> is the dominant trigger for
          source-blocking against WAF&apos;d targets — if a hardened target returns 0 live servers,
          drop to <Mono>gentle</Mono> (this, not the stealth headers, is the real anti-block lever).
        </p>
        <div className="space-y-1.5">
          {THROTTLE_PROFILES.map((p) => (
            <div key={p} className="flex flex-col gap-0.5 rounded-lg border border-border p-3 sm:flex-row sm:items-baseline sm:gap-3">
              <Mono>{p}</Mono>
              <span className="text-xs text-muted-foreground">{THROTTLE_NOTES[p]}</span>
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">Exact knob values per tier:</p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse whitespace-nowrap text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-2 py-1.5 font-medium">Tier</th>
                <th className="px-2 py-1.5 font-medium">httpx rl / threads</th>
                <th className="px-2 py-1.5 font-medium">nuclei rl</th>
                <th className="px-2 py-1.5 font-medium">takeovers rl</th>
                <th className="px-2 py-1.5 font-medium">dnsx rl</th>
                <th className="px-2 py-1.5 font-medium">tlsx conc</th>
                <th className="px-2 py-1.5 font-medium">sslscan timeout</th>
                <th className="px-2 py-1.5 font-medium" title="default / tls / playwright">conc (def/tls/pw)</th>
              </tr>
            </thead>
            <tbody className="[&_td]:px-2 [&_td]:py-1.5">
              {THROTTLE_DETAIL.map((r) => (
                <tr key={r.tier} className="border-b border-border/50">
                  <td><Mono>{r.tier}</Mono></td>
                  <td className="font-mono text-foreground">{r.httpx}</td>
                  <td className="font-mono">{r.nuclei}</td>
                  <td className="font-mono">{r.takeovers}</td>
                  <td className="font-mono">{r.dnsx}</td>
                  <td className="font-mono">{r.tlsx}</td>
                  <td className="font-mono">{r.tls}</td>
                  <td className="font-mono">{r.conc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-muted-foreground">
          <Mono>rl</Mono> = rate limit (requests/sec). <Mono>conc</Mono> = parallel host caps
          (generic fan-out / TLS scans / browser contexts).
        </p>
      </Section>

      <Section id="identity" title="Stealth identity">
        <Callout tone="warn">
          <strong>For AUTHORIZED testing of your own assets.</strong> A coherent browser identity
          defeats naive UA / header WAF rules only — <strong>not</strong> TLS / JA3 fingerprinting
          or IP-reputation. For those, get the scanner IP allowlisted.
        </Callout>
        <p>
          <Mono>identity.preset</Mono> bundles a coherent browser User-Agent + headers + locale,
          injected into <strong>httpx</strong>, <strong>nuclei</strong>, and the{" "}
          <strong>Playwright crawler</strong>. The default is <Mono>chrome-win</Mono> — every scan
          presents a Chrome-on-Windows identity unless set to <Mono>off</Mono>.{" "}
          <Mono>user_agent</Mono> / <Mono>headers</Mono> / <Mono>locale</Mono> override or extend it
          (decoys like <Mono>X-Forwarded-For</Mono> go in <Mono>headers</Mono>).
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-2 py-1.5 font-medium">Preset</th>
                <th className="px-2 py-1.5 font-medium">User-Agent</th>
                <th className="px-2 py-1.5 font-medium">Platform hint</th>
                <th className="px-2 py-1.5 font-medium">UA Client Hints</th>
              </tr>
            </thead>
            <tbody className="[&_td]:px-2 [&_td]:py-1.5 [&_td]:align-top">
              {IDENTITY_PRESETS.map((p) => (
                <tr key={p.name} className="border-b border-border/50">
                  <td>
                    <Mono>{p.name}</Mono>
                    {p.isDefault && <span className="ml-1.5 text-[10px] text-accent">default</span>}
                  </td>
                  <td className="text-muted-foreground">{p.ua}</td>
                  <td className="font-mono">{p.platform}</td>
                  <td className="text-muted-foreground">{p.hints}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p>
          <strong>Why only low-entropy client hints?</strong> Chrome presets ship just the hints a
          real browser sends on a cold first request — <Mono>Sec-CH-UA</Mono>,{" "}
          <Mono>Sec-CH-UA-Mobile</Mono>, <Mono>Sec-CH-UA-Platform</Mono>. The high-entropy hints
          (<Mono>-Arch</Mono>, <Mono>-Full-Version-List</Mono>, <Mono>-Platform-Version</Mono>…) and
          Google-proprietary <Mono>x-client-data</Mono> / <Mono>x-browser-*</Mono> are{" "}
          <strong>omitted on purpose</strong>: a browser only sends those after the server opts in
          via <Mono>Accept-CH</Mono>, so sending them unsolicited is itself a bot tell.
        </p>
        <p>
          <strong>Referrer rotation.</strong> A browser preset rotates a plausible{" "}
          <Mono>Referer</Mono> per tool run (httpx / nuclei / the crawler each get an independent
          one) from a 10-entry pool of external search / social origins. Because every entry is an
          external origin, the coherent <Mono>Sec-Fetch-Site</Mono> is <Mono>cross-site</Mono> (a
          click in from elsewhere — not <Mono>none</Mono>, which means a typed / bookmarked URL).
          Pin a fixed value via <Mono>headers.Referer</Mono> to opt out.
        </p>
        <div className="flex flex-wrap gap-1.5">
          {REFERER_POOL.map((r) => (
            <span key={r} className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">{r}</span>
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
            severity ceilings (default: medium confidence, medium severity ceiling) so high-severity
            findings are never auto-hidden.
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

      {/* Capabilities reference at the end — it's a lookup table, not a narrative step. */}
      <Section id="capabilities" title="Capability reference">
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
    </div>
  );
}

/* ── diagram compositions (English labels) — primitives live in @/components/docs/ui ── */

function PipelineDiagram() {
  const stages: { t: string; s: string; accent?: boolean }[] = [
    { t: "Recon", s: "discover + triage" },
    { t: "Audit", s: "parallel fan-out" },
    { t: "AI", s: "profile · triage · summary" },
    { t: "Aggregate", s: "merge findings" },
    { t: "report + executive", s: "self-contained", accent: true },
  ];
  return (
    <div className="overflow-x-auto pb-1">
      <div className="flex min-w-max items-stretch gap-2">
        {stages.map((st, i) => (
          <Fragment key={st.t}>
            <FlowNode title={st.t} sub={st.s} tone={st.accent ? "accent" : "default"} />
            {i < stages.length - 1 && <span className="flex items-center"><Arrow /></span>}
          </Fragment>
        ))}
      </div>
    </div>
  );
}

function ReconFlow() {
  return (
    <div className="flex flex-col items-center gap-1.5">
      <FlowNode title="subfinder + roots" sub="candidate names" />
      <Arrow dir="down" />

      {/* the DNS → TLS re-discovery loop, drawn as a cycle with a return wire */}
      <div className="relative w-full max-w-sm rounded-lg border border-dashed border-accent/50 px-3 pb-3 pt-4">
        <span className="absolute -top-2 left-1/2 -translate-x-1/2 whitespace-nowrap bg-card px-1.5 text-[10px] font-medium text-accent">
          🔁 DNS → TLS re-discovery loop · ≤ 3×
        </span>
        <div className="flex items-stretch gap-3">
          {/* return wire: tlsx (bottom) → dnsx (top) */}
          <div className="relative flex w-5 flex-col items-center">
            <span className="text-sm leading-none text-accent">▲</span>
            <div className="w-px flex-1 bg-accent/50" />
            <span className="absolute top-1/2 -translate-y-1/2 text-[9px] uppercase tracking-wide text-accent [writing-mode:vertical-rl] rotate-180">
              new SANs
            </span>
          </div>
          {/* forward path */}
          <div className="flex flex-1 flex-col items-center gap-1.5">
            <FlowNode title="dnsx" sub="resolve A + CNAME" className="w-full" />
            <Arrow dir="down" />
            <FlowNode title="triage" sub="liveness — live / dead" tone="accent" className="w-full" />
            <Arrow dir="down" />
            <FlowNode title="tlsx :443" sub="SAN harvest + cert dossier" className="w-full" />
          </div>
        </div>
      </div>

      <Arrow dir="down" />
      <FlowNode title="httpx" sub="live web servers → PageSignals" />
    </div>
  );
}

function AuditFanout() {
  const nodes = [
    { t: "takeovers", s: "nuclei + offline DB" },
    { t: "tls", s: "sslscan scorecard" },
    { t: "nuclei", s: "web CVEs" },
    { t: "headers", s: "OWASP + CSP" },
    { t: "supply-chain", s: "crawler" },
  ];
  return (
    <div className="flex flex-col items-center gap-1.5">
      <FlowNode title="live hosts" sub="from recon" tone="accent" />
      <Arrow dir="down" />
      <div className="grid w-full grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {nodes.map((n) => <FlowNode key={n.t} title={n.t} sub={n.s} className="min-w-0" />)}
      </div>
    </div>
  );
}

function AiFlow() {
  return (
    <div className="flex flex-col items-center gap-1.5">
      <FlowNode title="ai.profile" sub="what is this app? · expected controls" tone="accent" />
      <Arrow dir="down" />
      <div className="grid w-full grid-cols-1 gap-2 sm:grid-cols-2">
        <FlowNode title="ai.triage" sub="soft-suppress FPs + header gaps" className="min-w-0" />
        <FlowNode title="ai.supply-chain" sub="script risk, party-weighted" className="min-w-0" />
      </div>
    </div>
  );
}
