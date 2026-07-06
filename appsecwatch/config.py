from __future__ import annotations

import random
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ThrottleProfile = Literal["paranoid", "gentle", "normal", "aggressive", "insane"]


class ConcurrencyConfig(BaseModel):
    default: int = 10
    llm: int = 4
    playwright: int = 5
    tls: int = 5             # parallel sslscan host scans


class LLMConfig(BaseModel):
    base_url: str
    api_key: str = "placeholder"
    model: str
    timeout_seconds: int = 120
    max_retries: int = 1
    # Request attribution. OpenRouter surfaces these in its activity log so you can
    # see which calls spent what. `app_title` → the `X-Title` header (the request
    # "name"); `app_url` → the optional `HTTP-Referer`. When `tag_requests` is on,
    # each call's purpose (profile / triage / supply / nuclei-gen) is appended to
    # the title — so spend breaks down by call type — and, on OpenRouter, the
    # OpenAI `user` field carries the full per-host label. Both are plain HTTP
    # headers / a standard field that other backends (Ollama, llama.cpp, …) ignore,
    # so this is harmless off OpenRouter.
    app_title: str = "AppSecWatch"
    app_url: str | None = None
    tag_requests: bool = True
    # Optional per-call-type model overrides, keyed by call purpose:
    # `profile`, `triage`, `supply`, `nuclei-gen`. A purpose not listed falls back
    # to `model`. Lets you run a cheap/fast model for profiling (and supply-chain)
    # and a stronger one for triage (the highest-stakes call, since it can suppress
    # findings) without changing anything else. Empty = one model for everything.
    models: dict[str, str] = Field(default_factory=dict)


class AIPromptsConfig(BaseModel):
    """Optional per-slot overrides of the built-in AI **system** prompts.

    Each field maps to a slot id in `appsecwatch.ai.prompts.PROMPT_SLOTS`. None or
    a blank/whitespace value means "use the built-in default" — the engine never
    stores a frozen copy, so improving a default in code is picked up unless the
    slot is explicitly overridden. Shape-hints and user-message assembly stay in
    code, so an override can change tone/judgment but never break JSON validation.
    """
    profile_system: str | None = None
    triage_system_default: str | None = None
    triage_system_profiled: str | None = None
    supply_system_default: str | None = None
    supply_system_profiled: str | None = None
    low_confidence_nudge: str | None = None
    summary_system: str | None = None

    def as_overrides(self) -> dict[str, str]:
        """Slot-id → override text, dropping unset/blank slots."""
        return {
            k: v.strip()
            for k, v in self.model_dump().items()
            if isinstance(v, str) and v.strip()
        }


class SuppressionConfig(BaseModel):
    """AI false-positive suppression across ALL deterministic findings (the
    `ai.triage` pass), not just header checks.

    Soft-suppress only: a hidden finding is dropped from the report + severity
    counts but kept in findings.json and a collapsible section, so every call is
    auditable and reversible. An AI degrade suppresses nothing (the no-gating
    invariant). A finding is hidden only when: suppression is `enabled`, the AI
    marked it suppressed at >= `min_confidence`, its severity is <= `max_severity`
    (above the ceiling the verdict is advisory only — the finding stays visible),
    and — only if `require_profile` — the host has a usable, non-low profile.
    """
    enabled: bool = True
    # Minimum AI verdict confidence required to actually hide a finding.
    min_confidence: Literal["low", "medium", "high"] = "medium"
    # Highest severity the AI may auto-hide. Findings above this are never offered
    # to the AI for suppression and always stay visible + counted.
    max_severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    # When True, suppression only applies to hosts with a usable, non-low-confidence
    # profile (the legacy gate). Default False: the profile is a calibration input,
    # not a precondition.
    require_profile: bool = False


class AIProfileConfig(BaseModel):
    """Profiling-pass knobs (the `ai.profiling` flag still gates the pass itself).

    `render` selects the profiler's INPUT source:
      - auto   (default): consume the crawler's rendered text + curated surface
               manifest when supply-chain ran for the host; otherwise fall back to
               httpx pre-JS signals. The browser is never spun up just to profile.
      - always: force a headless-browser render per host even when supply-chain is
               not selected (slower; opens a browser for every profiled host).
      - never:  httpx pre-JS signals only, even when a crawl is available.
    """
    render: Literal["auto", "always", "never"] = "auto"


class AIConfig(BaseModel):
    """AI behavior. `profiling` toggles the context-aware profiling pass.

    When True (default), an AppProfile is inferred per host and fed into the
    triage + supply-chain prompts. When False, those prompts use their default
    context-light form and no 03_ai/profile/ artifact is written.

    `prompts` holds optional system-prompt overrides; `suppression` tunes the
    cross-source false-positive filter run by the `ai.triage` step; `profile`
    holds the profiling-pass input/render knob.
    """
    profiling: bool = True
    prompts: AIPromptsConfig = Field(default_factory=AIPromptsConfig)
    suppression: SuppressionConfig = Field(default_factory=SuppressionConfig)
    profile: AIProfileConfig = Field(default_factory=AIProfileConfig)


class HeadersConfig(BaseModel):
    """Deterministic security-header analysis (the `headers` capability).

    The checker always emits first-class findings; these knobs only tune severity
    and which checks run. AI soft-suppression of false-positives now spans all
    sources and lives under `ai.suppression` (see SuppressionConfig).
    """
    # Per-check severity overrides, keyed by check_id (e.g. {"hsts.missing": "high"}).
    severity_overrides: dict[str, str] = Field(default_factory=dict)
    # check_ids (or dotted prefixes) to skip entirely, e.g. ["permissions-policy"].
    disabled_checks: list[str] = Field(default_factory=list)


class ToolBlock(BaseModel):
    extra_flags: list[str] = Field(default_factory=list)


class DnsxConfig(ToolBlock):
    rate_limit: int = 1000          # DNS queries/sec (-rl). DNS is cheap; high default.


class TlsxConfig(ToolBlock):
    # tlsx parallel connection threads (-c). tlsx has no rate-limit flag; -c is
    # its real pacing knob. Used for the recon cert-grab against target:443.
    concurrency: int = 100


class SslscanConfig(ToolBlock):
    # sslscan is sequential per host; the cross-host pacing knob is
    # `concurrency.tls` (throttle-controlled). No anti-WAF "slow" flag needed.
    timeout: int = 300              # per-host outer timeout (seconds)


class HttpxConfig(ToolBlock):
    rate_limit: int = 100
    # httpx -threads (concurrent connections). THE dominant blocking trigger
    # against hardened/WAF'd targets: 50 (httpx's own default) floods a bank's few
    # IPs and trips temporary source-blocking; ~2-3 enumerates cleanly. Set by the
    # throttle profile unless the operator pins it.
    threads: int = 25
    timeout: int = 10


class NucleiConfig(ToolBlock):
    severities: list[Literal["info", "low", "medium", "high", "critical"]] = Field(
        default_factory=lambda: ["low", "medium", "high", "critical"]
    )
    auto_scan: bool = True
    # Granular template selection → nuclei -tags/-etags/-id/-t/-et. Any of
    # tags/template_ids/templates disables -as (explicit selection takes over).
    tags: list[str] = Field(default_factory=list)
    exclude_tags: list[str] = Field(default_factory=list)
    template_ids: list[str] = Field(default_factory=list)
    templates: list[str] = Field(default_factory=list)            # paths/dirs (-t)
    exclude_templates: list[str] = Field(default_factory=list)    # -et
    rate_limit: int = 100
    timeout: int = 5
    user_agent: str = "AppSecWatch/0.1"


class TakeoversConfig(ToolBlock):
    severities: list[Literal["info", "low", "medium", "high", "critical"]] = Field(
        default_factory=lambda: ["high", "critical"]
    )
    rate_limit: int = 50


class PlaywrightConfig(ToolBlock):
    wait_until: Literal["load", "domcontentloaded", "networkidle", "commit"] = "networkidle"
    timeout_ms: int = 30_000
    user_agent: str | None = None
    # Capture a per-host viewport screenshot during the crawl. Dashboard-only
    # inventory: stored as a run artifact, surfaced in the UI, NEVER sent to the LLM
    # and NEVER inlined into report.html (keeps the report emailable). Disable for
    # large inventories to save disk.
    screenshot: bool = True


# Coherent browser identities for the stealth layer. Each preset bundles a UA
# with a *matching* header set (a browser UA with non-browser headers is itself a
# bot tell). Accept-Language leads with tr-TR — fits Turkish targets. Applied to
# httpx, nuclei, and the Playwright crawler. NB: this defeats UA/header/signature
# WAF rules — NOT TLS/JA3 fingerprinting or IP-reputation (see DESIGN/README).
#
# Client-hint policy: we send ONLY the LOW-entropy hints a real browser emits on a
# cold first navigation (Sec-CH-UA / -Mobile / -Platform). The high-entropy hints
# (-Arch, -Bitness, -Full-Version[-List], -Platform-Version, -Model, -Form-Factors,
# -Wow64) and the network hints (downlink/rtt, prefers-color-scheme) are sent by a
# real browser ONLY after the server requests them via `Accept-CH`. Our tools fire
# one-shot requests with no prior round-trip, so emitting those unsolicited is
# itself a bot tell — hence they're deliberately omitted. Likewise we never inject
# Google-proprietary headers (x-client-data, x-browser-*) — those go only to
# Google-owned origins and would scream "spoofed Chrome" against any other target.
#
# Referrer: browser presets emit a Referer rotated from REFERER_POOL (a real
# navigation almost always has one). All pool entries are external origins, so the
# coherent Sec-Fetch-Site is "cross-site" (a click from a search engine / social
# site — not "none", which means a typed/bookmarked URL with no referrer). Per
# Chrome's default `strict-origin-when-cross-origin` policy a cross-site Referer is
# the *origin only*, which is exactly what these are. An operator can pin a fixed
# Referer via `identity.headers` (it overrides the rotation).
REFERER_POOL: list[str] = [
    "https://www.google.com/",
    "https://www.google.com.tr/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://search.yahoo.com/",
    "https://yandex.com.tr/",
    "https://www.facebook.com/",
    "https://www.linkedin.com/",
    "https://t.co/",
    "https://www.reddit.com/",
]

IDENTITY_PRESETS: dict[str, dict[str, Any]] = {
    "chrome-win": {
        "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"),
        "locale": "tr-TR",
        "headers": {
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                       "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Sec-CH-UA": '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
    },
    "chrome-mac": {
        "user_agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"),
        "locale": "tr-TR",
        "headers": {
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                       "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Sec-CH-UA": '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"macOS"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
    },
    "firefox": {
        "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) "
                       "Gecko/20100101 Firefox/140.0"),
        "locale": "tr-TR",
        "headers": {
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                       "image/webp,*/*;q=0.8"),
            "Accept-Language": "tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3",
            # Firefox does not implement UA Client Hints — no Sec-CH-UA here by design.
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
    },
}


class IdentityConfig(BaseModel):
    """Stealth identity applied across active HTTP tools (httpx/nuclei/crawler).

    `preset` picks a coherent browser UA+headers bundle; `user_agent` and `headers`
    override/extend it (headers merged over the preset's; decoys like
    X-Forwarded-For go here). Defaults to `chrome-win` — every scan presents a
    coherent Chrome-on-Windows identity unless an operator sets `off` (tools then
    use their own defaults). A browser preset also rotates a plausible cross-site
    Referer from REFERER_POOL (pin one via `headers['Referer']` to opt out)."""
    preset: Literal["off", "chrome-win", "chrome-mac", "firefox"] = "chrome-win"
    user_agent: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    locale: str | None = None

    @property
    def active(self) -> bool:
        return self.preset != "off" or bool(self.user_agent) or bool(self.headers)

    def _preset(self) -> dict[str, Any]:
        return IDENTITY_PRESETS.get(self.preset, {}) if self.preset != "off" else {}

    def effective_user_agent(self) -> str | None:
        return self.user_agent or self._preset().get("user_agent")

    def effective_locale(self) -> str | None:
        return self.locale or self._preset().get("locale")

    def effective_headers(self) -> dict[str, str]:
        """Preset headers with the free-form overrides merged on top (UA excluded —
        each tool sets its own UA flag). For a browser preset, a Referer is rotated
        in from REFERER_POOL (coherent with the preset's Sec-Fetch-Site: cross-site)
        unless the operator pinned one via `headers`. Called once per tool run, so
        httpx / nuclei / the crawler each get an independently-rotated referrer."""
        out = dict(self._preset().get("headers", {}))
        if self.preset != "off" and not any(k.lower() == "referer" for k in self.headers):
            out["Referer"] = random.choice(REFERER_POOL)
        out.update(self.headers)
        return out


class ReportConfig(BaseModel):
    """Executive-report branding + output knobs. All optional with safe fallbacks
    so an unconfigured run still produces a clean executive.html.

    - org_name:      leadership-facing org name on the letterhead. Blank → falls
                     back to the scanned root(s).
    - classification: banner label (e.g. "Confidential"). Blank → omitted.
    - logo_path:     a logo file base64-embedded into executive.html so it stays
                     self-contained. Missing/unreadable → silently no logo.
    - executive_pdf: also auto-render executive.pdf via the bundled Chromium
                     (best-effort; degrades silently if the browser is unavailable).
    - language:      report language. "en" (default) or "tr" — when "tr", the AI
                     website-profile summary and the executive-summary narrative are
                     written in Turkish and executive.html chrome is Turkish;
                     vulnerability/finding NAMES and technical report.html stay English.
    """
    org_name: str | None = None
    classification: str = "Confidential"
    logo_path: str | None = None
    executive_pdf: bool = True
    language: Literal["en", "tr"] = "en"


class ZapConfig(BaseModel):
    """OWASP ZAP active-scan capability (the opt-in `zap` capability).

    ZAP is NOT bundled in the AppSecWatch image and is NOT a `run_tool` subprocess —
    it runs as a separate sidecar daemon (`ghcr.io/zaproxy/zaproxy`) that
    `audit/zap_runner.py` drives over the ZAP REST API. The capability is
    active-scan only (it fires live SQLi/XSS/traversal payloads), so it is OFF by
    default and never part of any preset: it runs only when explicitly enabled here
    AND selected per-scan with in-scope `targets`.

    Safety gate: `enabled` AND `base_url` must both be set or the capability is
    unavailable (omitted from /capabilities; scan submit → 409). `api_key` is a
    secret — masked on GET /config and redacted from the config snapshot, exactly
    like `llm.api_key`.

    Deliberately a TOP-LEVEL config section (like `llm`), NOT a `ToolBlock` under
    `tools`: it is a REST service with a base_url + secret, and it does not
    participate in `_apply_throttle` (ZAP self-paces; the Python poll-deadline is
    the only AppSecWatch-side bound).
    """
    # Safety gate — both must be set for the capability to be available.
    enabled: bool = False
    base_url: str = ""            # e.g. http://zap:8090 — admin/deploy decision
    api_key: str = ""            # ZAP API key (secret → masked/redacted like llm.api_key)

    # Per-request, scope-locked targets (each must be under_any_root(cfg.roots)).
    # Empty on the CLI unless set in YAML; the Web API injects ScanRequest.zap_targets
    # here at config-merge time. ZapStage re-validates scope as defense-in-depth.
    targets: list[str] = Field(default_factory=list)

    # Time bounding. The Python status-poll deadline is primary (ZAP has no
    # run_tool timeout); the same values are also pushed to ZAP's spider/ascan
    # max-duration options. On expiry the scan is stopped and partial alerts kept.
    max_minutes_total: int = 60
    max_minutes_per_host: int = 20
    spider_max_minutes: int = 5

    # Engine knobs.
    ajax_spider: bool = False            # the zaproxy image ships a browser; slower/noisier
    scan_policy: str = "Default Policy"  # ZAP scan-policy name
    poll_interval_seconds: float = 5.0   # status-poll cadence
    request_timeout: int = 30            # per-HTTP-call timeout to the daemon
    alert_cap: int = 5000                # max alert instances pulled per target

    # Future-auth seam (unused in v1). When populated later these feed a ZAP
    # Replacer/HttpSender header-injection rule for authenticated scanning.
    auth_headers: dict[str, str] = Field(default_factory=dict)


class ToolsConfig(BaseModel):
    subfinder: ToolBlock = Field(default_factory=ToolBlock)
    dnsx: DnsxConfig = Field(default_factory=DnsxConfig)
    tlsx: TlsxConfig = Field(default_factory=TlsxConfig)
    httpx: HttpxConfig = Field(default_factory=HttpxConfig)
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    takeovers: TakeoversConfig = Field(default_factory=TakeoversConfig)
    sslscan: SslscanConfig = Field(default_factory=SslscanConfig)
    playwright: PlaywrightConfig = Field(default_factory=PlaywrightConfig)


# Throttle profiles. The "normal" row equals every field's own default, so an
# unset `throttle` (=> normal) reproduces prior behavior exactly. Each value is
# applied ONLY to a field the user did not explicitly set (see _apply_throttle),
# so any per-tool field in the YAML always overrides the profile.
_PROFILES: dict[str, dict[str, Any]] = {
    # nmap-like timing ladder. httpx_threads is the dominant block trigger vs WAF'd
    # targets (see stealth/blocking memory) — paranoid=1, insane=200.
    "paranoid": {  # T0 — max stealth: ~serial, tiny rates, long waits
        "httpx_rl": 2, "httpx_threads": 1, "nuclei_rl": 2, "takeovers_rl": 2,
        "dnsx_rl": 50, "tlsx_conc": 5,
        "tls_timeout": 900,
        "conc_default": 1, "conc_tls": 1, "conc_playwright": 1,
    },
    "gentle": {
        "httpx_rl": 10, "httpx_threads": 2, "nuclei_rl": 10, "takeovers_rl": 10,
        "dnsx_rl": 100, "tlsx_conc": 20,
        "tls_timeout": 600,
        "conc_default": 3, "conc_tls": 2, "conc_playwright": 2,
    },
    "normal": {
        "httpx_rl": 100, "httpx_threads": 10, "nuclei_rl": 100, "takeovers_rl": 50,
        "dnsx_rl": 1000, "tlsx_conc": 100,
        "tls_timeout": 300,
        "conc_default": 10, "conc_tls": 5, "conc_playwright": 5,
    },
    "aggressive": {
        "httpx_rl": 500, "httpx_threads": 50, "nuclei_rl": 500, "takeovers_rl": 150,
        "dnsx_rl": 5000, "tlsx_conc": 300,
        "tls_timeout": 180,
        "conc_default": 20, "conc_tls": 10, "conc_playwright": 8,
    },
    "insane": {  # T5 — fastest, loud: will trip WAFs (httpx default 50 already did)
        "httpx_rl": 1000, "httpx_threads": 200, "nuclei_rl": 1000, "takeovers_rl": 300,
        "dnsx_rl": 10000, "tlsx_conc": 500,
        "tls_timeout": 120,
        "conc_default": 40, "conc_tls": 20, "conc_playwright": 15,
    },
}


# Ordered profile names (paranoid → insane) + a summary for the UI/API.
THROTTLE_PROFILE_NAMES: tuple[str, ...] = tuple(_PROFILES)


def throttle_profile_details() -> dict[str, dict[str, Any]]:
    """Per-profile knob values so the UI can SHOW what each tier does."""
    return {name: dict(vals) for name, vals in _PROFILES.items()}


class AppSecWatchConfig(BaseModel):
    # Unknown keys are ignored so older stored configs (e.g. carrying the removed
    # sanctioned_cidrs / sanctioned_asns) still load cleanly.
    model_config = ConfigDict(extra="ignore")

    roots: list[str]
    # Optional ASN/org enrichment source (MaxMind GeoLite2-ASN). Display-only —
    # it does NOT gate scanning; omit it and assets simply show no ASN/org.
    mmdb_path: str | None = None
    # Global politeness tier. Sets conservative rates across all tools at once;
    # any explicit per-tool / concurrency field overrides it.
    throttle: ThrottleProfile = "normal"
    concurrency: ConcurrencyConfig = Field(default_factory=ConcurrencyConfig)
    paths_per_host: list[str] = Field(default_factory=lambda: ["/"])
    llm: LLMConfig
    ai: AIConfig = Field(default_factory=AIConfig)
    headers: HeadersConfig = Field(default_factory=HeadersConfig)
    # Stealth identity (UA + headers) applied to httpx/nuclei/crawler.
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    # Executive-report branding + PDF toggle (display-only; never gates a scan).
    report: ReportConfig = Field(default_factory=ReportConfig)
    # OWASP ZAP active-scan capability (opt-in; sidecar daemon over REST). Disabled
    # by default — see ZapConfig. NOT a `tools.*` block (not in _apply_throttle).
    zap: ZapConfig = Field(default_factory=ZapConfig)

    @model_validator(mode="after")
    def _apply_throttle(self) -> "AppSecWatchConfig":
        prof = _PROFILES[self.throttle]

        def fill(model: BaseModel, field: str, value: Any) -> None:
            # Only set fields the user did not explicitly provide in the YAML.
            if field not in model.model_fields_set:
                setattr(model, field, value)

        fill(self.tools.httpx, "rate_limit", prof["httpx_rl"])
        fill(self.tools.httpx, "threads", prof["httpx_threads"])
        fill(self.tools.nuclei, "rate_limit", prof["nuclei_rl"])
        fill(self.tools.takeovers, "rate_limit", prof["takeovers_rl"])
        fill(self.tools.dnsx, "rate_limit", prof["dnsx_rl"])
        fill(self.tools.tlsx, "concurrency", prof["tlsx_conc"])
        fill(self.tools.sslscan, "timeout", prof["tls_timeout"])
        fill(self.concurrency, "default", prof["conc_default"])
        fill(self.concurrency, "tls", prof["conc_tls"])
        fill(self.concurrency, "playwright", prof["conc_playwright"])
        return self

    @field_validator("roots")
    @classmethod
    def _non_empty_roots(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("roots must contain at least one domain")
        return [d.strip().lower().rstrip(".") for d in v]


def load_config(path: str | Path) -> AppSecWatchConfig:
    raw: dict[str, Any] = yaml.safe_load(Path(path).read_text())
    return AppSecWatchConfig.model_validate(raw)
