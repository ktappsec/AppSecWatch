from __future__ import annotations

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


class AIPromptsConfig(BaseModel):
    """Optional per-slot overrides of the built-in AI **system** prompts.

    Each field maps to a slot id in `watchtower.ai.prompts.PROMPT_SLOTS`. None or
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


class AIConfig(BaseModel):
    """AI behavior. `profiling` toggles the context-aware profiling pass.

    When True (default), an AppProfile is inferred per host and fed into the
    triage + supply-chain prompts. When False, those prompts use their default
    context-light form and no 03_ai/profile/ artifact is written.

    `prompts` holds optional system-prompt overrides; `suppression` tunes the
    cross-source false-positive filter run by the `ai.triage` step.
    """
    profiling: bool = True
    prompts: AIPromptsConfig = Field(default_factory=AIPromptsConfig)
    suppression: SuppressionConfig = Field(default_factory=SuppressionConfig)


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
    user_agent: str = "WatchTower/0.1"


class TakeoversConfig(ToolBlock):
    severities: list[Literal["info", "low", "medium", "high", "critical"]] = Field(
        default_factory=lambda: ["high", "critical"]
    )
    rate_limit: int = 50


class PlaywrightConfig(ToolBlock):
    wait_until: Literal["load", "domcontentloaded", "networkidle", "commit"] = "networkidle"
    timeout_ms: int = 30_000
    user_agent: str | None = None


# Coherent browser identities for the stealth layer. Each preset bundles a UA
# with a *matching* header set (a browser UA with non-browser headers is itself a
# bot tell). Accept-Language leads with tr-TR — fits Turkish targets. Applied to
# httpx, nuclei, and the Playwright crawler. NB: this defeats UA/header/signature
# WAF rules — NOT TLS/JA3 fingerprinting or IP-reputation (see DESIGN/README).
IDENTITY_PRESETS: dict[str, dict[str, Any]] = {
    "chrome-win": {
        "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
        "locale": "tr-TR",
        "headers": {
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                       "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
    },
    "chrome-mac": {
        "user_agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
        "locale": "tr-TR",
        "headers": {
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                       "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"macOS"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
    },
    "firefox": {
        "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
                       "Gecko/20100101 Firefox/125.0"),
        "locale": "tr-TR",
        "headers": {
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                       "image/webp,*/*;q=0.8"),
            "Accept-Language": "tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3",
            "Upgrade-Insecure-Requests": "1",
        },
    },
}


class IdentityConfig(BaseModel):
    """Stealth identity applied across active HTTP tools (httpx/nuclei/crawler).

    `preset` picks a coherent browser UA+headers bundle; `user_agent` and `headers`
    override/extend it (headers merged over the preset's; decoys like
    X-Forwarded-For go here). preset='off' + no overrides → tools use their own
    defaults (unchanged behavior)."""
    preset: Literal["off", "chrome-win", "chrome-mac", "firefox"] = "off"
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
        each tool sets its own UA flag)."""
        out = dict(self._preset().get("headers", {}))
        out.update(self.headers)
        return out


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


class WatchTowerConfig(BaseModel):
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

    @model_validator(mode="after")
    def _apply_throttle(self) -> "WatchTowerConfig":
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


def load_config(path: str | Path) -> WatchTowerConfig:
    raw: dict[str, Any] = yaml.safe_load(Path(path).read_text())
    return WatchTowerConfig.model_validate(raw)
