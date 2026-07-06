"""ServerConfig — UI-managed runtime config (WEB_API_PLAN.md §4, REVISED).

`server.yaml` is an optional bootstrap seed; the writable store (ConfigManager)
is the primary source of truth, editable at runtime via GET/PUT /config. The only
env-resolved secrets are the API's own auth (`APPSECWATCH_API_KEYS`) + the webhook
signing secret; the LLM api_key is UI-managed and persists in the store
(`APPSECWATCH_LLM_API_KEY` only seeds first boot). There is **no scan-target
allowlist** — the per-request `roots` is the only scope; the server boots even
fully unconfigured and gates scans on a valid base config at submit time.

The base scan config is kept as a **raw dict** (`base_config_raw`) rather than a
validated `AppSecWatchConfig`, because per-request overrides (roots, throttle) must
be merged *before* validation: the throttle profile only fills tool rate-limits a
user did not explicitly set, and re-validating an already-validated dump would
pin every field (see config._apply_throttle).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from appsecwatch.config import AppSecWatchConfig

# Env var names (secrets). Kept here so auth/security import one source of truth.
ENV_API_KEYS = "APPSECWATCH_API_KEYS"
ENV_WEBHOOK_SECRET = "APPSECWATCH_WEBHOOK_SECRET"
ENV_LLM_API_KEY = "APPSECWATCH_LLM_API_KEY"
# Path to the writable runtime config store (overrides the default under output_root).
ENV_CONFIG_STORE = "APPSECWATCH_CONFIG_STORE"

# Returned in place of a stored llm.api_key on GET /config (write-only secret).
CONFIG_KEY_MASK = "********"


class BindConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080


class LimitsConfig(BaseModel):
    max_concurrent_scans: int = 2
    max_queue_depth: int = 10


class WebhookConfig(BaseModel):
    callback_host_allowlist: list[str] = Field(default_factory=list)
    timeout_seconds: int = 10


class NotifierConfig(BaseModel):
    """Outbound notifications (new-domain alerts, etc.). The in-app channel is
    always on (writes the `notifications` table). A webhook is opt-in. Email is a
    documented future channel (the schema/stub exists; no SMTP impl in v1)."""
    webhook_url: str = ""                                       # Slack/Teams/generic incoming webhook
    webhook_format: Literal["generic", "slack", "teams"] = "generic"
    timeout_seconds: int = 10
    # Future: email (SMTP host/port/from/to). Not implemented in v1.
    email_enabled: bool = False


class ServerConfig(BaseModel):
    """Server configuration + resolved secrets and base scan config.

    No scope allowlist: the per-request `roots` is the only scan scope (decided
    with the operator — the UI is the manager and specifies the domain per scan).
    The server boots even fully unconfigured (no config file, empty base config);
    a scan is gated at submit time on a *valid* base config (llm endpoint; mmdb
    is optional), not on boot. With auth OPEN there is NO server-side ceiling — keep
    `APPSECWATCH_API_KEYS` set before exposing the API.
    """

    bind: BindConfig = Field(default_factory=BindConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)
    notifier: NotifierConfig = Field(default_factory=NotifierConfig)
    docs_enabled: bool = True
    output_root: str = "/data/runs"

    # Resolved at load time (not part of the YAML schema):
    base_config_raw: dict[str, Any] = Field(default_factory=dict, exclude=True)
    api_keys: list[str] = Field(default_factory=list, exclude=True)
    webhook_secret: str | None = Field(default=None, exclude=True)

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_keys)


def _resolve_base_config(node: Any, server_yaml_path: Path | None) -> dict[str, Any]:
    """Resolve `base_config` (a path string, or an inline mapping) to a raw dict.

    A relative path is resolved against the server.yaml's directory so a mounted
    config bundle works regardless of CWD.
    """
    if isinstance(node, dict):
        return dict(node)
    if isinstance(node, str):
        p = Path(node)
        if not p.is_absolute() and server_yaml_path is not None:
            p = server_yaml_path.parent / p
        return yaml.safe_load(p.read_text()) or {}
    raise ValueError("`base_config` must be a path string or an inline mapping")


def _overlay_secrets(raw: dict[str, Any]) -> tuple[list[str], str | None, dict[str, Any]]:
    """Pull secrets from the environment (which override any file values)."""
    keys_env = os.environ.get(ENV_API_KEYS, "")
    api_keys = [k.strip() for k in keys_env.split(",") if k.strip()]
    webhook_secret = os.environ.get(ENV_WEBHOOK_SECRET) or None

    llm_key = os.environ.get(ENV_LLM_API_KEY)
    if llm_key:
        raw.setdefault("llm", {})
        raw["llm"]["api_key"] = llm_key
    return api_keys, webhook_secret, raw


# --------------------------------------------------------------------------- #
# Runtime config store (UI-managed; primary source of truth)
# --------------------------------------------------------------------------- #
# server.yaml seeds first boot, but once the store exists it OWNS the base scan
# config (the UI is the manager from here on; the YAML is a bootstrap seed that
# may be dropped later). Secrets editable from the UI (notably llm.api_key)
# persist IN the store — a deliberate departure from the original "secrets only
# from env" stance (see WEB_API_PLAN §4).

class ConfigError(ValueError):
    """Invalid PUT /config payload (→ 422)."""


def default_store_path(config: ServerConfig) -> Path:
    env = os.environ.get(ENV_CONFIG_STORE)
    if env:
        return Path(env)
    return Path(config.output_root) / ".config" / "server-config.json"


def load_config_store(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def save_config_store(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(path, 0o600)  # the store can hold the llm.api_key secret
    except OSError:
        pass


# Config sections whose `api_key` is a write-only secret (masked on GET, preserved
# on a blank/masked PUT, redacted from snapshots). llm + zap.
_SECRET_PATHS = (("llm", "api_key"), ("zap", "api_key"))


def _mask_secrets(base: dict[str, Any]) -> dict[str, Any]:
    """Mask every write-only secret (llm.api_key, zap.api_key) for GET /config."""
    out = dict(base)
    for section, key in _SECRET_PATHS:
        node = dict(out.get(section) or {})
        if node.get(key):
            node[key] = CONFIG_KEY_MASK
            out[section] = node
    return out


# Back-compat alias (was llm-only).
_mask_llm_key = _mask_secrets


class ConfigManager:
    """Owns the live, mutable effective config (the same `ServerConfig` instance
    the JobManager reads), applies the persisted store on boot, and handles
    GET/PUT /config. Edits mutate the instance in place + persist to the store,
    so the next scan picks them up without a restart."""

    def __init__(self, config: ServerConfig, store_path: Path | None = None) -> None:
        self.config = config
        self.store_path = store_path or default_store_path(config)
        store = load_config_store(self.store_path)
        if store:
            self._apply(store)

    def _apply(self, data: dict[str, Any]) -> None:
        if isinstance(data.get("base_config"), dict):
            base = dict(data["base_config"])
            # Env key remains a fallback only when the store didn't persist one.
            llm = dict(base.get("llm") or {})
            if not llm.get("api_key"):
                env_key = os.environ.get(ENV_LLM_API_KEY)
                if env_key:
                    llm["api_key"] = env_key
                    base["llm"] = llm
            self.config.base_config_raw = base

    def effective(self) -> dict[str, Any]:
        """The current config for GET /config, with secret api_keys (llm, zap) masked."""
        return {"base_config": _mask_secrets(self.config.base_config_raw)}

    def update(self, base_config: dict[str, Any]) -> dict[str, Any]:
        """Validate + persist + apply a full replacement of the base scan config.
        Raises pydantic.ValidationError (→ 422 at the route)."""
        new_base = dict(base_config or {})
        # Write-only key: a blank/masked incoming api_key keeps the stored one.
        llm = dict(new_base.get("llm") or {})
        incoming = llm.get("api_key")
        if not incoming or incoming == CONFIG_KEY_MASK:
            existing = (self.config.base_config_raw.get("llm") or {}).get("api_key")
            if existing:
                llm["api_key"] = existing
            else:
                llm.pop("api_key", None)
        new_base["llm"] = llm

        # Same write-only handling for zap.api_key, but zap is optional → only touch
        # it when the incoming config carries a zap section or there's a stored key.
        stored_zap_key = (self.config.base_config_raw.get("zap") or {}).get("api_key")
        if "zap" in new_base or stored_zap_key:
            zap = dict(new_base.get("zap") or {})
            z_incoming = zap.get("api_key")
            if not z_incoming or z_incoming == CONFIG_KEY_MASK:
                if stored_zap_key:
                    zap["api_key"] = stored_zap_key
                else:
                    zap.pop("api_key", None)
            new_base["zap"] = zap

        # Validate the scan config (roots are per-request → placeholder).
        probe = dict(new_base)
        probe.setdefault("roots", ["placeholder.invalid"])
        AppSecWatchConfig.model_validate(probe)  # raises ValidationError on bad input

        self.config.base_config_raw = new_base
        save_config_store(self.store_path, {"base_config": new_base})
        return self.effective()

    def prompt_overrides(self) -> dict[str, Any]:
        """Current `ai.prompts` override subtree (slot-id → text), may be empty."""
        ai = self.config.base_config_raw.get("ai") or {}
        return dict(ai.get("prompts") or {})

    def set_prompt_overrides(self, prompts: dict[str, Any]) -> dict[str, Any]:
        """Replace the `ai.prompts` override subtree + persist.

        Validated against AIPromptsConfig ONLY (not the whole scan config), so
        prompts can be edited before the base config is otherwise complete. Returns
        the normalized override dict.
        """
        from appsecwatch.config import AIPromptsConfig

        validated = AIPromptsConfig.model_validate(prompts or {}).model_dump()
        base = dict(self.config.base_config_raw)
        ai = dict(base.get("ai") or {})
        ai["prompts"] = validated
        base["ai"] = ai
        self.config.base_config_raw = base
        save_config_store(self.store_path, {"base_config": base})
        return validated


def load_server_config(path: str | Path | None) -> ServerConfig:
    """Build a ServerConfig, overlaying env secrets + the (optional) base config.

    `path` is optional: with no `server.yaml` the server boots UI-managed (empty
    base config seeded only from env / the runtime store). When given, the YAML
    seeds first boot; `base_config` itself is optional (defaults to empty).
    """
    data: dict[str, Any] = {}
    p: Path | None = None
    base_node: Any = None
    if path is not None:
        p = Path(path)
        data = yaml.safe_load(p.read_text()) or {}
        base_node = data.pop("base_config", None)

    base_raw = _resolve_base_config(base_node, p) if base_node is not None else {}
    api_keys, webhook_secret, base_raw = _overlay_secrets(base_raw)

    return ServerConfig(
        **data,
        base_config_raw=base_raw,
        api_keys=api_keys,
        webhook_secret=webhook_secret,
    )
