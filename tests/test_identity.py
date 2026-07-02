"""Stealth identity: preset resolution + injection into httpx/nuclei commands."""
from __future__ import annotations

import types
from pathlib import Path

import appsecwatch.recon.web_probe as wp
from appsecwatch.audit.nuclei_runner import build_nuclei_cmd
from appsecwatch.config import HttpxConfig, IdentityConfig, NucleiConfig
from appsecwatch.recon.web_probe import run_httpx


class _Log:
    def debug(self, *a, **k): ...
    def info(self, *a, **k): ...
    def warn(self, *a, **k): ...


def _hvals(cmd):
    return [cmd[i + 1] for i, x in enumerate(cmd) if x == "-H"]


# --- IdentityConfig --------------------------------------------------------
def test_preset_resolution():
    i = IdentityConfig(preset="chrome-win")
    assert i.active
    assert "Chrome/149" in i.effective_user_agent()
    h = i.effective_headers()
    assert h["Accept-Language"].startswith("tr-TR")
    assert "Sec-CH-UA" in h and h["Sec-CH-UA-Platform"] == '"Windows"'
    assert i.effective_locale() == "tr-TR"


def test_overrides_merge_over_preset():
    i = IdentityConfig(preset="chrome-win", user_agent="Custom/1.0",
                       headers={"X-Forwarded-For": "1.2.3.4", "Accept-Language": "en-US"})
    assert i.effective_user_agent() == "Custom/1.0"        # UA override wins
    h = i.effective_headers()
    assert h["X-Forwarded-For"] == "1.2.3.4"               # decoy added
    assert h["Accept-Language"] == "en-US"                 # override beats preset
    assert "Sec-CH-UA" in h                                # untouched preset header kept


def test_default_is_chrome_win():
    # Default identity is now an active Chrome-on-Windows preset (was 'off').
    i = IdentityConfig()
    assert i.preset == "chrome-win" and i.active
    assert "Chrome/149" in i.effective_user_agent()


def test_off_is_inactive():
    i = IdentityConfig(preset="off")
    assert i.preset == "off" and not i.active
    assert i.effective_user_agent() is None and i.effective_headers() == {}


def test_browser_preset_rotates_referer():
    from appsecwatch.config import REFERER_POOL

    i = IdentityConfig(preset="chrome-win")
    h = i.effective_headers()
    assert h["Sec-Fetch-Site"] == "cross-site"          # coherent with a referrer
    assert h["Referer"] in REFERER_POOL                 # rotated from the pool
    # 'off' never injects a referrer.
    assert "Referer" not in IdentityConfig(preset="off").effective_headers()


def test_explicit_referer_overrides_pool():
    i = IdentityConfig(preset="chrome-win", headers={"Referer": "https://intranet.local/"})
    assert i.effective_headers()["Referer"] == "https://intranet.local/"


# --- command injection -----------------------------------------------------
def test_nuclei_cmd_identity_headers():
    cmd = build_nuclei_cmd(NucleiConfig(), Path("/tmp/o.jsonl"),
                           user_agent="UA/9", extra_headers={"Accept-Language": "tr-TR"})
    hs = _hvals(cmd)
    assert "User-Agent: UA/9" in hs            # override beats cfg.user_agent
    assert "Accept-Language: tr-TR" in hs


async def test_httpx_cmd_includes_identity(tmp_path, monkeypatch):
    captured = {}

    async def fake_run_tool(cmd, **k):
        captured["cmd"] = cmd
        return types.SimpleNamespace(stdout=b"", stderr=b"", ok=True, returncode=0)

    monkeypatch.setattr(wp, "run_tool", fake_run_tool)
    await run_httpx(["example.com"], tmp_path / "h.jsonl", HttpxConfig(), _Log(),
                    user_agent="UA/7",
                    extra_headers={"Accept-Language": "tr-TR", "X-Forwarded-For": "9.9.9.9"})
    hs = _hvals(captured["cmd"])
    assert "User-Agent: UA/7" in hs
    assert "Accept-Language: tr-TR" in hs and "X-Forwarded-For: 9.9.9.9" in hs
    # concurrency knob is passed (the real anti-block lever)
    cmd = captured["cmd"]
    assert "-threads" in cmd and cmd[cmd.index("-threads") + 1] == "25"
