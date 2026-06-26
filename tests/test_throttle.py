"""Throttle profile resolution + sslyze command building."""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from watchtower.audit.sslyze_runner import build_sslyze_cmd
from watchtower.config import LLMConfig, WatchTowerConfig


def _cfg(**kw) -> WatchTowerConfig:
    base = dict(roots=["x.com"], mmdb_path="/dev/null",
                llm=LLMConfig(base_url="http://h/v1", model="m"))
    base.update(kw)
    return WatchTowerConfig(**base)


def test_normal_is_the_default_and_matches_prior_defaults():
    c = _cfg()
    assert c.throttle == "normal"
    assert c.tools.httpx.rate_limit == 100
    assert c.tools.httpx.threads == 10
    assert c.tools.nuclei.rate_limit == 100
    assert c.tools.takeovers.rate_limit == 50
    assert c.tools.dnsx.rate_limit == 1000
    assert c.tools.tlsx.concurrency == 100
    assert c.tools.sslyze.slow_connection is False
    assert c.tools.sslyze.timeout == 300
    assert c.concurrency.default == 10
    assert c.concurrency.sslyze == 5
    assert c.concurrency.playwright == 5


def test_nmap_like_tiers_paranoid_and_insane():
    p = _cfg(throttle="paranoid")
    assert p.tools.httpx.threads == 1 and p.tools.httpx.rate_limit == 2
    assert p.concurrency.default == 1 and p.tools.sslyze.slow_connection is True
    i = _cfg(throttle="insane")
    assert i.tools.httpx.threads == 200 and i.tools.httpx.rate_limit == 1000
    assert i.concurrency.default == 40
    # threads ladder is monotonic across the 5 tiers
    threads = [_cfg(throttle=t).tools.httpx.threads
               for t in ("paranoid", "gentle", "normal", "aggressive", "insane")]
    assert threads == sorted(threads) and threads == [1, 2, 10, 50, 200]


def test_gentle_lowers_everything_and_slows_sslyze_extra():
    g = _cfg(throttle="gentle")
    assert g.tools.httpx.rate_limit == 10
    assert g.tools.httpx.threads == 2
    assert g.tools.nuclei.rate_limit == 10
    assert g.tools.takeovers.rate_limit == 10
    assert g.tools.tlsx.concurrency == 20
    assert g.tools.sslyze.slow_connection is True
    assert g.tools.sslyze.timeout == 600          # higher: slow_connection takes longer
    assert g.concurrency.default == 3
    assert g.concurrency.sslyze == 2
    assert g.concurrency.playwright == 2


def test_aggressive_raises_limits():
    a = _cfg(throttle="aggressive")
    assert a.tools.httpx.rate_limit == 500
    assert a.tools.sslyze.slow_connection is False
    assert a.concurrency.default == 20
    assert a.concurrency.sslyze == 10


def test_explicit_per_tool_field_overrides_profile():
    o = _cfg(throttle="gentle", tools={"nuclei": {"rate_limit": 200}})
    assert o.tools.nuclei.rate_limit == 200        # explicit wins
    assert o.tools.httpx.rate_limit == 10          # unset → gentle


def test_explicit_concurrency_overrides_profile():
    o = _cfg(throttle="gentle", concurrency={"sslyze": 8})
    assert o.concurrency.sslyze == 8               # explicit wins
    assert o.concurrency.default == 3              # unset → gentle


def test_explicit_sslyze_slow_false_under_gentle():
    o = _cfg(throttle="gentle", tools={"sslyze": {"slow_connection": False}})
    assert o.tools.sslyze.slow_connection is False  # explicit wins
    assert o.tools.sslyze.timeout == 600            # timeout still from gentle


def test_invalid_throttle_rejected():
    with pytest.raises(ValidationError):
        _cfg(throttle="soft")


def test_sslyze_cmd_reflects_slow_connection():
    g = _cfg(throttle="gentle")
    cmd = build_sslyze_cmd("h", 443, Path("/tmp/o.json"), g.tools.sslyze)
    assert "--slow_connection" in cmd
    assert "h:443" in cmd

    n = _cfg()
    cmd2 = build_sslyze_cmd("h", 443, Path("/tmp/o.json"), n.tools.sslyze)
    assert "--slow_connection" not in cmd2


def test_sslyze_cmd_appends_extra_flags_after_target():
    c = _cfg(tools={"sslyze": {"extra_flags": ["--mozilla_config=intermediate"]}})
    cmd = build_sslyze_cmd("h", 443, Path("/tmp/o.json"), c.tools.sslyze)
    assert cmd[-1] == "--mozilla_config=intermediate"
    assert "h:443" in cmd
