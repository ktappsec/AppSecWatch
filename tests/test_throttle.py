"""Throttle profile resolution + sslscan command building."""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from appsecwatch.audit.sslscan_runner import build_sslscan_cmd
from appsecwatch.config import LLMConfig, AppSecWatchConfig


def _cfg(**kw) -> AppSecWatchConfig:
    base = dict(roots=["x.com"], mmdb_path="/dev/null",
                llm=LLMConfig(base_url="http://h/v1", model="m"))
    base.update(kw)
    return AppSecWatchConfig(**base)


def test_normal_is_the_default_and_matches_prior_defaults():
    c = _cfg()
    assert c.throttle == "normal"
    assert c.tools.httpx.rate_limit == 100
    assert c.tools.httpx.threads == 10
    assert c.tools.nuclei.rate_limit == 100
    assert c.tools.takeovers.rate_limit == 50
    assert c.tools.dnsx.rate_limit == 1000
    assert c.tools.tlsx.concurrency == 100
    assert c.tools.sslscan.timeout == 300
    assert c.concurrency.default == 10
    assert c.concurrency.tls == 5
    assert c.concurrency.playwright == 5


def test_nmap_like_tiers_paranoid_and_insane():
    p = _cfg(throttle="paranoid")
    assert p.tools.httpx.threads == 1 and p.tools.httpx.rate_limit == 2
    assert p.concurrency.default == 1 and p.concurrency.tls == 1
    assert p.tools.sslscan.timeout == 900            # paranoid gives the longest TLS budget
    i = _cfg(throttle="insane")
    assert i.tools.httpx.threads == 200 and i.tools.httpx.rate_limit == 1000
    assert i.concurrency.default == 40
    # threads ladder is monotonic across the 5 tiers
    threads = [_cfg(throttle=t).tools.httpx.threads
               for t in ("paranoid", "gentle", "normal", "aggressive", "insane")]
    assert threads == sorted(threads) and threads == [1, 2, 10, 50, 200]


def test_gentle_lowers_everything():
    g = _cfg(throttle="gentle")
    assert g.tools.httpx.rate_limit == 10
    assert g.tools.httpx.threads == 2
    assert g.tools.nuclei.rate_limit == 10
    assert g.tools.takeovers.rate_limit == 10
    assert g.tools.tlsx.concurrency == 20
    assert g.tools.sslscan.timeout == 600            # higher: low concurrency takes longer
    assert g.concurrency.default == 3
    assert g.concurrency.tls == 2
    assert g.concurrency.playwright == 2


def test_aggressive_raises_limits():
    a = _cfg(throttle="aggressive")
    assert a.tools.httpx.rate_limit == 500
    assert a.tools.sslscan.timeout == 180
    assert a.concurrency.default == 20
    assert a.concurrency.tls == 10


def test_explicit_per_tool_field_overrides_profile():
    o = _cfg(throttle="gentle", tools={"nuclei": {"rate_limit": 200}})
    assert o.tools.nuclei.rate_limit == 200        # explicit wins
    assert o.tools.httpx.rate_limit == 10          # unset → gentle


def test_explicit_concurrency_overrides_profile():
    o = _cfg(throttle="gentle", concurrency={"tls": 8})
    assert o.concurrency.tls == 8                   # explicit wins
    assert o.concurrency.default == 3              # unset → gentle


def test_explicit_sslscan_timeout_overrides_profile():
    o = _cfg(throttle="gentle", tools={"sslscan": {"timeout": 120}})
    assert o.tools.sslscan.timeout == 120          # explicit wins
    assert o.concurrency.tls == 2                  # other gentle knobs still apply


def test_invalid_throttle_rejected():
    with pytest.raises(ValidationError):
        _cfg(throttle="soft")


def test_sslscan_cmd_basics():
    c = _cfg()
    cmd = build_sslscan_cmd("h", 443, Path("/tmp/o.xml"), c.tools.sslscan)
    assert cmd[0] == "sslscan"
    assert "--no-failed" in cmd
    assert "--xml=/tmp/o.xml" in cmd
    assert cmd[-1] == "h:443"            # target must be last


def test_sslscan_cmd_extra_flags_precede_target():
    c = _cfg(tools={"sslscan": {"extra_flags": ["--no-heartbleed"]}})
    cmd = build_sslscan_cmd("h", 443, Path("/tmp/o.xml"), c.tools.sslscan)
    assert cmd[-1] == "h:443"
    assert "--no-heartbleed" in cmd
    assert cmd.index("--no-heartbleed") < cmd.index("h:443")
