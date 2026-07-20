"""Throttle profile resolution + sslscan command building."""
from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest
from pydantic import ValidationError

from appsecwatch.audit.sslscan_runner import build_sslscan_cmd
from appsecwatch.config import (
    _EDGE_FACING_KNOBS,
    _PROFILES,
    _assert_profiles_coherent,
    LLMConfig,
    AppSecWatchConfig,
)


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
    assert c.tools.tlsx.concurrency == 10
    assert c.tools.sslscan.timeout == 300
    assert c.tools.sslscan.sleep_ms == 0             # fast tiers don't pace handshakes
    assert c.concurrency.default == 10
    assert c.concurrency.tls == 5
    assert c.concurrency.playwright == 5


def test_nmap_like_tiers_paranoid_and_insane():
    p = _cfg(throttle="paranoid")
    assert p.tools.httpx.threads == 1 and p.tools.httpx.rate_limit == 2
    assert p.concurrency.default == 1 and p.concurrency.tls == 1
    assert p.tools.sslscan.timeout == 900            # paranoid gives the longest TLS budget
    assert p.tools.sslscan.sleep_ms == 400           # …and paces handshakes the most
    i = _cfg(throttle="insane")
    assert i.tools.sslscan.sleep_ms == 0             # insane never paces
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
    assert g.tools.tlsx.concurrency == 2         # == httpx threads: one edge budget
    assert g.tools.sslscan.timeout == 600            # higher: low concurrency takes longer
    assert g.tools.sslscan.sleep_ms == 150           # paces between handshakes
    assert g.concurrency.default == 3
    assert g.concurrency.tls == 2
    assert g.concurrency.playwright == 2


def test_aggressive_raises_limits():
    a = _cfg(throttle="aggressive")
    assert a.tools.httpx.rate_limit == 500
    assert a.tools.sslscan.timeout == 180
    assert a.concurrency.default == 20
    assert a.concurrency.tls == 10


def test_no_tool_exceeds_its_tier_edge_concurrency():
    """Every target-facing tool shares ONE connection budget per tier.

    Regression guard: `gentle` used to pace httpx to 2 threads and then let tlsx
    open 20 simultaneous handshakes, which blackholed the source IP ~30s in —
    before httpx ran at all. A tier is only as quiet as its loudest tool.
    """
    for name, prof in _PROFILES.items():
        edge = prof["edge_conc"]
        for knob in _EDGE_FACING_KNOBS:
            assert prof[knob] <= edge, f"{name}: {knob}={prof[knob]} > edge_conc={edge}"


def test_tlsx_concurrency_tracks_httpx_threads_on_every_tier():
    # tlsx has no -rl flag, so -c is its only pacing knob: it must spend exactly
    # the tier's edge budget — no more (blocks) and no less (needless slowdown).
    for t in ("paranoid", "gentle", "normal", "aggressive", "insane"):
        c = _cfg(throttle=t)
        assert c.tools.tlsx.concurrency == c.tools.httpx.threads, f"tier {t} incoherent"


def test_tlsx_concurrency_ladder_is_monotonic():
    conc = [_cfg(throttle=t).tools.tlsx.concurrency
            for t in ("paranoid", "gentle", "normal", "aggressive", "insane")]
    assert conc == sorted(conc) and conc == [1, 2, 10, 50, 200]


def test_incoherent_profile_is_rejected_at_definition():
    # The coherence check is the enforcement, not the comment above the table.
    bad = {"x": dict(_PROFILES["gentle"], tlsx_conc=20)}
    with mock.patch.dict("appsecwatch.config._PROFILES", bad, clear=True):
        with pytest.raises(ValueError, match="tlsx_conc"):
            _assert_profiles_coherent()


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


def test_sslscan_cmd_drops_unused_probes_keeps_scorecard_inputs():
    c = _cfg()
    cmd = build_sslscan_cmd("h", 443, Path("/tmp/o.xml"), c.tools.sslscan)
    # Probes we never parse are disabled → fewer handshakes, quieter signature.
    for flag in ("--no-heartbleed", "--no-compression", "--no-fallback", "--no-groups"):
        assert flag in cmd
    # Scorecard inputs must stay ON: renegotiation + ciphersuites are NOT disabled.
    assert "--no-renegotiation" not in cmd
    assert "--no-ciphersuites" not in cmd


def test_sslscan_sleep_flag_only_when_paced():
    # normal (sleep_ms=0) → no --sleep; gentle (150) → --sleep=150, before target.
    fast = build_sslscan_cmd("h", 443, Path("/tmp/o.xml"), _cfg().tools.sslscan)
    assert not any(a.startswith("--sleep") for a in fast)
    paced = build_sslscan_cmd("h", 443, Path("/tmp/o.xml"), _cfg(throttle="gentle").tools.sslscan)
    assert "--sleep=150" in paced
    assert paced.index("--sleep=150") < paced.index("h:443")


def test_sslscan_cmd_extra_flags_precede_target():
    c = _cfg(tools={"sslscan": {"extra_flags": ["--no-check-certificate"]}})
    cmd = build_sslscan_cmd("h", 443, Path("/tmp/o.xml"), c.tools.sslscan)
    assert cmd[-1] == "h:443"
    assert "--no-check-certificate" in cmd
    assert cmd.index("--no-check-certificate") < cmd.index("h:443")
