"""run_tool structured logging — the signals used to locate rate-limit/WAF hits."""
from __future__ import annotations

import asyncio

import pytest

from appsecwatch.util.subproc import run_tool


class _CapLog:
    def __init__(self):
        self.records: list[tuple[str, str, dict]] = []

    def _rec(self, level):
        def f(msg, **fields):
            self.records.append((level, msg, fields))
        return f

    def __getattr__(self, name):
        if name in ("info", "warn", "error", "debug"):
            return self._rec(name)
        raise AttributeError(name)

    def events(self) -> set[str]:
        return {f.get("event") for _, _, f in self.records}


async def test_timeout_emits_tool_timeout_event():
    cap = _CapLog()
    with pytest.raises(asyncio.TimeoutError):
        await run_tool(["sleep", "5"], timeout=0.2, log=cap, label="sleeptest")
    timeouts = [r for r in cap.records if r[2].get("event") == "tool_timeout"]
    assert timeouts, "expected a tool_timeout warning"
    level, msg, fields = timeouts[0]
    assert level == "warn"
    assert fields["tool"] == "sleeptest"
    assert "rate-limiting" in msg or "WAF" in msg
    assert fields["timeout_s"] == 0.2


async def test_success_emits_tool_done():
    cap = _CapLog()
    res = await run_tool(["true"], log=cap, label="t")
    assert res.ok
    done = [r for r in cap.records if r[2].get("event") == "tool_done"]
    assert done and done[0][0] == "debug"
    assert "elapsed_s" in done[0][2]


async def test_nonzero_emits_tool_nonzero():
    cap = _CapLog()
    res = await run_tool(["false"], log=cap, label="t")
    assert not res.ok
    nz = [r for r in cap.records if r[2].get("event") == "tool_nonzero"]
    assert nz and nz[0][0] == "warn"
    assert nz[0][2]["returncode"] != 0


async def test_no_log_is_silent_and_still_works():
    res = await run_tool(["true"])     # log=None → no events, no crash
    assert res.ok
