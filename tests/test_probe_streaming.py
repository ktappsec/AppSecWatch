"""httpx streaming path: partial results survive a kill, and a mid-pass edge block
is distinguishable from an estate that simply has no web servers.

Regression cover for the 2026-07-20 run that reported "0 live servers / degraded"
after probing only a fraction of the estate: results were buffered to EOF, so the
timeout kill discarded every host already probed and left the cause unattributable.
"""
from __future__ import annotations

import json

import appsecwatch.recon.web_probe as wp
from appsecwatch.config import HttpxConfig
from appsecwatch.models import ProbeCoverage
from appsecwatch.recon.web_probe import ProbeProgress, parse_httpx_records
from appsecwatch.util.subproc import StreamOutcome, stream_tool


class _Log:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def _rec(self, msg, **kw):
        self.events.append((kw.get("event", ""), kw))

    debug = info = warn = error = _rec

    def has(self, event: str) -> bool:
        return any(e == event for e, _ in self.events)

    def get(self, event: str) -> dict:
        return next(kw for e, kw in self.events if e == event)


def _rec_line(host: str, *, failed: bool = False, status: int = 200) -> str:
    if failed:
        return json.dumps({"input": host, "url": f"http://{host}", "failed": True,
                           "status_code": 0, "error": "context deadline exceeded"})
    return json.dumps({"input": host, "url": f"https://{host}", "failed": False,
                       "status_code": status, "title": "ok", "tech": []})


def _fake_stream(lines: list[str], *, timed_out: bool = False):
    """Stand-in for stream_tool: yields the given lines, then ends (optionally as a
    timeout kill, which must NOT raise — the caller keeps what it consumed)."""
    async def _gen(cmd, outcome, **k):
        for ln in lines:
            yield ln
        outcome.timed_out = timed_out
        outcome.returncode = None if timed_out else 0
        outcome.lines = len(lines)
    return _gen


# --- partial results survive -------------------------------------------------

async def test_timeout_keeps_hosts_already_probed(tmp_path, monkeypatch):
    lines = [_rec_line(f"h{i}.example.com") for i in range(5)]
    monkeypatch.setattr(wp, "stream_tool", _fake_stream(lines, timed_out=True))
    out = tmp_path / "httpx.jsonl"
    log = _Log()

    live, signals = await wp.run_httpx(
        [f"h{i}.example.com" for i in range(50)], out, HttpxConfig(), log,
    )

    # The kill must not discard the 5 hosts already probed (the actual defect).
    assert len(live) == 5
    assert len(signals) == 5
    assert log.has("probe_partial")
    assert log.get("probe_partial")["probed"] == 5
    # ...and they must be on disk, written incrementally.
    assert len([ln for ln in out.read_text().splitlines() if ln.strip()]) == 5


async def test_failed_probe_records_are_not_live_servers(tmp_path, monkeypatch):
    """`-probe` emits a record per input; `failed:true` ones are telemetry, not
    servers. Admitting them would invent a live server per blackholed host."""
    lines = [_rec_line("up.example.com"),
             _rec_line("down.example.com", failed=True),
             _rec_line("also-down.example.com", failed=True)]
    monkeypatch.setattr(wp, "stream_tool", _fake_stream(lines))
    live, signals = await wp.run_httpx(
        ["up.example.com", "down.example.com", "also-down.example.com"],
        tmp_path / "h.jsonl", HttpxConfig(), _Log(),
    )
    assert [s.host for s in live] == ["up.example.com"]
    assert set(signals) == {"up.example.com"}


def test_parse_rejects_failed_records_directly():
    servers, signals = parse_httpx_records([_rec_line("x.example.com", failed=True)])
    assert servers == [] and signals == {}


# --- block detection ---------------------------------------------------------

def test_stall_trips_only_after_edge_was_answering():
    prog = ProbeProgress(total=100, stall_run=5)
    assert not prog.observe("a.example.com", False)
    tripped = [prog.observe(f"f{i}.example.com", True) for i in range(5)]
    assert tripped == [False, False, False, False, True]   # fires once, on the 5th
    assert prog.stalled and prog.stalled_after == 1
    assert prog.last_responding_host == "a.example.com"
    # Does not re-fire.
    assert not prog.observe("f9.example.com", True)


def test_unreachable_estate_from_the_start_is_not_a_stall():
    """A run of failures with no prior success means the estate never answered —
    that is not a block, and must not be reported as one."""
    prog = ProbeProgress(total=100, stall_run=3)
    assert not any(prog.observe(f"f{i}.example.com", True) for i in range(20))
    assert not prog.stalled


def test_scattered_failures_do_not_trip():
    """~35% failures scattered through the pass is the normal baseline on an estate
    with internal-only names — it must stay quiet."""
    prog = ProbeProgress(total=100, stall_run=15)
    for i in range(100):
        prog.observe(f"h{i}.example.com", failed=(i % 3 == 0))
    assert not prog.stalled
    assert prog.failed == 34 and prog.responded == 66


async def test_stall_is_logged_while_the_stage_runs(tmp_path, monkeypatch):
    lines = [_rec_line("good.example.com")] + [
        _rec_line(f"d{i}.example.com", failed=True) for i in range(20)
    ]
    monkeypatch.setattr(wp, "stream_tool", _fake_stream(lines, timed_out=True))
    log = _Log()
    await wp.run_httpx([f"h{i}" for i in range(200)], tmp_path / "h.jsonl",
                       HttpxConfig(), log, progress=ProbeProgress(200))
    assert log.has("probe_stalled")
    ev = log.get("probe_stalled")
    assert ev["last_responding_host"] == "good.example.com"
    # Fires mid-stream, on the 16th record (1 good + the 15th consecutive failure) —
    # not after the stream drains. 184 hosts were still unprobed at that moment.
    assert ev["probed"] == 16 and ev["unprobed"] == 184
    assert ev["stalled_after"] == 1


# --- the streaming primitive itself -----------------------------------------

async def test_stream_tool_yields_incrementally_and_survives_timeout():
    outcome = StreamOutcome()
    got = []
    # Emit two lines, then sleep past the deadline — the kill must end the iteration
    # cleanly, keeping both lines, rather than raising them away.
    script = 'import time,sys\nprint("a", flush=True)\nprint("b", flush=True)\ntime.sleep(30)\n'
    async for line in stream_tool(["python3", "-c", script], outcome, timeout=1.5):
        got.append(line)
    assert got == ["a", "b"]
    assert outcome.timed_out is True
    assert outcome.lines == 2


async def test_stream_tool_normal_exit():
    outcome = StreamOutcome()
    got = [ln async for ln in stream_tool(
        ["python3", "-c", 'print("x")\nprint("y")'], outcome, timeout=30)]
    assert got == ["x", "y"]
    assert outcome.ok and not outcome.timed_out


async def test_stream_tool_handles_records_larger_than_the_readline_limit():
    """httpx `-include-response` embeds the whole response body, so a single JSON
    record routinely exceeds asyncio's 64 KiB readline ceiling. Caught only by
    running the real binary against a real page — readline() raised
    `ValueError: Separator is not found, and chunk exceed the limit` and killed
    the stage mid-pass."""
    outcome = StreamOutcome()
    big = 300_000
    script = f'print("x" * {big})\nprint("after")'
    got = [ln async for ln in stream_tool(
        ["python3", "-c", script], outcome, timeout=30)]
    assert len(got) == 2
    assert len(got[0]) == big          # the oversized record survives intact
    assert got[1] == "after"           # ...and the stream continues past it
    assert outcome.ok


async def test_stream_tool_feeds_stdin():
    outcome = StreamOutcome()
    script = "import sys\nfor ln in sys.stdin: print(ln.strip().upper())"
    got = [ln async for ln in stream_tool(
        ["python3", "-c", script], outcome, stdin=b"a\nb\n", timeout=30)]
    assert got == ["A", "B"]


# --- degraded attribution ----------------------------------------------------

def test_probe_coverage_flags():
    cov = ProbeCoverage(total=440, probed=62, responded=30, failed=32, stalled_after=31)
    assert cov.stalled and not cov.complete
    assert ProbeCoverage(total=10, probed=10).complete
