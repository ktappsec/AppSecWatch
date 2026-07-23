from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from appsecwatch.logging import RunLogger


@dataclass
class ProcResult:
    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _kill_process_group(proc: "asyncio.subprocess.Process") -> None:
    """Best-effort SIGKILL of the child's whole process group.

    Tools like nuclei/playwright fork their own children; killing only the
    direct child leaves those orphans running (and still hammering the target).
    Because every tool is launched with ``start_new_session=True`` the child is a
    process-group leader, so ``killpg`` reaps the entire tree. Falls back to
    killing just the child if the group lookup fails."""
    pid = proc.pid
    if pid is None:
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    except (OSError, AttributeError):
        # No killpg/getpgid (non-POSIX) or already gone — fall back to the child.
        with contextlib.suppress(ProcessLookupError):
            proc.kill()


class ToolError(RuntimeError):
    def __init__(self, cmd: list[str], result: ProcResult) -> None:
        self.cmd = cmd
        self.result = result
        super().__init__(
            f"{cmd[0]} exited {result.returncode}: {result.stderr.decode('utf-8', 'replace')[-400:]}"
        )


async def run_tool(
    cmd: list[str],
    *,
    stdin: bytes | None = None,
    timeout: float | None = None,
    check: bool = False,
    env: dict[str, str] | None = None,
    log: "RunLogger | None" = None,
    label: str | None = None,
) -> ProcResult:
    """Run a subprocess via asyncio. Captures stdout/stderr. Hard timeout kills process tree.

    When `log` is supplied, emits structured timing/outcome events keyed by `label`
    (or the binary name): `tool_done`, `tool_nonzero`, and crucially `tool_timeout`
    — the last is the primary signal for "where did we hit a rate limit / WAF block",
    since edge throttling typically manifests as stalled handshakes/timeouts.

    Every child is started with ``start_new_session=True`` so it leads its own
    process group; on timeout *or* on ``asyncio.CancelledError`` (a Web-API scan
    cancel) the whole group is SIGKILLed so tool-spawned children die too.
    """
    tool = label or (cmd[0] if cmd else "tool")
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(input=stdin), timeout=timeout)
    except asyncio.TimeoutError:
        _kill_process_group(proc)
        await proc.wait()
        elapsed = round(time.monotonic() - start, 1)
        if log is not None:
            log.warn(
                f"{tool}: TIMEOUT after {elapsed}s (limit {timeout}s) — process killed; "
                f"may indicate rate-limiting or a WAF/firewall block",
                tool=tool, event="tool_timeout", elapsed_s=elapsed, timeout_s=timeout,
            )
        raise
    except asyncio.CancelledError:
        # Scan cancelled (Web API POST /cancel) — stop the tool tree, don't wait
        # forever, and propagate the cancellation up to the runner/JobManager.
        _kill_process_group(proc)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=5)
        if log is not None:
            log.warn(
                f"{tool}: cancelled — process group killed",
                tool=tool, event="tool_cancelled",
            )
        raise

    elapsed = round(time.monotonic() - start, 1)
    result = ProcResult(returncode=proc.returncode or 0, stdout=stdout, stderr=stderr)
    if log is not None:
        if result.ok:
            log.debug(
                f"{tool}: done in {elapsed}s", tool=tool, event="tool_done",
                elapsed_s=elapsed, returncode=result.returncode,
                stdout_bytes=len(stdout), stderr_bytes=len(stderr),
            )
        else:
            log.warn(
                f"{tool}: exited {result.returncode} in {elapsed}s",
                tool=tool, event="tool_nonzero", elapsed_s=elapsed,
                returncode=result.returncode,
                stderr_tail=stderr.decode("utf-8", "replace")[-300:],
            )
    if check and not result.ok:
        raise ToolError(cmd, result)
    return result


class StreamOutcome:
    """Terminal state of a streamed run. Mutated by `stream_tool` as it goes so the
    caller still sees how far it got when the stream ends early."""

    __slots__ = ("returncode", "timed_out", "elapsed_s", "lines")

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.timed_out: bool = False
        self.elapsed_s: float = 0.0
        self.lines: int = 0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


async def stream_tool(
    cmd: list[str],
    outcome: StreamOutcome,
    *,
    stdin: bytes | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
    log: "RunLogger | None" = None,
    label: str | None = None,
) -> AsyncIterator[str]:
    """Like `run_tool`, but yields decoded stdout lines AS THEY ARRIVE.

    `run_tool` reads via `communicate()`, which buffers to EOF — so a timeout kill
    discards every line the tool already produced, and nothing downstream can react
    mid-pass. That is exactly how a mid-scan edge block turned into an ambiguous
    "0 live servers". This variant exists so a long probe pass stays observable and
    its partial results survive the kill.

    On timeout the iterator simply STOPS (no raise) after flagging
    `outcome.timed_out` — the caller keeps whatever it consumed. `CancelledError`
    still propagates, since a Web-API cancel must unwind the stage.

    Preserves the `run_tool` contracts: `start_new_session=True` + process-group
    SIGKILL on timeout/cancel, and the same `tool_*` logging events.
    """
    tool = label or (cmd[0] if cmd else "tool")
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        start_new_session=True,
    )

    async def _feed() -> None:
        if stdin is None or proc.stdin is None:
            return
        try:
            proc.stdin.write(stdin)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with contextlib.suppress(Exception):
                proc.stdin.close()

    feeder = asyncio.ensure_future(_feed())
    deadline = (start + timeout) if timeout is not None else None
    try:
        assert proc.stdout is not None
        # Chunk-and-split rather than `readline()`: StreamReader.readline caps a line
        # at 64 KiB and raises, and one httpx `-include-response` record embeds an
        # entire response body (hundreds of KiB is routine). Splitting ourselves has
        # no line-length ceiling.
        buf = bytearray()
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                outcome.timed_out = True
                break
            try:
                chunk = await asyncio.wait_for(proc.stdout.read(65536), timeout=remaining)
            except asyncio.TimeoutError:
                outcome.timed_out = True
                break
            if not chunk:  # EOF
                break
            buf.extend(chunk)
            while (idx := buf.find(b"\n")) >= 0:
                raw = bytes(buf[:idx])
                del buf[: idx + 1]
                outcome.lines += 1
                yield raw.decode("utf-8", "replace")
        # A trailing record with no newline (tool exited cleanly without one).
        if buf and not outcome.timed_out:
            outcome.lines += 1
            yield bytes(buf).decode("utf-8", "replace")
    except asyncio.CancelledError:
        _kill_process_group(proc)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=5)
        if log is not None:
            log.warn(
                f"{tool}: cancelled — process group killed",
                tool=tool, event="tool_cancelled",
            )
        raise
    finally:
        feeder.cancel()
        with contextlib.suppress(Exception):
            await feeder
        if outcome.timed_out or proc.returncode is None:
            _kill_process_group(proc)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=5)
        outcome.returncode = proc.returncode
        outcome.elapsed_s = round(time.monotonic() - start, 1)
        if log is not None:
            if outcome.timed_out:
                log.warn(
                    f"{tool}: TIMEOUT after {outcome.elapsed_s}s (limit {timeout}s) — "
                    f"process killed; {outcome.lines} line(s) already streamed were KEPT",
                    tool=tool, event="tool_timeout", elapsed_s=outcome.elapsed_s,
                    timeout_s=timeout, lines=outcome.lines, partial=True,
                )
            else:
                log.debug(
                    f"{tool}: done in {outcome.elapsed_s}s ({outcome.lines} lines)",
                    tool=tool, event="tool_done", elapsed_s=outcome.elapsed_s,
                    returncode=outcome.returncode, lines=outcome.lines,
                )


async def tool_version(binary: str) -> str:
    """Best-effort version string capture. Used by versions.json provenance."""
    for flag in ("-version", "--version", "version"):
        try:
            res = await run_tool([binary, flag], timeout=10)
            out = (res.stdout + res.stderr).decode("utf-8", "replace").strip()
            if out:
                return out.splitlines()[0][:200]
        except (FileNotFoundError, asyncio.TimeoutError):
            return "unavailable"
        except Exception:
            continue
    return "unknown"
