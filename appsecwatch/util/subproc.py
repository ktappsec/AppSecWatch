from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import time
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
