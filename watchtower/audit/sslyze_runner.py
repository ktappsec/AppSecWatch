"""Node B — TLS deep scan via sslyze, projected to a pass/fail checklist.

The pass/fail checklist (DESIGN.md §2.5) is the report's canonical TLS view.
Raw sslyze JSON is preserved per host for forensics.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import time

from watchtower.config import SslyzeConfig
from watchtower.logging import RunLogger
from watchtower.models import Finding, LiveWebServer, TLSCheck, TLSHostReport
from watchtower.util.domains import host_to_filename
from watchtower.util.subproc import run_tool


def build_sslyze_cmd(host: str, port: int, out_path: Path, cfg: SslyzeConfig) -> list[str]:
    """Construct the sslyze CLI invocation. Extracted for testability."""
    cmd: list[str] = ["python", "-m", "sslyze", "--json_out", str(out_path)]
    if cfg.slow_connection:
        cmd.append("--slow_connection")     # 1 connection at a time — avoids tripping WAFs
    cmd.append(f"{host}:{port}")
    cmd.extend(cfg.extra_flags)
    return cmd

# Cipher suite substrings that should never be negotiable.
_WEAK_CIPHER_SUBSTRINGS = ("RC4", "3DES", "DES_", "EXPORT", "NULL", "MD5", "anon")


def _check_protocols(scan: dict[str, Any]) -> list[TLSCheck]:
    """Verify TLS 1.0 / 1.1 are disabled."""
    checks: list[TLSCheck] = []
    proto_results = scan.get("scan_result", {})

    for cmd_name, proto_label in (("ssl_2_0_cipher_suites", "SSL 2.0"),
                                  ("ssl_3_0_cipher_suites", "SSL 3.0"),
                                  ("tls_1_0_cipher_suites", "TLS 1.0"),
                                  ("tls_1_1_cipher_suites", "TLS 1.1")):
        cmd = proto_results.get(cmd_name) or {}
        result = cmd.get("result") or {}
        suites = result.get("accepted_cipher_suites") or []
        passed = len(suites) == 0
        checks.append(
            TLSCheck(
                name=f"{proto_label} disabled",
                passed=passed,
                detail=("" if passed else f"{len(suites)} cipher(s) negotiated"),
                severity="high",
            )
        )
    return checks


def _check_weak_ciphers(scan: dict[str, Any]) -> TLSCheck:
    """No RC4 / 3DES / EXPORT / NULL / MD5 / anon ciphers."""
    proto_results = scan.get("scan_result", {})
    offenders: list[str] = []
    for cmd_name in ("tls_1_2_cipher_suites", "tls_1_3_cipher_suites"):
        cmd = proto_results.get(cmd_name) or {}
        result = cmd.get("result") or {}
        for suite in (result.get("accepted_cipher_suites") or []):
            name = (suite.get("cipher_suite") or {}).get("name", "")
            if any(bad in name for bad in _WEAK_CIPHER_SUBSTRINGS):
                offenders.append(name)
    return TLSCheck(
        name="No weak ciphers (RC4/3DES/EXPORT/NULL/anon)",
        passed=not offenders,
        detail=("" if not offenders else "weak: " + ", ".join(sorted(set(offenders)))),
        severity="high",
    )


def _check_certificate(scan: dict[str, Any]) -> list[TLSCheck]:
    proto_results = scan.get("scan_result", {})
    cert_cmd = (proto_results.get("certificate_info") or {}).get("result") or {}
    deployments = cert_cmd.get("certificate_deployments") or []
    if not deployments:
        return [TLSCheck(name="Certificate scan", passed=False, detail="no deployments returned")]

    dep = deployments[0]
    leaf_cert = ((dep.get("received_certificate_chain") or [{}])[0]) or {}
    not_after_raw = leaf_cert.get("not_valid_after")
    chain_trusted = bool(dep.get("verified_chain_has_legacy_symantec_anchor") is False
                         and dep.get("verified_certificate_chain"))

    checks: list[TLSCheck] = []
    expiry_pass = False
    expiry_detail = ""
    if not_after_raw:
        try:
            not_after = datetime.fromisoformat(not_after_raw.replace("Z", "+00:00"))
            days_remaining = (not_after - datetime.now(timezone.utc)).days
            expiry_pass = days_remaining > 30
            expiry_detail = f"{days_remaining} days remaining"
        except Exception as e:
            expiry_detail = f"parse error: {e}"
    checks.append(TLSCheck(name="Cert valid and >30 days remaining", passed=expiry_pass,
                           detail=expiry_detail, severity="high"))
    checks.append(TLSCheck(name="Full chain trusted", passed=chain_trusted, severity="high"))
    return checks


def _check_hsts(scan: dict[str, Any]) -> TLSCheck:
    cmd = ((scan.get("scan_result", {}).get("http_headers") or {}).get("result") or {})
    hsts = cmd.get("strict_transport_security_header")
    return TLSCheck(name="HSTS header present", passed=hsts is not None)


def _check_ocsp(scan: dict[str, Any]) -> TLSCheck:
    proto_results = scan.get("scan_result", {})
    cert_cmd = (proto_results.get("certificate_info") or {}).get("result") or {}
    deployments = cert_cmd.get("certificate_deployments") or []
    if not deployments:
        return TLSCheck(name="OCSP stapling", passed=False, detail="no cert data")
    dep = deployments[0]
    ocsp_response = dep.get("ocsp_response")
    return TLSCheck(name="OCSP stapling", passed=ocsp_response is not None)


def _evaluate_checklist(scan: dict[str, Any]) -> list[TLSCheck]:
    checks: list[TLSCheck] = []
    checks.extend(_check_protocols(scan))
    checks.append(_check_weak_ciphers(scan))
    checks.extend(_check_certificate(scan))
    checks.append(_check_hsts(scan))
    checks.append(_check_ocsp(scan))
    return checks


def _checks_to_findings(host: str, checks: list[TLSCheck]) -> list[Finding]:
    return [
        Finding(
            source="sslyze",
            host=host,
            severity=c.severity,
            title=f"TLS: {c.name}",
            description=c.detail or "Check failed",
            evidence={"check": c.name, "detail": c.detail},
        )
        for c in checks
        if not c.passed
    ]


async def _sslyze_one(
    server: LiveWebServer,
    out_dir: Path,
    cfg: SslyzeConfig,
    log: RunLogger,
    semaphore: asyncio.Semaphore,
) -> tuple[TLSHostReport, list[Finding]]:
    parsed = urlparse(server.url)
    if parsed.scheme != "https":
        report = TLSHostReport(host=server.host, error="not HTTPS")
        return report, []

    host = parsed.hostname or server.host
    port = parsed.port or 443
    out_path = out_dir / f"{host_to_filename(host)}.json"
    cmd = build_sslyze_cmd(host, port, out_path, cfg)

    async with semaphore:
        log.debug("running sslyze", cmd=cmd, host=host,
                  slow_connection=cfg.slow_connection, timeout=cfg.timeout)
        start = time.monotonic()
        try:
            res = await run_tool(cmd, timeout=float(cfg.timeout), log=log, label=f"sslyze {host}")
        except asyncio.TimeoutError:
            elapsed = round(time.monotonic() - start, 1)
            # run_tool already emitted a structured tool_timeout warning.
            return TLSHostReport(
                host=host,
                error=(f"timeout after {elapsed}s (limit {cfg.timeout}s) — likely "
                       f"rate-limiting or a WAF/firewall block"),
            ), []
    elapsed = round(time.monotonic() - start, 1)

    if not out_path.exists():
        msg = res.stderr.decode("utf-8", "replace")[-400:] or "no JSON output"
        log.warn(f"sslyze produced no output for {host} after {elapsed}s",
                 host=host, event="sslyze_no_output", elapsed_s=elapsed, stderr=msg)
        return TLSHostReport(host=host, error=msg), []

    try:
        scan = json.loads(out_path.read_text())
    except json.JSONDecodeError as e:
        return TLSHostReport(host=host, error=f"parse error: {e}"), []

    # sslyze JSON top-level shape: {"server_scan_results": [...], ...}
    server_results = scan.get("server_scan_results") or []
    if not server_results:
        return TLSHostReport(host=host, error="empty server_scan_results"), []

    checks = _evaluate_checklist(server_results[0])
    report = TLSHostReport(host=host, checks=checks)
    findings = _checks_to_findings(host, checks)
    log.info(f"sslyze {host}: {report.pass_count}/{report.total} checks passed "
             f"({len(findings)} failing) in {elapsed}s",
             host=host, event="sslyze_host_done", elapsed_s=elapsed,
             passed=report.pass_count, total=report.total)
    return report, findings


async def run_sslyze(
    live_servers: list[LiveWebServer],
    out_dir: Path,
    cfg: SslyzeConfig,
    log: RunLogger,
    concurrency: int = 5,
) -> tuple[list[TLSHostReport], list[Finding]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    if not live_servers:
        log.info("sslyze: no live servers")
        return [], []

    https_only = [s for s in live_servers if s.url.startswith("https://")]
    if not https_only:
        log.info("sslyze: no HTTPS servers among live set")
        return [], []

    log.info(f"sslyze: scanning {len(https_only)} host(s), concurrency={concurrency}, "
             f"slow_connection={cfg.slow_connection}, per-host timeout={cfg.timeout}s")
    sem = asyncio.Semaphore(concurrency)
    coros = [_sslyze_one(s, out_dir, cfg, log, sem) for s in https_only]
    results = await asyncio.gather(*coros, return_exceptions=True)

    reports: list[TLSHostReport] = []
    findings: list[Finding] = []
    errored = 0
    for s, r in zip(https_only, results):
        if isinstance(r, BaseException):
            reports.append(TLSHostReport(host=s.host, error=f"{type(r).__name__}: {r}"))
            errored += 1
            continue
        rep, finds = r  # type: ignore[misc]
        reports.append(rep)
        findings.extend(finds)
        if rep.error:
            errored += 1

    ok = len(reports) - errored
    log.info(
        f"sslyze: {len(reports)} host(s) — {ok} scanned, {errored} errored/timed out; "
        f"{len(findings)} failing checks",
        event="sslyze_summary", hosts=len(reports), ok=ok, errored=errored,
        failing_checks=len(findings),
    )
    return reports, findings
