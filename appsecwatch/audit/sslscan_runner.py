"""Node B — TLS deep scan via **sslscan**, projected to a pass/fail checklist.

Replaces the former sslyze runner. sslscan does protocol + cipher enumeration and
a cert dump over connections that a hardened WAF tolerates, where sslyze's full
default suite (ROBOT/CCS/heartbleed oracle probes at 5-host parallelism) gets the
source IP blocked. We never parsed those vuln probes anyway — the report's
canonical TLS view (DESIGN.md §2.5) is the protocol/cipher/cert scorecard, all of
which sslscan provides (plus key-strength + signature-algorithm for free).

Raw sslscan XML is preserved per host for forensics.
"""
from __future__ import annotations

import asyncio
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from appsecwatch.config import SslscanConfig
from appsecwatch.logging import RunLogger
from appsecwatch.models import Finding, LiveWebServer, TLSCheck, TLSHostReport
from appsecwatch.util.domains import host_to_filename
from appsecwatch.util.subproc import run_tool


def build_sslscan_cmd(host: str, port: int, xml_path: Path, cfg: SslscanConfig) -> list[str]:
    """Construct the sslscan CLI invocation. Extracted for testability.

    `--no-failed` trims the XML to negotiated ciphers only. We also drop the probe
    categories the scorecard never reads — **heartbleed** (an ACTIVE
    malformed-heartbeat exploit probe, the loudest "attack scanner" tell),
    **compression** (CRIME), **fallback** SCSV, and key-exchange **group**
    enumeration — for fewer handshakes and a quieter signature. Protocol / cipher /
    cert / renegotiation (the scorecard inputs) stay ON. `cfg.sleep_ms` (>0, set by
    the throttle profile → `--sleep`) paces between handshakes so a full cipher
    enumeration doesn't burst a hardened target's edge. Options must precede the
    `host:port` target, so `extra_flags` and the target go last.
    """
    cmd: list[str] = ["sslscan", "--no-failed", f"--xml={xml_path}"]
    cmd += ["--no-heartbleed", "--no-compression", "--no-fallback", "--no-groups"]
    if cfg.sleep_ms > 0:
        cmd.append(f"--sleep={cfg.sleep_ms}")
    cmd.extend(cfg.extra_flags)
    cmd.append(f"{host}:{port}")
    return cmd


# Cipher suite substrings that should never be negotiable.
_WEAK_CIPHER_SUBSTRINGS = ("RC4", "3DES", "DES-", "DES_", "EXPORT", "NULL", "MD5", "anon")
# sslscan's own per-cipher strength verdicts we treat as weak.
_WEAK_STRENGTHS = {"null", "anonymous", "weak"}


def _first_ssltest(root: ET.Element) -> ET.Element | None:
    return root.find(".//ssltest")


def _check_protocols(ssltest: ET.Element) -> list[TLSCheck]:
    """SSL 2.0 / SSL 3.0 / TLS 1.0 / TLS 1.1 must be disabled."""
    enabled: dict[tuple[str, str], bool] = {}
    for p in ssltest.findall("protocol"):
        key = (p.get("type", ""), p.get("version", ""))
        enabled[key] = p.get("enabled") == "1"

    checks: list[TLSCheck] = []
    for ptype, pver, label in (("ssl", "2", "SSL 2.0"), ("ssl", "3", "SSL 3.0"),
                               ("tls", "1.0", "TLS 1.0"), ("tls", "1.1", "TLS 1.1")):
        on = enabled.get((ptype, pver), False)
        checks.append(TLSCheck(
            name=f"{label} disabled", fail_title=f"{label} enabled",
            passed=not on,
            detail="" if not on else "protocol negotiated", severity="high",
        ))
    return checks


def _check_weak_ciphers(ssltest: ET.Element) -> TLSCheck:
    """No RC4 / 3DES / EXPORT / NULL / MD5 / anon (or <112-bit / sslscan-weak)."""
    offenders: list[str] = []
    for c in ssltest.findall("cipher"):
        name = c.get("cipher", "")
        try:
            bits = int(c.get("bits") or 0)
        except ValueError:
            bits = 0
        strength = (c.get("strength") or "").lower()
        if (any(bad in name for bad in _WEAK_CIPHER_SUBSTRINGS)
                or (0 < bits < 112) or strength in _WEAK_STRENGTHS):
            offenders.append(name)
    uniq = sorted(set(offenders))
    return TLSCheck(
        name="No weak ciphers (RC4/3DES/EXPORT/NULL/anon)",
        fail_title="Weak ciphers supported (RC4/3DES/EXPORT/NULL/anon)",
        passed=not uniq,
        detail="" if not uniq else "weak: " + ", ".join(uniq),
        severity="high",
    )


def _parse_cert_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    txt = raw.strip().replace(" GMT", "").replace(" UTC", "")
    for fmt in ("%b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(txt, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _check_certificate(ssltest: ET.Element) -> list[TLSCheck]:
    """Expiry (>30d), public-key strength, and signature-algorithm sanity.

    NB: sslscan does NOT robustly validate chain-of-trust, so the old
    'full chain trusted' check is intentionally dropped (the recon tlsx cert
    dossier already carries issuer/expiry/self-signed). HSTS lives in the
    `headers` capability.
    """
    cert = ssltest.find(".//certificate")
    if cert is None:
        return [TLSCheck(name="Certificate scan",
                         fail_title="No certificate returned by server", passed=False,
                         detail="no certificate in sslscan output", severity="high")]

    checks: list[TLSCheck] = []

    not_after = _parse_cert_date((cert.findtext("not-valid-after") or "").strip())
    if not_after is None:
        checks.append(TLSCheck(name="Cert valid and >30 days remaining",
                               fail_title="Certificate validity period unreadable", passed=False,
                               detail="could not parse not-valid-after", severity="high"))
    else:
        days = (not_after - datetime.now(timezone.utc)).days
        checks.append(TLSCheck(
            name="Cert valid and >30 days remaining",
            fail_title="Certificate expired" if days < 0 else "Certificate expiring soon (<30 days)",
            passed=days > 30, detail=f"{days} days remaining", severity="high"))

    pk = cert.find("pk")
    if pk is not None:
        ktype = (pk.get("type") or "").upper()
        try:
            kbits = int(pk.get("bits") or 0)
        except ValueError:
            kbits = 0
        floor = 256 if ktype in ("EC", "ECDSA", "ED25519", "ED448") else 2048
        ok = kbits >= floor
        checks.append(TLSCheck(name="Strong key (RSA≥2048 / EC≥256)",
                               fail_title="Weak public key (below RSA-2048 / EC-256)", passed=ok,
                               detail=f"{ktype or '?'} {kbits}-bit", severity="high"))

    sig = (cert.findtext("signature-algorithm") or "").strip()
    if sig:
        low = sig.lower()
        weak_sig = "sha1" in low or "md5" in low
        checks.append(TLSCheck(name="Strong signature algorithm",
                               fail_title="Weak certificate signature algorithm (SHA-1/MD5)",
                               passed=not weak_sig, detail=sig, severity="medium"))
    return checks


def _check_renegotiation(ssltest: ET.Element) -> TLSCheck | None:
    """Flag insecure (client-initiated) renegotiation. Skipped if not reported."""
    reneg = ssltest.find("renegotiation")
    if reneg is None:
        return None
    supported = reneg.get("supported") == "1"
    secure = reneg.get("secure") == "1"
    insecure = supported and not secure
    return TLSCheck(
        name="Secure renegotiation",
        fail_title="Insecure client-initiated renegotiation supported",
        passed=not insecure,
        detail="" if not insecure else "insecure renegotiation supported",
        severity="high",
    )


def _evaluate_checklist(ssltest: ET.Element) -> list[TLSCheck]:
    checks: list[TLSCheck] = []
    checks.extend(_check_protocols(ssltest))
    checks.append(_check_weak_ciphers(ssltest))
    checks.extend(_check_certificate(ssltest))
    reneg = _check_renegotiation(ssltest)
    if reneg is not None:
        checks.append(reneg)
    return checks


def _checks_to_findings(host: str, checks: list[TLSCheck]) -> list[Finding]:
    # Title uses the problem-phrased `fail_title` ("TLS 1.0 enabled"), NOT the
    # pass-condition `name` ("TLS 1.0 disabled") which would read backwards for a
    # failing check. evidence["check"] keeps `name` so `group_key` (and thus
    # cross-scan dedup + manual-suppression fingerprints) stays stable.
    return [
        Finding(
            source="sslscan",
            host=host,
            severity=c.severity,
            title=f"TLS: {c.fail_title or c.name}",
            description=c.detail or "Check failed",
            evidence={"check": c.name, "detail": c.detail},
        )
        for c in checks
        if not c.passed
    ]


async def _sslscan_one(
    server: LiveWebServer,
    out_dir: Path,
    cfg: SslscanConfig,
    log: RunLogger,
    semaphore: asyncio.Semaphore,
) -> tuple[TLSHostReport, list[Finding]]:
    parsed = urlparse(server.url)
    if parsed.scheme != "https":
        return TLSHostReport(host=server.host, error="not HTTPS"), []

    host = parsed.hostname or server.host
    port = parsed.port or 443
    xml_path = out_dir / f"{host_to_filename(host)}.xml"
    cmd = build_sslscan_cmd(host, port, xml_path, cfg)

    async with semaphore:
        log.debug("running sslscan", cmd=cmd, host=host, timeout=cfg.timeout)
        start = time.monotonic()
        try:
            res = await run_tool(cmd, timeout=float(cfg.timeout), log=log, label=f"sslscan {host}")
        except asyncio.TimeoutError:
            elapsed = round(time.monotonic() - start, 1)
            return TLSHostReport(
                host=host,
                error=(f"timeout after {elapsed}s (limit {cfg.timeout}s) — likely "
                       f"rate-limiting or a WAF/firewall block"),
            ), []
    elapsed = round(time.monotonic() - start, 1)

    if not xml_path.exists():
        msg = res.stderr.decode("utf-8", "replace")[-400:] or "no XML output"
        log.warn(f"sslscan produced no output for {host} after {elapsed}s",
                 host=host, event="sslscan_no_output", elapsed_s=elapsed, stderr=msg)
        return TLSHostReport(host=host, error=msg), []

    try:
        root = ET.fromstring(xml_path.read_text())
    except ET.ParseError as e:
        return TLSHostReport(host=host, error=f"parse error: {e}"), []

    ssltest = _first_ssltest(root)
    if ssltest is None:
        return TLSHostReport(host=host, error="no ssltest element in sslscan output"), []

    checks = _evaluate_checklist(ssltest)
    report = TLSHostReport(host=host, checks=checks)
    findings = _checks_to_findings(host, checks)
    log.info(f"sslscan {host}: {report.pass_count}/{report.total} checks passed "
             f"({len(findings)} failing) in {elapsed}s",
             host=host, event="sslscan_host_done", elapsed_s=elapsed,
             passed=report.pass_count, total=report.total)
    return report, findings


async def run_sslscan(
    live_servers: list[LiveWebServer],
    out_dir: Path,
    cfg: SslscanConfig,
    log: RunLogger,
    concurrency: int = 5,
) -> tuple[list[TLSHostReport], list[Finding]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    if not live_servers:
        log.info("sslscan: no live servers")
        return [], []

    https_only = [s for s in live_servers if s.url.startswith("https://")]
    if not https_only:
        log.info("sslscan: no HTTPS servers among live set")
        return [], []

    log.info(f"sslscan: scanning {len(https_only)} host(s), concurrency={concurrency}, "
             f"per-host timeout={cfg.timeout}s")
    sem = asyncio.Semaphore(concurrency)
    coros = [_sslscan_one(s, out_dir, cfg, log, sem) for s in https_only]
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
        f"sslscan: {len(reports)} host(s) — {ok} scanned, {errored} errored/timed out; "
        f"{len(findings)} failing checks",
        event="sslscan_summary", hosts=len(reports), ok=ok, errored=errored,
        failing_checks=len(findings),
    )
    return reports, findings
