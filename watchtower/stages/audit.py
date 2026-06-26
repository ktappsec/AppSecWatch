"""Audit-phase stages."""
from __future__ import annotations

import json
from pathlib import Path

from watchtower.audit.nuclei_runner import run_nuclei
from watchtower.audit.sslyze_runner import run_sslyze
from watchtower.audit.takeover_fingerprints import scan_cname_takeovers
from watchtower.audit.takeovers import run_takeovers
from watchtower.stages.base import Stage, StageResult
from watchtower.util.domains import host_to_filename


class TakeoversStage(Stage):
    name = "audit.takeovers"

    def _path(self, run_dir: Path) -> Path:
        return run_dir / "02_audit" / "takeovers" / "nuclei-takeovers.jsonl"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        # Deterministic dangling-CNAME check over the dead bucket (no network):
        # catches NXDOMAIN-target takeovers the HTTP nuclei templates can't reach.
        det = scan_cname_takeovers(state.dead())
        # nuclei HTTP-fingerprint templates need a RESOLVING host → feed the
        # shadow_it CNAME candidates (resolving + third-party CNAME), not dead.
        candidates = [a for a in state.shadow_it() if a.cname_chain]
        nuclei_findings, error = await run_takeovers(
            candidates, self._path(run_dir), cfg.tools.takeovers, log,
        )
        if det:
            log.info(f"takeovers: {len(det)} dangling-CNAME finding(s) (deterministic)")
        state.takeover_findings = det + nuclei_findings
        return StageResult([(None, error)]) if error else None


class SslyzeStage(Stage):
    name = "audit.sslyze"

    def _dir(self, run_dir: Path) -> Path:
        return run_dir / "02_audit" / "sslyze"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        reports, findings = await run_sslyze(
            state.live_servers, self._dir(run_dir), cfg.tools.sslyze, log,
            concurrency=cfg.concurrency.sslyze,
        )
        state.tls_reports = reports
        state.sslyze_findings = findings
        # Per-host TLS scan failures (timeouts, no output, parse errors).
        return StageResult([(r.host, r.error) for r in reports if r.error])


class NucleiStage(Stage):
    name = "audit.nuclei"

    def __init__(self, severities: list[str] | None = None) -> None:
        # Override the config's severities for this run (the nuclei.<sev>
        # sub-tokens). None → use cfg.tools.nuclei.severities as-is.
        self.severities = severities

    def _path(self, run_dir: Path) -> Path:
        return run_dir / "02_audit" / "nuclei" / "findings.jsonl"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        nuclei_cfg = cfg.tools.nuclei
        if self.severities:
            nuclei_cfg = nuclei_cfg.model_copy(update={"severities": list(self.severities)})
        findings, error = await run_nuclei(
            state.live_servers, self._path(run_dir), nuclei_cfg, log,
            user_agent=cfg.identity.effective_user_agent(),
            extra_headers=cfg.identity.effective_headers(),
        )
        state.nuclei_findings = findings
        return StageResult([(None, error)]) if error else None


class HeadersStage(Stage):
    """Deterministic security-header analysis over the captured PageSignals.

    Passive (no new requests); runs in the audit phase so its findings exist
    before the ai.headers stage (ai-analyze phase) can attach suppression
    verdicts. `do_csp` / `do_best_practice` come from the headers.csp /
    headers.best-practice sub-tokens.
    """
    name = "audit.headers"

    def __init__(self, do_csp: bool = True, do_best_practice: bool = True) -> None:
        self.do_csp = do_csp
        self.do_best_practice = do_best_practice

    def _dir(self, run_dir: Path) -> Path:
        return run_dir / "02_audit" / "headers"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        from watchtower.audit.header_checks import run_header_checks

        out_dir = self._dir(run_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        url_by_host = {s.host: s.url for s in state.live_servers}

        findings = []
        for host, signals in state.page_signals.items():
            url = url_by_host.get(host, f"https://{host}")
            host_findings = run_header_checks(
                url, signals,
                do_csp=self.do_csp, do_best_practice=self.do_best_practice,
                cfg=cfg.headers,
            )
            findings.extend(host_findings)
            (out_dir / f"{host_to_filename(host)}.json").write_text(
                json.dumps([f.model_dump() for f in host_findings], indent=2)
            )

        state.header_findings = findings
        log.info(f"headers: {len(findings)} finding(s) across {len(state.page_signals)} host(s)")
        return None


class CrawlerStage(Stage):
    name = "audit.crawler"

    def _dir(self, run_dir: Path) -> Path:
        return run_dir / "02_audit" / "playwright"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        # Lazy import: playwright is only needed when the crawler actually runs,
        # so importing this module stays free of the heavy browser dependency.
        from watchtower.audit.crawler import run_crawler

        state.crawler_artifacts = await run_crawler(
            state.live_servers, cfg.paths_per_host, self._dir(run_dir),
            cfg.tools.playwright, log, concurrency=cfg.concurrency.playwright,
            identity={
                "user_agent": cfg.identity.effective_user_agent(),
                "headers": cfg.identity.effective_headers(),
                "locale": cfg.identity.effective_locale(),
            },
        )
        # Deterministic vulnerable-JS-library scan over the captured scripts
        # (retire.js-style; offline, no extra requests).
        try:
            from watchtower.audit.js_libs import scan_scripts

            state.js_lib_findings = scan_scripts(state.crawler_artifacts)
            if state.js_lib_findings:
                log.info(f"js-lib findings: {len(state.js_lib_findings)}")
        except Exception as e:  # noqa: BLE001 — never fail the crawl on this
            log.warn(f"js-lib scan failed: {e}")
        # Per-host crawl failures (nav timeouts/errors).
        return StageResult(
            [(art.host, msg) for art in state.crawler_artifacts for msg in art.errors]
        )
