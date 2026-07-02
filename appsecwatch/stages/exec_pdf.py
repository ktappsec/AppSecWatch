"""ExecPdfStage — render executive.pdf from executive.html via the bundled Chromium.

Runs after ReportStage (which wrote executive.html) and before CompressStage.
STRICTLY best-effort: the whole body is wrapped so a missing browser, a launch
failure, or any render error is logged and swallowed — it must NEVER raise, or the
executor would record it in errors.json and flip `--strict` to a failure exit. The
executive report is already complete as HTML; the PDF is a convenience artifact.

Only added to the pipeline when `cfg.report.executive_pdf` is true (see runner).
"""
from __future__ import annotations

from appsecwatch.stages.base import Stage


class ExecPdfStage(Stage):
    name = "report.pdf"

    async def run(self, state, run_dir, cfg, ipinfo, log):
        src = run_dir / "executive.html"
        if not src.is_file():
            return None
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page()
                    await page.goto(src.resolve().as_uri(), wait_until="load")
                    # Use the print stylesheet (forces the light, ink-friendly palette
                    # and hides interactive chrome) for the PDF.
                    await page.emulate_media(media="print")
                    await page.pdf(
                        path=str(run_dir / "executive.pdf"),
                        format="A4",
                        print_background=True,
                        margin={"top": "14mm", "bottom": "14mm",
                                "left": "12mm", "right": "12mm"},
                    )
                finally:
                    await browser.close()
            log.info(f"executive.pdf rendered: {run_dir / 'executive.pdf'}")
        except Exception as e:  # incl. ImportError — best-effort, never fail the run
            log.warn(f"executive.pdf skipped (best-effort): {e}")
        return None
