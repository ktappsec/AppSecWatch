from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _make_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def severity_class(sev: str) -> str:
        return f"sev sev-{sev}"

    def passfail_class(passed: bool) -> str:
        return "pf-pass" if passed else "pf-fail"

    def verdict_label(source: str | None) -> str:
        """Who suppressed a finding — the AI, a deterministic engine rule, or an
        operator. Reader-facing names for AIFindingVerdict.source."""
        return {
            "ai_triage": "AI triage",
            "ai_headers": "AI triage",   # legacy source name
            "policy": "Policy (N/A here)",
            "coverage": "Not assessed",
            "manual": "Manual",
        }.get(source or "", "AI triage")

    env.filters["sev_class"] = severity_class
    env.filters["pf_class"] = passfail_class
    env.filters["verdict_label"] = verdict_label
    return env


def _render(template_name: str, context: dict[str, Any], out_path: Path) -> None:
    html = _make_env().get_template(template_name).render(**context)
    out_path.write_text(html, encoding="utf-8")


def render_report(context: dict[str, Any], out_path: Path) -> None:
    """Render the full technical report.html (shares _base.html.j2 with the exec one)."""
    _render("report.html.j2", context, out_path)


def render_executive(context: dict[str, Any], out_path: Path) -> None:
    """Render the executive one-pager executive.html. Consumes the same context dict
    (it reads context['executive'] + context['run'])."""
    _render("executive.html.j2", context, out_path)
