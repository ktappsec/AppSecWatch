from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_report(context: dict[str, Any], out_path: Path) -> None:
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

    env.filters["sev_class"] = severity_class
    env.filters["pf_class"] = passfail_class

    template = env.get_template("report.html.j2")
    html = template.render(**context)
    out_path.write_text(html, encoding="utf-8")
