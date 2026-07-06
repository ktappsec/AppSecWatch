"""Server-rendered inline SVG charts for the executive report.

Pure string builders — no JS, no external assets. Fills use the report's theme CSS
custom properties (var(--crit) …) so the charts follow the light/dark toggle and
the print palette automatically. Every function degrades gracefully on empty input
(returns a small placeholder), so the executive report renders cleanly even with
no findings and no history (e.g. a CLI run with no cross-scan data).
"""
from __future__ import annotations

import math

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_VAR = {
    "critical": "var(--crit)", "high": "var(--high)", "medium": "var(--med)",
    "low": "var(--low)", "info": "var(--info)",
}


def donut_svg(counts: dict[str, int], *, size: int = 132) -> str:
    """Severity-distribution donut. `counts` keyed by severity name."""
    total = sum(max(0, counts.get(s, 0)) for s in _SEV_ORDER)
    r, cx, cy, sw = 52, 60, 60, 20
    circ = 2 * math.pi * r
    segments: list[str] = []
    if total == 0:
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="var(--border)" stroke-width="{sw}"/>'
        )
        center = '<text x="60" y="64" text-anchor="middle" font-size="13" fill="var(--muted)">0</text>'
    else:
        offset = 0.0
        for sev in _SEV_ORDER:
            n = max(0, counts.get(sev, 0))
            if not n:
                continue
            frac = n / total
            seg = frac * circ
            segments.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="{_SEV_VAR[sev]}" stroke-width="{sw}" '
                f'stroke-dasharray="{seg:.2f} {circ - seg:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}"/>'
            )
            offset += seg
        center = (f'<text x="60" y="64" text-anchor="middle" font-size="20" '
                  f'font-weight="700" fill="var(--text)">{total}</text>')
    return (
        f'<svg viewBox="0 0 120 120" width="{size}" height="{size}" role="img" '
        f'aria-label="Findings by severity" style="transform:rotate(-90deg)">'
        + "".join(segments)
        + f'<g style="transform:rotate(90deg);transform-origin:60px 60px">{center}</g></svg>'
    )


def trend_line_svg(history: list[dict], *, width: int = 340, height: int = 96) -> str:
    """Risk-score (0..100) trend over the last N scans. `history` is oldest→newest
    dicts each carrying `risk_score`."""
    pts = [max(0, min(100, int(h.get("risk_score") or 0))) for h in (history or [])]
    pad = 8
    w, h = width, height
    if len(pts) < 2:
        return (f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" '
                f'aria-label="Risk trend"><text x="{w//2}" y="{h//2}" text-anchor="middle" '
                f'font-size="12" fill="var(--muted)">insufficient history</text></svg>')
    n = len(pts)
    dx = (w - 2 * pad) / (n - 1)

    def y(v: int) -> float:
        return pad + (h - 2 * pad) * (1 - v / 100)

    coords = [(pad + i * dx, y(v)) for i, v in enumerate(pts)]
    poly = " ".join(f"{x:.1f},{yy:.1f}" for x, yy in coords)
    area = f"{pad:.1f},{h - pad:.1f} " + poly + f" {pad + (n - 1) * dx:.1f},{h - pad:.1f}"
    last_x, last_y = coords[-1]
    return (
        f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="Risk-score trend">'
        f'<polygon points="{area}" fill="var(--accent)" opacity="0.10"/>'
        f'<polyline points="{poly}" fill="none" stroke="var(--accent)" stroke-width="2" '
        f'stroke-linejoin="round" stroke-linecap="round"/>'
        f'<circle cx="{last_x:.1f}" cy="{last_y:.1f}" r="3.5" fill="var(--accent)"/>'
        f'<text x="{last_x - 4:.1f}" y="{max(12, last_y - 8):.1f}" text-anchor="end" '
        f'font-size="12" font-weight="700" fill="var(--text)">{pts[-1]}</text>'
        f'</svg>'
    )


def delta_bars_svg(diff: dict[str, int] | None, *, width: int = 340) -> str:
    """New / recurring / resolved bars since the previous scan."""
    diff = diff or {}
    rows = [
        ("New", int(diff.get("new", 0)), "var(--high)"),
        ("Recurring", int(diff.get("recurring", 0)), "var(--med)"),
        ("Resolved", int(diff.get("resolved", 0)), "var(--pass)"),
    ]
    top = max((v for _, v, _ in rows), default=0)
    bar_w = width - 150
    lines: list[str] = []
    y = 14
    for label, val, color in rows:
        frac = (val / top) if top else 0
        w = max(2, bar_w * frac) if val else 0
        lines.append(
            f'<text x="0" y="{y + 4}" font-size="12" fill="var(--muted)">{label}</text>'
            f'<rect x="86" y="{y - 8}" width="{w:.1f}" height="12" rx="3" fill="{color}"/>'
            f'<text x="{86 + w + 6:.1f}" y="{y + 3}" font-size="12" font-weight="700" '
            f'fill="var(--text)">{val}</text>'
        )
        y += 26
    return (f'<svg viewBox="0 0 {width} {y}" width="{width}" height="{y}" role="img" '
            f'aria-label="Change since last scan">' + "".join(lines) + "</svg>")
