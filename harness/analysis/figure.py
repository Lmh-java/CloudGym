"""Self-contained SVG of a run's API traffic (stdlib only).

Lanes are the API actors only: ``api:main`` (the agent) and one
``api:<distractor>`` lane per distractor. Every call is a bar from its
``before`` event to its ``after_*`` event, so a held call is visibly long;
failed calls are drawn in the error colour and marked ✗. Hover for details.

Colours follow the Nature Publishing Group palette (the `npg` scheme used in
Nature figures): main = navy #3C5488, distractors = #E64B35, #F39B7F, #00A087,
#4DBBD5, #8491B4, #7E6148; errors = #DC0000.
"""

from __future__ import annotations

from typing import Iterable
from xml.sax.saxutils import escape

from .timeline import TimelineEntry

NPG_MAIN = "#3C5488"
NPG_DISTRACTORS = ["#E64B35", "#F39B7F", "#00A087", "#4DBBD5", "#8491B4", "#7E6148", "#B09C85", "#91D1C2"]
NPG_ERROR = "#DC0000"
GRID = "#E5E5E5"
TEXT = "#333333"

WIDTH = 1200
LEFT = 170
RIGHT = 30
ROW = 40
TOP = 44
BOTTOM = 40


def _api_lanes(entries: list[TimelineEntry]) -> list[str]:
    present = {e.lane for e in entries if e.lane.startswith("api:")}
    lanes = ["api:main"] if "api:main" in present else []
    lanes += sorted(lane for lane in present if lane != "api:main")
    return lanes


def _colors(lanes: list[str]) -> dict[str, str]:
    colors = {}
    index = 0
    for lane in lanes:
        if lane == "api:main":
            colors[lane] = NPG_MAIN
        else:
            colors[lane] = NPG_DISTRACTORS[index % len(NPG_DISTRACTORS)]
            index += 1
    return colors


def _tick_step(span: float) -> float:
    for step in (1, 2, 5, 10, 15, 30, 60, 120, 300, 600):
        if span / step <= 12:
            return float(step)
    return float(int(span // 10) or 1)


def render_svg(entries: Iterable[TimelineEntry], *, title: str = "") -> str:
    api = [e for e in entries if e.lane.startswith("api:") and e.kind.startswith("api.")]
    if not api:
        return ('<svg xmlns="http://www.w3.org/2000/svg" width="400" height="60" font-family="Helvetica, Arial, sans-serif" '
                'font-size="12"><text x="10" y="35">no API calls recorded</text></svg>')
    lanes = _api_lanes(api)
    colors = _colors(lanes)
    t_min = min(e.t_rel_s for e in api)
    t_max = max(e.t_rel_s for e in api)
    span = max(t_max - t_min, 1.0)
    height = TOP + ROW * len(lanes) + BOTTOM
    plot_width = WIDTH - LEFT - RIGHT

    def x(t: float) -> float:
        return LEFT + (t - t_min) / span * plot_width

    def y(lane: str) -> float:
        return TOP + ROW * lanes.index(lane) + ROW / 2

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" '
        f'font-family="Helvetica, Arial, sans-serif" font-size="11" fill="{TEXT}">',
        f'<rect width="{WIDTH}" height="{height}" fill="#FFFFFF"/>',
        f'<text x="{LEFT}" y="22" font-size="13" font-weight="bold">{escape(title)}</text>' if title else "",
    ]
    step = _tick_step(span)
    tick = (t_min // step) * step
    while tick <= t_max + step:
        if tick >= t_min:
            parts.append(f'<line x1="{x(tick):.1f}" y1="{TOP}" x2="{x(tick):.1f}" y2="{height - BOTTOM}" stroke="{GRID}"/>')
            parts.append(f'<text x="{x(tick):.1f}" y="{height - BOTTOM + 16}" text-anchor="middle">{tick:g} s</text>')
        tick += step
    parts.append(f'<line x1="{LEFT}" y1="{height - BOTTOM}" x2="{WIDTH - RIGHT}" y2="{height - BOTTOM}" stroke="{TEXT}"/>')
    for lane in lanes:
        cy = y(lane)
        label = "agent" if lane == "api:main" else lane[4:]
        parts.append(f'<text x="{LEFT - 10}" y="{cy + 4:.1f}" text-anchor="end" font-weight="bold" fill="{colors[lane]}">{escape(label)}</text>')

    # pair before/after per lane and operation, in order
    open_calls: dict[tuple[str, str], list[TimelineEntry]] = {}
    for entry in api:
        op = entry.summary.split(" ")[0]
        key = (entry.lane, op)
        if entry.kind == "api.before":
            open_calls.setdefault(key, []).append(entry)
            continue
        start = open_calls.get(key, [None]).pop(0) if open_calls.get(key) else None
        cy = y(entry.lane)
        x1 = x(entry.t_rel_s)
        x0 = x(start.t_rel_s) if start else x1 - 3
        failed = entry.kind == "api.after_error"
        fill = NPG_ERROR if failed else colors[entry.lane]
        tip = escape(f"{(start.t_rel_s if start else entry.t_rel_s):.2f}–{entry.t_rel_s:.2f} s  {entry.summary}")
        parts.append(f'<rect x="{x0:.1f}" y="{cy - 9:.1f}" width="{max(x1 - x0, 3):.1f}" height="18" rx="2" fill="{fill}">'
                     f'<title>{tip}</title></rect>')
        label = op.split(".")[-1] + (" ✗" if failed else "")
        parts.append(f'<text x="{x0:.1f}" y="{cy - 12:.1f}" font-size="9" fill="{fill}">{escape(label)}</text>')
    for (lane, op), starts in open_calls.items():
        for start in starts:
            cy = y(lane)
            x0 = x(start.t_rel_s)
            parts.append(f'<rect x="{x0:.1f}" y="{cy - 9:.1f}" width="{WIDTH - RIGHT - x0:.1f}" height="18" rx="2" '
                         f'fill="{colors[lane]}" fill-opacity="0.3"><title>{escape(start.summary)} (no response recorded)</title></rect>')
    parts.append("</svg>")
    return "\n".join(p for p in parts if p)
