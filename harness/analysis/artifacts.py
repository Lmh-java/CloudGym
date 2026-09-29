"""Per-run artifacts generated automatically at the end of every run."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .figure import render_svg
from .timeline import build_timeline, render_text


def _fmt(value: Any) -> str:
    if value is None:
        return "–"
    if isinstance(value, float):
        return f"{value:.3g}" if abs(value) < 10 else f"{value:.1f}"
    if isinstance(value, list):
        return ", ".join(_fmt(v) for v in value) or "–"
    return str(value)


def run_summary_markdown(run_dir: Path) -> str:
    from harness.bench.report import COLUMNS, row_from_run  # local: bench imports analysis

    result = json.loads((run_dir / "result.json").read_text())
    row = row_from_run(run_dir)
    lines = [f"# Run {result.get('run_id')}", ""]
    if row is not None:
        values = row.as_list()
        keep = [(c, v) for c, v in zip(COLUMNS, values) if c not in {"run_dir", "batch", "arm", "trial"} or v is not None]
        lines += ["| field | value |", "|---|---|"]
        lines += [f"| {c} | {_fmt(v)} |" for c, v in keep]
    metrics = result.get("metrics") or {}
    if metrics:
        lines += ["", "## Metrics", "", "| metric | value |", "|---|---|"]
        for key in ("time_to_first_api_call_s", "time_to_trigger_s", "hold_duration_s", "interference_before_finish",
                    "agent_calls_after_interference", "turns_after_interference", "finish_called_at_s",
                    "tool_calls", "tool_calls_errored", "tool_call_median_ms"):
            if key in metrics:
                lines.append(f"| {key} | {_fmt(metrics[key])} |")
        errors = metrics.get("errors_seen_by_agent") or []
        if errors:
            lines.append(f"| errors_seen_by_agent | {', '.join(f'{e.get('operation')}:{e.get('code')}' for e in errors)} |")
        by_op = metrics.get("api_calls_by_operation") or {}
        if by_op:
            lines += ["", "## API calls", "", "| actor | operation | calls |", "|---|---|---|"]
            for actor, ops in sorted(by_op.items()):
                for op, n in sorted(ops.items()):
                    lines.append(f"| {actor} | {op} | {n} |")
    denials = (result.get("agent") or {}).get("permission_denials") or []
    if denials:
        lines += ["", "## Denied tool calls", ""]
        lines += [f"- `{d.get('tool')}`: `{(d.get('command') or '')[:120]}`" for d in denials]
    lines += ["", "## Timeline", "", "![timeline](timeline.svg)", "", "Text version: [timeline.txt](timeline.txt)"]
    return "\n".join(lines) + "\n"


def write_run_artifacts(run_dir: Path) -> dict[str, Path]:
    """timeline.txt, timeline.svg and summary.md next to result.json."""
    run_dir = Path(run_dir)
    entries = build_timeline(run_dir)
    written = {}
    text_path = run_dir / "timeline.txt"
    text_path.write_text(render_text(entries) + "\n")
    written["timeline_txt"] = text_path
    title = run_dir.name
    if (run_dir / "result.json").is_file():
        try:
            result = json.loads((run_dir / "result.json").read_text())
            title = f"{result.get('run_id')} · {result.get('status')} · verdict={result.get('verdict')}"
        except json.JSONDecodeError:
            pass
    svg_path = run_dir / "timeline.svg"
    svg_path.write_text(render_svg(entries, title=title))
    written["timeline_svg"] = svg_path
    if (run_dir / "result.json").is_file():
        summary_path = run_dir / "summary.md"
        summary_path.write_text(run_summary_markdown(run_dir))
        written["summary_md"] = summary_path
    return written
