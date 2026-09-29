"""Post-run analysis: timelines, figures, derived metrics, per-run artifacts."""

from .artifacts import run_summary_markdown, write_run_artifacts
from .figure import render_svg
from .timeline import TimelineEntry, build_timeline, compute_metrics, render_text, write_metrics

__all__ = ["TimelineEntry", "build_timeline", "compute_metrics", "render_svg", "render_text",
           "run_summary_markdown", "write_metrics", "write_run_artifacts"]
