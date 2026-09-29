"""Prompt templates as Markdown files with ``{variable}`` injections.

Templates live next to this module (``harness/prompts/*.md``). ``load_prompt``
reads one and fills its ``{name}`` placeholders; a missing variable is an
error rather than a silent blank, and literal braces are written ``{{``/``}}``.
"""

from __future__ import annotations

from pathlib import Path
from string import Formatter
from typing import Any

PROMPTS_DIR = Path(__file__).resolve().parent


class PromptError(KeyError):
    pass


def prompt_path(name: str) -> Path:
    path = PROMPTS_DIR / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"no prompt template {name!r} under {PROMPTS_DIR}")
    return path


def prompt_variables(name: str) -> set[str]:
    """The placeholder names a template expects."""
    text = prompt_path(name).read_text(encoding="utf-8")
    return {field for _, field, _, _ in Formatter().parse(text) if field}


def load_prompt(name: str, **variables: Any) -> str:
    """Render ``harness/prompts/<name>.md`` with ``variables``."""
    text = prompt_path(name).read_text(encoding="utf-8")
    expected = prompt_variables(name)
    missing = sorted(expected - variables.keys())
    if missing:
        raise PromptError(f"prompt {name!r} needs {missing}")
    return text.format(**variables)


__all__ = ["PROMPTS_DIR", "PromptError", "load_prompt", "prompt_path", "prompt_variables"]
