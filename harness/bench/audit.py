"""Transcript audit: did the agent look outside its workspace?

Second line of defence behind the sandbox (``harness.agents.sandbox``). Every tool call
in the agent's event log is checked for paths that are neither inside the workspace nor
part of the system tree, and whether the call succeeded. Before the sandbox existed
(paper-config-1 on the ops VM, 2026-09-21) such reads reached the published cases'
reference answers and interference designs, the certification runs and other cells'
results; a cell where one succeeded is *contaminated* and is excluded from every table
until it is rerun. With the sandbox, the same reads fail and are reported as attempts.

What counts (schema 2, 2026-09-24):

- sandboxed runs: a read of another session's records (``SESSION_MARKERS``: the agent CLIs'
  transcripts, snapshots, histories), or an outside read whose output shows host material
  (``HOST_EVIDENCE_RE``: the sandbox itself leaked). Nothing else outside ``/work`` exists
  inside, so every other outside path is an attempt that delivered nothing; the textual test
  flagged EC2 user-data (``mkdir -p /mnt/efs``), commands run over SSH on the agent's own
  instance and ``cat ~/.aws/config || echo none`` as reads (cases 130/191/423: ~100 cells).
- legacy runs (no sandbox): every successful outside read, as before, plus session records.

Layouts:

- sandboxed runs: the workspace is mounted at ``result.json["confinement"]["workspace_mount"]``
  (``/work``); nothing of the host's home or working tree exists, so any path under a
  home directory (``OUTSIDE_ROOTS``) is an attempt;
- legacy runs: the workspace is ``<run_dir>/private/agent-workspace`` as the agent's host
  saw it (the transcripts record the VM's paths, not this machine's), recognised by the
  run directory's name; anything else under the run directory or the working tree is
  outside.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator

SCHEMA_VERSION = 2
WORKSPACE_DIRNAME = "agent-workspace"

# Where host material an agent must not see lives: home directories and mounted data.
# Anything else that looks like an absolute path is the system tree or not a filesystem
# path at all (log-group names, SSM parameters, URL paths, ARNs).
OUTSIDE_ROOTS = ("/home", "/Users", "/root", "/mnt", "/srv", "/media", "/data", "~")
# The agent CLIs' own state and caches: outside the workspace, but not case material.
TOOLING_MARKERS = ("/.claude", "/.codex", "/.cache/", "/.npm/", "/.terraform.d", "/.terraformrc", "/node_modules/",
                   "terraform-plugin-cache-agent", "/.local/share/uv", "/.venv/", "/.bashrc", "/.profile")
# Other sessions' records in the agent CLIs' state dirs (per-cell overlays since 2026-09-24, but
# a read of one is contamination in any run).
SESSION_MARKERS = ("/.claude/projects", "/.claude/sessions", "/.claude/session-env", "/.claude/shell-snapshots",
                   "/.claude/file-history", "/.claude/todos", "/.codex/sessions", "/.codex/shell_snapshots",
                   "/.codex/history", "/.codex/thread_history", "/.codex/memories", "/.codex/state_", "/.codex/logs_")
# Output that could only come from the host (the VM user's home, the repository): proof that an
# outside read in a sandboxed run really delivered something.
# ("cloudgym" alone is too weak: the harness tags AWS resources with it, and the sandbox's
# empty home is /home/ubuntu too.)
HOST_EVIDENCE_RE = re.compile(r"/(?:home/\w+|Users/\w+|root)/cloudgym-bench/(?:cases|artifacts|harness|scripts|seeds|"
                              r"docs|experiments|\.cloudgym)")
# Case material and harness files: a successful read of one of these is contamination
# in itself, whatever else the cell did.
SENSITIVE_RE = re.compile(
    r"(expected\.tf|design\.md|oracle\.rego|handover\.md|/evaluator(/|$)|/cases/|cases/_staging|"
    r"artifacts/experiments|artifacts/runs|/\.cloudgym|/private/|/agent/|result\.json|run\.json|"
    r"/seeds/|/distractors?(/|\b)|/snapshots(/|$)|/harness(/|$)|/scripts(/|$)|/docs(/|$))")
# A tool result that starts like this did not deliver the file.
ERROR_RE = re.compile(
    r"(No such file or directory|File does not exist|EISDIR|Permission denied|cannot access|"
    r"not found|does not exist|Not a directory|Operation not permitted|Is a directory)", re.I)
_PATH_RE = re.compile(r"(?<![\w.:/-])(~?/(?:[\w.@%+=,~-]+/)*[\w.@%+=,~-]*)")
_HOME_RE = re.compile(r"\$\{?HOME\}?(/[\w.@%+=,~/-]*)?")
_PARENT_RE = re.compile(r"(?:^|[\s;&|(=\"'])(?:cd\s+)?(\.\./|\.\.(?=[\s;&|)\"']|$))")


@dataclass
class Attempt:
    tool: str
    path: str
    kind: str                # outside | sessions | tooling | parent
    sensitive: bool
    succeeded: bool
    excerpt: str
    host_evidence: bool = False      # the tool's output shows host material (see HOST_EVIDENCE_RE)


@dataclass
class Audit:
    schema_version: int = SCHEMA_VERSION
    sandboxed: bool = False
    workspace: str | None = None
    calls: int = 0
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def outside_attempts(self) -> int:
        return sum(1 for a in self.attempts if a.kind == "outside")

    @property
    def outside_successes(self) -> int:
        return sum(1 for a in self.attempts if a.kind == "outside" and a.succeeded)

    @property
    def sensitive_successes(self) -> int:
        return sum(1 for a in self.attempts if a.sensitive and a.succeeded)

    @property
    def contaminating(self) -> list[Attempt]:
        """The reads that make the cell contaminated: other sessions' records in any run; in a
        run without the sandbox, also every other successful outside read. Tooling paths and
        bare ``..`` steps (``cd build && zip ../x.zip`` stays inside) never count."""
        if not self.sandboxed:
            return [a for a in self.attempts if a.kind in ("sessions", "outside") and a.succeeded]
        return [a for a in self.attempts if a.succeeded and
                (a.kind == "sessions" or (a.kind == "outside" and a.host_evidence))]

    @property
    def contaminated(self) -> bool:
        return bool(self.contaminating)

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "outside_attempts": self.outside_attempts,
                "outside_successes": self.outside_successes, "sensitive_successes": self.sensitive_successes,
                "contaminating_reads": len(self.contaminating),
                "contaminated": self.contaminated}


@dataclass(frozen=True)
class ToolCall:
    tool: str
    text: str        # the input as text (command, file path, JSON)
    output: str


# -- reading the event log -------------------------------------------------------------

def tool_calls(events_path: Path) -> Iterator[ToolCall]:
    """Every tool call with its result, from a Claude or Codex event log."""
    pending: dict[str, tuple[str, str]] = {}
    try:
        lines = events_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        message = event.get("message") if isinstance(event.get("message"), dict) else {}
        content = message.get("content") if isinstance(message.get("content"), list) else []
        if kind == "assistant":
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    pending[str(block.get("id"))] = (str(block.get("name")), _input_text(block.get("input")))
        elif kind == "user":
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    use = pending.pop(str(block.get("tool_use_id")), None)
                    if use is not None:
                        yield ToolCall(use[0], use[1], _result_text(block.get("content")))
        elif kind == "item.completed":
            item = event.get("item") if isinstance(event.get("item"), dict) else {}
            if item.get("type") == "command_execution":
                yield ToolCall("command_execution", str(item.get("command") or ""),
                               str(item.get("aggregated_output") or ""))
            elif item.get("type") == "file_change":
                paths = " ".join(str(c.get("path", "")) for c in item.get("changes") or [] if isinstance(c, dict))
                yield ToolCall("file_change", paths, "ok")
    for tool, text in pending.values():          # calls without a result (run cut short)
        yield ToolCall(tool, text, "")


def _input_text(value: Any) -> str:
    if isinstance(value, dict):
        parts = []
        # Inputs that name what the tool touches; not the text it writes (a script the
        # agent writes may mention host paths without reading anything).
        for key in ("command", "file_path", "path", "pattern", "notebook_path"):
            if key in value:
                parts.append(str(value[key]))
        return "\n".join(parts) if parts else json.dumps(value)
    return str(value)


def _result_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(c.get("text", "")) if isinstance(c, dict) else str(c) for c in content)
    return "" if content is None else json.dumps(content)


# -- classifying paths -----------------------------------------------------------------

def extract_paths(text: str) -> list[str]:
    """Absolute paths mentioned in a command or tool input (``~`` and ``$HOME`` kept as ``~``)."""
    found: list[str] = []
    for match in _HOME_RE.finditer(text):
        found.append("~" + (match.group(1) or ""))
    for match in _PATH_RE.finditer(text):
        path = match.group(1).rstrip("/") or "/"
        if path in ("/", "~") or path.startswith("/dev/null"):
            continue
        found.append(path)
    seen: set[str] = set()
    return [p for p in found if not (p in seen or seen.add(p))]


def classify(path: str, *, workspace: str | None, mount: str | None) -> str | None:
    """None when the path is inside the workspace or the system tree; otherwise the attempt kind."""
    if mount and (path == mount or path.startswith(mount + "/")):
        return None
    if workspace and (path == workspace or path.startswith(workspace + "/")):
        return None
    if not any(path == root or path.startswith(root + "/") for root in OUTSIDE_ROOTS):
        return None
    if any(marker in path for marker in SESSION_MARKERS):
        return "sessions"
    if any(marker in path + "/" for marker in TOOLING_MARKERS):
        return "tooling"
    return "outside"


def _workspace_as_seen(run_dir: Path, calls: Iterable[ToolCall]) -> str | None:
    """The workspace path as the agent's host had it (legacy layout), from the transcript."""
    needle = re.compile(r"(?P<ws>(?:~|/[^\s'\"]*?)/" + re.escape(run_dir.name) + "/private/" + WORKSPACE_DIRNAME + r")(?=/|\s|$|['\"])")
    for call in calls:
        match = needle.search(call.text) or needle.search(call.output)
        if match:
            return match.group("ws")
    return None


def _succeeded(output: str) -> bool:
    head = output.strip()[:400]
    return bool(head) and not ERROR_RE.search(head)


# -- the audit -------------------------------------------------------------------------

def own_sessions(events_path: Path) -> set[str]:
    """The agent's own session ids (claude's ``session_id``, codex's thread id): its own session
    records (e.g. claude's ``projects/<cwd>/<session>/tool-results/`` for a long tool output) are
    tooling, not another session's."""
    ids: set[str] = set()
    try:
        lines = events_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ids
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            for key in ("session_id", "thread_id"):
                value = event.get(key)
                if isinstance(value, str) and len(value) >= 8:
                    ids.add(value)
    return ids


def audit_events(events_path: Path, *, run_dir: Path, mount: str | None = None,
                 workspace: str | None = None) -> Audit:
    calls = list(tool_calls(events_path))
    mine = own_sessions(events_path)
    if workspace is None and mount is None:
        workspace = _workspace_as_seen(run_dir, calls)
    audit = Audit(sandboxed=mount is not None, workspace=mount or workspace, calls=len(calls))
    for call in calls:
        succeeded = _succeeded(call.output)
        evidence = bool(HOST_EVIDENCE_RE.search(call.output[:4000]))
        excerpt = call.text.replace("\n", " ")[:200]
        for path in extract_paths(call.text):
            kind = classify(path, workspace=workspace, mount=mount)
            if kind is None:
                continue
            if kind == "sessions" and any(sid in path for sid in mine):
                kind = "tooling"                      # its own session's records
            audit.attempts.append(Attempt(tool=call.tool, path=path, kind=kind,
                                          sensitive=bool(SENSITIVE_RE.search(path)), succeeded=succeeded,
                                          excerpt=excerpt, host_evidence=evidence))
        if _PARENT_RE.search(call.text):
            audit.attempts.append(Attempt(tool=call.tool, path="..", kind="parent", sensitive=False,
                                          succeeded=succeeded, excerpt=excerpt))
    return audit


def audit_run(run_dir: Path) -> Audit | None:
    """Audit one run directory from its ``result.json`` and event log; None without a transcript."""
    result_path = run_dir / "result.json"
    sandbox: dict[str, Any] = {}
    events_rel = "agent/events.jsonl"
    if result_path.is_file():
        try:
            result = json.loads(result_path.read_text())
        except ValueError:
            result = {}
        sandbox = result.get("confinement") if isinstance(result.get("confinement"), dict) else {}
        transcript = ((result.get("agent") or {}).get("transcript") or {})
        events_rel = transcript.get("events") or events_rel
    events_path = run_dir / events_rel
    if not events_path.is_file():
        return None
    mount = sandbox.get("workspace_mount") if sandbox.get("backend") not in (None, "none") else None
    return audit_events(events_path, run_dir=run_dir, mount=mount)


def write_audit(run_dir: Path, audit: Audit) -> Path:
    path = run_dir / "agent" / "audit.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(audit.as_dict(), indent=2, sort_keys=True) + "\n")
    return path


def summarize(audits: dict[str, Audit]) -> dict[str, Any]:
    """Counts over a batch keyed by run-dir name: per arm and in total."""
    arms: dict[str, dict[str, int]] = {}
    for name, audit in audits.items():
        arm = re.sub(r"-iac-eval-.*$", "", name)
        row = arms.setdefault(arm, {"cells": 0, "attempted": 0, "contaminated": 0, "sensitive": 0})
        row["cells"] += 1
        row["attempted"] += 1 if audit.outside_attempts else 0
        row["contaminated"] += 1 if audit.contaminated else 0
        row["sensitive"] += 1 if audit.sensitive_successes else 0
    total = {k: sum(r[k] for r in arms.values()) for k in ("cells", "attempted", "contaminated", "sensitive")}
    return {"arms": arms, "total": total}


def _posix(path: Path | str) -> str:
    return str(PurePosixPath(path))
