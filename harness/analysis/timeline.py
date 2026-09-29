"""Per-run timeline and derived metrics.

Joins three sources by wall time:

* ``events.jsonl``            harness events (API calls, triggers, distractors, snapshots)
* ``agent/turns.jsonl``         the agent's tool calls (from the streamed transcript)
* ``run.json``                lifecycle status

and derives the numbers a benchmark row needs (``metrics.json``).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from harness.awareness import AWARENESS_TOOL_NAMES
from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class TimelineEntry:
    ts: float                 # epoch seconds
    t_rel_s: float            # seconds since run.started (may be negative for baseline work)
    lane: str                 # agent | api:<actor> | trigger | distractor | snapshot | harness
    kind: str
    summary: str
    ref: str | None = None    # event sequence or turn id

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_wall(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _snapshot_summary(record: Mapping[str, Any]) -> str:
    resources = (record.get("snapshot") or {}).get("resources") or {}
    counts = ", ".join(f"{t.split('::')[-1]}={len(v)}" for t, v in sorted(resources.items()))
    return f"{record.get('snapshot_id')} [{counts}]"


def _api_summary(record: Mapping[str, Any]) -> str:
    op = f"{record.get('service')}.{record.get('operation')}"
    phase = record.get("phase")
    if phase == "before":
        params = record.get("parameters") or {}
        keys = ", ".join(f"{k}={params[k]}" for k in sorted(params)[:3] if not isinstance(params[k], (dict, list)))
        return f"{op} before" + (f" ({keys})" if keys else "")
    if phase == "after_success":
        status = (record.get("outcome") or {}).get("status")
        return f"{op} ok {status}"
    return f"{op} ERROR {_error_code(record.get('error') or {})}"


def _error_code(error: Mapping[str, Any]) -> str | None:
    """The provider's code for a failed call: what the proxy recorded (runs after
    2026-09-22), else recovered from the body it kept (legacy runs recorded "HTTP")."""
    code = error.get("code")
    if code and code != "HTTP":
        return str(code)
    return _aws_error_code(str(error.get("message", ""))) or (str(code) if code else None)


def _aws_error_code(message: str) -> str | None:
    if "<Code>" in message:
        return message.split("<Code>", 1)[1].split("</Code>", 1)[0]
    if message.startswith("{"):
        try:
            payload = json.loads(message)
        except json.JSONDecodeError:
            return None
        for key in ("__type", "code", "Code"):
            value = payload.get(key) if isinstance(payload, dict) else None
            if isinstance(value, str) and value:
                return value.rsplit("#", 1)[-1]
    return None


def _turn_summary(record: Mapping[str, Any]) -> str:
    tool = record.get("tool") or "?"
    preview = (record.get("command") or record.get("input_preview") or "").replace("\n", " ")
    flag = " ERROR" if record.get("is_error") else ""
    if record.get("is_finish"):
        return f"{tool} → finish"
    return f"{tool}{flag}: {preview[:100]}"


def build_timeline(run_dir: Path) -> list[TimelineEntry]:
    run_dir = Path(run_dir)
    events = _read_jsonl(run_dir / "events.jsonl")
    turns = _read_jsonl(run_dir / "agent" / "turns.jsonl")
    started_at = None
    for record in events:
        if record.get("kind") == "run.started":
            started_at = _parse_wall(record.get("wall_time"))
            break
    raw: list[tuple[float, str, str, str, str | None]] = []
    for record in events:
        kind = record.get("kind", "")
        ts = _parse_wall(record.get("wall_time"))
        ref = str(record.get("sequence", ""))
        if kind == "snapshot.observed":
            if ts is None:
                continue  # observations carry no wall time; skipped unless timestamped
            raw.append((ts, "snapshot", kind, _snapshot_summary(record), ref))
        elif kind == "api.lifecycle":
            if ts is None:
                continue
            raw.append((ts, f"api:{record.get('actor_id')}", f"api.{record.get('phase')}", _api_summary(record), ref))
        elif kind in {"trigger.matched", "trigger.failed"}:
            data = record.get("data", {})
            raw.append((ts or 0.0, "trigger", kind,
                        f"{','.join(data.get('trigger_ids', []))} on {data.get('snapshot_id')} "
                        f"→ {','.join(data.get('distractor_ids', []))}", ref))
        elif kind.startswith("distractor."):
            data = record.get("data", {})
            raw.append((ts or 0.0, "distractor", kind, str(data.get("distractor_id")), ref))
        elif kind.startswith("run.") or kind.startswith("submission.") or kind == "api.denied":
            if ts is None:
                continue
            data = record.get("data", {})
            summary = kind if kind != "api.denied" else f"denied {data.get('method')} {data.get('path')}: {data.get('reason')}"
            raw.append((ts, "harness", kind, summary, ref))
    for record in turns:
        ts = record.get("ts")
        if not isinstance(ts, (int, float)):
            continue
        raw.append((float(ts), "agent", "tool_call", _turn_summary(record), f"turn {record.get('turn')}"))
    raw.sort(key=lambda item: item[0])
    base = started_at if started_at is not None else (raw[0][0] if raw else 0.0)
    return [TimelineEntry(ts, round(ts - base, 3), lane, kind, summary, ref) for ts, lane, kind, summary, ref in raw]


def render_text(entries: Iterable[TimelineEntry]) -> str:
    lines = []
    for entry in entries:
        lines.append(f"{entry.t_rel_s:>8.2f}s  {entry.lane:<18} {entry.kind:<22} {entry.summary}")
    return "\n".join(lines)


def compute_metrics(run_dir: Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    events = _read_jsonl(run_dir / "events.jsonl")
    turns = _read_jsonl(run_dir / "agent" / "turns.jsonl")
    started_at = next((_parse_wall(r.get("wall_time")) for r in events if r.get("kind") == "run.started"), None)

    def rel(ts: float | None) -> float | None:
        return None if ts is None or started_at is None else round(ts - started_at, 3)

    api = [r for r in events if r.get("kind") == "api.lifecycle"]
    main_before = [r for r in api if r.get("actor_id") == "main" and r.get("phase") == "before"]
    first_api = rel(_parse_wall(main_before[0]["wall_time"])) if main_before else None

    triggers = [r for r in events if r.get("kind") == "trigger.matched"]
    first_trigger_ts = _parse_wall(triggers[0].get("wall_time")) if triggers else None
    trigger_kinds = sorted({str(r.get("data", {}).get("trigger_kind")) for r in triggers})
    interference_before_finish = any(r.get("data", {}).get("snapshot_id") != "final-observation" for r in triggers)

    # Hold duration: the held call is the main 'before' whose observation_id the trigger names.
    hold_durations = []
    by_call: dict[str, dict[str, float]] = {}
    for r in api:
        ts = _parse_wall(r.get("wall_time"))
        if ts is None:
            continue
        by_call.setdefault(str(r.get("call_id")), {})[str(r.get("phase"))] = ts
    held_event_ids = {r.get("data", {}).get("observation_id") for r in triggers}
    for r in main_before:
        if r.get("event_id") in held_event_ids:
            phases = by_call.get(str(r.get("call_id")), {})
            after = phases.get("after_success") or phases.get("after_error")
            if after and "before" in phases:
                hold_durations.append(round(after - phases["before"], 3))

    errors_seen = []
    for r in api:
        if r.get("actor_id") == "main" and r.get("phase") == "after_error":
            errors_seen.append({"operation": f"{r.get('service')}.{r.get('operation')}",
                                "code": _error_code(r.get("error") or {})})

    calls_by_op: dict[str, dict[str, int]] = {}
    for r in api:
        if r.get("phase") != "before":
            continue
        actor = str(r.get("actor_id"))
        op = f"{r.get('service')}.{r.get('operation')}"
        calls_by_op.setdefault(actor, {})
        calls_by_op[actor][op] = calls_by_op[actor].get(op, 0) + 1

    after_interference_calls = 0
    if first_trigger_ts is not None:
        after_interference_calls = sum(
            1 for r in main_before if (_parse_wall(r.get("wall_time")) or 0) > first_trigger_ts)

    turn_ts = [float(t["ts"]) for t in turns if isinstance(t.get("ts"), (int, float))]
    turns_after = sum(1 for ts in turn_ts if first_trigger_ts is not None and ts > first_trigger_ts)
    finish_turn = next((t for t in turns if t.get("is_finish")), None)
    # Every awareness level's tool, not just `changes`: a level whose tool is named
    # something else would otherwise report zero asks in every run and every report.
    awareness_calls = [t for t in turns
                       if str(t.get("tool", "")).rpartition("__")[2] in AWARENESS_TOOL_NAMES]
    first_awareness = min((float(t["ts"]) for t in awareness_calls if isinstance(t.get("ts"), (int, float))), default=None)
    tool_durations = [t["duration_ms"] for t in turns if isinstance(t.get("duration_ms"), (int, float))]
    # The consult channel's own ledger (consult-summary.json): threads opened, replies
    # delivered, replies that arrived after the ask, and what the agent left unread.
    try:
        consult = json.loads((run_dir / "consult-summary.json").read_text())
    except (OSError, ValueError):
        consult = {}

    return {
        "schema_version": 1,
        "time_to_first_api_call_s": first_api,
        "time_to_trigger_s": rel(first_trigger_ts),
        "trigger_kinds": trigger_kinds,
        "hold_duration_s": hold_durations,
        "interference_before_finish": interference_before_finish if triggers else None,
        "agent_calls_after_interference": after_interference_calls,
        "turns_after_interference": turns_after,
        "api_calls_by_operation": calls_by_op,
        "errors_seen_by_agent": errors_seen,
        "finish_called_at_s": rel(float(finish_turn["ts"])) if finish_turn and isinstance(finish_turn.get("ts"), (int, float)) else None,
        "awareness_tool_calls": len(awareness_calls),
        "first_awareness_call_s": rel(first_awareness),
        "awareness_call_after_interference": bool(first_trigger_ts is not None and first_awareness is not None
                                                  and first_awareness > first_trigger_ts),
        "consult_asks": consult.get("asks"),
        "consult_replies_delivered": consult.get("replies_delivered"),
        "consult_replies_delivered_late": consult.get("replies_delivered_late"),
        "consult_threads_silent": consult.get("threads_silent"),
        "consult_answer_rate": consult.get("answer_rate"),
        "consult_replies_per_ask": consult.get("replies_per_ask"),
        "consult_unread_replies_at_finish": consult.get("unread_replies_at_finish"),
        "tool_calls": len(turns),
        "tool_calls_errored": sum(1 for t in turns if t.get("is_error")),
        "tool_call_median_ms": round(median(tool_durations)) if tool_durations else None,
        "tools_used": sorted({str(t.get("tool")) for t in turns if t.get("tool")}),
        # Execution conflict (harness.analysis.refusal_trace): provider state refusals after the
        # interference began, how long until the refused call went through, and whether the
        # agent cleared the way (delete / cancel / stop) instead of waiting.
        **_refusal_metrics(run_dir),
    }


def _refusal_metrics(run_dir: Path) -> dict[str, Any]:
    from harness.analysis.refusal_trace import run_metrics

    return run_metrics(Path(run_dir) / "events.jsonl")


def write_metrics(run_dir: Path) -> dict[str, Any]:
    metrics = compute_metrics(run_dir)
    (Path(run_dir) / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    return metrics
