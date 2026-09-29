"""Tabulate runs: one row per live cell -> results.csv + summary.md.

Works on a batch directory (``<arm>-<case>-t<N>/result.json``, superseded
``.intN`` dirs skipped) or on a flat runs directory (``artifacts/runs/*``).
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, fields
from pathlib import Path
from statistics import median
from typing import Any, Iterable

from harness.pricing import agent_cost_usd

_PARTIAL = re.compile(r"\.int\d+$")

COLUMNS = [
    "batch", "arm", "case", "trial", "run_id", "agent", "model", "awareness", "modality", "distractors", "status", "verdict",
    "validity", "validity_reason", "error",
    "cost_usd", "input_tokens", "output_tokens", "cache_read_tokens", "num_turns", "tool_calls",
    "duration_s", "api_calls_main", "api_calls_distractor", "denied_tool_calls",
    "trigger_fired", "trigger_kind", "interference_before_finish", "time_to_trigger_s",
    "hold_duration_s", "turns_after_interference", "errors_seen", "awareness_tool_calls",
    "first_awareness_call_s", "consult_asks", "consult_replies_delivered", "consult_replies_delivered_late",
    "consult_unread_replies_at_finish", "consult_answer_rate", "consult_replies_per_ask", "leaked", "distractor_status", "case_dir", "case_status", "run_dir",
]


@dataclass
class Row:
    batch: str | None
    arm: str | None
    case: str | None
    trial: int | None
    run_id: str
    agent: str | None
    model: str | None
    awareness: str | None
    modality: str | None
    distractors: bool | None
    status: str | None
    verdict: str | None
    validity: str | None          # valid | partial | invalid (see classify_validity)
    validity_reason: str | None
    error: str | None
    cost_usd: float | None
    input_tokens: int | None
    output_tokens: int | None
    cache_read_tokens: int | None
    num_turns: int | None
    tool_calls: int | None
    duration_s: float | None
    api_calls_main: int | None
    api_calls_distractor: int | None
    denied_tool_calls: int | None
    trigger_fired: bool | None
    trigger_kind: str | None
    interference_before_finish: bool | None
    time_to_trigger_s: float | None
    hold_duration_s: float | None
    turns_after_interference: int | None
    errors_seen: str | None
    awareness_tool_calls: int | None
    first_awareness_call_s: float | None
    consult_asks: int | None
    consult_replies_delivered: int | None
    consult_replies_delivered_late: int | None
    consult_unread_replies_at_finish: int | None
    consult_answer_rate: float | None
    consult_replies_per_ask: float | None
    leaked: int | None
    distractor_status: str | None     # JSON {id: succeeded|failed|not-fired}, distractor arms only
    case_dir: str | None
    case_status: str | None           # lifecycle.status from the case's task.json (active when absent)
    run_dir: str

    def as_list(self) -> list[Any]:
        return [getattr(self, f.name) for f in fields(self)]


def classify_validity(result: dict[str, Any]) -> tuple[str, str | None]:
    """Whether a run's verdict is a fair measurement of the agent.

    ``invalid``: no verdict could be scored, or the agent CLI died before doing any work
    (model at capacity, usage limit, terraform/apply failure): says nothing about the model.
    ``partial``: a verdict exists but the run deviated from the design — a distractor never
    fired, interference landed after the agent finished, the agent hit the time budget, the
    CLI died after calling finish, or cleanup failed. Score it, but flag it.
    ``valid``: everything else."""
    agent = result.get("agent") or {}
    error = str(agent.get("error") or "")
    if result.get("verdict") is None:
        return "invalid", (result.get("error") or error or "no verdict")[:160]
    if error.startswith("AgentRunnerError") and not agent.get("called_finish"):
        return "invalid", error[:160]
    reasons = []
    if result.get("distractors_enabled"):
        triggers = result.get("triggers") or {}
        fired = triggers.get("fired") or []
        declared = result.get("distractors") or []
        if declared and len(fired) < len(declared):
            reasons.append(f"{len(declared) - len(fired)} of {len(declared)} distractors never fired")
        if result.get("interference_before_finish") is False:
            reasons.append("interference landed after the agent finished")
    if error.startswith("AgentTimeoutError"):
        reasons.append("agent hit the time budget")
    elif error.startswith("AgentRunnerError"):
        reasons.append("agent CLI exited non-zero after calling finish")
    if result.get("status") != "completed":
        reasons.append(f"run status {result.get('status')}: {str(result.get('error') or '')[:80]}")
    if reasons:
        return "partial", "; ".join(reasons)[:200]
    return "valid", None


def row_from_run(run_dir: Path, *, batch: str | None = None, arm: str | None = None,
                 case: str | None = None, trial: int | None = None) -> Row | None:
    result_path = run_dir / "result.json"
    if not result_path.is_file():
        return None
    r = json.loads(result_path.read_text())
    agent = r.get("agent") or {}
    usage = agent.get("usage") or {}
    metrics = r.get("metrics") or {}
    if not metrics and (run_dir / "metrics.json").is_file():
        metrics = json.loads((run_dir / "metrics.json").read_text())
    triggers = r.get("triggers") or {}
    fired = triggers.get("fired") or []
    kinds = triggers.get("fired_kinds") or {}
    api = r.get("api_calls") or {}
    hold = metrics.get("hold_duration_s") or []
    errors = metrics.get("errors_seen_by_agent") or []
    validity, validity_reason = classify_validity(r)
    num_turns = agent.get("num_turns")
    if agent.get("provider") == "codex" and (num_turns in (None, 1)) and (run_dir / "agent" / "events.jsonl").is_file():
        # Runs recorded before the codex adapter counted round trips report 1 turn per session;
        # recount from the event stream so old and new batches are comparable.
        from harness.agents.codex import round_trips  # noqa: PLC0415
        events = []
        for line in (run_dir / "agent" / "events.jsonl").read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        num_turns = round_trips(events) or num_turns
    return Row(
        batch=batch, arm=arm, case=case or (Path(r["case_dir"]).name if r.get("case_dir") else r.get("seed_id")),
        trial=trial, run_id=r.get("run_id", run_dir.name),
        agent=agent.get("provider"), model=agent.get("model") or agent.get("requested_model"),
        awareness=r.get("awareness"), modality=r.get("modality") or "hybrid", distractors=r.get("distractors_enabled"),
        status=r.get("status"), verdict=r.get("verdict"),
        validity=validity, validity_reason=validity_reason,
        error=(r.get("error") or agent.get("error") or None),
        cost_usd=agent_cost_usd(agent), input_tokens=usage.get("input_tokens"),
        output_tokens=usage.get("output_tokens"),
        cache_read_tokens=usage.get("cache_read_input_tokens", usage.get("cached_input_tokens")),
        num_turns=num_turns, tool_calls=agent.get("tool_calls") or metrics.get("tool_calls"),
        duration_s=round(agent["duration_seconds"], 1) if isinstance(agent.get("duration_seconds"), (int, float)) else None,
        api_calls_main=api.get("main"), api_calls_distractor=api.get("distractor"),
        denied_tool_calls=agent.get("permission_denial_count"),
        trigger_fired=bool(fired) if triggers else None,
        trigger_kind=",".join(sorted(set(kinds.values()))) or None,
        interference_before_finish=r.get("interference_before_finish"),
        time_to_trigger_s=metrics.get("time_to_trigger_s"),
        hold_duration_s=hold[0] if hold else None,
        turns_after_interference=metrics.get("turns_after_interference"),
        errors_seen=";".join(f"{e.get('operation')}:{e.get('code')}" for e in errors) or None,
        awareness_tool_calls=metrics.get("awareness_tool_calls"),
        first_awareness_call_s=metrics.get("first_awareness_call_s"),
        consult_asks=metrics.get("consult_asks"),
        consult_replies_delivered=metrics.get("consult_replies_delivered"),
        consult_replies_delivered_late=metrics.get("consult_replies_delivered_late"),
        consult_unread_replies_at_finish=metrics.get("consult_unread_replies_at_finish"),
        consult_answer_rate=metrics.get("consult_answer_rate"),
        consult_replies_per_ask=metrics.get("consult_replies_per_ask"),
        leaked=len(r["leaked"]) if isinstance(r.get("leaked"), list) else None,
        distractor_status=(json.dumps({d: (o or {}).get("status") for d, o in sorted(outcomes.items())}, sort_keys=True)
                           if isinstance((outcomes := r.get("distractor_outcomes")), dict) and outcomes else None),
        case_dir=r.get("case_dir"),
        case_status=case_lifecycle(r.get("case_dir")),
        run_dir=str(run_dir),
    )


def collect_batch(batch_dir: Path) -> list[Row]:
    """One row per live cell dir (``<arm>-<case>-tN/``); ``.intK`` partials skipped.

    Arm/case/trial come from the run's own ``result.json`` metadata, so the
    directory name is only a container, not a parser contract.
    """
    rows: list[Row] = []
    batch = batch_dir.name
    for run_dir in sorted(p for p in batch_dir.iterdir() if p.is_dir()):
        if _PARTIAL.search(run_dir.name) or not (run_dir / "result.json").is_file():
            continue
        meta = json.loads((run_dir / "result.json").read_text())
        row = row_from_run(run_dir, batch=meta.get("batch", batch), arm=meta.get("arm"),
                           case=meta.get("case"), trial=meta.get("trial"))
        if row is not None:
            rows.append(row)
    return rows


def collect_runs(runs_dir: Path) -> list[Row]:
    rows = []
    for run_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        row = row_from_run(run_dir)
        if row is not None:
            rows.append(row)
    return rows


def write_csv(rows: Iterable[Row], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        for row in rows:
            writer.writerow(row.as_list())


def _fmt(value: Any, digits: int = 2) -> str:
    if value is None:
        return "–"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _agg(values: list[Any]) -> tuple[Any, Any, Any]:
    nums = [v for v in values if isinstance(v, (int, float))]
    if not nums:
        return None, None, None
    return median(nums), min(nums), max(nums)


def summarize(rows: list[Row]) -> str:
    groups: dict[tuple[str, str], list[Row]] = {}
    for row in rows:
        groups.setdefault((row.arm or row.agent or "?", row.case or "?"), []).append(row)
    lines = ["| arm | case | n | pass (of scored) | invalid | partial | denied | cost $ med (min–max) | turns med | duration s med | trigger fired | before finish | errors seen | used `changes` |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    stats: dict[tuple[str, str], dict[str, Any]] = {}
    for (arm, case), group in sorted(groups.items()):
        scored = [r for r in group if r.validity != "invalid"]
        n = len(group)
        passed = sum(1 for r in scored if r.verdict == "pass")
        invalid = sum(1 for r in group if r.validity == "invalid")
        partial = sum(1 for r in group if r.validity == "partial")
        cost_med, cost_min, cost_max = _agg([r.cost_usd for r in group])
        turns_med, _, _ = _agg([r.num_turns for r in group])
        dur_med, _, _ = _agg([r.duration_s for r in group])
        fired = sum(1 for r in group if r.trigger_fired)
        before = sum(1 for r in group if r.interference_before_finish)
        errors = sum(1 for r in group if r.errors_seen)
        used = sum(1 for r in group if r.awareness_tool_calls)
        denied = sum(1 for r in group if r.denied_tool_calls)
        stats[(arm, case)] = {"n": n, "pass_rate": passed / len(scored) if scored else None, "cost_med": cost_med}
        status = next((r.case_status for r in group if r.case_status), None)
        shown = case if status in (None, "active") else f"{case} ({status})"
        lines.append(f"| {arm} | {shown} | {n} | {passed}/{len(scored)} | {invalid} | {partial} | {denied}/{n} | {_fmt(cost_med)} ({_fmt(cost_min)}–{_fmt(cost_max)}) "
                     f"| {_fmt(turns_med, 0)} | {_fmt(dur_med, 0)} | {fired}/{n} | {before}/{n} | {errors}/{n} | {used}/{n} |")
    arms_by_case: dict[str, list[str]] = {}
    for arm, case in stats:
        arms_by_case.setdefault(case, []).append(arm)
    shared = {case: arms for case, arms in arms_by_case.items() if len(arms) > 1}
    if shared:
        lines += ["", "## Comparison (treatment − baseline; negative cost delta = better)", "",
                  "| case | baseline | treatment | pass Δ | cost Δ $ |", "|---|---|---|---|---|"]
        for case, arms in sorted(shared.items()):
            base = sorted(arms)[0]
            for arm in sorted(arms)[1:]:
                b, t = stats[(base, case)], stats[(arm, case)]
                pass_delta = None if b["pass_rate"] is None or t["pass_rate"] is None else t["pass_rate"] - b["pass_rate"]
                cost_delta = None if b["cost_med"] is None or t["cost_med"] is None else t["cost_med"] - b["cost_med"]
                lines.append(f"| {case} | {base} | {arm} | {_fmt(pass_delta)} | {_fmt(cost_delta)} |")
    stale = sorted({r.case for r in rows if r.case_status and r.case_status != "active"})
    if stale:
        lines += ["", f"Cases marked stale or retired (kept for these recorded runs, not part of the benchmark set): "
                      + ", ".join(stale)]
    lines += _norms(rows)
    lines += _gaps(rows)
    return "\n".join(lines) + "\n"


# A norm's success or firing rate this far below what certification recorded is an alert;
# so is any program that failed every time it fired, whatever certification said.
NORM_DRIFT = 0.25


def _certification(case_dir: str | None) -> dict[str, Any]:
    if not case_dir:
        return {}
    try:
        return json.loads((Path(case_dir) / "evaluator" / "certification.json").read_text())
    except (OSError, ValueError):
        return {}


def _norms(rows: list[Row]) -> list[str]:
    """Per case and distractor: how often the program fired and succeeded across every
    distractor-on run, next to what certification measured, plus the case's partial rate.

    The oracle drops a norm whose program did not succeed, so a program that quietly
    fails makes its case easier without changing a single verdict's validity. The rates
    are the only place that shows; the alert line is what a batch operator reads.
    """
    per_case: dict[str, dict[str, list[int]]] = {}
    partial: dict[str, list[int]] = {}
    case_dirs: dict[str, str | None] = {}
    for r in rows:
        if r.distractors is False or not r.case:
            continue
        partial.setdefault(r.case, [0, 0])
        partial[r.case][1] += 1
        partial[r.case][0] += r.validity == "partial"
        case_dirs.setdefault(r.case, r.case_dir)
        if not r.distractor_status:
            continue
        try:
            statuses = json.loads(r.distractor_status)
        except ValueError:
            continue
        for did, status in statuses.items():
            fired, succeeded, runs = per_case.setdefault(r.case, {}).setdefault(did, [0, 0, 0])
            per_case[r.case][did] = [fired + (status != "not-fired"), succeeded + (status == "succeeded"), runs + 1]
    if not per_case:
        return []
    out = ["", "## Norms (distractor arms: fired / succeeded per run, against certification)", "",
           "| case | distractor | runs | fired | succeeded | certified fire | certified success | note |",
           "|---|---|---|---|---|---|---|---|"]
    alerts: list[str] = []
    for case in sorted(per_case):
        cert = _certification(case_dirs.get(case))
        cert_fire = cert.get("trigger_rates") or {}
        cert_ok = cert.get("program_success_rates") or {}
        for did, (fired, succeeded, runs) in sorted(per_case[case].items()):
            fire_rate, ok_rate = fired / runs, (succeeded / fired if fired else None)
            note = ""
            if fired and succeeded == 0:
                note = "ALERT program never succeeds"
            elif did in cert_ok and ok_rate is not None and ok_rate < cert_ok[did] - NORM_DRIFT:
                note = f"ALERT success {ok_rate:.2f} vs certified {cert_ok[did]:.2f}"
            elif did in cert_fire and fire_rate < cert_fire[did] - NORM_DRIFT:
                note = f"ALERT fires {fire_rate:.2f} vs certified {cert_fire[did]:.2f}"
            elif not cert:
                note = "no certification.json"
            if note.startswith("ALERT"):
                alerts.append(f"{case}/{did}: {note[6:]}")
            out.append(f"| {case} | {did} | {runs} | {fired}/{runs} | {succeeded}/{max(fired, 1) if fired else 0} "
                       f"| {_fmt(cert_fire.get(did))} | {_fmt(cert_ok.get(did))} | {note} |")
        p_bad, p_n = partial.get(case, [0, 0])
        if p_n and p_bad / p_n > NORM_DRIFT:
            alerts.append(f"{case}: {p_bad}/{p_n} runs partial (a distractor never fired or the agent hit the budget)")
    if alerts:
        out += ["", "**Alerts:**", ""] + [f"- {a}" for a in alerts]
    return out


def case_lifecycle(case_dir: str | None) -> str | None:
    """The case's lifecycle status from its task.json; None when there is no case dir."""
    if not case_dir:
        return None
    try:
        task = json.loads((Path(case_dir) / "agent" / "task.json").read_text())
    except (OSError, ValueError):
        return None
    return str((task.get("lifecycle") or {}).get("status") or "active")


def _rate(group: list[Row]) -> float | None:
    scored = [r for r in group if r.validity != "invalid"]
    return sum(1 for r in scored if r.verdict == "pass") / len(scored) if scored else None


def _gaps(rows: list[Row]) -> list[str]:
    """The two gaps a case must open to be discriminative.

    * interference gap — same model: control (no distractors) minus the
      distractor arm at awareness ``none``. Zero means the distractors are
      decorative for that model.
    * model gap — read across the ``none`` column. It is only interpretable
      where the model's control rate is high: a model that fails *without*
      interference is failing the base task or fighting the harness (see the
      ``denied`` column), not the resolution.
    """
    cells: dict[tuple[str, str, str], list[Row]] = {}
    for r in rows:
        if r.validity == "invalid" or not r.model or not r.case:
            continue
        if r.distractors is False:
            kind = "control"
        elif (r.awareness or "none") == "none":
            kind = "none"
        else:
            continue
        cells.setdefault((r.case, r.model, kind), []).append(r)
    pairs = sorted({(case, model) for case, model, _ in cells})
    if not any((case, model, "control") in cells and (case, model, "none") in cells for case, model in pairs):
        return []
    out = ["", "## Gaps (control − none per model; model gap across the `none` column)", "",
           "| case | model | control | none | interference gap | denied (control/none) | interpretable |",
           "|---|---|---|---|---|---|---|"]
    for case, model in pairs:
        ctl, non = cells.get((case, model, "control"), []), cells.get((case, model, "none"), [])
        c, t = _rate(ctl), _rate(non)
        gap = None if c is None or t is None else c - t
        d_ctl = sum(1 for r in ctl if r.denied_tool_calls)
        d_non = sum(1 for r in non if r.denied_tool_calls)
        interpretable = "yes" if (c is not None and c >= 0.8 and d_ctl == 0 and d_non == 0) else "no"
        out.append(f"| {case} | {model} | {_fmt(c)} (n={len(ctl)}) | {_fmt(t)} (n={len(non)}) | {_fmt(gap)} "
                   f"| {d_ctl}/{d_non} | {interpretable} |")
    return out


def write_report(rows: list[Row], out_dir: Path, *, title: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "results.csv"
    md_path = out_dir / "summary.md"
    write_csv(rows, csv_path)
    md_path.write_text(f"# {title}\n\n{len(rows)} run(s)\n\n" + summarize(rows))
    return csv_path, md_path
