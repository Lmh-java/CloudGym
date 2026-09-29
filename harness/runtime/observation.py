"""Did the agent read a fact? One rule, used live and offline.

The proxy stores every response body the agent received under ``private/api/<call_id>.res``
and journals the call (actor, phase, ``monotonic_ns``) in ``events.jsonl``. A distractor's
outcome records ``landed_ns`` on the same clock and the ``fingerprint`` its program returned.
A fact counts as observed when a response the agent received *after* the program landed
carries the fact's ``seen`` token.

The consult channel asks this live (``RuntimeCoordinator._observed_by_agent``) to decide
whether a citing question is answered. Certification asks it offline, over a finished
reference run, to decide whether a norm is reachable at all through the reads an agent
doing the task actually makes — a fact no response ever carried can only be cited after a
deliberate extra read, and such a case is not certified.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .consult import fingerprint_facts


def fact_pattern(seen: str) -> re.Pattern[bytes]:
    """The byte pattern a response body must match to carry ``seen``. A whole token, case-
    insensitively; a purely numeric fact must additionally sit in value position (after
    ``:``, ``=`` or ``>``) so a retention term of 731 is not found inside a timestamp."""
    needle = re.escape(seen.strip().encode())
    if seen.strip().isdigit():
        return re.compile(rb'[:=>]\s*"?' + needle + rb"(?![0-9A-Za-z])")
    return re.compile(rb"(?<![0-9A-Za-z])" + needle + rb"(?![0-9A-Za-z])", re.IGNORECASE)


def body_carries(body: bytes, seen: str) -> bool:
    return fact_pattern(seen).search(body) is not None


def responses_carrying(api_dir: Path, call_ids: Iterable[str], seen: str) -> str | None:
    """The first of ``call_ids`` whose stored response body carries ``seen``, or None."""
    pattern = fact_pattern(seen)
    for call_id in call_ids:
        try:
            body = (api_dir / f"{call_id}.res").read_bytes()
        except OSError:
            continue
        if pattern.search(body):
            return call_id
    return None


def main_responses(events_path: Path) -> list[tuple[int, str]]:
    """(monotonic_ns, call_id) of the agent's successful calls, from the run's journal."""
    out: list[tuple[int, str]] = []
    try:
        lines = events_path.read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if (event.get("kind") == "api.lifecycle" and event.get("actor_kind") == "main"
                and event.get("phase") == "after_success" and event.get("call_id")):
            out.append((int(event.get("monotonic_ns") or 0), str(event["call_id"])))
    out.sort()
    return out


def observed_fingerprints(run_dir: Path, distractor_summary: Mapping[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Offline: for every program that landed with a fingerprint, which of its facts the
    agent's responses carried after the landing.

    Returns ``{distractor_id: {"facts": {said: seen}, "observed": {seen: call_id | None},
    "unobserved": [seen, ...], "landed_ns": int}}``. Programs with no fingerprint are absent.
    """
    run_dir = Path(run_dir)
    if distractor_summary is None:
        try:
            distractor_summary = json.loads((run_dir / "distractor-summary.json").read_text())
        except (OSError, ValueError):
            distractor_summary = {}
    responses = main_responses(run_dir / "events.jsonl")
    api_dir = run_dir / "private" / "api"
    report: dict[str, dict[str, Any]] = {}
    for did, entry in (distractor_summary or {}).items():
        facts: dict[str, str] = {}
        landed: list[int] = []
        for outcome in (entry or {}).get("outcomes") or []:
            if (outcome or {}).get("status") != "succeeded":
                continue
            facts.update(fingerprint_facts(outcome.get("result")))
            if isinstance(outcome.get("landed_ns"), int):
                landed.append(outcome["landed_ns"])
        if not facts:
            continue
        since = min(landed) if landed else 0
        call_ids = [c for at, c in responses if at >= since]
        observed = {seen: responses_carrying(api_dir, call_ids, seen) for seen in set(facts.values())}
        report[did] = {"facts": facts, "observed": observed,
                       "unobserved": sorted(s for s, c in observed.items() if c is None),
                       "landed_ns": since}
    return report
