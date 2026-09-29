"""Declarative benchmark experiments: YAML spec -> resolved, frozen ``Spec`` -> cells.

    batch: intent-conflict-v1
    artifacts: ../artifacts/experiments     # optional; default artifacts/experiments
    defaults: {agent: claude, timeout: 900, poll_interval: 10}   # intercept defaults to true
    cases:                                  # case dirs (Step 5 layout) or bare seed dirs
      - ../cases/aws/iac-eval-313-cloudwatch-event-rule-001
      - ../seeds/aws/<seed-id>
    arms:
      - name: claude-fable
        model: claude-fable-5
        trials: 3
      - name: codex
        agent: codex
        trials: 2
        cases: [../cases/aws/iac-eval-313-cloudwatch-event-rule-001]   # optional subset
        args: {max_turns: 40}                       # passthrough RunOptions fields

Relative paths resolve against the spec file's directory, so a spec means the
same thing from any working directory. Unknown keys are errors. ``spec_hash``
covers the resolved content minus ``artifacts`` (moving outputs is not drift).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from harness.awareness import AWARENESS_LEVELS

import yaml

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
AGENTS = ("claude", "codex")
TOP_KEYS = {"batch", "artifacts", "defaults", "cases", "cases_from", "arms", "trials_from", "after", "peers"}
ACTIVE_LIFECYCLE = {"active"}          # agent/task.json lifecycle.status values that belong to the set
ARM_KEYS = {"name", "agent", "model", "trials", "cases", "timeout", "poll_interval", "intercept", "awareness", "modality", "distractors", "policy", "args", "hold", "order"}
DEFAULT_KEYS = {"agent", "model", "timeout", "poll_interval", "intercept", "awareness", "modality", "distractors", "policy", "args", "trials", "hold", "order"}
AWARENESS = AWARENESS_LEVELS  # noqa: F401  (spec-facing alias)
MODALITIES = ("hybrid", "iac", "sdk", "cli")   # mirrors harness.runtime.case.MODALITIES
# RunOptions fields the runner owns; a spec may not set them through ``args``.
RESERVED_ARGS = {"seed_id", "case_dir", "agent", "model", "agent_timeout", "run_id", "run_dir", "region",
                 "agent_env", "lifecycle_env", "snapshot_poll_interval", "intercept", "awareness", "modality", "distractors", "metadata",
                 "allowed_services", "upstream_override", "agent_executable"}


class SpecError(ValueError):
    pass


@dataclass(frozen=True)
class CaseRef:
    name: str
    path: Path
    seed_id: str
    case_dir: Path | None       # None for a bare seed


@dataclass(frozen=True)
class Arm:
    name: str
    agent: str
    model: str | None
    trials: int
    cases: tuple[str, ...]      # case names
    timeout: float
    poll_interval: float
    intercept: bool
    awareness: str = "none"
    modality: str = "hybrid"
    distractors: bool = True
    # False: the case's resolution policy is left out of the prompt, with no consult channel
    # either (the EC policy ablation, 2026-09-22). Awareness levels that withhold it anyway
    # (consult) are unaffected.
    policy: bool = True
    args: Mapping[str, Any] = field(default_factory=dict)
    hold: bool = False          # cells are created (queued) but never run until the flag is dropped
    order: int = 0              # scheduling only: pending cells of a higher order run after every lower one


@dataclass(frozen=True)
class Cell:
    """One unit of work: arm x case x trial -> one ``run_case`` invocation."""

    batch: str
    arm: Arm
    case: CaseRef
    trial: int

    @property
    def key(self) -> str:
        return f"{self.arm.name}/{self.case.name}/t{self.trial}"

    @property
    def run_id(self) -> str:
        return f"{self.batch}-{self.arm.name}-{self.case.name}-t{self.trial}"

    @property
    def dir_name(self) -> str:
        return f"{self.arm.name}-{self.case.name}-t{self.trial}"

    def run_dir(self, batch_dir: Path) -> Path:
        return batch_dir / self.dir_name


@dataclass(frozen=True)
class Spec:
    batch: str
    path: Path
    artifacts_dir: Path
    cases: tuple[CaseRef, ...]
    arms: tuple[Arm, ...]
    spec_hash: str
    # Trials this batch runs: trials_from..arm.trials (a batch of trial 2 only: trials 2, trials_from 2).
    trials_from: int = 1
    # Scheduling across batches (``bench watch``), never part of the hash:
    #   after  - specs whose runnable pending cells all go first (a trial-2 batch after trial 1)
    #   peers  - specs whose pending cells share this one's ``order`` levels (Fable last across both)
    after: tuple[Path, ...] = ()
    peers: tuple[Path, ...] = ()

    # -- launches: each `bench run` gets its own stamped directory --------------

    def stable_batch_dir(self) -> Path:
        """``<artifacts>/<batch>/`` — the default target: re-running the same batch
        identifier writes here again, so completed cells are skipped and only new
        or unfinished ones run (the ledger enforces one batch identity per dir).
        Change the ``batch`` name in the spec to start a separate folder."""
        return self.artifacts_dir / self.batch

    def new_batch_dir(self, when: datetime | None = None) -> Path:
        """``<artifacts>/<batch>-<YYYYMMDD-HHMMSS>/`` for an explicitly fresh, stamped launch."""
        stamp = (when or datetime.now(timezone.utc)).strftime("%Y%m%d-%H%M%S")
        return self.artifacts_dir / f"{self.batch}-{stamp}"

    def launches(self) -> list[Path]:
        """Existing launch directories of this batch, oldest first."""
        if not self.artifacts_dir.is_dir():
            return []
        pattern = re.compile(rf"^{re.escape(self.batch)}-\d{{8}}-\d{{6}}$")
        return sorted(p for p in self.artifacts_dir.iterdir() if p.is_dir() and pattern.match(p.name))

    def latest_batch_dir(self) -> Path | None:
        stable = self.stable_batch_dir()
        if stable.is_dir():          # exists as soon as a run/start targets it, before its ledger lands
            return stable
        launches = self.launches()
        return launches[-1] if launches else None

    def case(self, name: str) -> CaseRef:
        return next(c for c in self.cases if c.name == name)

    def cells(self) -> list[Cell]:
        """Trial-major: every arm x case for t1, then t2, ... so an interrupted
        batch still holds one comparable result per cell."""
        out: list[Cell] = []
        most = max((arm.trials for arm in self.arms), default=0)
        for trial in range(self.trials_from, most + 1):
            for arm in self.arms:
                if trial > arm.trials:
                    continue
                for case_name in arm.cases:
                    out.append(Cell(self.batch, arm, self.case(case_name), trial))
        return out

    def resolved(self) -> dict[str, Any]:
        return {
            "batch": self.batch,
            "spec_hash": self.spec_hash,
            "artifacts_dir": str(self.artifacts_dir),
            "cases": [{"name": c.name, "path": str(c.path), "seed_id": c.seed_id,
                       "case_dir": str(c.case_dir) if c.case_dir else None} for c in self.cases],
            "arms": [{"name": a.name, "agent": a.agent, "model": a.model, "trials": a.trials,
                      "cases": list(a.cases), "timeout": a.timeout, "poll_interval": a.poll_interval,
                      "intercept": a.intercept, "awareness": a.awareness, "modality": a.modality,
                      "distractors": a.distractors, "policy": a.policy, "args": dict(a.args)} for a in self.arms],
        }


def _resolve(base: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return (path if path.is_absolute() else base / path).resolve()


def case_lifecycle(case_dir: Path) -> str | None:
    """``lifecycle.status`` of ``<case>/agent/task.json`` (``active`` when absent), ``None``
    when the directory is not a case."""
    task = case_dir / "agent" / "task.json"
    if not task.is_file():
        return None
    try:
        data = json.loads(task.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return str((data.get("lifecycle") or {}).get("status") or "active")


def active_case_dirs(root: Path) -> list[Path]:
    """Case directories under ``root`` whose lifecycle is active, oldest first (by the
    task file's mtime, then name) so an accumulating batch appends rather than reorders."""
    if not root.is_dir():
        raise SpecError(f"'cases_from': no such directory {root}")
    found = []
    for child in root.iterdir():
        if child.is_dir() and NAME_RE.match(child.name) and case_lifecycle(child) in ACTIVE_LIFECYCLE:
            found.append(((child / "agent" / "task.json").stat().st_mtime, child.name, child))
    return [c for _, _, c in sorted(found)]


def _case_ref(base: Path, value: Any, seeds_dir: Path, where: str) -> CaseRef:
    if not isinstance(value, str) or not value:
        raise SpecError(f"{where}: case entries must be directory paths")
    path = _resolve(base, value)
    if not path.is_dir():
        raise SpecError(f"{where}: no such directory {path}")
    name = path.name
    if not NAME_RE.match(name):
        raise SpecError(f"{where}: directory name {name!r} is not a valid case name")
    task = path / "agent" / "task.json"
    if task.is_file():
        try:
            seed_id = json.loads(task.read_text())["seed_id"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise SpecError(f"{where}: {task} lacks a seed_id ({exc})") from None
        case_dir: Path | None = path
    elif (path / "source.json").is_file():
        seed_id, case_dir = name, None
    else:
        raise SpecError(f"{where}: {path} is neither a case dir (agent/task.json) nor a seed dir (source.json)")
    self_contained = case_dir is not None and (case_dir / "initial.tf").is_file()
    if not self_contained and not (seeds_dir / seed_id).is_dir():
        raise SpecError(f"{where}: seed {seed_id!r} not found under {seeds_dir}")
    return CaseRef(name=name, path=path, seed_id=seed_id, case_dir=case_dir)


def _check_keys(mapping: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise SpecError(f"{where}: unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def load_spec(path: Path, *, seeds_dir: Path, default_artifacts: Path) -> Spec:
    path = Path(path).resolve()
    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise SpecError(f"cannot read spec {path}: {exc}") from None
    if not isinstance(raw, Mapping):
        raise SpecError(f"{path}: top level must be a mapping")
    _check_keys(raw, TOP_KEYS, str(path))
    base = path.parent

    batch = raw.get("batch")
    if not isinstance(batch, str) or not NAME_RE.match(batch):
        raise SpecError(f"{path}: 'batch' must be a name matching {NAME_RE.pattern}")
    artifacts_dir = _resolve(base, raw["artifacts"]) if raw.get("artifacts") else default_artifacts.resolve()

    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, Mapping):
        raise SpecError("'defaults' must be a mapping")
    _check_keys(defaults, DEFAULT_KEYS, "defaults")

    case_list = raw.get("cases")
    cases_from = raw.get("cases_from")
    if cases_from is not None:
        # Accumulating batch: every active case dir under the directory, oldest certified
        # first, re-scanned on every load so a watcher picks up new cases without edits.
        if case_list is not None:
            raise SpecError("'cases' and 'cases_from' are mutually exclusive")
        if not isinstance(cases_from, str) or not cases_from:
            raise SpecError("'cases_from' must be a directory path")
        case_list = [str(p) for p in active_case_dirs(_resolve(base, cases_from))]
    elif not isinstance(case_list, list) or not case_list:
        raise SpecError("'cases' must be a non-empty list of directory paths")
    cases: list[CaseRef] = []
    for index, value in enumerate(case_list):
        ref = _case_ref(base, value, seeds_dir, f"cases[{index}]")
        if any(c.name == ref.name for c in cases):
            raise SpecError(f"cases[{index}]: duplicate case name {ref.name!r}")
        cases.append(ref)
    case_names = {c.name: c for c in cases}
    by_path = {c.path: c.name for c in cases}

    arm_list = raw.get("arms")
    if not isinstance(arm_list, list) or not arm_list:
        raise SpecError("'arms' must be a non-empty list")
    arms: list[Arm] = []
    for index, entry in enumerate(arm_list):
        where = f"arms[{index}]"
        if not isinstance(entry, Mapping):
            raise SpecError(f"{where}: must be a mapping")
        _check_keys(entry, ARM_KEYS, where)
        merged: dict[str, Any] = {**defaults, **entry}
        name = merged.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise SpecError(f"{where}: 'name' must match {NAME_RE.pattern}")
        if any(a.name == name for a in arms):
            raise SpecError(f"{where}: duplicate arm name {name!r}")
        agent = merged.get("agent", "claude")
        if agent not in AGENTS:
            raise SpecError(f"{where}: agent must be one of {AGENTS}")
        trials = merged.get("trials", 1)
        if not isinstance(trials, int) or isinstance(trials, bool) or trials < 1:
            raise SpecError(f"{where}: trials must be a positive integer")
        selected = merged.get("cases")
        if selected is None:
            arm_cases = tuple(case_names)
        else:
            if not isinstance(selected, list) or not selected:
                raise SpecError(f"{where}: 'cases' must be a non-empty list of paths from the batch cases")
            arm_cases = []
            for value in selected:
                resolved = _resolve(base, str(value))
                case_name = by_path.get(resolved) or (resolved.name if resolved.name in case_names else None)
                if case_name is None:
                    raise SpecError(f"{where}: case {value!r} is not in the batch 'cases' list")
                arm_cases.append(case_name)
            arm_cases = tuple(arm_cases)
        args = dict(merged.get("args") or {})
        _check_args(args, where)
        awareness = merged.get("awareness", "none")
        if awareness not in AWARENESS:
            raise SpecError(f"{where}: awareness must be one of {AWARENESS}")
        modality = merged.get("modality", "hybrid")
        if modality not in MODALITIES:
            raise SpecError(f"{where}: modality must be one of {MODALITIES}")
        arms.append(Arm(
            name=name, agent=agent, model=merged.get("model"), trials=trials, cases=arm_cases,
            timeout=float(merged.get("timeout", 1800.0)), poll_interval=float(merged.get("poll_interval", 10.0)),
            intercept=bool(merged.get("intercept", True)), awareness=awareness, modality=modality,
            distractors=bool(merged.get("distractors", True)), policy=bool(merged.get("policy", True)), args=args,
            hold=bool(merged.get("hold", False)),   # not in the spec hash: lifting a hold is not drift
            order=_order(merged.get("order", 0), where),   # scheduling only, not in the spec hash
        ))

    trials_from = raw.get("trials_from", 1)
    if not isinstance(trials_from, int) or isinstance(trials_from, bool) or trials_from < 1:
        raise SpecError(f"{path}: trials_from must be a positive integer")
    links = {}
    for key in ("after", "peers"):
        value = raw.get(key) or []
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise SpecError(f"{path}: '{key}' must be a list of spec paths")
        links[key] = tuple(_resolve(base, v) for v in value)
    spec_hash = _spec_hash(batch, cases, arms, trials_from)
    return Spec(batch=batch, path=path, artifacts_dir=artifacts_dir, cases=tuple(cases), arms=tuple(arms),
                spec_hash=spec_hash, trials_from=trials_from, after=links["after"], peers=links["peers"])


def _order(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise SpecError(f"{where}: order must be an integer (higher runs later)")
    return value


def _check_args(args: Mapping[str, Any], where: str) -> None:
    from scripts.run_case import RunOptions  # local import: scripts depends on harness, not vice versa

    fields = set(RunOptions.__dataclass_fields__)
    for key in args:
        if key in RESERVED_ARGS:
            raise SpecError(f"{where}.args: {key!r} is owned by the runner")
        if key not in fields:
            raise SpecError(f"{where}.args: unknown RunOptions field {key!r}")


def _spec_hash(batch: str, cases: list[CaseRef], arms: list[Arm], trials_from: int = 1) -> str:
    norm = {
        "batch": batch,
        **({"trials_from": trials_from} if trials_from != 1 else {}),   # existing hashes unchanged
        "cases": [{"name": c.name, "seed_id": c.seed_id, "case_dir": str(c.case_dir) if c.case_dir else None} for c in cases],
        "arms": [{"name": a.name, "agent": a.agent, "model": a.model, "trials": a.trials, "cases": list(a.cases),
                  "timeout": a.timeout, "poll_interval": a.poll_interval, "intercept": a.intercept,
                  "awareness": a.awareness, "distractors": a.distractors,
                  # Only a non-default modality enters the hash, so every batch recorded
                  # before the arm existed keeps its spec_hash and stays resumable.
                  **({"modality": a.modality} if a.modality != "hybrid" else {}),
                  **({"policy": False} if not a.policy else {}),   # likewise: existing hashes unchanged
                  "args": {str(k): a.args[k] for k in sorted(a.args)}} for a in arms],
    }
    blob = json.dumps(norm, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()
