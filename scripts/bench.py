"""Declarative benchmark batches over run-case.

    uv run bench run experiments/<exp>.yml --allow-aws [--only 'arm/case/*'] [--dry-run]
    uv run bench start experiments/<exp>.yml --allow-aws            # same, detached (survives the terminal)
    uv run bench stop experiments/<exp>.yml                         # graceful SIGINT + wait; resumable
    uv run bench logs experiments/<exp>.yml -f
    uv run bench status experiments/<exp>.yml
    uv run bench watch experiments/<exp>.yml --allow-aws   # accumulating: cases_from re-scanned every 2 min;
                                                            # failed/contaminated cells auto-rerun (3 finished attempts)
    uv run bench requeue experiments/<exp>.yml [--dry-run]  # token-exhausted failed cells -> pending
    uv run bench pool                                               # sandbox accounts + leases
    uv run bench report experiments/<exp>.yml | <batch-dir> | --runs-dir artifacts/runs
    uv run bench timeline <run-dir | run-id>
    uv run bench show <run-dir | run-id>
    uv run bench doctor

Every ``bench run`` is a *launch* with its own directory
``<artifacts>/<batch>/`` by default (re-running the same batch resumes in place; --fresh
makes a separate ``<batch>-<YYYYMMDD-HHMMSS>/`` launch); each cell (arm x case x trial) is one
``run_case`` invocation in ``<launch>/<arm>-<case>-t<N>/``. ``--resume`` continues
the latest launch via its ``ledger.json``.

Cells run one per leased sandbox account (``harness/sandbox/pool.py``; ``--slots N`` caps
how many of the configured accounts a batch uses). ``bench start`` is ``bench run`` in its own session, logging to ``<launch>/daemon.log``
with its pid in ``<launch>/daemon.pid`` (plus a ``caffeinate -i -w <pid>`` sidecar on
macOS); ``stop``/``status``/``logs`` read that pid file.
"""

from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone
import asyncio
import json
import re
import signal
import sys
import threading
from pathlib import Path

from harness.analysis import build_timeline, compute_metrics, render_text, write_metrics, write_run_artifacts
from harness.aws_env import scrubbed_environment
from harness.aws_safety import AwsSafetyError, aws_environment, config_path, verify_aws_target
from harness.bench import (
    Ledger,
    CellEnv, DaemonError, SpecError, collect_batch, collect_runs, daemon_state, describe_cells, follow_log,
    load_spec, run_batch, select_cells, start_daemon, status_text, stop_daemon, write_report,
)
from harness.bench.doctor import render, run_checks
from harness.bench.routes import RouteBook, load_fallback
from harness.runtime.case import CaseHooks
from harness.sandbox import Pool, PoolError

try:
    from .common import PLUGIN_CACHE, REPO_ROOT, SCAFFOLD, die
    from .run_case import RUNS_DIR, SEEDS_DIR, _allowed_services, _frozen_credentials, collect_versions
except ImportError:  # direct file invocation
    from common import PLUGIN_CACHE, REPO_ROOT, SCAFFOLD, die
    from run_case import RUNS_DIR, SEEDS_DIR, _allowed_services, _frozen_credentials, collect_versions

EXPERIMENTS_DIR = REPO_ROOT / "artifacts" / "experiments"


def _load(path: Path):
    try:
        return load_spec(path, seeds_dir=SEEDS_DIR, default_artifacts=EXPERIMENTS_DIR)
    except SpecError as exc:
        die(str(exc))


def _resolve_run_dir(value: str) -> Path:
    path = Path(value)
    if path.is_dir():
        return path.resolve()
    candidate = RUNS_DIR / value
    if candidate.is_dir():
        return candidate
    for hit in EXPERIMENTS_DIR.glob(f"*/{value}"):
        if hit.is_dir():
            return hit
    # a batch run id is "<batch>-<arm>-<case>-tN"; the launch dir is "<batch>-<stamp>"
    if EXPERIMENTS_DIR.is_dir():
        for launch in sorted(EXPERIMENTS_DIR.iterdir(), reverse=True):
            batch = launch.name.rsplit("-", 2)[0] if launch.name.count("-") >= 2 else launch.name
            prefix = batch + "-"
            if value.startswith(prefix) and (launch / value[len(prefix):]).is_dir():
                return launch / value[len(prefix):]
    die(f"no run directory for {value!r}")


# -- commands -------------------------------------------------------------------

def _batch_dir_for(spec, args: argparse.Namespace, *, create: bool) -> Path | None:
    """Which launch directory a command addresses.

    ``--batch-dir`` names one explicitly; ``--resume`` (or any read-only command)
    takes the latest launch; otherwise ``run`` starts a fresh stamped one.
    """
    if getattr(args, "batch_dir", None):
        return args.batch_dir.resolve()
    if create and getattr(args, "fresh", False):
        return spec.new_batch_dir()
    if create:
        # Default: the stable <batch>/ dir — re-running the same identifier resumes in
        # place. --resume is now implicit; --fresh forces a separate stamped launch.
        return spec.stable_batch_dir()
    latest = spec.latest_batch_dir()
    if latest is None and create:
        return spec.new_batch_dir()
    return latest


def _open_pool(slots: int | None) -> tuple[Pool, dict[str, dict[str, str]]]:
    """The leasable sandboxes (capped to the first ``slots``), each verified through STS."""
    try:
        pool = Pool.open(REPO_ROOT, limit=slots)
        identities = {}
        for target in pool.targets.values():
            identities[target.account_id] = verify_aws_target(target, aws_environment(target))
    except (AwsSafetyError, PoolError) as exc:
        die(str(exc))
    return pool, identities


def cmd_run(args: argparse.Namespace) -> int:
    spec = _load(args.spec)
    cells = select_cells(spec, args.only)
    batch_dir = _batch_dir_for(spec, args, create=True)
    if args.dry_run:
        print(describe_cells(spec, cells, batch_dir))
        return 0
    if not args.allow_aws:
        die("refusing real AWS execution without --allow-aws")
    _install_drain_handler(lambda m: print(m, file=sys.stderr, flush=True))
    result = _run_spec(spec, batch_dir, args, routes=_route_book(), force_route=getattr(args, "force_route", None))
    if result is None:
        return 130
    print(json.dumps({"batch": spec.batch, "batch_dir": str(result.batch_dir), "ran": len(result.ran),
                      "outcomes": result.outcomes, "stopped": result.stopped_reason}, indent=2))
    return 0 if result.stopped_reason is None else 1


def _route_book(log=lambda m: print(m, file=sys.stderr, flush=True)) -> RouteBook:
    """Routes for this process: claude on the box's login, the configured API fallback while the
    login's window is spent (``harness.bench.routes``). Reading the fallback also scrubs every
    routing secret out of this process's environment, so no cell inherits one by accident."""
    try:
        fallback = load_fallback()
    except ValueError as exc:
        die(str(exc))
    book = RouteBook(config_path(REPO_ROOT).parent, fallback, log=log)
    log(f"routes: claude on the subscription; fallback {fallback.kind if fallback else 'none (cells wait for the reset)'}; "
        "codex on its login (waits for its reset)")
    return book


# `bench stop --drain` sends SIGUSR1: start no new cell, let running cells finish, then exit.
DRAIN = threading.Event()


def _install_drain_handler(log) -> None:
    def on_usr1(signum, frame):  # noqa: ARG001
        if not DRAIN.is_set():
            DRAIN.set()
            log("drain requested: no new cells start; running cells finish, then exit")
    try:
        signal.signal(signal.SIGUSR1, on_usr1)
    except (ValueError, AttributeError):     # not the main thread / no SIGUSR1 (tests, Windows)
        pass


def _run_spec(spec, batch_dir: Path, args: argparse.Namespace, routes: RouteBook | None = None,
              force_route: str | None = None, max_order: int | None = None, yield_to=None):
    """Run every pending cell of ``spec`` into ``batch_dir`` (the body of ``bench run``);
    ``None`` on Ctrl+C. Shared with ``bench watch``."""
    pool, identities = _open_pool(args.slots)
    primary = next(iter(pool.targets.values()))
    region = args.region or primary.region
    print(f"verified {len(pool.targets)} sandbox account(s) in {region}: "
          + ", ".join(f"{t.label}={t.account_id}" for t in pool.targets.values()), file=sys.stderr)
    from harness.runtime.case import load_case

    def cell_env(cell, target) -> CellEnv:
        # Fresh credentials per cell: SSO sessions expire mid-batch (and org-role sessions last 1 h).
        credentials = _frozen_credentials(target.profile, region)
        aws_vars = {**credentials, "AWS_REGION": region, "AWS_DEFAULT_REGION": region,
                    "AWS_EC2_METADATA_DISABLED": "true"}
        lifecycle_env = {**scrubbed_environment(), **aws_vars,
                         "TF_VAR_expected_aws_account_id": target.account_id, "TF_VAR_region": region}
        case_spec = load_case(cell.case.seed_id, SEEDS_DIR, cell.case.case_dir)
        return CellEnv(region=region, agent_env=dict(aws_vars), lifecycle_env=lifecycle_env,
                       metadata={"account": identities[target.account_id]["Account"], "sandbox": target.label,
                                 "versions": collect_versions(cell.arm.agent)},
                       allowed_services=_allowed_services(case_spec))

    def hooks_factory(cell, run_dir: Path, env: CellEnv):
        case_spec = load_case(cell.case.seed_id, SEEDS_DIR, cell.case.case_dir)
        hooks = CaseHooks(case_spec, run_dir=run_dir, region=env.region, env=env.lifecycle_env,
                          scaffold=SCAFFOLD, plugin_cache=PLUGIN_CACHE)
        return hooks.lifecycle_hooks(), hooks.capture_baseline

    try:
        return asyncio.run(run_batch(spec, hooks_factory=hooks_factory, cell_env=cell_env, batch_dir=batch_dir,
                                     only=args.only, pool=pool, concurrency=len(pool.targets),
                                     log=lambda m: print(m, file=sys.stderr, flush=True),
                                     pin_code=not args.allow_dirty, routes=routes, force_route=force_route,
                                     max_order=max_order, drain=DRAIN, yield_to=yield_to))
    except RuntimeError as exc:
        die(str(exc))
    except KeyboardInterrupt:
        print("interrupted; ledger updated, cleanup ran", file=sys.stderr)
        return None


DEFAULT_LIMIT_BACKOFF = "1800,3600"
# `bench watch`: failed (harness fault) and contaminated cells rerun until this many finished attempts.
DEFAULT_AUTO_RERUN = 3


def backoff_schedule(value: str | float) -> list[float]:
    """``--limit-backoff`` as the seconds to sleep after the 1st, 2nd, ... consecutive
    token-exhaustion stop (the last value repeats); a single number is a flat backoff.
    A run that stops for any other reason, or finishes its pass, resets the count."""
    parts = [float(x) for x in str(value).split(",") if x.strip()]
    if not parts or any(x < 0 for x in parts):
        die(f"--limit-backoff: expected non-negative seconds, comma-separated for escalation; got {value!r}")
    return parts


def cmd_watch(args: argparse.Namespace) -> int:
    """Accumulating batch: re-load the spec (``cases_from`` re-scans the case directory),
    run whatever is pending, sleep, repeat. Meant for a spec whose case list grows while
    casegen converts cases; also picks up a raised ``trials``."""
    if not args.allow_aws:
        die("refusing real AWS execution without --allow-aws")
    spec = _load(args.spec)
    batch_dir = _batch_dir_for(spec, args, create=True)
    log = lambda m: print(f"[watch {datetime.now(timezone.utc).strftime('%H:%M:%S')}] {m}", file=sys.stderr, flush=True)  # noqa: E731
    schedule = backoff_schedule(getattr(args, "limit_backoff", DEFAULT_LIMIT_BACKOFF))
    log(f"batch {spec.batch} -> {batch_dir}; every {args.interval:g}s; token-exhaustion backoff "
        + ", ".join(f"{s:g}s" for s in schedule))
    limited_in_a_row = 0
    max_attempts = getattr(args, "auto_rerun", DEFAULT_AUTO_RERUN)
    routes = _route_book(log)
    _install_drain_handler(log)
    while True:
        if DRAIN.is_set():
            log("drained; exiting")
            return 0
        spec = _load(args.spec)
        cells = select_cells(spec, args.only)
        if max_attempts > 1 and (batch_dir / "ledger.json").is_file():
            ledger = Ledger.open(batch_dir, batch=spec.batch, spec_hash=spec.spec_hash, cells=spec.cells())
            requeued, exhausted = ledger.auto_requeue(cells, max_attempts=max_attempts)
            for key, why in requeued:
                log(f"requeued {key}: {why}")
            for key in exhausted:
                log(f"{key}: {max_attempts} finished attempts, left {ledger.status(key)} for a manual look")
        todo = pending_keys(batch_dir, cells)
        held = sum(1 for c in cells if c.arm.hold)
        opened: dict[tuple, bool] = {}
        runnable = runnable_cells(spec, cells, todo, routes, opened)
        unknown = any(k not in {c.key for c in cells} for k in todo)     # counted as runnable
        blocked = _after_gate(spec, routes, opened) if todo else None
        cap = _order_cap(runnable, spec, routes, opened)
        mine = [c for c in runnable if cap is None or c.arm.order <= cap]
        waiting = None
        if todo and blocked:
            waiting = blocked
        elif todo and not mine and not unknown:
            waiting = ("all waiting for a route (limit window spent)" if not runnable
                       else f"order {min(c.arm.order for c in runnable)}+ waits for order-{cap} cells of the peer batches")
        _write_watch_state(batch_dir, waiting)
        if waiting:
            log(f"{len(todo)} pending, waiting: {waiting}; checking again in {args.interval:g}s")
            if not (batch_dir / "ledger.json").is_file():   # the dashboard shows a gated batch's cells too
                Ledger.open(batch_dir, batch=spec.batch, spec_hash=spec.spec_hash, cells=spec.cells())
        elif todo:
            log(f"{len(todo)} pending of {len(cells)} cells over {len(spec.cases)} case(s)"
                + (f", {held} held" if held else "") + "; running")
            result = _run_spec(spec, batch_dir, args, routes=routes, max_order=cap,
                               force_route=getattr(args, "force_route", None),
                               yield_to=_yield_check(spec, routes) if spec.after else None)
            if result is None:
                return 130
            log(f"ran {len(result.ran)}: {result.outcomes}" + (f"; stopped: {result.stopped_reason}" if result.stopped_reason else ""))
            if result.stopped_reason == "drained" or DRAIN.is_set():
                log("drained: running cells finished, nothing interrupted; exiting")
                return 0
            if result.stopped_reason == "interrupted":
                # `bench stop` (SIGINT) landed mid-pass: the runner absorbs it and reports the
                # pass interrupted. That is the operator asking the daemon to go, not a
                # transient stop for --keep-going to ride out.
                log("interrupted by the operator; exiting")
                return 130
            if result.stopped_reason and result.stopped_reason.startswith("rate-limited"):
                pause = schedule[min(limited_in_a_row, len(schedule) - 1)]
                limited_in_a_row += 1
                log(f"backing off {pause:g}s for the usage window (exhaustion {limited_in_a_row} in a row)")
                if args.once:
                    return 1
                try:
                    time.sleep(pause)
                except KeyboardInterrupt:
                    return 130
                continue
            limited_in_a_row = 0
            if result.stopped_reason and not args.keep_going:
                return 1
        else:
            log(f"nothing pending ({len(cells)} cells, {len(spec.cases)} case(s)); waiting for new cases")
        if args.once:
            return 0
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            return 130


def _write_watch_state(batch_dir: Path, waiting: str | None) -> None:
    """``<batch>/watch-state.json``: why a live watch is idle (the dashboard shows it)."""
    batch_dir.mkdir(parents=True, exist_ok=True)
    (batch_dir / "watch-state.json").write_text(json.dumps({"waiting": waiting, "at": round(time.time(), 3)}) + "\n")


def runnable_cells(spec, cells, todo, routes: RouteBook, opened: dict[tuple, bool]) -> list:
    """Pending cells whose route is open now (``opened`` memoises the route book per agent/model)."""
    keys = set(todo)
    out = []
    for c in cells:
        if c.key not in keys:
            continue
        route = (c.arm.agent, c.arm.model)
        if route not in opened:
            opened[route] = routes.choose(*route) is not None
        if opened[route]:
            out.append(c)
    return out


def _linked_runnable(path: Path, routes: RouteBook, opened: dict[tuple, bool]) -> tuple[str, list]:
    other = _load(path)
    other_cells = other.cells()
    return other.batch, runnable_cells(other, other_cells, pending_keys(other.stable_batch_dir(), other_cells),
                                       routes, opened)


def _yield_check(spec, routes: RouteBook, ttl: float = 60.0):
    """``run_batch``'s yield_to for a batch with ``after:`` specs: the after-gate, re-evaluated at
    most every ``ttl`` seconds (it loads specs and ledgers)."""
    state = {"at": 0.0, "why": None}

    def check() -> str | None:
        if time.monotonic() - state["at"] >= ttl:
            state["at"], state["why"] = time.monotonic(), _after_gate(spec, routes, {})
        return state["why"]
    return check


def _after_gate(spec, routes: RouteBook, opened: dict[tuple, bool]) -> str | None:
    """Why this batch must wait: a spec in ``after:`` still has cells that could run now."""
    for path in spec.after:
        batch, cells = _linked_runnable(path, routes, opened)
        if cells:
            return f"{batch} goes first ({len(cells)} runnable cell(s) left)"
    return None


def _order_cap(runnable, spec, routes: RouteBook, opened: dict[tuple, bool]) -> int | None:
    """The lowest ``order`` with a runnable pending cell here or in a ``peers:`` batch: only cells
    up to it run, so e.g. Fable (order 1) starts after every other arm of both configs."""
    orders = {c.arm.order for c in runnable}
    for path in spec.peers:
        orders |= {c.arm.order for c in _linked_runnable(path, routes, opened)[1]}
    return min(orders) if orders else None


def cmd_routes(args: argparse.Namespace) -> int:
    """Where agent cells run right now (subscription / API fallback / waiting), recent switches;
    ``--enable-fallback`` turns the fallback back on after it was switched off (credits added)."""
    from harness.bench.routes import route_status
    state_dir = config_path(REPO_ROOT).parent
    if args.enable_fallback:
        book = RouteBook(state_dir, None, record=False)      # flipping the switch needs no key
        print("fallback re-enabled" if book.enable_fallback() else "fallback was not off")
    status = route_status(state_dir, now=time.time())
    fmt = lambda ts: datetime.fromtimestamp(ts, timezone.utc).strftime("%b %d %H:%M UTC") if ts else "-"  # noqa: E731
    c, x = status["claude"], status["codex"]
    print(f"claude: {c['mode']}  (fallback {c['fallback'] or 'none'}"
          + (f", OFF since {fmt(c['fallback_off']['at'])}: {c['fallback_off']['reason'][:100]}" if c.get("fallback_off") else "")
          + ")")
    for model, m in c["models"].items():
        print(f"  {model}: subscription spent until {fmt(m['until'])} -> {m['mode']}   {str(m.get('reason'))[:90]}")
    if c.get("api"):
        print(f"  api paused until {fmt(c['api']['until'])}: {str(c['api'].get('reason'))[:90]}")
    print(f"codex:  {x['mode']}" + (f" until {fmt(x['limit']['until'])}" if x.get("limit") else ""))
    for e in status["events"][:args.history]:
        print(f"  {fmt(e.get('ts'))}  {e.get('route'):<32} {e.get('event'):<9} {str(e.get('reason') or '')[:80]}")
    return 0


def cmd_requeue(args: argparse.Namespace) -> int:
    """Flip failed/interrupted cells whose last reason looks like token exhaustion (or matches
    ``--match``) back to pending, so the next run/watch pass retries them."""
    from harness.bench.runner import RATE_LIMIT_RE
    spec = _load(args.spec)
    batch_dir = _batch_dir_for(spec, args, create=False)
    if batch_dir is None or not (batch_dir / "ledger.json").is_file():
        die(f"batch {spec.batch}: no ledger yet")
    pattern = re.compile(args.match, re.I) if args.match else RATE_LIMIT_RE
    ledger = Ledger.open(batch_dir, batch=spec.batch, spec_hash=spec.spec_hash, cells=spec.cells())
    flipped = []
    for key, entry in ledger.data["cells"].items():
        if entry.get("orphaned"):
            continue
        case_re = re.compile(args.case) if getattr(args, "case", None) else None
        if case_re is not None:
            # A case was changed (fixture, wording): every finished cell of it reruns.
            if entry.get("status") not in ("done", "failed", "interrupted", "contaminated") or not case_re.search(key):
                continue
            flipped.append((key, f"{entry.get('status')}; case changed"))
            if not args.dry_run:
                ledger.requeue(key, reason=f"requeue: case changed ({args.case})")
            continue
        if getattr(args, "contaminated", False):
            if entry.get("status") != "contaminated":
                continue
            flipped.append((key, str((entry.get("contaminated") or {}).get("reason") or "contaminated")))
            if not args.dry_run:
                ledger.requeue(key, reason="requeue: contaminated cell released for rerun")
            continue
        if entry.get("status") not in ("failed", "interrupted"):
            continue
        last = entry["attempts"][-1] if entry.get("attempts") else {}
        reason = str(last.get("reason") or "")
        if args.all or pattern.search(reason):
            flipped.append((key, reason))
            if not args.dry_run:
                ledger.requeue(key, reason=f"requeue: {reason[:120]}")
    for key, reason in flipped:
        print(f"  {'would requeue' if args.dry_run else 'requeued'} {key}  ({reason[:90]})")
    print(f"{len(flipped)} cell(s) {'matched' if args.dry_run else 'requeued'} in {batch_dir}", file=sys.stderr)
    return 0


def pending_keys(batch_dir: Path, cells) -> list[str]:
    """Cell keys the next run would execute, from the ledger on disk without touching it
    (unknown cells count as pending, like ``Ledger.open`` would create them)."""
    try:
        data = json.loads((batch_dir / "ledger.json").read_text())
    except (OSError, ValueError):
        data = {"cells": {}}
    entries = data.get("cells", {})
    return [c.key for c in cells if not c.arm.hold
            and entries.get(c.key, {}).get("status", "pending") in {"pending", "interrupted"}]


def _run_argv(args: argparse.Namespace, batch_dir: Path) -> list[str]:
    """The foreground ``bench run`` a detached start re-invokes, pinned to ``batch_dir``."""
    mode = "watch" if getattr(args, "watch", False) else "run"
    argv = [sys.executable, "-m", "scripts.bench", mode, str(args.spec.resolve()), "--allow-aws",
            "--batch-dir", str(batch_dir)]
    if mode == "watch":
        argv += ["--interval", str(args.interval), "--keep-going", "--limit-backoff", str(args.limit_backoff),
                 "--auto-rerun", str(getattr(args, "auto_rerun", DEFAULT_AUTO_RERUN))]
    if args.only:
        argv += ["--only", args.only]
    if args.region:
        argv += ["--region", args.region]
    if args.slots:
        argv += ["--slots", str(args.slots)]
    if args.allow_dirty:
        argv.append("--allow-dirty")
    if getattr(args, "force_route", None):
        argv += ["--force-route", args.force_route]
    return argv


def cmd_start(args: argparse.Namespace) -> int:
    spec = _load(args.spec)
    if not args.allow_aws:
        die("refusing real AWS execution without --allow-aws")
    batch_dir = _batch_dir_for(spec, args, create=True)
    try:
        state = start_daemon(_run_argv(args, batch_dir), batch_dir, cwd=REPO_ROOT, caffeinate=not args.no_caffeinate)
    except DaemonError as exc:
        die(f"batch {spec.batch}: {exc}")
    print(f"batch {spec.batch}: {state.describe()}", file=sys.stderr)
    print(f"  uv run bench status {args.spec}\n  uv run bench logs {args.spec} -f\n  uv run bench stop {args.spec}",
          file=sys.stderr)
    if args.follow:
        return follow_log(batch_dir, lines=20, follow=True)
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    spec = _load(args.spec)
    batch_dir = _batch_dir_for(spec, args, create=False)
    if batch_dir is None:
        die(f"batch {spec.batch} has no launches under {spec.artifacts_dir}")
    before = daemon_state(batch_dir)
    if not before.alive:
        print(f"batch {spec.batch}: {before.describe()}", file=sys.stderr)
        stop_daemon(batch_dir)          # clears a stale pid file
        return 0
    drain = getattr(args, "drain", False)
    timeout = args.timeout if args.timeout is not None else (5400.0 if drain else 900.0)
    if drain:
        print(f"batch {spec.batch}: draining (no new cells; running ones finish, up to {timeout:g}s)", file=sys.stderr)
    state = stop_daemon(batch_dir, timeout=timeout, sig=signal.SIGUSR1 if drain else signal.SIGINT,
                        log=lambda m: print(m, file=sys.stderr, flush=True))
    args.timeout = timeout
    if state.alive:
        print(f"batch {spec.batch}: still {state.describe()} after {args.timeout:g}s; it keeps shutting down "
              f"(re-run `bench stop` to wait more)", file=sys.stderr)
        return 1
    print(f"batch {spec.batch}: stopped; `bench start` resumes it", file=sys.stderr)
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    spec = _load(args.spec)
    batch_dir = _batch_dir_for(spec, args, create=False)
    if batch_dir is None:
        die(f"batch {spec.batch} has no launches under {spec.artifacts_dir}")
    return follow_log(batch_dir, lines=args.lines, follow=args.follow)


def cmd_status(args: argparse.Namespace) -> int:
    spec = _load(args.spec)
    batch_dir = _batch_dir_for(spec, args, create=False)
    print(status_text(spec, batch_dir))
    if batch_dir is not None:
        print(f"daemon {daemon_state(batch_dir).describe()}")
    try:
        counts = Pool.open(REPO_ROOT).counts()
        print("pool   " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    except (AwsSafetyError, PoolError):
        pass
    return 0


def cmd_pool(args: argparse.Namespace) -> int:
    try:
        pool = Pool.open(REPO_ROOT)
    except (AwsSafetyError, PoolError) as exc:
        die(str(exc))
    print(pool.describe())
    print("  " + " ".join(f"{k}={v}" for k, v in sorted(pool.counts().items())))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    if args.runs_dir:
        rows = collect_runs(args.runs_dir.resolve())
        out_dir = args.out or args.runs_dir.resolve()
        title = f"runs in {args.runs_dir}"
    else:
        target = args.target
        if target.is_dir() and not target.suffix:
            batch_dir = target.resolve()
        else:
            spec = _load(target)
            batch_dir = _batch_dir_for(spec, args, create=False)
            if batch_dir is None:
                die(f"batch {spec.batch} has no launches under {spec.artifacts_dir}")
        rows = collect_batch(batch_dir)
        out_dir = args.out or batch_dir
        title = f"batch {batch_dir.name}"
    csv_path, md_path = write_report(rows, out_dir, title=title)
    print(md_path.read_text())
    print(f"wrote {csv_path} and {md_path}", file=sys.stderr)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Audit every cell's transcript for reads outside its workspace (harness/bench/audit.py):
    writes agent/audit.json per cell, prints a per-arm summary, and with --mark retires the
    contaminated cells in the ledger (excluded from every table until `requeue --contaminated`)."""
    from harness.bench.audit import audit_run, summarize, write_audit
    from harness.bench.report import _PARTIAL

    target = args.target
    spec = None
    if target.is_dir() and not target.suffix:
        batch_dir = target.resolve()
    else:
        spec = _load(target)
        batch_dir = _batch_dir_for(spec, args, create=False)
        if batch_dir is None:
            die(f"batch {spec.batch} has no launches under {spec.artifacts_dir}")
    audits = {}
    for run_dir in sorted(p for p in batch_dir.iterdir() if p.is_dir()):
        if _PARTIAL.search(run_dir.name):
            continue
        audit = audit_run(run_dir)
        if audit is None:
            continue
        write_audit(run_dir, audit)
        audits[run_dir.name] = audit
    summary = summarize(audits)
    if args.json:
        print(json.dumps({name: a.as_dict() for name, a in audits.items()}, indent=2, sort_keys=True))
    else:
        print(f"{'arm':28} {'cells':>5} {'attempted':>9} {'contaminated':>12} {'sensitive':>9}")
        for arm, row in sorted(summary["arms"].items()):
            print(f"{arm:28} {row['cells']:5} {row['attempted']:9} {row['contaminated']:12} {row['sensitive']:9}")
        t = summary["total"]
        print(f"{'total':28} {t['cells']:5} {t['attempted']:9} {t['contaminated']:12} {t['sensitive']:9}")
        for name, audit in sorted(audits.items()):
            if audit.contaminated:
                reads = audit.contaminating
                print(f"  {name}: {len(reads)} contaminating read(s), e.g. {reads[0].kind} {reads[0].path}")
    if args.mark or args.clear:
        if spec is None:
            spec_path = batch_dir.parent.parent.parent / "experiments" / f"{batch_dir.name}.yml"
            if not spec_path.is_file():
                die("--mark needs the batch spec: pass the .yml instead of the directory")
            spec = _load(spec_path)
        ledger = Ledger.open(batch_dir, batch=spec.batch, spec_hash=spec.spec_hash, cells=spec.cells())
        by_run_dir = {}
        for key, entry in ledger.data["cells"].items():
            for attempt in entry.get("attempts") or []:
                if attempt.get("run_dir"):
                    by_run_dir[Path(attempt["run_dir"]).name] = key
        marked = cleared = 0
        for name, audit in audits.items():
            key = by_run_dir.get(name)
            if not key:
                continue
            if args.mark and audit.contaminated:
                reads = audit.contaminating
                reason = f"audit: {len(reads)} read(s) of {'session records' if audit.sandboxed else 'host files'} outside the workspace"
                if ledger.mark_contaminated(key, reason=reason):
                    marked += 1
            elif args.clear and not audit.contaminated:
                if ledger.clear_contamination(key, run_dir_name=name,
                                              reason=f"audit schema {audit.schema_version}: no contaminating read"):
                    cleared += 1
        print(f"marked {marked}, cleared {cleared} cell(s) in {ledger.path}", file=sys.stderr)
    return 0


def cmd_timeline(args: argparse.Namespace) -> int:
    run_dir = _resolve_run_dir(args.run)
    entries = build_timeline(run_dir)
    print(render_text(entries))
    if args.metrics:
        print(json.dumps(compute_metrics(run_dir), indent=2, sort_keys=True))
    if args.write:
        write_metrics(run_dir)
        written = write_run_artifacts(run_dir)
        print("wrote " + ", ".join(str(p) for p in written.values()), file=sys.stderr)
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    run_dir = _resolve_run_dir(args.run)
    result = json.loads((run_dir / "result.json").read_text())
    agent = result.get("agent") or {}
    essentials = {
        "run_id": result.get("run_id"), "status": result.get("status"), "verdict": result.get("verdict"),
        "error": result.get("error"), "agent": {k: agent.get(k) for k in
            ("provider", "model", "num_turns", "tool_calls", "cost_usd", "duration_seconds",
             "permission_denial_count", "called_finish", "stop_reason", "partial")},
        "triggers": (result.get("triggers") or {}).get("fired"),
        "interference_before_finish": result.get("interference_before_finish"),
        "api_calls": result.get("api_calls"), "leaked": result.get("leaked"),
        "metrics": {k: (result.get("metrics") or {}).get(k) for k in
                    ("time_to_trigger_s", "hold_duration_s", "turns_after_interference", "errors_seen_by_agent")},
        "transcript": (run_dir / (agent.get("transcript") or {}).get("markdown", "")).as_posix() if agent.get("transcript") else None,
        "run_dir": str(run_dir),
    }
    print(json.dumps(essentials, indent=2, default=str))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    checks = run_checks(REPO_ROOT)
    print(render(checks))
    return 1 if any(c.status == "FAIL" for c in checks) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="run (or resume) every pending cell of a batch")
    p.add_argument("spec", type=Path)
    p.add_argument("--allow-aws", action="store_true")
    p.add_argument("--only", help="glob over cell keys, e.g. 'claude-fable/*/t1'")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--region")
    p.add_argument("--resume", action="store_true",
                   help="(kept for compatibility; runs now resume the stable <batch>/ dir by default)")
    p.add_argument("--fresh", action="store_true",
                   help="start a separate timestamped launch instead of the stable <batch>/ dir")
    p.add_argument("--batch-dir", type=Path, help="continue this specific launch directory")
    p.add_argument("--slots", type=int, help="use only the first N configured sandbox accounts (default: all)")
    p.add_argument("--allow-dirty", action="store_true",
                   help="run on a dirty tree / let HEAD move mid-batch (development only; cells then record no commit)")
    p.add_argument("--force-route", choices=("api",), help="claude cells skip the subscription (smoke-test the fallback)")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("start", help="`run` detached: survives the terminal; see stop/status/logs")
    p.add_argument("spec", type=Path)
    p.add_argument("--allow-aws", action="store_true")
    p.add_argument("--only", help="glob over cell keys, e.g. 'claude-fable/*/t1'")
    p.add_argument("--region")
    p.add_argument("--fresh", action="store_true", help="start a separate timestamped launch")
    p.add_argument("--batch-dir", type=Path, help="continue this specific launch directory")
    p.add_argument("--slots", type=int, help="use only the first N configured sandbox accounts (default: all)")
    p.add_argument("--allow-dirty", action="store_true",
                   help="run on a dirty tree / let HEAD move mid-batch (development only; cells then record no commit)")
    p.add_argument("--force-route", choices=("api",), help="claude cells skip the subscription and run on the API fallback")
    p.add_argument("--no-caffeinate", action="store_true", help="do not hold off idle sleep (macOS)")
    p.add_argument("-f", "--follow", action="store_true", help="then tail the daemon log")
    p.add_argument("--watch", action="store_true", help="detach `bench watch` instead of `run` (accumulating batch)")
    p.add_argument("--interval", type=float, default=120.0, help="with --watch: seconds between re-scans")
    p.add_argument("--auto-rerun", type=int, default=DEFAULT_AUTO_RERUN, metavar="N",
                   help=f"with --watch: rerun failed/contaminated cells up to N finished attempts (default "
                        f"{DEFAULT_AUTO_RERUN}; 1 turns it off)")
    p.add_argument("--limit-backoff", default=DEFAULT_LIMIT_BACKOFF,
                   help="with --watch: seconds to pause after each consecutive token exhaustion, comma-separated "
                        f"(default {DEFAULT_LIMIT_BACKOFF}: 30 min, then 1 h onward)")
    p.set_defaults(fn=cmd_start)

    p = sub.add_parser("watch", help="accumulating batch: re-scan cases_from, run pending, sleep, repeat")
    p.add_argument("spec", type=Path)
    p.add_argument("--allow-aws", action="store_true")
    p.add_argument("--only", help="glob over cell keys")
    p.add_argument("--region")
    p.add_argument("--batch-dir", type=Path, help="continue this specific launch directory")
    p.add_argument("--slots", type=int, help="use only the first N configured sandbox accounts (default: all)")
    p.add_argument("--allow-dirty", action="store_true", help="run without a commit pin (development checkouts or source archives)")
    p.add_argument("--interval", type=float, default=120.0, help="seconds between re-scans (default 120)")
    p.add_argument("--auto-rerun", type=int, default=DEFAULT_AUTO_RERUN, metavar="N",
                   help=f"rerun failed (harness fault) and contaminated cells until N finished attempts "
                        f"(default {DEFAULT_AUTO_RERUN}; 1 turns it off); interruptions never count")
    p.add_argument("--force-route", choices=("api",), help="claude cells skip the subscription and run on the API fallback")
    p.add_argument("--once", action="store_true", help="one pass, then exit")
    p.add_argument("--keep-going", action="store_true",
                   help="keep watching after a run stops early (pool exhausted, network); default: exit 1")
    p.add_argument("--limit-backoff", default=DEFAULT_LIMIT_BACKOFF,
                   help="seconds to wait after each consecutive token-exhaustion stop, comma-separated "
                        f"(default {DEFAULT_LIMIT_BACKOFF}: 30 min, then 1 h onward)")
    p.set_defaults(fn=cmd_watch)

    p = sub.add_parser("routes", help="where agent cells run now: subscription / API fallback / waiting")
    p.add_argument("--enable-fallback", action="store_true", help="turn the API fallback back on after it was switched off")
    p.add_argument("--history", type=int, default=10)
    p.set_defaults(fn=cmd_routes)

    p = sub.add_parser("requeue", help="failed/interrupted cells that died of token exhaustion -> pending")
    p.add_argument("spec", type=Path)
    p.add_argument("--match", help="regex over the last attempt's reason (default: the rate-limit patterns)")
    p.add_argument("--all", action="store_true", help="every failed/interrupted cell, whatever the reason")
    p.add_argument("--contaminated", action="store_true",
                   help="release cells retired by `bench audit --mark` for a rerun (once the sandbox is in place)")
    p.add_argument("--case", metavar="REGEX",
                   help="every finished cell whose key matches (the case was changed and must rerun)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--batch-dir", type=Path)
    p.set_defaults(fn=cmd_requeue)

    p = sub.add_parser("audit", help="transcript audit: reads outside the agent workspace; --mark retires them")
    p.add_argument("target", type=Path, help="batch spec (.yml) or batch directory")
    p.add_argument("--mark", action="store_true", help="set contaminated cells to `contaminated` in the ledger")
    p.add_argument("--clear", action="store_true",
                   help="cells marked contaminated whose latest attempt the audit now finds clean go back to done/failed")
    p.add_argument("--json", action="store_true", help="print the per-cell audits as JSON")
    p.add_argument("--batch-dir", type=Path)
    p.set_defaults(fn=cmd_audit)

    p = sub.add_parser("stop", help="SIGINT the detached batch (ledger + AWS teardown) and wait; --drain lets running cells finish")
    p.add_argument("spec", type=Path)
    p.add_argument("--batch-dir", type=Path)
    p.add_argument("--drain", action="store_true",
                   help="start no new cell, let running cells finish normally, then exit (for restarts: nothing is "
                        "interrupted, no account dirtied); stop several batches with --drain at once")
    p.add_argument("--timeout", type=float, default=None,
                   help="seconds to wait (default 900; 5400 with --drain, the longest cell)")
    p.set_defaults(fn=cmd_stop)

    p = sub.add_parser("logs", help="daemon.log of the latest launch")
    p.add_argument("spec", type=Path)
    p.add_argument("--batch-dir", type=Path)
    p.add_argument("-n", "--lines", type=int, default=50)
    p.add_argument("-f", "--follow", action="store_true")
    p.set_defaults(fn=cmd_logs)

    p = sub.add_parser("pool", help="sandbox account pool: lease state per account")
    p.set_defaults(fn=cmd_pool)

    p = sub.add_parser("status", help="ledger dashboard + daemon state (latest launch)")
    p.add_argument("spec", type=Path)
    p.add_argument("--batch-dir", type=Path)
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("report", help="results.csv + summary.md")
    p.add_argument("target", type=Path, nargs="?", help="spec file or batch dir")
    p.add_argument("--runs-dir", type=Path, help="tabulate a flat runs directory instead")
    p.add_argument("--batch-dir", type=Path, help="a specific launch (default: latest)")
    p.add_argument("--out", type=Path)
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("timeline", help="chronological events of one run")
    p.add_argument("run", help="run dir or run id")
    p.add_argument("--metrics", action="store_true")
    p.add_argument("--write", action="store_true", help="(re)generate metrics.json, timeline.txt/svg, summary.md")
    p.set_defaults(fn=cmd_timeline)

    p = sub.add_parser("show", help="essentials of one run")
    p.add_argument("run")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("doctor", help="check prerequisites")
    p.set_defaults(fn=cmd_doctor)

    args = parser.parse_args(argv)
    if args.command == "report" and not args.target and not args.runs_dir:
        parser.error("report needs a spec/batch dir or --runs-dir")
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
