"""Run a batch: every pending cell, one worker per leased sandbox account, resumably."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import re
import shutil
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Awaitable

from harness.aws_safety import AwsTarget
from harness.netcheck import is_transient_network_error, wait_for_network
from harness.sandbox import Lease, Pool, PoolExhausted, teardown_clean

from .ledger import Ledger, append_event, rename_partial
from .routes import API, BILLING_RE, Route, RouteBook
from .spec import Cell, Spec

REPO_ROOT = Path(__file__).resolve().parents[2]

# Callable building (hooks, before_start) for a cell; injectable for tests.
HooksFactory = Callable[[Cell, Path, "CellEnv"], tuple[Any, Callable[[], Awaitable[Any]] | None]]
# Callable building the per-cell environment for the sandbox the cell was leased (None without a pool).
CellEnvFactory = Callable[[Cell, AwsTarget | None], "CellEnv"]


@dataclass
class CellEnv:
    region: str
    agent_env: dict[str, str]
    lifecycle_env: dict[str, str]
    metadata: dict[str, Any]
    allowed_services: set[str] | None = None
    upstream_override: str | None = None


@dataclass
class BatchResult:
    batch_dir: Path
    ran: list[str]
    outcomes: dict[str, str]
    stopped_reason: str | None = None


# Token/usage exhaustion on the agent's side: the subscription window, an API quota, the
# model at capacity. None of it is a verdict about the model, so such a cell is re-queued
# (status interrupted) and the batch pauses instead of burning every pending cell.
RATE_LIMIT_RE = re.compile(r"usage limit|session limit|weekly limit|hit your .{0,20}limit|reached your .{0,30}limit|"
                           r"rate[ _-]?limit|too many requests|"
                           r"\b429\b|at capacity|overloaded|quota (?:exceeded|reached)|limit reached|resets? (?:at )?\d|"
                           r"insufficient credits|billing", re.I)


def rate_limit_reason(result: dict, run_dir: Path | None = None, pattern: re.Pattern = RATE_LIMIT_RE) -> str | None:
    """The matching text when the cell's agent run died of token exhaustion, else None.

    Looks at the agent summary (``error``, ``stop_reason``) and, for ``claude -p``, at the
    final ``result`` event (``is_error`` + the message, e.g. "Claude AI usage limit reached").
    ``pattern`` swaps the test (the API route also treats a refused key as its route failing)."""
    agent = result.get("agent") or {}
    for text in (str(agent.get("error") or ""), str(agent.get("stop_reason") or "")):
        m = pattern.search(text)
        if m:
            return text[:300]
    events = run_dir / "agent" / "events.jsonl" if run_dir else None
    if events and events.is_file():
        try:
            lines = events.read_text(errors="replace").splitlines()
        except OSError:
            return None
        for line in reversed(lines[-50:]):
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("type") == "result":
                text = str(event.get("result") or event.get("error") or "")
                if event.get("is_error") and pattern.search(text):
                    return text[:300]
                # claude's own status for a spent window, whatever the wording ("You've reached your
                # Fable limit." on 2026-09-24 matched no pattern and was retried 15 times)
                if event.get("is_error") and event.get("api_error_status") == 429 and pattern is RATE_LIMIT_RE:
                    return (text or "api_error_status 429")[:300]
                break
    return None


def describe_cells(spec: Spec, cells: list[Cell], batch_dir: Path | None = None) -> str:
    lines = [f"batch {spec.batch}  ({spec.spec_hash[:19]}…)  → {batch_dir or spec.new_batch_dir()}", ""]
    for cell in cells:
        arm = cell.arm
        lines.append(f"  {cell.key:<48} run_id={cell.run_id}" + ("  [HELD: queued, not run]" if arm.hold else ""))
        lines.append(f"    agent={arm.agent} model={arm.model or '-'} intercept={arm.intercept} awareness={arm.awareness} modality={arm.modality} distractors={arm.distractors} timeout={arm.timeout:g}s "
                     f"poll={arm.poll_interval:g}s seed={cell.case.seed_id} case_dir={cell.case.case_dir or '-'}"
                     + (f" args={json.dumps(dict(arm.args))}" if arm.args else ""))
    return "\n".join(lines)


def select_cells(spec: Spec, only: str | None) -> list[Cell]:
    cells = spec.cells()
    if only:
        cells = [c for c in cells if fnmatch.fnmatch(c.key, only)]
    return cells


def code_identity(repo: Path | None = None) -> dict[str, Any] | None:
    """The commit the harness is running from, and whether the tree is dirty. None when
    the code is not in a git checkout (or git is unavailable)."""
    import subprocess
    repo = repo or REPO_ROOT
    try:
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True,
                              timeout=10)
        status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
                                capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if head.returncode != 0 or status.returncode != 0:
        return None
    return {"commit": head.stdout.strip(), "dirty": bool(status.stdout.strip())}


def code_changed(pinned: dict[str, Any] | None, now: dict[str, Any] | None) -> str | None:
    """Why a cell may not start: the tree is dirty, or HEAD moved since the batch began.
    Every cell is a fresh process reading the working tree, so a batch whose code drifts
    mid-way measures two harnesses under one name."""
    if pinned is None or now is None:
        return None
    if now["dirty"]:
        return "working tree is dirty (commit or stash before running a batch, or pass --allow-dirty)"
    if now["commit"] != pinned["commit"]:
        return f"HEAD moved from {pinned['commit'][:12]} to {now['commit'][:12]} since the batch started"
    return None


async def run_batch(spec: Spec, *, hooks_factory: HooksFactory, cell_env: CellEnvFactory,
                    batch_dir: Path | None = None, only: str | None = None, stop_on_leak: bool = True,
                    pool: Pool | None = None, concurrency: int = 1, log=print,
                    pin_code: bool = False, network_wait_s: float = 1800.0,
                    routes: RouteBook | None = None, force_route: str | None = None,
                    max_order: int | None = None, drain: "threading.Event | None" = None,
                    yield_to: "Callable[[], str | None] | None" = None) -> BatchResult:
    """Run every pending cell into ``batch_dir`` (the stable <batch>/ dir by default, or a stamped
    launch directory when omitted) with ``concurrency`` workers.

    With a ``pool`` each worker leases one sandbox account per cell and releases it clean only
    when the cell's own leak check was clean; a leak (or a cell that died before its teardown
    could be proven) dirties that account and the batch goes on with the rest, stopping only
    when no clean account remains. Without a pool (tests) ``stop_on_leak`` keeps the old
    meaning: the first leak stops the batch. ``hooks_factory`` and ``cell_env`` are the real
    AWS implementations in ``scripts.bench`` and fakes in tests.

    With ``routes`` each cell is given its route (``harness.bench.routes``) before it leases an
    account: claude on the subscription, or on the API fallback while the subscription is spent;
    a cell whose every route is spent waits for the next pass instead of holding an account, and
    a cell that hits a limit marks its route and goes back in the queue (the batch keeps going).

    ``drain`` (set by ``bench stop --drain``): no new cell starts, running cells finish normally,
    and the pass ends with stopped_reason "drained" (nothing interrupted, no account dirtied).

    ``yield_to`` is asked before each new lease; a reason means a batch that goes first (``after:``)
    has cells that can run, so this pass leases nothing more and ends ("yielded: ..."): a batch
    re-leasing every account the moment it frees would otherwise starve it."""
    from scripts.run_case import RunOptions, run_case  # noqa: PLC0415 - scripts depends on harness
    from harness.runtime.case import load_case

    batch_dir = batch_dir or spec.new_batch_dir()
    batch_dir.mkdir(parents=True, exist_ok=True)
    snapshot = batch_dir / "spec.snapshot.yml"
    if not snapshot.exists():
        shutil.copy2(spec.path, snapshot)
    code = code_identity() if pin_code else None
    if pin_code and code is None:
        raise RuntimeError("cannot pin the code: not a git checkout")
    if pin_code and code["dirty"]:
        raise RuntimeError("refusing to start a batch on a dirty working tree; commit or stash first, "
                           "or pass --allow-dirty")
    (batch_dir / "spec.resolved.json").write_text(
        json.dumps({**spec.resolved(), "code": code}, indent=2, sort_keys=True) + "\n")
    cells = select_cells(spec, only)
    ledger = Ledger.open(batch_dir, batch=spec.batch, spec_hash=spec.spec_hash, cells=spec.cells())
    ledger.reconcile_running(spec.cells())
    # Arms with a higher ``order`` run after every lower one (stable: trial-major within an order).
    pending = sorted(ledger.pending(cells), key=lambda c: c.arm.order)
    if max_order is not None:     # higher orders wait for lower-order cells of peer batches (bench watch)
        pending = [c for c in pending if c.arm.order <= max_order]
    concurrency = max(1, min(concurrency, len(pending) or 1))
    append_event(batch_dir, "batch-start", pending=len(pending), selected=len(cells), only=only,
                 concurrency=concurrency, pool=[t.label for t in pool.targets.values()] if pool else None)
    log(f"batch {spec.batch}: {len(pending)} pending of {len(cells)} selected "
        f"({json.dumps(ledger.counts())}); {concurrency} worker(s)")
    from .report import case_lifecycle
    stale = sorted({c.case.name for c in cells if c.case.case_dir
                    and (case_lifecycle(str(c.case.case_dir)) or "active") != "active"})
    if stale:
        log(f"note: {len(stale)} selected case(s) are marked stale/retired and are not part of the benchmark set: "
            + ", ".join(stale))

    queue: deque[Cell] = deque(pending)
    total = len(pending)
    retried: set[str] = set()
    ran: list[str] = []
    outcomes: dict[str, str] = {}
    stopped: list[str] = []            # first entry wins; a list so workers can share it
    stop = asyncio.Event()

    waiting: list[Cell] = []           # this pass: every route of theirs is spent

    async def run_cell(cell: Cell, index: int, target: AwsTarget | None,
                       route: Route | None = None) -> tuple[str, bool | None]:
        """Run one cell; returns (outcome, clean) where clean is None when unknown."""
        run_dir = cell.run_dir(batch_dir)
        moved = rename_partial(run_dir)
        if moved:
            log(f"  moved superseded {moved.name}")
        drift = code_changed(code, code_identity()) if pin_code else None
        if drift:
            # Left pending, not failed: the cell has not run. The batch stops so the
            # operator can commit and resume with every remaining cell on one commit.
            log(f"    refusing {cell.key}: {drift}")
            return "code-changed", True
        ledger.start(cell, run_dir, account=target.label if target else None, route=route.label if route else None)
        where = (f" on {target.label}" if target else "") + (f" via {route.label}" if route and route.name == API else "")
        log(f"[{index}/{total}] {cell.key}{where}  → {run_dir}")
        started = time.monotonic()
        hooks = None
        try:
            spec_case = load_case(cell.case.seed_id, _seeds_dir(), cell.case.case_dir)
            env = cell_env(cell, target)
            if route is not None:
                env.agent_env.update(route.env)
                env.metadata = {**env.metadata, "route": route.label}
            hooks, before_start = hooks_factory(cell, run_dir, env)
            options = RunOptions(
                seed_id=cell.case.seed_id, case_dir=cell.case.case_dir, agent=cell.arm.agent,
                model=route.model(cell.arm.model) if route else cell.arm.model,
                agent_timeout=cell.arm.timeout, run_id=cell.run_id, run_dir=run_dir, region=env.region,
                agent_env=env.agent_env, lifecycle_env=env.lifecycle_env,
                snapshot_poll_interval=cell.arm.poll_interval, intercept=cell.arm.intercept,
                awareness=cell.arm.awareness, modality=cell.arm.modality, distractors=cell.arm.distractors,
                policy=cell.arm.policy,
                allowed_services=env.allowed_services, upstream_override=env.upstream_override,
                metadata={**env.metadata, "batch": spec.batch, "arm": cell.arm.name, "case": cell.case.name,
                          "trial": cell.trial, "spec_hash": spec.spec_hash,
                          "commit": code["commit"] if code else None},
                # Batches are the record: on Linux the agent must be confined and prove it;
                # elsewhere (a laptop smoke test) the run records that it was not.
                sandbox="required" if sys.platform == "linux" else "auto",
                **dict(cell.arm.args),
            )
            outcome = await run_case(spec_case, options, hooks=hooks, before_start=before_start)
        except (KeyboardInterrupt, asyncio.CancelledError):
            ledger.finish(cell, "interrupted", reason="operator interrupt")
            return "interrupted", teardown_clean(run_dir)
        except Exception as exc:  # noqa: BLE001 - a broken cell must not take the batch down
            reason = f"{type(exc).__name__}: {exc}"[:500]
            if is_transient_network_error(reason):
                # The machine lost the network (SSO federation endpoint, DNS): nothing
                # about the account or the agent. Wait for it, then re-queue without
                # spending the cell's one retry. If the seed was deployed, tear it down
                # once the network is back so the account is not dirtied for a blip.
                ledger.finish(cell, "interrupted", reason=f"network: {reason}")
                log(f"    network error, waiting: {reason[:160]}")
                back = await asyncio.to_thread(wait_for_network, timeout_s=network_wait_s, log=log)
                if not back:
                    return "network-down", None if hooks is not None else True
                clean = True if hooks is None else await _teardown_again(hooks, run_dir, log)
                return "retry-free", clean
            if reason.startswith("RuntimeError: sandbox"):
                # The host cannot confine the agent (no bwrap, or the self-test saw a hidden
                # path). Raised before the seed is deployed: the account is untouched, the
                # cell is re-queued, and the operator must fix the host before anything runs.
                ledger.finish(cell, "interrupted", reason=f"sandbox: {reason}"[:500])
                log(f"    SANDBOX UNAVAILABLE, cell re-queued: {reason[:200]}")
                return "retry", True
            if _failed_before_deploy(run_dir):
                # init/plan blew up before any apply: the account is untouched and the
                # cause is local (plugin cache, network), so the cell is re-queued, not failed.
                ledger.finish(cell, "interrupted", reason=f"pre-deploy: {reason}")
                log(f"    pre-deploy error, will retry: {reason[:200]}")
                return "retry", True
            ledger.finish(cell, "failed", reason=reason)
            log(f"    failed: {reason[:300]}")
            return "failed", teardown_clean(run_dir)
        elapsed = round(time.monotonic() - started, 1)
        result = json.loads(outcome.result_path.read_text())
        leaked = result.get("leaked")
        agent_error = str((result.get("agent") or {}).get("error") or "")
        limited = rate_limit_reason(result, run_dir)
        if not limited and route is not None and route.name == API:
            limited = rate_limit_reason(result, run_dir, BILLING_RE)      # a refused key: the route is down
        if limited and routes is not None and route is not None and not (result.get("agent") or {}).get("called_finish"):
            # Spent (or refused): the route waits until its reset; the cell is not a verdict and
            # goes straight back in the queue, where it picks the next open route.
            routes.note_limited(route, limited)
            ledger.finish(cell, "interrupted", reason=f"rate-limited ({route.label}): {limited}"[:500], elapsed_s=elapsed)
            log(f"    {route.label} limited, re-queued: {limited[:160]}")
            return "route-limited", (not leaked) if leaked is not None else None
        if limited and not (result.get("agent") or {}).get("called_finish"):
            ledger.finish(cell, "interrupted", reason=f"rate-limited: {limited}"[:500], elapsed_s=elapsed)
            log(f"    rate-limited, re-queued: {limited[:160]}")
            return "rate-limited", (not leaked) if leaked is not None else None
        if agent_error.startswith("AgentRunnerError") and not (result.get("agent") or {}).get("called_finish"):
            # The agent CLI itself failed before doing any work (model at capacity, account
            # usage limit): that is not a verdict about the model, so the cell is re-queued
            # once instead of recorded as a fail. A CLI that died *after* calling finish is
            # scored (the report flags it partial). Teardown already ran.
            ledger.finish(cell, "interrupted", reason=f"agent runner: {agent_error}"[:500], elapsed_s=elapsed)
            log(f"    agent runner error, will retry: {agent_error[:200]}")
            return "retry", (not leaked) if leaked is not None else None
        status = "done" if outcome.status == "completed" else "failed"
        ledger.finish(cell, status, reason=outcome.error, verdict=outcome.verdict, elapsed_s=elapsed,
                      cost_usd=(result.get("agent") or {}).get("cost_usd"))
        audit = result.get("audit") if isinstance(result.get("audit"), dict) else {}
        if audit.get("contaminated"):
            # The transcript shows a read outside the workspace that delivered something:
            # the sandbox should make that impossible, so this is both a retired cell and
            # a signal the confinement is broken. Kept out of every table until rerun.
            reason = (f"audit: {audit.get('contaminating_reads', audit.get('outside_successes'))} read(s) of "
                      f"{'session records' if audit.get('sandboxed') else 'host files'} outside the workspace")
            ledger.mark_contaminated(cell.key, reason=reason)
            log(f"    CONTAMINATED: {reason}")
        elif audit.get("outside_attempts"):
            log(f"    audit: {audit['outside_attempts']} attempt(s) outside the workspace, none succeeded")
        ran.append(cell.key)
        _refresh_report(batch_dir, spec.batch, log)
        log(f"    {status}: verdict={outcome.verdict} status={outcome.status} "
            f"cost=${(result.get('agent') or {}).get('cost_usd')} {elapsed}s")
        cleanup_error = str(result.get("error") or "")
        if leaked and hooks is not None and is_transient_network_error(cleanup_error):
            # The run itself is scored; only its teardown lost the network. Retry the
            # teardown once the network is back instead of marking the account dirty.
            log(f"    teardown hit a network error{where}; waiting to retry: {cleanup_error[:160]}")
            if await asyncio.to_thread(wait_for_network, timeout_s=network_wait_s, log=log):
                if await _teardown_again(hooks, run_dir, log):
                    leaked = []
        if leaked:
            log(f"    leaked{where}: {leaked}")
        # leaked is None when the run never reached its leak check: unknown, treated as dirty
        return status, (not leaked) if leaked is not None else None

    def should_stop_leasing() -> bool:
        """A drain or a yield arrived: stop waiting for accounts (checked between pool polls)."""
        if drain is not None and drain.is_set():
            return True
        if yield_to is not None:
            why = yield_to()
            if why:
                if not stopped:
                    stopped.append(f"yielded: {why}")
                    log(f"    yielding the accounts: {why}")
                return True
        return False

    async def worker(worker_id: int) -> None:
        nonlocal total
        while queue and not stop.is_set() and not (drain is not None and drain.is_set()):
            if yield_to is not None:
                why = yield_to()
                if why:
                    if not stopped:
                        stopped.append(f"yielded: {why}")
                        log(f"    yielding the accounts: {why}")
                    stop.set()
                    return
            cell = queue.popleft()
            index = total - len(queue)
            route = routes.choose(cell.arm.agent, cell.arm.model, force=force_route) if routes is not None else None
            if routes is not None and route is None:
                waiting.append(cell)          # its routes are spent: no account is leased for it
                continue
            lease: Lease | None = None
            if pool is not None:
                try:
                    lease = await pool.acquire_async(cell.key, run_id=cell.run_id, abort=should_stop_leasing)
                    if lease is None:           # drain/yield arrived while waiting for an account
                        queue.appendleft(cell)
                        stop.set()
                        return
                except PoolExhausted as exc:
                    queue.appendleft(cell)
                    if not stopped:
                        stopped.append(str(exc))
                        log(f"    stopping batch: {exc}")
                    stop.set()
                    return
            try:
                outcome, clean = await run_cell(cell, index, lease.target if lease else None, route)
            except BaseException:
                if lease is not None:
                    pool.release(lease, clean=False, error="worker crashed")
                raise
            outcomes[cell.key] = outcome
            if lease is not None:
                state = pool.release(lease, clean=bool(clean),
                                     error=None if clean else f"{cell.key}: {outcome}, teardown not proven clean")
                if state != "clean":
                    log(f"    {lease.target.label} marked {state}")
            if outcome in ("retry-free", "route-limited"):
                queue.append(cell)
                total += 1
                continue
            if outcome in ("network-down", "code-changed", "rate-limited"):
                if not stopped:
                    stopped.append({"network-down": "network unreachable; resume when it is back",
                                    "code-changed": "code changed under the batch; commit, then resume",
                                    "rate-limited": "rate-limited: agent tokens exhausted; cell re-queued, resume when the window resets"}[outcome])
                    log(f"    stopping batch: {stopped[0]}")
                stop.set()
                return
            if outcome == "retry":
                if cell.key not in retried:
                    retried.add(cell.key)
                    queue.append(cell)
                    total += 1
                else:
                    log(f"    {cell.key}: second harness/agent-runner error; left interrupted for the next resume")
                continue
            if outcome == "interrupted":
                if not stopped:
                    stopped.append("interrupted")
                stop.set()
                return
            if pool is None and clean is False and stop_on_leak:
                if not stopped:
                    stopped.append(f"leak after {cell.key}")
                    log(f"    stopping batch: {stopped[0]}")
                stop.set()
                return

    workers = [asyncio.create_task(worker(i), name=f"bench-worker-{i}") for i in range(concurrency)]
    try:
        await asyncio.gather(*workers)
    except (KeyboardInterrupt, asyncio.CancelledError):
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        if not stopped:
            stopped.append("interrupted")
    if not stopped and drain is not None and drain.is_set() and (queue or waiting):
        stopped.append("drained")
        log(f"drained: {len(queue) + len(waiting)} cell(s) left pending, nothing interrupted")
    stopped_reason = stopped[0] if stopped else None
    if waiting:
        agents = sorted({c.arm.agent for c in waiting})
        log(f"{len(waiting)} cell(s) waiting for a route ({', '.join(agents)}: limit window spent); next pass")
        append_event(batch_dir, "cells-waiting-for-route", count=len(waiting), agents=agents)
    if stopped_reason is None and not ledger.pending(cells):
        append_event(batch_dir, "batch-complete")
    return BatchResult(batch_dir, ran, outcomes, stopped_reason)


async def _teardown_again(hooks, run_dir: Path, log) -> bool:
    """Re-run destroy and the leak check on a cell whose first teardown lost the network.
    Records the attempt in the run directory; returns whether the account is clean."""
    try:
        destroy = await hooks.destroy()
        leak = await hooks.leak_check()
    except Exception as exc:  # noqa: BLE001 - reported; the account stays dirty
        (run_dir / "teardown-retry.json").write_text(json.dumps({"error": f"{type(exc).__name__}: {exc}"[:800]}) + "\n")
        log(f"    teardown retry failed: {str(exc)[:200]}")
        return False
    leaked = (leak or {}).get("leaked")
    (run_dir / "teardown-retry.json").write_text(json.dumps({"destroy": destroy, "leak_check": leak},
                                                            default=str, indent=2) + "\n")
    clean = leaked == []
    log("    teardown retry: clean" if clean else f"    teardown retry: still leaked {leaked}")
    return clean


def _failed_before_deploy(run_dir: Path) -> bool:
    """True when terraform ran (init/plan logs exist) but never reached apply-initial."""
    logs = run_dir / "private" / "terraform-logs"
    if not logs.is_dir():
        return False
    names = [p.name for p in logs.glob("*.log.jsonl")]
    return bool(names) and not any("apply-initial" in n for n in names)


def _refresh_report(batch_dir: Path, batch: str, log) -> None:
    from .report import collect_batch, write_report

    try:
        write_report(collect_batch(batch_dir), batch_dir, title=f"batch {batch}")
    except Exception as exc:  # noqa: BLE001 - reporting never blocks the batch
        log(f"    warning: report not refreshed: {exc}")


def _seeds_dir() -> Path:
    from scripts.run_case import SEEDS_DIR
    return SEEDS_DIR


_COND_ORDER = {"control": 0, "none": 1, "observed": 2, "disclosed": 3}


def _arm_condition(arm) -> str:
    """The interference condition an arm runs under: control (distractors off)
    else its awareness level. Semantic, not parsed from the arm name."""
    if not arm.distractors:
        return "control"
    return arm.awareness if arm.policy else f"{arm.awareness}-no-policy"


def _attempt_detail(entry: dict) -> str:
    last = entry.get("attempts", [])[-1] if entry.get("attempts") else {}
    if not last:
        return ""
    parts = [f"#{last.get('n')} {last.get('outcome') or 'running'}"]
    if last.get("account"):
        parts.append(f"@{last['account']}")
    if last.get("verdict"):
        parts.append(f"verdict={last['verdict']}")
    if last.get("cost_usd") is not None:
        parts.append(f"${last['cost_usd']:.2f}")
    if last.get("reason"):
        parts.append(f"({str(last['reason'])[:70]})")
    return " ".join(parts)


def ledger_counts(batch_dir: Path) -> dict[str, int]:
    """Cells per status in ``<batch>/ledger.json`` (``{}`` when no ledger has landed yet).

    Orphaned cells count under ``"<status> (orphaned)"``, exactly as ``status_text``
    prints them, so dashboards built on either agree.
    """
    path = batch_dir / "ledger.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    counts: dict[str, int] = {}
    for entry in data.get("cells", {}).values():
        status = entry.get("status") or "?"
        if entry.get("orphaned"):
            status += " (orphaned)"
        elif entry.get("held") and status not in ("done", "failed"):
            status += " (held)"
        counts[status] = counts.get(status, 0) + 1
    return counts


def status_text(spec: Spec, batch_dir: Path | None = None) -> str:
    batch_dir = batch_dir or spec.latest_batch_dir()
    if batch_dir is None:
        return f"batch {spec.batch}: no launches under {spec.artifacts_dir}"
    if not (batch_dir / "ledger.json").is_file():
        return f"batch {spec.batch}  {batch_dir}\nno ledger yet"
    data = json.loads((batch_dir / "ledger.json").read_text())
    drift = data.get("spec_hash") != spec.spec_hash
    others = [p.name for p in spec.launches() if p != batch_dir]
    lines = [f"batch {spec.batch}  {batch_dir}" + (f"  (other launches: {', '.join(others)})" if others else ""),
             f"spec_hash {data.get('spec_hash')}" + ("  (DRIFT vs current spec)" if drift else "")]

    arms = {arm.name: arm for arm in spec.arms}
    counts = ledger_counts(batch_dir)
    rows = []
    for key, entry in data.get("cells", {}).items():
        arm_name, _, rest = key.partition("/")
        case_name, _, trial = rest.rpartition("/")
        arm = arms.get(arm_name)
        model = (arm.model if arm and arm.model else arm_name) or "-"
        cond = _arm_condition(arm) if arm else "?"
        status = entry.get("status") or "?"
        if entry.get("orphaned"):
            status += " (orphaned)"
        elif entry.get("held") and status not in ("done", "failed"):
            status += " (held)"
        modality = arm.modality if arm else "?"
        rows.append({"model": model, "cond": cond, "mode": modality, "case": case_name, "trial": trial,
                     "status": status, "detail": _attempt_detail(entry),
                     "sort": (model, _COND_ORDER.get(cond, 9), modality, case_name, trial)})

    rows.sort(key=lambda r: r["sort"])
    headers = {"model": "MODEL", "cond": "COND", "mode": "MODE", "case": "CASE", "trial": "TR", "status": "STATUS"}
    widths = {c: max(len(headers[c]), *(len(r[c]) for r in rows)) if rows else len(headers[c])
              for c in headers}

    def fmt(r) -> str:
        cells = "  ".join(f"{r[c]:<{widths[c]}}" for c in ("model", "cond", "mode", "case", "trial", "status"))
        return f"  {cells}" + (f"  {r['detail']}" if r["detail"] else "")

    lines.append("")
    lines.append("  " + "  ".join(f"{headers[c]:<{widths[c]}}" for c in headers))
    lines.extend(fmt(r) for r in rows)
    lines.append("")
    lines.append("  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return "\n".join(lines)


def print_and_flush(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
