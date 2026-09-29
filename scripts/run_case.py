"""Run a coding agent against one seed (+ optional case dir) on real AWS.

    uv run run-case <seed-id> [--case-dir cases/aws/<case>] --agent claude --allow-aws

The driver owns the whole run in one process:

    baseline capture -> deploy initial (terraform) -> S0 -> serve MCP `finish`
    -> launch agent with AWS credentials -> poll snapshots / fire distractors
    -> finish (final snapshot, oracle) -> destroy -> leak check -> result.json

The harness selects the sandbox through ``.cloudgym/aws.local.toml``.
By default, the agent receives dummy credentials and its AWS calls pass through
the instrumented proxy. Everything is written under ``artifacts/runs/<run-id>/``.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from harness.agents import AgentCall, AgentResult, AgentRunner, AgentRunnerError, AgentTimeoutError
from harness.aws_env import credential_environment, scrubbed_environment
from harness.aws_safety import AwsSafetyError, aws_environment, load_aws_target, verify_aws_target
from harness.awareness import AWARENESS_LEVELS, AWARENESS_TOOLS, POLICY_WITHHELD  # noqa: E402
from harness.runtime.consult import excluded_terms  # noqa: E402
from harness.mcp.server import BackgroundServer, create_server
from harness.proxy import Actor, ApiProxy, credentials_from_env, dummy_credential_environment
from harness.runtime.case import (
    CaseError,
    CaseHooks,
    CaseSpec,
    build_prompt,
    declared_invariants,
    declared_triggers,
    distractor_definitions,
    invariant_definitions,
    load_case,
)
from harness.runtime.coordinator import LifecycleHooks, RuntimeConfig, RuntimeCoordinator
from harness.runtime.distractors import DistractorDefinition
from harness.runtime.events import ActorKind
from harness.analysis import write_metrics, write_run_artifacts

try:
    from .common import PLUGIN_CACHE, REPO_ROOT, SCAFFOLD, die, now_utc
except ImportError:  # direct file invocation
    from common import PLUGIN_CACHE, REPO_ROOT, SCAFFOLD, die, now_utc

SEEDS_DIR = REPO_ROOT / "seeds" / "aws"
RUNS_DIR = REPO_ROOT / "artifacts" / "runs"
MCP_SERVER_NAME = "cloudgym"


@dataclass
class RunOptions:
    seed_id: str
    case_dir: Path | None
    agent: str
    model: str | None
    agent_timeout: float
    run_id: str
    run_dir: Path
    region: str
    agent_env: dict[str, str]
    lifecycle_env: dict[str, str]
    snapshot_poll_interval: float = 10.0
    distractor_timeout: float = 120.0
    agent_executable: str | None = None
    # Allowlist: unrestricted Bash, workspace file tools, and only the harness
    # `finish` tool; everything else (Agent, Skill, WebFetch, ...) is denied by
    # `dontAsk`. Bash is deliberately not prefix-scoped: the earlier
    # `Bash(aws:*)`-style list denied every heredoc, `VAR=... cmd`, `for`,
    # `set -e`, `export` and `cd x && ...` the agents wrote (100+ denials in the
    # first batches) and weaker models spiralled on the denials — a harness
    # artifact that contaminated the model comparison. The agent only ever
    # holds scoped sandbox credentials, so the shell itself is not the boundary.
    extra_allowed_tools: tuple[str, ...] = (
        "Bash",
        "Read", "Write", "Edit", "Glob", "Grep",
        f"mcp__{MCP_SERVER_NAME}__finish",
    )
    metadata: dict[str, Any] = field(default_factory=dict)
    # Route actors through the interception proxy with dummy credentials.
    intercept: bool = True
    # Services the proxy lets through (None = anything); sts:GetCallerIdentity always allowed.
    allowed_services: set[str] | None = None
    # Tests: forward every proxied request to this base URL instead of AWS.
    upstream_override: str | None = None
    # Stream the agent's event log into agent/ (events/transcript/turns).
    transcript: bool = True
    max_turns: int | None = None
    # What the agent may learn about other principals: none | observed | disclosed.
    awareness: str = "none"
    # False: leave the case's resolution policy out of the prompt (no consult channel either).
    policy: bool = True
    # How the prompt tells the agent to manage infrastructure: hybrid (agent's choice, the
    # historical prompt) | iac (Terraform) | sdk (Python/boto3) | cli (aws CLI).
    modality: str = "hybrid"
    # False: control arm — the case's distractors are not loaded, so no
    # trigger can fire; the oracle still runs (its verdict may be case-dependent).
    distractors: bool = True
    # Filesystem confinement of the agent (harness.agents.sandbox): "required" fails the
    # run unless bubblewrap confines it and proves it, "auto" confines where bubblewrap
    # exists (Linux) and records "none" elsewhere, "off" never confines.
    sandbox: str = "auto"


@dataclass
class RunOutcome:
    run_id: str
    status: str
    verdict: str | None
    error: str | None
    result_path: Path


def _agent_summary(result: AgentResult | None, error: BaseException | None, run_dir: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "exit_code": None, "duration_seconds": None, "usage": {}, "cost_usd": None, "session_id": None,
        "error": None, "model": None, "num_turns": None, "tool_calls": None, "model_usage": {},
        "permission_denials": [], "permission_denial_count": 0, "duration_api_ms": None,
        "stop_reason": None, "partial": False, "transcript": None,
    }
    if result is not None:
        def rel(path: Path | None) -> str | None:
            if path is None:
                return None
            try:
                return str(Path(path).relative_to(run_dir))
            except ValueError:
                return str(path)
        denials = [
            {"tool": d.get("tool_name"), "command": (d.get("tool_input") or {}).get("command"),
             "input_keys": sorted((d.get("tool_input") or {}).keys())}
            for d in result.permission_denials if isinstance(d, Mapping)
        ]
        summary.update(
            exit_code=result.exit_code, duration_seconds=result.duration_seconds, usage=dict(result.usage),
            cost_usd=result.cost_usd, session_id=result.session_id, model=result.model,
            num_turns=result.num_turns, tool_calls=result.tool_calls, model_usage=dict(result.model_usage),
            permission_denials=denials, permission_denial_count=len(denials),
            duration_api_ms=result.duration_api_ms, stop_reason=result.stop_reason, partial=result.partial,
            transcript={"events": rel(result.events_path), "markdown": rel(result.transcript_path),
                        "turns": rel(result.turns_path)} if result.events_path else None,
        )
    if error is not None:
        summary["error"] = f"{type(error).__name__}: {error}"
        if isinstance(error, AgentRunnerError):
            summary["exit_code"] = error.exit_code if error.exit_code is not None else summary["exit_code"]
    return summary


def _tool_version(argv: list[str]) -> str | None:
    if shutil.which(argv[0]) is None:
        return None
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (completed.stdout or completed.stderr).strip().splitlines()[0][:120] if (completed.stdout or completed.stderr) else None


def collect_versions(agent: str, agent_executable: str | None = None) -> dict[str, Any]:
    """Provenance stamp for a run: repo state and every tool the run depends on."""
    git_sha = git_dirty = None
    try:
        git_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True,
                                 text=True, timeout=10).stdout.strip() or None
        git_dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True,
                                        text=True, timeout=10).stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass
    return {
        "git_sha": git_sha,
        "git_dirty": git_dirty,
        "python": sys.version.split()[0],
        "agent_cli": _tool_version([agent_executable or agent, "--version"]),
        "terraform": _tool_version(["terraform", "version"]),
        "opa": _tool_version(["opa", "version"]),
        "aws_cli": _tool_version(["aws", "--version"]),
    }


def _interference_before_finish(events_path: Path) -> bool | None:
    """True if any trigger fired before the run's final observation."""
    if not events_path.is_file():
        return None
    fired = False
    for line in events_path.read_text().splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("kind") == "trigger.matched":
            data = record.get("data", {})
            if data.get("snapshot_id") != "final-observation":
                fired = True
    return fired


def _write_agent_file(run_dir: Path, name: str, text: str) -> None:
    directory = run_dir / "agent"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text)


async def run_case(spec: CaseSpec, options: RunOptions, *, hooks: LifecycleHooks,
                   before_start=None) -> RunOutcome:
    """Drive one run. ``hooks`` are real (``CaseHooks``) or fakes in tests."""
    definitions = distractor_definitions(spec, timeout=options.distractor_timeout) if options.distractors else {}
    proxy: ApiProxy | None = None
    proxy_server: BackgroundServer | None = None
    agent_actor = Actor(actor_id="main", kind=ActorKind.MAIN)
    distractor_actors = {d: Actor(actor_id=d, kind=ActorKind.DISTRACTOR) for d in definitions}
    config = RuntimeConfig(
        run_id=options.run_id,
        run_dir=options.run_dir,
        region=options.region,
        triggers=declared_triggers(definitions),
        invariants=declared_invariants(invariant_definitions(spec)),
        distractors=definitions,
        input_hashes=spec.input_hashes(),
        allow_unscoped_credentials=True,
        distractor_environment={} if options.intercept else credential_environment(options.lifecycle_env),
        snapshot_poll_interval=options.snapshot_poll_interval,
        consult_excluded_terms=tuple(sorted(excluded_terms(spec.utterance))),
    )
    coordinator = RuntimeCoordinator(config, hooks=hooks)
    prompt = build_prompt(spec, region=options.region, mcp_server_name=MCP_SERVER_NAME,
                          awareness=options.awareness, modality=options.modality, policy=options.policy)
    started_at = now_utc()
    agent_result: AgentResult | None = None
    agent_error: BaseException | None = None
    finish_result: dict[str, Any] | None = None
    agent_env = dict(options.agent_env)
    # An agent that runs `terraform init` in its workspace would otherwise download ~760 MB
    # of providers per run (72 IaC cells filled the disk in modality-matrix-v1). It gets a
    # plugin cache of its own, seeded from the harness's: Terraform's cache is not safe for
    # concurrent writers, the harness serialises its own inits with a lock the agent does
    # not hold, and one agent init writing into the shared cache made a harness
    # `terraform show` fail to load provider schemas. Agents racing each other in their own
    # cache can only break an agent init, which the agent retries.
    agent_cache = _agent_plugin_cache()
    agent_env["TF_PLUGIN_CACHE_DIR"] = str(agent_cache)          # override, never inherit
    agent_env["TF_CLI_CONFIG_FILE"] = str(_agent_terraformrc(agent_cache))
    audit: dict[str, Any] | None = None
    # The sandbox and its self-test come first: a host that cannot confine the agent
    # fails here, before the seed is deployed, so the account is never touched and the
    # batch runner re-queues the cell as a pre-deploy error instead of dirtying an account.
    workspace = options.run_dir / "private" / "agent-workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    workspace.chmod(0o700)
    sandbox, sandbox_info = _agent_sandbox(options, workspace, agent_cache)
    try:
        if before_start is not None:
            await before_start()
        if options.intercept:
            # The proxy must exist before start(): the coordinator freezes the
            # distractor environments (with their per-actor endpoint) at start.
            proxy = ApiProxy(
                None, run_id=options.run_id, run_dir=options.run_dir,  # controller bound after start()
                credentials=credentials_from_env(options.lifecycle_env),
                actors={"main": agent_actor, **distractor_actors}, region=options.region,
                allowed_services=options.allowed_services,
                upstream_override=options.upstream_override,
            )
            proxy_server = BackgroundServer(app=proxy.asgi_app())
            await proxy_server.__aenter__()
            for distractor_id, definition in list(definitions.items()):
                definitions[distractor_id] = DistractorDefinition(
                    distractor_id=definition.distractor_id, source_path=definition.source_path,
                    sha256=definition.sha256, role_arn=definition.role_arn,
                    environment={**definition.environment,
                                 **dummy_credential_environment(distractor_actors[distractor_id],
                                                                proxy_server.url, options.region)},
                    timeout=definition.timeout)
            agent_env = {k: v for k, v in agent_env.items()
                         if not k.startswith("AWS_")}
            agent_env.update(dummy_credential_environment(agent_actor, proxy_server.url, options.region))
        await coordinator.start()
        if proxy is not None:
            proxy.controller = coordinator.controller
        _write_agent_file(options.run_dir, "prompt.txt", prompt)
        server = create_server(coordinator, manage_lifecycle=False, awareness=options.awareness)
        async with BackgroundServer(server) as mcp:
            sandbox_info["seeded_files"] = _seed_workspace(spec.case_dir, workspace)
            call = AgentCall(
                provider=options.agent,
                prompt=prompt,
                cwd=workspace,
                model=options.model,
                timeout=options.agent_timeout,
                env={**agent_env, "CLOUDGYM_RUN_ID": options.run_id},
                executable=options.agent_executable,
                safe_mode=False,
                mcp_servers={MCP_SERVER_NAME: mcp.url},
                allowed_tools=(*options.extra_allowed_tools,
                               *(f"mcp__{MCP_SERVER_NAME}__{tool}"
                                 for tool in AWARENESS_TOOLS.get(options.awareness, ()))),
                inherit_env=False,
                transcript_dir=(options.run_dir / "agent") if options.transcript else None,
                max_turns=options.max_turns,
                sandbox=sandbox,
            )
            try:
                agent_result = await AgentRunner().run(call)
            except AgentTimeoutError as exc:
                agent_error = exc
                agent_result = exc.partial
                _write_agent_file(options.run_dir, "stdout.txt", exc.stdout)
                _write_agent_file(options.run_dir, "stderr.txt", exc.stderr)
            except AgentRunnerError as exc:
                agent_error = exc
                _write_agent_file(options.run_dir, "stdout.txt", exc.stdout)
                _write_agent_file(options.run_dir, "stderr.txt", exc.stderr)
            else:
                _write_agent_file(options.run_dir, "stdout.txt", agent_result.stdout)
                _write_agent_file(options.run_dir, "stderr.txt", agent_result.stderr)
            _prune_agent_terraform(workspace)
            audit = _audit_agent(options.run_dir, sandbox_info)
            agent_called_finish = coordinator.finished
            finish_result = await coordinator.finish()
    except BaseException as exc:
        await coordinator.abort()
        if finish_result is None:
            finish_result = {"status": "aborted", "error": f"{type(exc).__name__}: {exc}",
                             "oracle": None, "cleanup": None}
        agent_called_finish = False
        if not isinstance(exc, Exception):
            raise
        agent_error = agent_error or exc
    finally:
        if proxy_server is not None and proxy is not None:
            await proxy_server.__aexit__(None, None, None)

    oracle = finish_result.get("oracle") if isinstance(finish_result, Mapping) else None
    verdict = oracle.get("verdict") if isinstance(oracle, Mapping) else None
    cleanup = finish_result.get("cleanup") if isinstance(finish_result, Mapping) else None
    leak = cleanup.get("leak_check") if isinstance(cleanup, Mapping) else None
    leaked = leak.get("leaked", []) if isinstance(leak, Mapping) else None
    triggers = None
    summary_path = options.run_dir / "trigger-summary.json"
    if summary_path.is_file():
        triggers = json.loads(summary_path.read_text())
    interference_before_finish = _interference_before_finish(options.run_dir / "events.jsonl")
    result = {
        "schema_version": 1,
        "run_id": options.run_id,
        "seed_id": spec.seed_id,
        "case_dir": str(spec.case_dir) if spec.case_dir else None,
        "region": options.region,
        "agent": {"provider": options.agent, "requested_model": options.model,
                  "called_finish": agent_called_finish, "allowed_tools": list(options.extra_allowed_tools),
                  **_agent_summary(agent_result, agent_error, options.run_dir)},
        "versions": options.metadata.pop("versions", None) or collect_versions(options.agent, options.agent_executable),
        "status": finish_result.get("status") if finish_result else "unknown",
        "error": finish_result.get("error") if finish_result else None,
        "verdict": verdict,
        "oracle": oracle,
        "triggers": triggers,
        "interference_before_finish": interference_before_finish,
        "api_calls": dict(proxy.calls) if proxy is not None else None,
        "intercepted": options.intercept,
        "awareness": options.awareness,
        "policy_shown": options.policy and options.awareness not in POLICY_WITHHELD,
        "modality": options.modality,
        "distractors_enabled": options.distractors,
        "distractors": sorted(definitions),
        # Per-distractor outcome (succeeded / failed / not-fired, with each firing's
        # result): the oracle saw the same record as input.distractors.
        "distractor_outcomes": finish_result.get("distractors") if isinstance(finish_result, Mapping) else None,
        "invariants": finish_result.get("invariants") if isinstance(finish_result, Mapping) else None,
        "leaked": leaked,
        "cleanup": cleanup,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "input_hashes": spec.input_hashes(),
        # How the agent was confined (harness.agents.sandbox; "sandbox" is taken by the
        # account label in metadata) and what its transcript shows it reaching for outside
        # the workspace (harness.bench.audit).
        "confinement": sandbox_info,
        "audit": audit,
        "started_at": started_at,
        "finished_at": now_utc(),
        **options.metadata,
    }
    options.run_dir.mkdir(parents=True, exist_ok=True)
    try:
        result["metrics"] = write_metrics(options.run_dir)
    except Exception as exc:  # noqa: BLE001 - metrics are derived; never lose the row
        result["metrics"] = {"error": str(exc)}
    result_path = options.run_dir / "result.json"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
    try:
        write_run_artifacts(options.run_dir)  # timeline.txt, timeline.svg, summary.md
    except Exception as exc:  # noqa: BLE001 - derived artifacts never fail the run
        print(f"warning: run artifacts not written: {exc}", file=sys.stderr)
    return RunOutcome(options.run_id, result["status"], verdict, result["error"], result_path)


# Cloud Control namespace -> the botocore service id(s) the proxy decodes calls as.
# Only namespaces that do not equal their service id need an entry: ELBv2 signs as
# `elasticloadbalancing` and is decoded as `elbv2` (`elb` is the classic API).
_NAMESPACE_SERVICES = {
    "cloudwatch": ("cloudwatch",),
    "elasticloadbalancingv2": ("elbv2", "elb"),
    # AWS::KinesisFirehose is the `firehose` service: until 2026-09-24 the proxy refused every
    # Firehose call in EC cases 66 and 70 ("service firehose is not allowed in this case").
    "kinesisfirehose": ("firehose",),
    # AWS::Lex::Bot is Lex V2 (`lexv2-models`); `lex-models` is the v1 API sharing its signing name.
    "lex": ("lexv2-models", "lex-models"),
}


AGENT_PLUGIN_CACHE = PLUGIN_CACHE.parent / "terraform-plugin-cache-agent"


def _agent_plugin_cache(source: Path = PLUGIN_CACHE, target: Path = AGENT_PLUGIN_CACHE) -> Path:
    """The agents' plugin cache, seeded once from the harness cache (under its read lock)."""
    if not target.is_dir() and source.is_dir():
        from harness.terraform.cache import use_lock

        with use_lock(source):
            shutil.copytree(source, target, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns(".terraform-init.lock"))
    target.mkdir(parents=True, exist_ok=True)
    return target


def _agent_terraformrc(cache: Path) -> Path:
    """A CLI config beside the agent cache that pins the same cache dir.

    Belt and braces with TF_PLUGIN_CACHE_DIR: an agent that sets its own CLI config
    or clears the variable still cannot be routed to the harness cache by this file,
    and the harness cache is what a stray agent init overwrote on 2026-09-10.
    """
    rc = cache.parent / "terraform-plugin-cache-agent.tfrc"
    body = f'plugin_cache_dir = "{cache}"\nplugin_cache_may_break_dependency_lock_file = true\n'
    if not rc.is_file() or rc.read_text() != body:
        rc.write_text(body)
    return rc


def _prune_agent_terraform(workspace: Path) -> int:
    """Drop provider binaries an agent's `terraform init` left in its workspace.

    They are re-downloadable and identical to the plugin cache's; keeping them per run
    costs hundreds of megabytes each. The lock file and state stay, so the run remains
    inspectable. Returns the number of directories removed.
    """
    removed = 0
    # Provider binaries live under a registry.terraform.io/ tree wherever Terraform put
    # them: .terraform/providers, or a cache directory the agent invented for itself
    # (one Fable agent created .plugin-cache/ in its workspace and pulled aws 6.64.0 into
    # it). Either way it is a re-downloadable copy, not evidence.
    for registry in sorted(workspace.rglob("registry.terraform.io"), key=lambda q: len(q.parts)):
        if registry.is_dir():
            shutil.rmtree(registry, ignore_errors=True)
            removed += 1
    return removed


# Host paths that must not exist inside the sandbox; the self-test probes each one. The
# repository root itself does exist inside, as an otherwise empty directory: the harness
# venv and the agents' plugin cache are bound at their real paths beneath it (the venv's
# symlinks and pyvenv.cfg are absolute), so the probes name what the root must not hold.
def _sandbox_hidden(options: RunOptions) -> list[Path]:
    return [REPO_ROOT / name for name in ("cases", "seeds", "harness", "scripts", "docs", "experiments", ".git")] + [
        REPO_ROOT / "artifacts" / "experiments", REPO_ROOT / "artifacts" / "runs", options.run_dir,
        Path.home() / ".cloudgym", Path.home() / ".aws"]


def _agent_sandbox(options: RunOptions, workspace: Path, agent_cache: Path):
    """The bubblewrap sandbox for this run, proven by a self-test, or None with a record.

    Raises when ``options.sandbox`` is "required" and bubblewrap is missing or the
    self-test still sees a hidden path: an agent never runs unconfined by accident.
    """
    from harness.agents import sandbox as sb

    mode = options.sandbox
    info: dict[str, Any] = {"backend": "none", "mode": mode}
    if mode == "off":
        return None, info
    if not sb.available():
        if mode == "required":
            raise RuntimeError("sandbox required but bubblewrap (bwrap) is not available on this host")
        info["reason"] = "bwrap not available"
        return None, info
    # The agent's PATH resolves python3 to the harness's uv-managed interpreter (boto3
    # lives there); the venv's editable install of the harness package points at the
    # repository, which does not exist inside.
    ro_binds = [REPO_ROOT / ".venv", Path.home() / ".local" / "share" / "uv"]
    rw_binds = [agent_cache, _agent_terraformrc(agent_cache)]
    sandbox = sb.default_sandbox(workspace, rw_binds=rw_binds, ro_binds=ro_binds,
                                 session_root=options.run_dir / "private" / "agent-sessions")
    selftest = sb.selftest(sandbox, _sandbox_hidden(options))
    info = {**sandbox.describe(), "mode": mode, "selftest": selftest}
    if not selftest["ok"]:
        raise RuntimeError(f"sandbox self-test failed: {selftest}")
    return sandbox, info


def _seed_workspace(case_dir: Path | None, workspace: Path) -> list[str]:
    """Copy the case's ``agent/files/`` tree into the workspace: what the task hands the agent.

    A task that says "the code in lambda.js" ships that file here; without it the agents
    went looking for one across the host (paper-config-1, cases 149/157/158).
    """
    if case_dir is None:
        return []
    source = Path(case_dir) / "agent" / "files"
    if not source.is_dir():
        return []
    copied = []
    for path in sorted(source.rglob("*")):
        if path.is_file():
            rel = path.relative_to(source)
            target = workspace / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            copied.append(rel.as_posix())
    return copied


def _audit_agent(run_dir: Path, sandbox_info: Mapping[str, Any]) -> dict[str, Any] | None:
    """Audit the transcript for reads outside the workspace; written to agent/audit.json."""
    from harness.bench.audit import audit_events, write_audit

    events_path = run_dir / "agent" / "events.jsonl"
    if not events_path.is_file():
        return None
    mount = sandbox_info.get("workspace_mount") if sandbox_info.get("backend") != "none" else None
    workspace = None if mount else str(run_dir / "private" / "agent-workspace")
    try:
        audit = audit_events(events_path, run_dir=run_dir, mount=mount, workspace=workspace)
        write_audit(run_dir, audit)
        return audit.as_dict()
    except Exception as exc:  # noqa: BLE001 - the audit is derived; never lose the row
        return {"error": f"{type(exc).__name__}: {exc}"}


def _allowed_services(spec: CaseSpec) -> set[str]:
    """Service ids the case's resource types live in, plus sts and read-only helpers."""
    prefixes = {t.split("::")[1].lower() for t in spec.cloudcontrol_types}
    services = {"sts", "cloudcontrol", "cloudformation"}
    for prefix in prefixes:
        services.update(_NAMESPACE_SERVICES.get(prefix, (prefix,)))
    return services


def _frozen_credentials(profile: str, region: str) -> dict[str, str]:
    import boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    creds = session.get_credentials()
    if creds is None:
        die(f"profile {profile!r} yields no credentials")
    frozen = creds.get_frozen_credentials()
    values = {"AWS_ACCESS_KEY_ID": frozen.access_key, "AWS_SECRET_ACCESS_KEY": frozen.secret_key}
    if frozen.token:
        values["AWS_SESSION_TOKEN"] = frozen.token
    return values


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("seed_id", help="seed directory name under seeds/aws/")
    parser.add_argument("--case-dir", type=Path, help="Step 5 case directory (prompt, oracle, distractors)")
    parser.add_argument("--agent", choices=("claude", "codex"), default="claude")
    parser.add_argument("--model")
    parser.add_argument("--agent-executable", help="path to the agent CLI (default: from PATH)")
    parser.add_argument("--timeout", type=float, default=1800.0, help="agent wall-clock limit in seconds")
    parser.add_argument("--region", help="override the sandbox region")
    parser.add_argument("--run-id")
    parser.add_argument("--run-dir", type=Path, help="run directory (default artifacts/runs/<run-id>)")
    parser.add_argument("--max-turns", type=int)
    parser.add_argument("--no-transcript", action="store_true", help="use the CLI's single JSON result instead of streaming")
    parser.add_argument("--awareness", choices=AWARENESS_LEVELS, default="none",
                        help="what the agent can learn about other principals via the `changes` tool")
    parser.add_argument("--no-policy", action="store_true",
                        help="leave the case's resolution policy out of the prompt (policy ablation)")
    parser.add_argument("--modality", choices=("hybrid", "iac", "sdk", "cli"), default="hybrid",
                        help="how the prompt tells the agent to manage infrastructure: hybrid (its choice), "
                             "iac (Terraform), sdk (Python/boto3), cli (aws CLI)")
    parser.add_argument("--no-distractors", action="store_true",
                        help="control run: do not load the case's distractors (no interference)")
    parser.add_argument("--poll-interval", type=float, default=10.0, help="snapshot poll interval (s)")
    parser.add_argument("--allow-aws", action="store_true", help="required: this run touches a real AWS account")
    parser.add_argument("--no-intercept", action="store_true",
                        help="give the agent real credentials and skip the API proxy (no API trace/triggers)")
    parser.add_argument("--sandbox", choices=("auto", "required", "off"), default="auto",
                        help="confine the agent with bubblewrap: auto (where available), required, off")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if not args.allow_aws:
        die("refusing real AWS execution without --allow-aws")
    try:
        spec = load_case(args.seed_id, SEEDS_DIR, args.case_dir.resolve() if args.case_dir else None)
    except CaseError as exc:
        die(str(exc))
    try:
        target = load_aws_target(REPO_ROOT)
        region = args.region or target.region
        env = aws_environment(target, region=region)
        identity = verify_aws_target(target, env)
    except AwsSafetyError as exc:
        die(str(exc))
    print(f"verified AWS sandbox {identity['Account']} as {identity['Arn']} in {region}", file=sys.stderr)

    run_id = args.run_id or f"r-{secrets.token_hex(4)}"
    run_dir = args.run_dir.resolve() if args.run_dir else RUNS_DIR / run_id
    if run_dir.exists():
        die(f"run directory already exists: {run_dir}")

    # Resolve the sandbox profile (SSO, credential_process, ...) to static
    # session credentials once. Every actor — agent, distractors, capture,
    # Terraform — then receives exactly those variables and nothing that points
    # back at the host's profile configuration.
    credentials = _frozen_credentials(target.profile, region)
    aws_vars = {**credentials, "AWS_REGION": region, "AWS_DEFAULT_REGION": region,
                "AWS_EC2_METADATA_DISABLED": "true"}
    lifecycle_env = {**scrubbed_environment(), **aws_vars}
    lifecycle_env["TF_VAR_expected_aws_account_id"] = target.account_id
    lifecycle_env["TF_VAR_region"] = region
    # The agent gets the same identity; the harness never intercepts its calls.
    agent_env = dict(aws_vars)

    hooks = CaseHooks(spec, run_dir=run_dir, region=region, env=lifecycle_env,
                      scaffold=SCAFFOLD, plugin_cache=PLUGIN_CACHE)
    options = RunOptions(
        seed_id=spec.seed_id, case_dir=spec.case_dir, agent=args.agent, model=args.model,
        agent_timeout=args.timeout, run_id=run_id, run_dir=run_dir, region=region,
        agent_env=agent_env, lifecycle_env=lifecycle_env,
        snapshot_poll_interval=args.poll_interval, agent_executable=args.agent_executable,
        metadata={"account": identity["Account"]},
        intercept=not args.no_intercept,
        allowed_services=_allowed_services(spec),
        transcript=not args.no_transcript,
        max_turns=args.max_turns,
        awareness=args.awareness,
        policy=not args.no_policy,
        modality=args.modality,
        distractors=not args.no_distractors,
        sandbox=args.sandbox,
    )
    print(f"run {run_id}: seed={spec.seed_id} agent={args.agent} distractors={sorted(spec.distractor_sources)}",
          file=sys.stderr)
    outcome = asyncio.run(run_case(spec, options, hooks=hooks.lifecycle_hooks(),
                                   before_start=hooks.capture_baseline))
    print(json.dumps({"run_id": outcome.run_id, "status": outcome.status, "verdict": outcome.verdict,
                      "error": outcome.error, "result": str(outcome.result_path)}, indent=2))
    return 0 if outcome.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
