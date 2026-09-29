"""Command-line entry point for the Streamable HTTP MCP runtime."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path


from harness.mcp.server import create_server

from .config import distractors_from_config as _distractors
from .config import invariants_from_config as _invariants
from .config import triggers_from_config as _triggers
from .coordinator import LifecycleHooks, RuntimeConfig, RuntimeCoordinator
from .workers import _communicate


def _command_hook(command: list[str] | None, timeout: float):
    if not command:
        async def noop():
            return None
        return noop

    async def run():
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr, timed_out = await _communicate(process, timeout)
        if timed_out:
            raise RuntimeError(
                f"lifecycle command {command[0]!r} timed out after {timeout} seconds"
            )
        if process.returncode != 0:
            raise RuntimeError(
                f"lifecycle command {command[0]!r} failed: {stderr.decode(errors='replace')}"
            )
        text = stdout.decode(errors="replace").strip()
        if not text:
            return {"exit_code": 0}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"exit_code": 0, "stdout": text}

    return run


def load_runtime(config_path: Path) -> RuntimeCoordinator:
    raw = json.loads(config_path.read_text())
    base = config_path.resolve().parent
    run_dir = Path(raw["run_dir"])
    if not run_dir.is_absolute():
        run_dir = base / run_dir
    distractors, declared_triggers = _distractors(raw.get("distractors", []), base)
    config = RuntimeConfig(
        run_id=raw["run_id"],
        run_dir=run_dir,
        region=raw.get("region", "us-east-1"),
        triggers=_triggers(raw.get("triggers", []), declared_triggers),
        invariants=_invariants(raw.get("invariants", []), base),
        distractors=distractors,
        input_hashes=raw.get("input_hashes", {}),
        main_role_arn=raw.get("main_role_arn"),
        allow_unscoped_credentials=raw.get("allow_unscoped_credentials", False),
        distractor_environment=raw.get("distractor_environment", {}),
        lifecycle_timeout=raw.get("lifecycle_timeout", 900.0),
        distractor_drain_timeout=raw.get("distractor_drain_timeout", 180.0),
        snapshot_poll_interval=raw.get("snapshot_poll_interval", 5.0),
        fsync_events=raw.get("fsync_events", False),
    )
    lifecycle = raw.get("lifecycle", {})
    if not config.allow_unscoped_credentials:
        required_lifecycle = {
            "deploy_initial",
            "verify_initial",
            "observe_snapshot",
            "capture_final",
            "evaluate_oracle",
            "reset",
            "destroy",
            "leak_check",
        }
        missing_lifecycle = sorted(required_lifecycle - lifecycle.keys())
        if missing_lifecycle:
            raise ValueError(
                f"runtime config is missing lifecycle hooks: {missing_lifecycle}"
            )
    hooks = LifecycleHooks(
        deploy_initial=_command_hook(lifecycle.get("deploy_initial"), config.lifecycle_timeout),
        verify_initial=_command_hook(lifecycle.get("verify_initial"), config.lifecycle_timeout),
        observe_snapshot=_command_hook(
            lifecycle.get("observe_snapshot"), config.lifecycle_timeout
        ),
        capture_final=_command_hook(lifecycle.get("capture_final"), config.lifecycle_timeout),
        evaluate_oracle=_command_hook(
            lifecycle.get("evaluate_oracle"), config.lifecycle_timeout
        ),
        reset=_command_hook(lifecycle.get("reset"), config.lifecycle_timeout),
        destroy=_command_hook(lifecycle.get("destroy"), config.lifecycle_timeout),
        leak_check=_command_hook(lifecycle.get("leak_check"), config.lifecycle_timeout),
    )
    return RuntimeCoordinator(config, hooks=hooks)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    print(
        "WARNING: CloudGym AWS runtime is a trusted prototype; "
        "submitted Python is not isolated and runs are not certification eligible.",
        file=sys.stderr,
    )
    coordinator = load_runtime(args.config)
    server = create_server(coordinator)
    server.run(
        transport="streamable-http",
        host=args.host,
        port=args.port,
        streamable_http_path="/mcp",
        json_response=True,
    )


if __name__ == "__main__":
    main()
