"""Uninstrumented subprocess runner for frozen distractor programs."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from .controller import EventController


@dataclass(frozen=True)
class SubmissionResult:
    submission_id: str
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    result: Any = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_private_evidence(run_dir: Path, submission_id: str, *, stdout: str,
                           stderr: str, exit_code: int | None, status: str,
                           result: Any = None) -> Path:
    directory = Path(run_dir) / "private"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{submission_id}.result.json"
    path.write_text(json.dumps({"submission_id": submission_id, "status": status,
                                "exit_code": exit_code, "stdout": stdout,
                                "stderr": stderr, "result": result},
                               default=repr, ensure_ascii=False,
                               sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


async def _terminate(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except TimeoutError:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()


async def _communicate(process: asyncio.subprocess.Process, timeout: float):
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return stdout, stderr, False
    except TimeoutError:
        await _terminate(process)
        stdout, stderr = await process.communicate()
        return stdout, stderr, True


class SdkSubmissionRunner:
    """Run a frozen Python distractor without API interception or IPC."""

    def __init__(self, *, run_id: str, run_dir: Path, controller: EventController,
                 timeout: float = 120.0,
                 base_env: Mapping[str, str] | None = None):
        self.run_id = run_id
        self.run_dir = Path(run_dir)
        self.controller = controller
        self.timeout = timeout
        self.base_env = dict(os.environ if base_env is None else base_env)

    async def run(self, source: str, submission_id: str, *,
                  on_process_started: Callable[[], Awaitable[None]] | None = None) -> SubmissionResult:
        # One directory per distractor launch: the exact bytes handed to the
        # subprocess. Its outcome lands next door in <submission_id>.result.json.
        directory = self.run_dir / "private" / "distractor-runs" / submission_id
        directory.mkdir(parents=True, exist_ok=False)
        directory.chmod(0o700)
        source_path = directory / "submission.py"
        source_path.write_text(source, encoding="utf-8")
        source_path.chmod(0o600)
        digest = hashlib.sha256(source.encode()).hexdigest()
        (directory / "manifest.json").write_text(
            json.dumps({"sha256": digest, "runner": "python"}, sort_keys=True) + "\n"
        )
        await self.controller.record_runtime("submission.received",
                                             {"submission_id": submission_id,
                                              "runner": "python", "sha256": digest})
        try:
            process = await asyncio.create_subprocess_exec(
                sys.executable, str(source_path), stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=self.base_env,
                start_new_session=True)
        except OSError as exc:
            await self.controller.record_runtime("submission.failed",
                                                 {"submission_id": submission_id,
                                                  "runner": "python", "error": str(exc)})
            write_private_evidence(self.run_dir, submission_id, stdout="", stderr=str(exc),
                                   exit_code=None, status="failed")
            return SubmissionResult(submission_id, "failed", None, "", str(exc))
        if on_process_started is not None:
            try:
                await on_process_started()
            except BaseException:
                await _terminate(process)
                await process.communicate()
                raise
        stdout_b, stderr_b, timed_out = await _communicate(process, self.timeout)
        stdout, stderr = stdout_b.decode(errors="replace"), stderr_b.decode(errors="replace")
        status = "timed_out" if timed_out else ("succeeded" if process.returncode == 0 else "failed")
        await self.controller.record_runtime(f"submission.{status}",
                                             {"submission_id": submission_id,
                                              "runner": "python", "exit_code": process.returncode})
        parsed = None
        if stdout.strip():
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                pass
        write_private_evidence(self.run_dir, submission_id, stdout=stdout, stderr=stderr,
                               exit_code=process.returncode, status=status, result=parsed)
        return SubmissionResult(submission_id, status, process.returncode, stdout, stderr, parsed)
