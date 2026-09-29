"""Single-state Terraform workspace runner for seed certification.

One workspace holds exactly one ``.terraform/`` directory and one
``terraform.tfstate`` across the whole ``initial -> expected -> initial``
transition. ``stage()`` replaces only the active ``*.tf`` sources;
state, lockfile, and provider installs survive restaging — the mechanical
basis of the same-state proof, together with lineage/serial tracking.

Every phase uses a saved plan (`plan -out` then `apply <plan>`), and the
setup / clean-main-transition / no-op / reset walks force ``-parallelism=1``
with no caller override; destroy does not. Every command writes a fresh,
mode-0600, never-reused ``TF_LOG_PATH`` with ``TF_LOG=JSON`` (stream
encoding) and ``TF_LOG_PROVIDER=DEBUG`` (provider verbosity) — the
configuration validated by the trace-feasibility spike. Raw logs are
sensitive (credential-provider responses); the trace pipeline extracts a
sanitized derivative and unlinks them.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import string
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .cache import init_lock, prune_broken_providers, seed_lockfile, use_lock

TERRAFORM_VERSION_PIN = "1.15.4"
AWS_PROVIDER_VERSION_PIN = "5.100.0"

_CERTIFY_TEMPLATE = Path(__file__).resolve().parent / "aws" / "scaffold-certify.tf.tmpl"
_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


class TerraformError(RuntimeError):
    def __init__(self, message: str, result: "CommandResult | None" = None):
        super().__init__(message)
        self.result = result


@dataclass(frozen=True)
class CommandResult:
    label: str
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    log_path: Path


def render_certify_scaffold(
    run_id: str,
    seed_id: str,
    provider_version: str = AWS_PROVIDER_VERSION_PIN,
) -> str:
    """The per-run certification scaffold (ownership default tags)."""
    for name, value in (("run_id", run_id), ("seed_id", seed_id)):
        if not _ID_PATTERN.fullmatch(value):
            raise ValueError(f"{name} {value!r} is not a safe tag value")
    template = string.Template(_CERTIFY_TEMPLATE.read_text())
    return template.substitute(run_id=run_id, seed_id=seed_id,
                               provider_version=provider_version)


class Workspace:
    """A single-state terraform working directory plus its command log."""

    def __init__(
        self,
        workdir: Path,
        log_dir: Path,
        plugin_cache: Path,
        *,
        base_env: dict[str, str] | None = None,
        terraform_bin: str = "terraform",
    ):
        self.workdir = workdir
        self.log_dir = log_dir
        self.plugin_cache = plugin_cache
        self.base_env = dict(base_env if base_env is not None else os.environ)
        self.terraform_bin = terraform_bin
        self.commands: list[CommandResult] = []
        for directory in (workdir, log_dir):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        # Resume numbering over an existing run dir (e.g. `step2 cleanup`
        # reopening a failed run) so fresh-log-path refusal never trips on
        # our own earlier commands.
        existing = [int(p.name.split("-", 1)[0])
                    for p in log_dir.glob("[0-9][0-9][0-9]-*.log.jsonl")]
        self._log_seq = max(existing, default=0)

    # -- staging ------------------------------------------------------------

    def stage(self, tf_sources: list[Path], scaffold_text: str) -> None:
        """Replace active *.tf sources; preserve .terraform/, lockfile, state."""
        for old in self.workdir.glob("*.tf"):
            old.unlink()
        for source in sorted(tf_sources):
            shutil.copy(source, self.workdir / source.name)
        (self.workdir / "zz-scaffold.tf").write_text(scaffold_text)
        seed_lockfile(self.workdir)

    # -- command execution --------------------------------------------------

    def _fresh_log_path(self, label: str) -> Path:
        self._log_seq += 1
        path = self.log_dir / f"{self._log_seq:03d}-{label}.log.jsonl"
        if path.exists():
            raise TerraformError(
                f"refusing to reuse TF_LOG_PATH {path} (TF_LOG appends)")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        return path

    _LOCK_MISMATCH = ("does not match any of the checksums recorded in the dependency lock file",
                      "Required plugins are not installed")

    def _run(self, label: str, *args: str,
             ok_codes: tuple[int, ...] = (0,), shared_cache: bool = True,
             _healed: bool = False) -> CommandResult:
        try:
            return self._run_once(label, *args, ok_codes=ok_codes, shared_cache=shared_cache)
        except TerraformError as exc:
            stderr = exc.result.stderr if exc.result is not None else ""
            if _healed or not shared_cache or not any(m in stderr for m in self._LOCK_MISMATCH):
                raise
            # A cache entry no longer matches the pinned lock file (something rewrote the
            # shared cache's binary, 2026-09-10). Drop the offending provider from the cache
            # and the workdir, re-install it verified against the lock file, retry once.
            self._reinstall_providers(stderr)
            return self._run(label, *args, ok_codes=ok_codes, shared_cache=shared_cache, _healed=True)

    def _reinstall_providers(self, stderr: str) -> None:
        with init_lock(self.plugin_cache):
            for platform_dir in self.plugin_cache.glob("*/*/*/*/*"):
                # cache layout: <host>/<namespace>/<name>/<version>/<platform>
                if platform_dir.is_dir() and f"/{platform_dir.parts[-3]}" in stderr.replace("registry.terraform.io/", "/"):
                    shutil.rmtree(platform_dir, ignore_errors=True)
            shutil.rmtree(self.workdir / ".terraform" / "providers", ignore_errors=True)
            prune_broken_providers(self.workdir, self.plugin_cache)
            self._run_once("init-heal", "init", "-backend=false", "-input=false", shared_cache=False)

    def _run_once(self, label: str, *args: str,
                  ok_codes: tuple[int, ...] = (0,), shared_cache: bool = True) -> CommandResult:
        log_path = self._fresh_log_path(label)
        env = dict(self.base_env)
        self.plugin_cache.mkdir(parents=True, exist_ok=True)
        env["TF_PLUGIN_CACHE_DIR"] = str(self.plugin_cache)
        env["TF_IN_AUTOMATION"] = "1"
        env["TF_LOG"] = "JSON"
        env["TF_LOG_PROVIDER"] = "DEBUG"
        env["TF_LOG_PATH"] = str(log_path)
        argv = (self.terraform_bin, f"-chdir={self.workdir}", *args)
        # Plan/apply used to hold the cache's shared lock for their whole duration so no
        # concurrent init could rewrite a provider under them. A stalled destroy (VPC
        # DependencyViolation retries) then held it for 17 minutes and every other
        # cell's init queued behind it. Init only writes a cache entry that is missing
        # or mismatched, and a mismatch now heals with a retry (see _run), so the
        # shared lock is no longer worth the head-of-line blocking.
        completed = subprocess.run(argv, capture_output=True, text=True, env=env)
        result = CommandResult(label, argv, completed.returncode,
                               completed.stdout, completed.stderr, log_path)
        self.commands.append(result)
        if result.returncode not in ok_codes:
            raise TerraformError(
                f"terraform {label} exited {result.returncode}: "
                f"{result.stderr.strip()[:2000]}", result)
        return result

    # -- lifecycle operations ----------------------------------------------

    def init(self) -> CommandResult:
        with init_lock(self.plugin_cache):
            prune_broken_providers(self.workdir, self.plugin_cache)
            return self._run("init", "init", "-backend=false", "-input=false", shared_cache=False)

    def plan(self, plan_name: str, *, destroy: bool = False,
             detailed_exitcode: bool = False) -> CommandResult:
        args = ["plan", "-input=false"]
        if destroy:
            args.append("-destroy")
        else:
            # Reference-trace determinism: forced, never caller-overridable.
            args.append("-parallelism=1")
        if detailed_exitcode:
            args.append("-detailed-exitcode")
        args += ["-out", plan_name]
        ok = (0, 2) if detailed_exitcode else (0,)
        return self._run(f"plan-{plan_name}", *args, ok_codes=ok)

    def apply(self, plan_name: str, *, destroy: bool = False) -> CommandResult:
        args = ["apply", "-input=false"]
        if not destroy:
            args.append("-parallelism=1")
        args.append(plan_name)
        return self._run(f"apply-{plan_name}", *args)

    def show_json(self, target: str | None = None) -> dict:
        args = ["show", "-json"] + ([target] if target else [])
        label = f"show-{target}" if target else "show-state"
        result = self._run(label, *args)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise TerraformError(f"unparseable `terraform show -json` output: {e}",
                                 result) from e

    def state_json(self) -> dict:
        return self.show_json()

    def plan_json(self, plan_name: str) -> dict:
        return self.show_json(plan_name)

    # -- same-state proof ---------------------------------------------------

    def state_identity(self) -> tuple[str | None, int]:
        """(lineage, serial) of the local tfstate; (None, 0) before creation."""
        state_file = self.workdir / "terraform.tfstate"
        if not state_file.is_file():
            return None, 0
        try:
            state = json.loads(state_file.read_text())
        except json.JSONDecodeError as e:
            raise TerraformError(f"unparseable terraform.tfstate: {e}") from e
        return state.get("lineage"), int(state.get("serial", 0))
