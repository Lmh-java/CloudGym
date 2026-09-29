"""Shared Terraform provider-cache helpers.

The provider plugin cache (``TF_PLUGIN_CACHE_DIR``) is shared by every
workspace so provider packages are downloaded once and installed into
workspaces as symlinks. Two hazards need handling (extracted from the legacy
``scripts/deploy_case.py``):

- broken installs: workspace symlinks whose cache target vanished, and cache
  platform directories with no provider binary — both make ``terraform
  init`` fail hard instead of re-downloading; and
- concurrency: Terraform's plugin cache is not safe for concurrent writes,
  so batch runs must serialize the cache-mutating part of ``init``.
"""

from __future__ import annotations

import fcntl
import shutil
from contextlib import contextmanager
from pathlib import Path

# The pinned dependency lockfile staged into every certification workspace.
# Generated with:
#   terraform providers lock -platform=darwin_arm64 -platform=linux_amd64
# so runs on both macOS (dev) and linux (harness containers) verify the same
# provider checksums.
PINNED_LOCKFILE = Path(__file__).resolve().parent / "aws" / ".terraform.lock.hcl"


def prune_broken_providers(workdir: Path, cache: Path) -> None:
    """Heal provider-install damage that makes `terraform init` fail hard.

    Two related states are poison (typically after the shared cache was
    deleted or an init was interrupted): workdir provider entries that are
    symlinks into a now-missing cache path, and cache platform dirs whose
    provider binary is absent. Terraform trusts both without checking and
    errors instead of re-downloading, so drop them and let init re-install.
    """
    providers = workdir / ".terraform" / "providers"
    if providers.is_dir():
        for p in providers.rglob("*"):
            if p.is_symlink() and not p.exists():
                p.unlink()
    # cache layout: <host>/<namespace>/<name>/<version>/<platform>/<binary>
    for platform_dir in cache.glob("*/*/*/*/*"):
        if platform_dir.is_dir() and not any(platform_dir.glob("terraform-provider-*")):
            shutil.rmtree(platform_dir)


@contextmanager
def _cache_lock(cache: Path, mode: int):
    cache.mkdir(parents=True, exist_ok=True)
    lock_path = cache / ".terraform-init.lock"
    with open(lock_path, "a+") as handle:
        fcntl.flock(handle, mode)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


@contextmanager
def init_lock(cache: Path):
    """Exclusive lock around the cache-mutating ``terraform init``.

    Workspaces install providers as links into the shared cache, so an init that
    (re)downloads a provider rewrites a binary another workspace may be executing
    right now (seen 2026-09-08: a concurrent init replaced the archive provider
    under a running plan — "Failed to read any lines from plugin's stdout").
    Every other terraform command therefore holds ``use_lock`` (shared) and an
    init waits for them; inits also serialize among themselves.
    """
    with _cache_lock(cache, fcntl.LOCK_EX):
        yield


@contextmanager
def use_lock(cache: Path):
    """Shared lock held while a plan/apply/destroy/show executes cached providers."""
    with _cache_lock(cache, fcntl.LOCK_SH):
        yield


def seed_lockfile(workdir: Path) -> bool:
    """Copy the pinned lockfile into a workspace that lacks one.

    Returns True when the pinned lockfile was staged. Every workspace uses
    the same lockfile so all runs select identical provider versions and
    checksum sets.
    """
    target = workdir / ".terraform.lock.hcl"
    if target.exists() or not PINNED_LOCKFILE.is_file():
        return False
    shutil.copy(PINNED_LOCKFILE, target)
    return True
