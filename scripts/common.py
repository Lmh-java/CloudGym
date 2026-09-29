"""Shared paths and utilities for benchmark commands.

Repository discovery, Terraform paths, and verified sandbox credentials.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn


def _find_repo_root() -> Path:
    candidates = (Path.cwd(), Path(__file__).resolve().parent.parent)
    for base in candidates:
        for d in (base, *base.parents):
            if (d / "pyproject.toml").is_file() and (d / "harness").is_dir():
                return d
    print("error: cannot locate repo root — run from inside the repository",
          file=sys.stderr)
    raise SystemExit(1)


REPO_ROOT = _find_repo_root()

# Terraform fixtures shared by every step that stages or validates IaC.
SCAFFOLD = REPO_ROOT / "harness" / "terraform" / "aws" / "scaffold.tf"
PLUGIN_CACHE = REPO_ROOT / "artifacts" / "terraform-plugin-cache"


def die(msg: str) -> NoReturn:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sandbox_env(region: str | None = None, target: "AwsTarget | None" = None) -> dict[str, Any]:
    """Resolve a sandbox target (the primary by default) to frozen credentials, exactly as run-case does."""
    from harness.aws_env import scrubbed_environment
    from harness.aws_safety import aws_environment, load_aws_target, verify_aws_target
    from scripts.run_case import _frozen_credentials

    target = target or load_aws_target(REPO_ROOT)
    region = region or target.region
    identity = verify_aws_target(target, aws_environment(target, region=region))
    credentials = _frozen_credentials(target.profile, region)
    aws_vars = {**credentials, "AWS_REGION": region, "AWS_DEFAULT_REGION": region,
                "AWS_EC2_METADATA_DISABLED": "true"}
    lifecycle_env = {**scrubbed_environment(), **aws_vars,
                     "TF_VAR_expected_aws_account_id": target.account_id,
                     "TF_VAR_region": region}
    return {"region": region, "account": identity["Account"], "label": target.label,
            "lifecycle_env": lifecycle_env, "agent_env": dict(aws_vars)}
