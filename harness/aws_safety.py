"""Fail-closed selection and verification of the local AWS sandbox target."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class AwsSafetyError(RuntimeError):
    """The configured AWS target is missing, expired, or unsafe."""


@dataclass(frozen=True)
class AwsTarget:
    profile: str
    account_id: str
    region: str
    role_name: str | None = None
    access: str = "sso"        # "sso": an Identity Center permission set; "org-role": an assumed org role
    name: str | None = None    # pool label (defaults to the profile)

    @property
    def label(self) -> str:
        return self.name or self.profile


@dataclass(frozen=True)
class PoolConfig:
    """``[aws.pool]``: how pool accounts are created and reached."""

    management_profile: str
    ou_id: str
    email_template: str
    access_role: str = "OrganizationAccountAccessRole"
    profile_prefix: str = "cloudgym-pool-"
    account_name_prefix: str = "cloudgym-sbx-"


_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_CREDENTIAL_ENV = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
)


def config_path(repo_root: Path) -> Path:
    override = os.environ.get("CLOUDGYM_AWS_CONFIG")
    return Path(override).expanduser() if override else repo_root / ".cloudgym" / "aws.local.toml"


def _read_config(repo_root: Path) -> tuple[Path, Mapping]:
    path = config_path(repo_root)
    try:
        raw = tomllib.loads(path.read_text())
    except FileNotFoundError as exc:
        raise AwsSafetyError(
            f"missing {path}; copy .cloudgym/aws.example.toml to "
            ".cloudgym/aws.local.toml and configure the sandbox"
        ) from exc
    except tomllib.TOMLDecodeError as exc:
        raise AwsSafetyError(f"invalid AWS safety config {path}: {exc}") from exc
    if not isinstance(raw.get("aws"), Mapping):
        raise AwsSafetyError(f"invalid AWS safety config {path}: missing [aws]")
    return path, raw["aws"]


def _check_target(target: AwsTarget, path: Path, where: str) -> AwsTarget:
    if not target.profile.strip():
        raise AwsSafetyError(f"AWS profile is empty in {where} of {path}")
    if not _ACCOUNT_ID.fullmatch(target.account_id):
        raise AwsSafetyError(f"AWS account_id must be 12 digits in {where} of {path}")
    if not target.region.strip():
        raise AwsSafetyError(f"AWS region is empty in {where} of {path}")
    if target.access not in ("sso", "org-role"):
        raise AwsSafetyError(f"access must be 'sso' or 'org-role' in {where} of {path}")
    return target


def load_aws_target(repo_root: Path) -> AwsTarget:
    """The primary sandbox (``[aws]``): what every single-account command uses."""
    path, aws = _read_config(repo_root)
    try:
        target = AwsTarget(
            profile=str(aws["profile"]),
            account_id=str(aws["account_id"]),
            region=str(aws["region"]),
            role_name=str(aws["role_name"]) if aws.get("role_name") else None,
            access=str(aws.get("access") or "sso"),
            name=str(aws["name"]) if aws.get("name") else None,
        )
    except (KeyError, TypeError) as exc:
        raise AwsSafetyError(f"invalid AWS safety config {path}: {exc}") from exc
    return _check_target(target, path, "[aws]")


def load_pool_config(repo_root: Path) -> PoolConfig | None:
    """``[aws.pool]`` provisioning settings, or None when no pool is configured."""
    path, aws = _read_config(repo_root)
    pool = aws.get("pool")
    if pool is None:
        return None
    if not isinstance(pool, Mapping):
        raise AwsSafetyError(f"invalid [aws.pool] in {path}")
    try:
        config = PoolConfig(
            management_profile=str(pool["management_profile"]),
            ou_id=str(pool["ou_id"]),
            email_template=str(pool["email_template"]),
            access_role=str(pool.get("access_role") or "OrganizationAccountAccessRole"),
            profile_prefix=str(pool.get("profile_prefix") or "cloudgym-pool-"),
            account_name_prefix=str(pool.get("account_name_prefix") or "cloudgym-sbx-"),
        )
    except KeyError as exc:
        raise AwsSafetyError(f"[aws.pool] in {path} is missing {exc}") from exc
    if "{n" not in config.email_template or "@" not in config.email_template:
        raise AwsSafetyError(f"[aws.pool].email_template in {path} must contain '{{n}}' and an '@'")
    return config


def load_pool_targets(repo_root: Path) -> list[AwsTarget]:
    """Every sandbox a lease may hand out: the primary first, then ``[[aws.pool.accounts]]``.

    Pool accounts inherit the primary's region and are reached through the org access
    role unless an entry says otherwise. Duplicate account ids are an error."""
    path, aws = _read_config(repo_root)
    primary = load_aws_target(repo_root)
    pool_cfg = load_pool_config(repo_root)
    targets = [primary]
    entries = (aws.get("pool") or {}).get("accounts") or []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise AwsSafetyError(f"invalid [[aws.pool.accounts]] entry #{index + 1} in {path}")
        try:
            target = AwsTarget(
                profile=str(entry["profile"]),
                account_id=str(entry["account_id"]),
                region=str(entry.get("region") or primary.region),
                role_name=str(entry["role_name"]) if entry.get("role_name") else
                (pool_cfg.access_role if pool_cfg else "OrganizationAccountAccessRole"),
                access=str(entry.get("access") or "org-role"),
                name=str(entry["name"]) if entry.get("name") else None,
            )
        except (KeyError, TypeError) as exc:
            raise AwsSafetyError(f"invalid [[aws.pool.accounts]] entry #{index + 1} in {path}: {exc}") from exc
        targets.append(_check_target(target, path, f"[[aws.pool.accounts]] #{index + 1}"))
    seen: dict[str, str] = {}
    for target in targets:
        if target.account_id in seen:
            raise AwsSafetyError(f"account {target.account_id} listed twice in {path} "
                                 f"({seen[target.account_id]} and {target.label})")
        seen[target.account_id] = target.label
    return targets


def aws_environment(
    target: AwsTarget,
    *,
    base: Mapping[str, str] | None = None,
    region: str | None = None,
) -> dict[str, str]:
    """Select the named profile and remove credentials that could override it."""
    env = dict(os.environ if base is None else base)
    for name in _CREDENTIAL_ENV:
        env.pop(name, None)
    env["AWS_PROFILE"] = target.profile
    env["AWS_DEFAULT_PROFILE"] = target.profile
    env["AWS_REGION"] = region or target.region
    env["AWS_DEFAULT_REGION"] = region or target.region
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    return env


def activate_aws_environment(env: Mapping[str, str]) -> None:
    """Apply a prepared environment before creating a Boto3 session."""
    for name in _CREDENTIAL_ENV:
        os.environ.pop(name, None)
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_EC2_METADATA_DISABLED",
    ):
        if name in env:
            os.environ[name] = env[name]


def verify_aws_target(target: AwsTarget, env: Mapping[str, str]) -> dict[str, str]:
    """Resolve the caller through STS and reject anything except the target."""
    try:
        result = subprocess.run(
            [
                "aws", "sts", "get-caller-identity", "--profile", target.profile,
                "--output", "json",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=dict(env),
        )
    except FileNotFoundError as exc:
        raise AwsSafetyError("AWS CLI is required for the account safety check") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown AWS CLI error"
        raise AwsSafetyError(
            f"cannot verify profile {target.profile!r}: {detail}\n"
            f"Run: aws sso login --profile {target.profile}"
        )
    try:
        identity = json.loads(result.stdout)
        account = str(identity["Account"])
        arn = str(identity["Arn"])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise AwsSafetyError("STS returned an invalid caller identity") from exc
    if account != target.account_id:
        raise AwsSafetyError(
            f"refusing AWS operation: profile {target.profile!r} resolved to "
            f"account {account}, expected sandbox {target.account_id}"
        )
    if target.role_name:
        if target.access == "org-role":
            expected = f"assumed-role/{target.role_name}/"
        else:
            expected = f"assumed-role/AWSReservedSSO_{target.role_name}_"
        if expected not in arn:
            raise AwsSafetyError(
                f"refusing AWS operation: caller role does not match "
                f"{target.role_name!r} ({target.access}): {arn}"
            )
    return {"Account": account, "Arn": arn}
