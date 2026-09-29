"""Process-environment hygiene shared by every harness-spawned AWS actor."""

from __future__ import annotations

import os
from typing import Mapping

# Every ambient way a child process could pick up credentials or a profile.
AMBIENT_CREDENTIAL_VARS: tuple[str, ...] = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    # Endpoint overrides must never leak into harness processes: capture and
    # Terraform talk to AWS directly, only actors go through the proxy.
    "AWS_ENDPOINT_URL",
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
    "AWS_CA_BUNDLE",
)


def scrubbed_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """A copy of ``base`` (default ``os.environ``) with no ambient AWS identity."""
    environment = dict(os.environ if base is None else base)
    for name in list(environment):
        if name in AMBIENT_CREDENTIAL_VARS or name.startswith("AWS_ENDPOINT_URL_"):
            environment.pop(name, None)
    environment["AWS_EC2_METADATA_DISABLED"] = "true"
    return environment


def credential_environment(base: Mapping[str, str]) -> dict[str, str]:
    """Only the credential/region variables an actor needs, taken from ``base``."""
    keep = (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    )
    return {name: base[name] for name in keep if name in base}
