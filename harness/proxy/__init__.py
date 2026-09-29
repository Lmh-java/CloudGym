"""AWS API interception proxy (endpoint-override based)."""

from .server import (
    DUMMY_ACCESS_KEY_ID,
    DUMMY_SECRET_ACCESS_KEY,
    Actor,
    ApiProxy,
    credentials_from_env,
    dummy_credential_environment,
)

__all__ = [
    "Actor",
    "ApiProxy",
    "DUMMY_ACCESS_KEY_ID",
    "DUMMY_SECRET_ACCESS_KEY",
    "credentials_from_env",
    "dummy_credential_environment",
]
