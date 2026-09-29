"""Sanitize captured Cloud Control envelopes for check-in as golden fixtures.

The one transformation is replacing the sandbox account id with the
documentation account ``123456789012`` in every string (ARNs included).
Everything else — property shapes, casing, nesting, volatile fields — is kept
verbatim: the fixtures exist precisely to preserve the real shapes.
"""

from __future__ import annotations

import re
from typing import Any

PLACEHOLDER_ACCOUNT = "123456789012"
_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")


class SanitizeError(ValueError):
    pass


def _replace(value: Any, account_id: str) -> Any:
    if isinstance(value, str):
        return value.replace(account_id, PLACEHOLDER_ACCOUNT)
    if isinstance(value, dict):
        return {key.replace(account_id, PLACEHOLDER_ACCOUNT): _replace(item, account_id)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_replace(item, account_id) for item in value]
    return value


def sanitize_envelopes(envelopes: list[dict], account_id: str) -> list[dict]:
    """Sanitized deep copies of raw ``get_resource`` envelopes.

    ``account_id`` must be the full 12-digit sandbox account; a wrong or partial
    id would silently leave real identifiers in a checked-in fixture.
    """
    if not _ACCOUNT_ID.fullmatch(account_id or ""):
        raise SanitizeError(f"account_id must be 12 digits, got {account_id!r}")
    return [_replace(envelope, account_id) for envelope in envelopes]
