"""Targeted certification snapshots and recorded-resource cleanup checks.

Normal ``S0``/``SA`` capture never enumerates a region: physical identifiers
come from Terraform state bindings and each resource is read with a targeted
Cloud Control ``get_resource`` call. Cleanup uses the same targeted reads over
the physical identifiers recorded throughout the run; it never enumerates the
region.

The normalized snapshot produced here is the shared schema used by Steps 2-4
(S0/SA, Pk/SD, S*): resources keyed by Terraform logical address, only
capability-projected semantic properties, reserved ``cloudgym:*`` tags and
volatile fields removed, unordered collections sorted, cross-resource
physical references rewritten to ``${<logical address>}``.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from ..errors import BindingError, CaptureError, StabilityTimeout
from .capabilities import CAPABILITY_REGISTRY, adapter_for

SNAPSHOT_SCHEMA_VERSION = 1
RESERVED_TAG_PREFIX = "cloudgym:"

_RETRY = Config(retries={"max_attempts": 8, "mode": "standard"})


# ---------------------------------------------------------------------------
# Bindings: terraform state -> physical identifiers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Binding:
    address: str          # terraform logical address, e.g. aws_vpc.main
    terraform_type: str   # e.g. aws_vpc
    identifier: str       # Cloud Control identifier, e.g. vpc-0123...


def _managed_resources(module: dict) -> list[dict]:
    resources = [r for r in module.get("resources", [])
                 if r.get("mode") == "managed"]
    for child in module.get("child_modules", []):
        resources.extend(_managed_resources(child))
    return resources


def bindings_from_state(state_json: dict) -> list[Binding]:
    """Bindings for every managed resource in ``terraform show -json`` output.

    Fails closed: an unmapped type, a missing identifier, or two resources
    claiming one identifier all invalidate the run — the pipeline never
    guesses a resource identity.
    """
    root = state_json.get("values", {}).get("root_module", {})
    bindings: list[Binding] = []
    for resource in _managed_resources(root):
        tf_type = resource.get("type", "")
        adapter = adapter_for(tf_type)
        if not adapter.standalone:
            # A projection of another resource's Cloud Control document
            # (bucket sub-resource, rule target, policy attachment): the
            # parent's binding already reads it.
            continue
        address = resource["address"]
        identifier = adapter.identifier_from_state(resource.get("values", {}))
        bindings.append(Binding(address, tf_type, identifier))
    seen_addr: dict[str, Binding] = {}
    seen_id: dict[tuple[str, str], Binding] = {}
    for b in bindings:
        if b.address in seen_addr:
            raise BindingError(f"duplicate logical address {b.address!r}")
        # Identifiers are unique per Cloud Control type: a bucket and its
        # AWS::S3::BucketPolicy legitimately share the bucket name.
        key = (adapter_for(b.terraform_type).cloudcontrol_type, b.identifier)
        if key in seen_id:
            raise BindingError(
                f"identifier {b.identifier!r} bound to both "
                f"{seen_id[key].address!r} and {b.address!r}")
        seen_addr[b.address] = b
        seen_id[key] = b
    return bindings


# ---------------------------------------------------------------------------
# Targeted capture
# ---------------------------------------------------------------------------

def cloudcontrol_client(region: str, session: boto3.Session | None = None):
    session = session or boto3.Session()
    return session.client("cloudcontrol", region_name=region, config=_RETRY)


def _uses_native_read(adapter) -> bool:
    from .capabilities.base import CapabilityAdapter

    return type(adapter).native_describe is not CapabilityAdapter.native_describe


def _native_session(session, adapter):
    if session is None:
        raise CaptureError(
            f"{adapter.cloudcontrol_type} reads natively; caller must pass session=")
    return session


def targeted_capture(bindings: list[Binding], client, *, session=None) -> dict[str, dict]:
    """Raw properties per logical address via per-binding ``get_resource``.

    Types with no Cloud Control read support (``native_describe`` adapters) are
    read through ``adapter.native_read`` and need ``session``. Fails closed on
    any provider error, including NotFound: during normal capture every bound
    resource is expected to exist (post-destroy absence checks use
    ``find_present`` instead).
    """
    raw: dict[str, dict] = {}
    for binding in bindings:
        adapter = CAPABILITY_REGISTRY[binding.terraform_type]
        if _uses_native_read(adapter):
            region = client.meta.region_name
            try:
                props = adapter.native_read(
                    _native_session(session, adapter), region, binding.identifier)
            except (ClientError, BotoCoreError) as e:
                raise CaptureError(
                    f"native read {adapter.cloudcontrol_type} "
                    f"{binding.identifier} ({binding.address}): {e}") from e
            if props is None:
                raise CaptureError(
                    f"native read {adapter.cloudcontrol_type} {binding.identifier} "
                    f"({binding.address}): resource does not exist")
            raw[binding.address] = props
            continue
        try:
            result = client.get_resource(
                TypeName=adapter.cloudcontrol_type,
                Identifier=binding.identifier)
        except (ClientError, BotoCoreError) as e:
            raise CaptureError(
                f"get_resource {adapter.cloudcontrol_type} "
                f"{binding.identifier} ({binding.address}): {e}") from e
        raw[binding.address] = json.loads(
            result["ResourceDescription"]["Properties"])
    return raw


# ---------------------------------------------------------------------------
# Normalization (shared snapshot schema)
# ---------------------------------------------------------------------------

def _strip_reserved_tags(value: Any) -> Any:
    """Remove reserved cloudgym:* entries from a Tags collection."""
    if isinstance(value, list):
        return [t for t in value
                if not (isinstance(t, dict)
                        and str(t.get("Key", "")).startswith(RESERVED_TAG_PREFIX))]
    if isinstance(value, dict):
        return {k: v for k, v in value.items()
                if not str(k).startswith(RESERVED_TAG_PREFIX)}
    return value


def _canonical_sort(value: Any) -> Any:
    """Deterministically order unordered collections (rules, tags, lists)."""
    if isinstance(value, dict):
        return {k: _canonical_sort(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        items = [_canonical_sort(v) for v in value]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True))
    return value


def _rewrite_references(value: Any, id_to_address: dict[str, str]) -> Any:
    if isinstance(value, str):
        address = id_to_address.get(value)
        return f"${{{address}}}" if address else value
    if isinstance(value, dict):
        return {k: _rewrite_references(v, id_to_address) for k, v in value.items()}
    if isinstance(value, list):
        return [_rewrite_references(v, id_to_address) for v in value]
    return value


def normalize(raw: dict[str, dict], bindings: list[Binding]) -> dict:
    """Raw per-address properties -> the shared normalized snapshot schema."""
    by_address = {b.address: b for b in bindings}
    missing = sorted(set(by_address) - set(raw))
    if missing:
        raise BindingError(f"raw capture missing bound addresses: {missing}")
    # A borrowed identifier (a bucket policy's bucket name) must keep resolving
    # to the resource that owns it, never to the borrower.
    id_to_address = {b.identifier: b.address for b in bindings
                     if not CAPABILITY_REGISTRY[b.terraform_type].identifier_is_borrowed}
    resources: dict[str, dict] = {}
    for address in sorted(raw):
        adapter = CAPABILITY_REGISTRY[by_address[address].terraform_type]
        projected = adapter.project(raw[address])
        if "Tags" in projected:
            projected["Tags"] = _strip_reserved_tags(projected["Tags"])
        projected = _rewrite_references(projected, id_to_address)
        resources[address] = _canonical_sort(projected)
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "kind": "cloudgym-normalized-snapshot",
        "resources": resources,
    }


# ---------------------------------------------------------------------------
# Stability loop
# ---------------------------------------------------------------------------

def stable_snapshot(
    bindings: list[Binding],
    client,
    *,
    deadline_seconds: float = 300.0,
    interval_seconds: float = 5.0,
    capture: Callable[[list[Binding], Any], dict[str, dict]] = targeted_capture,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[dict, dict]:
    """Repeat targeted reads until two consecutive normalized views agree.

    Convergence additionally requires every adapter readiness predicate to
    hold on the raw properties — two equal but premature reads (e.g. before
    a resource settles) are not convergence. Returns
    ``(normalized_snapshot, last_raw_capture)``.
    """
    if not bindings:
        raise BindingError("stable_snapshot called with no bindings")
    started = monotonic()
    previous: dict | None = None
    attempts = 0
    while True:
        attempts += 1
        raw = capture(bindings, client)
        ready = all(
            CAPABILITY_REGISTRY[b.terraform_type].ready(raw[b.address])
            for b in bindings)
        current = normalize(raw, bindings)
        if ready and previous is not None and current == previous:
            return current, raw
        previous = current if ready else None
        if monotonic() - started > deadline_seconds:
            raise StabilityTimeout(
                f"snapshot did not stabilize after {attempts} reads within "
                f"{deadline_seconds}s (ready={ready})")
        sleep(interval_seconds)


# ---------------------------------------------------------------------------
# Targeted post-destroy absence verification
# ---------------------------------------------------------------------------

def find_present(bindings: list[Binding], client, *, session=None) -> list[dict]:
    """Return recorded resources that still exist after destroy.

    A Cloud Control ``ResourceNotFoundException`` is the expected absence
    signal (``native_read`` adapters signal absence with None). Every other
    provider error fails closed because it cannot prove that the resource is
    gone.
    """
    present: list[dict] = []
    for binding in bindings:
        adapter = adapter_for(binding.terraform_type)
        if _uses_native_read(adapter):
            try:
                props = adapter.native_read(
                    _native_session(session, adapter),
                    client.meta.region_name, binding.identifier)
            except (ClientError, BotoCoreError) as e:
                raise CaptureError(
                    f"native absence check {adapter.cloudcontrol_type} "
                    f"{binding.identifier}: {e}") from e
            if props is not None:
                present.append({
                    "address": binding.address,
                    "terraform_type": binding.terraform_type,
                    "cloudcontrol_type": adapter.cloudcontrol_type,
                    "identifier": binding.identifier,
                })
            continue
        try:
            client.get_resource(
                TypeName=adapter.cloudcontrol_type,
                Identifier=binding.identifier)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                continue
            if adapter.get_error_means_absent(binding.identifier, e):
                continue
            raise CaptureError(
                f"get_resource absence check {adapter.cloudcontrol_type} "
                f"{binding.identifier}: {e}") from e
        except BotoCoreError as e:
            raise CaptureError(
                f"get_resource absence check {adapter.cloudcontrol_type} "
                f"{binding.identifier}: {e}") from e
        present.append({
            "address": binding.address,
            "terraform_type": binding.terraform_type,
            "cloudcontrol_type": adapter.cloudcontrol_type,
            "identifier": binding.identifier,
        })
    return present


def absence_verified(
    bindings: list[Binding],
    client,
    *,
    deadline_seconds: float = 300.0,
    interval_seconds: float = 10.0,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[bool, list[dict]]:
    """Poll recorded identifiers until all are absent.

    Returns ``(ok, last_present_listing)``. An empty ledger is valid here: the
    caller is responsible for deciding whether it had enough evidence to
    establish a trustworthy ledger in the first place.
    """
    started = monotonic()
    while True:
        present = find_present(bindings, client)
        if not present:
            return True, []
        if monotonic() - started > deadline_seconds:
            return False, present
        sleep(interval_seconds)
