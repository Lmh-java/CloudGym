"""Raw capture of live AWS state via the Cloud Control API.

boto3 rather than the ``aws`` CLI: the extractor runs inside the harness
process (end-of-run snapshots now, watcher polling later), where per-call
subprocess spawns are real overhead and failures need to be discriminated
programmatically (throttling vs unsupported action vs denied), not parsed
out of stderr. Credentials follow the ambient environment — boto3 honors
``AWS_CONFIG_FILE`` and ``credential_process`` the same way the CLI does.

Capture stores verbatim response envelopes with no interpretation — every
judgment call lives downstream in shaping/checking, so a fix there never
invalidates a snapshot already taken. Any failure aborts the whole snapshot:
a snapshot silently missing a resource is indistinguishable from that
resource not existing, which is the vacuous-pass hazard the oracle verdict
contract defends against.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from ..errors import CaptureError

_RETRY = Config(retries={"max_attempts": 8, "mode": "standard"})


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def parse_envelope(envelope: dict) -> tuple[str, str, dict]:
    """Shape hook: a raw envelope's (type, identifier, parsed properties)."""
    description = envelope["ResourceDescription"]
    return (
        envelope["TypeName"],
        description["Identifier"],
        json.loads(description["Properties"]),
    )


def _pages_or_empty(pages):
    """Iterate ``pages``; a NotFound from the handler yields no pages at all."""
    try:
        yield from pages
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code not in ("ResourceNotFoundException", "NotFound"):
            raise


def _list_parents() -> dict[str, tuple[str, "Callable[[dict], dict]"]]:
    """Cloud Control types listed per parent: type -> (parent type, model fn)."""
    from .capabilities import CAPABILITY_REGISTRY

    parents: dict[str, tuple[str, Callable[[dict], dict]]] = {}
    for adapter in CAPABILITY_REGISTRY.values():
        if adapter.list_parent:
            parents[adapter.cloudcontrol_type] = (adapter.list_parent, adapter.list_resource_model)
    return parents


def _native_capturer(type_name: str):
    """The registered adapter's native_describe override for ``type_name``, or None."""
    from .capabilities import CAPABILITY_REGISTRY, CapabilityAdapter

    for adapter in CAPABILITY_REGISTRY.values():
        if (adapter.cloudcontrol_type == type_name
                and type(adapter).native_describe is not CapabilityAdapter.native_describe):
            return adapter.native_describe
    return None


def _native_lister(type_name: str):
    """The registered adapter's native_list override for ``type_name``, or None."""
    from .capabilities import CAPABILITY_REGISTRY, CapabilityAdapter

    for adapter in CAPABILITY_REGISTRY.values():
        if (adapter.cloudcontrol_type == type_name
                and type(adapter).native_list is not CapabilityAdapter.native_list):
            return adapter.native_list
    return None


def _get_error_tolerated(type_name: str, identifier: str, error: Exception) -> bool:
    """Whether an adapter for ``type_name`` vouches this listed item is unreadable by design."""
    from .capabilities import CAPABILITY_REGISTRY

    return any(adapter.cloudcontrol_type == type_name
               and adapter.tolerated_get_error(identifier, error)
               for adapter in CAPABILITY_REGISTRY.values())


def capture_order(types: list[str]) -> list[str]:
    """``types`` with every parent-listed type after its parent.

    Fails closed when a dependent type's parent is not in scope: listing it
    would be impossible, and silently skipping it is the blind-checker hazard.
    """
    parents = _list_parents()
    ordered = [t for t in types if t not in parents]
    pending = [t for t in types if t in parents]
    for type_name in pending:
        parent, _ = parents[type_name]
        if parent not in types:
            raise CaptureError(
                f"{type_name} is listed per {parent}, which is not in the capture scope")
    # A parent may itself be parent-listed (API Gateway methods per resource per API):
    # place each dependent only once its parent has been placed.
    while pending:
        placed = [t for t in pending if parents[t][0] in ordered]
        if not placed:
            raise CaptureError(f"cyclic parent listing among {pending}")
        ordered.extend(placed)
        pending = [t for t in pending if t not in placed]
    return ordered


def _vanished_between_list_and_get(error: ClientError) -> bool:
    """Whether ``error`` says the just-listed resource is gone *now*.

    Cloud Control reports it as a handler NotFound, which is a positive absence
    signal rather than the "could not read it" hazard the module docstring
    guards against: the resource was deleted between the list and the get.
    """
    response = getattr(error, "response", None) or {}
    code = (response.get("Error") or {}).get("Code")
    return code == "ResourceNotFoundException"


def capture_snapshot(types: list[str], region: str, out_dir: Path,
                     session: "boto3.Session | None" = None,
                     tolerate_vanished: bool = False) -> dict:
    """List and get every resource of ``types`` in ``region``.

    Writes one verbatim ``get-resource`` envelope (plus a ``ReadAt``
    timestamp) per resource under ``out_dir/raw/<Type>/<identifier>.json``
    and a ``manifest.json``; returns the manifest. An empty type directory
    means "captured, none found" — distinct from a type never captured.

    Types whose ``list`` handler needs a ResourceModel (``AWS::Lambda::Permission``
    needs ``FunctionName``) are listed once per captured parent resource, so
    their parent type must be in ``types`` and is captured first.

    ``tolerate_vanished`` skips a listed resource whose get reports NotFound —
    it was deleted between the two calls. Only for captures taken *while the
    agent is running* (the poll the snapshot observer feeds to triggers), where
    that race is normal; the quiescent captures the oracle reads (baseline, S0,
    S_final) stay fail-closed.
    """
    session = session or boto3.Session()
    cloudcontrol = session.client("cloudcontrol", region_name=region, config=_RETRY)
    raw_dir = out_dir / "raw"
    started = _utcnow()
    counts: dict[str, int] = {}
    parents = _list_parents()
    captured: dict[str, list[dict]] = {}
    for type_name in capture_order(list(types)):
        type_dir = raw_dir / _safe(type_name)
        type_dir.mkdir(parents=True, exist_ok=True)
        counts[type_name] = 0
        captured[type_name] = []
        if type_name in parents:
            parent, model_for = parents[type_name]
            list_kwargs = [{"TypeName": type_name, "ResourceModel": json.dumps(model_for(props))}
                           for props in captured[parent]]
        else:
            list_kwargs = [{"TypeName": type_name}]
        describe = _native_capturer(type_name)
        if describe is not None:
            # No Cloud Control read support for this type at all: envelopes carry the
            # service API's verbatim describe response instead of a GetResource one.
            try:
                for identifier, props in describe(session, region):
                    envelope = {
                        "TypeName": type_name,
                        "ResourceDescription": {"Identifier": identifier,
                                                "Properties": json.dumps(props)},
                        "ReadAt": _utcnow(),
                    }
                    out = type_dir / f"{_safe(identifier)}.json"
                    out.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n")
                    counts[type_name] += 1
                    captured[type_name].append(props)
            except (ClientError, BotoCoreError) as e:
                raise CaptureError(f"{type_name} in {region}: {e}") from e
            continue
        native = _native_lister(type_name)
        try:
            if native is not None:
                # Cloud Control LIST unsupported/unusable for this type: discover
                # identifiers natively; envelopes below still come verbatim from GetResource.
                identifier_lists = [list(native(session, region))]
            else:
                identifier_lists = []
                for kwargs in list_kwargs:
                    pages = cloudcontrol.get_paginator("list_resources").paginate(**kwargs)
                    if "ResourceModel" in kwargs:
                        # A per-parent listing can legitimately find nothing: Lambda's
                        # GetPolicy 404s for a function with no resource policy, so the
                        # AWS::Lambda::Permission handler reports NotFound rather than an
                        # empty page. The parent was captured moments ago, so NotFound
                        # here means "no dependents", not a missing parent.
                        pages = _pages_or_empty(pages)
                    identifier_lists.append([
                        description["Identifier"]
                        for page in pages for description in page["ResourceDescriptions"]])
            for identifiers in identifier_lists:
                    for identifier in identifiers:
                        try:
                            got = cloudcontrol.get_resource(
                                TypeName=type_name, Identifier=identifier
                            )
                        except ClientError as get_error:
                            if _get_error_tolerated(type_name, identifier, get_error):
                                continue
                            if tolerate_vanished and _vanished_between_list_and_get(get_error):
                                continue
                            raise
                        envelope = {
                            k: v for k, v in got.items() if k != "ResponseMetadata"
                        }
                        envelope["ReadAt"] = _utcnow()
                        out = type_dir / f"{_safe(identifier)}.json"
                        out.write_text(
                            json.dumps(envelope, indent=2, sort_keys=True) + "\n"
                        )
                        counts[type_name] += 1
                        captured[type_name].append(
                            json.loads(envelope["ResourceDescription"]["Properties"]))
        except (ClientError, BotoCoreError) as e:
            raise CaptureError(f"{type_name} in {region}: {e}") from e
    try:
        account = session.client("sts", config=_RETRY).get_caller_identity()["Account"]
    except (ClientError, BotoCoreError) as e:
        raise CaptureError(f"sts get-caller-identity: {e}") from e
    manifest = {
        "schema_version": 1,
        "region": region,
        "account": account,
        "types": list(types),
        "resource_counts": counts,
        "started_at": started,
        "finished_at": _utcnow(),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
