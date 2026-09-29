"""Canonicalization for the EC2 Query and AWS Query wire protocols."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, urlencode

import botocore.session
from botocore.model import Shape

# Any service whose botocore model speaks the query or ec2 protocol decodes here.
SUPPORTED_QUERY_PROTOCOLS = {"ec2", "query"}


class CanonicalizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CanonicalRequest:
    service: str
    operation: str
    region: str
    api_version: str
    parameters: dict[str, Any]


def _member(shape: Shape, token: str) -> tuple[str, Shape]:
    lowered = token.lower()
    for name, child in shape.members.items():
        wire_name = str(child.serialization.get("name", name))
        if name.lower() == lowered or wire_name.lower() == lowered:
            return name, child
    raise CanonicalizationError(f"{shape.name} has no member matching {token!r}")


def _scalar(shape: Shape, value: str) -> Any:
    kind = shape.type_name
    if kind == "boolean":
        if value.lower() not in {"true", "false"}:
            raise CanonicalizationError(f"invalid boolean {value!r}")
        return value.lower() == "true"
    if kind in {"byte", "short", "integer", "long"}:
        return int(value)
    if kind in {"float", "double"}:
        return float(value)
    if kind == "blob":
        return {"$base64": base64.b64encode(base64.b64decode(value)).decode("ascii")}
    return value


def _assign(container: Any, shape: Shape, tokens: list[str], value: str) -> None:
    if shape.type_name == "structure":
        if not tokens:
            raise CanonicalizationError(f"missing member below {shape.name}")
        name, child = _member(shape, tokens[0])
        if len(tokens) == 1 and child.type_name not in {"structure", "list", "map"}:
            container[name] = _scalar(child, value)
            return
        if child.type_name == "list":
            target = container.setdefault(name, [])
        elif child.type_name in {"structure", "map"}:
            target = container.setdefault(name, {})
        else:
            raise CanonicalizationError(f"unexpected path below scalar member {name}")
        _assign(target, child, tokens[1:], value)
        return

    if shape.type_name == "list":
        if not tokens:
            raise CanonicalizationError(f"missing list index below {shape.name}")
        member = shape.member
        # Non-flattened query lists carry the member element name before the
        # index (IAM ``Tags.member.1.Key``; botocore uses ``member`` unless the
        # member shape names itself); flattened lists (EC2 ``Filter.1``) do not.
        if not tokens[0].isdigit():
            element = str(member.serialization.get("name", "member"))
            if tokens[0].lower() != element.lower() or len(tokens) < 2:
                raise CanonicalizationError(f"invalid one-based list index {tokens[0]!r}")
            tokens = tokens[1:]
        try:
            index = int(tokens[0]) - 1
        except ValueError as exc:
            raise CanonicalizationError(f"invalid one-based list index {tokens[0]!r}") from exc
        if index < 0:
            raise CanonicalizationError("query list indices are one-based")
        while len(container) <= index:
            if member.type_name == "list":
                container.append([])
            elif member.type_name in {"structure", "map"}:
                container.append({})
            else:
                container.append(None)
        if len(tokens) == 1:
            if member.type_name in {"structure", "list", "map"}:
                raise CanonicalizationError(f"missing nested value below list {shape.name}")
            container[index] = _scalar(member, value)
        else:
            _assign(container[index], member, tokens[1:], value)
        return

    if shape.type_name == "map":
        # Query maps use Entry.N.Key and Entry.N.Value. They are uncommon in
        # the EC2 pilot; reject forms we cannot map unambiguously.
        raise CanonicalizationError(f"map query decoding is not supported for {shape.name}")

    if tokens:
        raise CanonicalizationError(f"unexpected tokens below scalar {shape.name}")


def decode_query_request(
    *,
    service: str,
    region: str,
    body: bytes | str,
    query: str = "",
    session: botocore.session.Session | None = None,
) -> CanonicalRequest:
    """Decode a supported AWS Query request into Botocore-shaped parameters."""
    service = service.lower()
    raw_body = body.decode("utf-8") if isinstance(body, bytes) else body
    pairs = parse_qsl(query, keep_blank_values=True) + parse_qsl(
        raw_body, keep_blank_values=True
    )
    flat: dict[str, str] = {}
    for key, value in pairs:
        if key in flat:
            raise CanonicalizationError(f"duplicate query parameter {key!r}")
        flat[key] = value
    operation = flat.pop("Action", None)
    requested_version = flat.pop("Version", None)
    if not operation:
        raise CanonicalizationError("AWS Query request is missing Action")

    loader = session or botocore.session.get_session()
    try:
        model = loader.get_service_model(service)
    except Exception as exc:
        raise CanonicalizationError(f"unknown service {service!r}") from exc
    if model.metadata.get("protocol") not in SUPPORTED_QUERY_PROTOCOLS:
        raise CanonicalizationError(
            f"service {service} uses unsupported protocol {model.metadata.get('protocol')}"
        )
    try:
        operation_model = model.operation_model(operation)
    except Exception as exc:
        raise CanonicalizationError(f"unknown {service} operation {operation!r}") from exc
    parameters: dict[str, Any] = {}
    input_shape = operation_model.input_shape
    if flat and input_shape is None:
        raise CanonicalizationError(f"{service}.{operation} accepts no parameters")
    if input_shape is not None:
        for key, value in flat.items():
            _assign(parameters, input_shape, key.split("."), value)
    return CanonicalRequest(
        service=service,
        operation=operation_model.name,
        region=region,
        api_version=requested_version or model.api_version,
        parameters=parameters,
    )


def encode_query(query: Mapping[str, Any] | Iterable[tuple[str, Any]] | str) -> str:
    if isinstance(query, str):
        return query
    return urlencode(query, doseq=True)
