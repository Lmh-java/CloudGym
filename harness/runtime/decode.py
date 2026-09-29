"""Decode intercepted AWS HTTP requests into (service, operation, parameters).

Botocore ships request *serializers* only, so this is their inverse, driven
by the pinned service models. Decoding is best-effort: the proxy forwards a
request whether or not its parameters could be decoded, and the event records
``parameters_decoded`` so predicates never silently match on missing data.

Coverage:
  query / ec2         full parameters (``canonicalize.decode_query_request``)
  json                full parameters (``X-Amz-Target`` + JSON body)
  rest-json           full parameters (URI template + query + JSON body)
  rest-xml            operation only
  smithy-rpc-v2-cbor  operation only
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Mapping
from urllib.parse import parse_qsl, unquote

import botocore.session
from botocore.model import OperationModel, ServiceModel

from .canonicalize import CanonicalizationError, decode_query_request


class DecodeError(RuntimeError):
    pass


@dataclass(frozen=True)
class DecodedRequest:
    service: str
    operation: str
    protocol: str
    api_version: str | None = None
    parameters: Mapping[str, Any] = field(default_factory=dict)
    decoded: bool = False
    error: str | None = None


_SIGV4_SCOPE = re.compile(r"Credential=([^/,\s]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request")


def parse_sigv4_scope(authorization: str | None) -> tuple[str, str, str]:
    """(access_key_id, region, signing_name) from a SigV4 Authorization header."""
    if not authorization:
        raise DecodeError("missing Authorization header")
    match = _SIGV4_SCOPE.search(authorization)
    if match is None:
        raise DecodeError("Authorization header is not SigV4")
    return match.group(1), match.group(3), match.group(4)


@lru_cache(maxsize=1)
def _session() -> botocore.session.Session:
    return botocore.session.get_session()


@lru_cache(maxsize=1)
def _signing_name_index() -> dict[str, list[str]]:
    """signing name / endpoint prefix -> botocore service ids (e.g. monitoring -> [cloudwatch]).

    A signing name can carry two APIs: ``elasticloadbalancing`` is both ``elb``
    (2012-06-01) and ``elbv2`` (2015-12-01). Every candidate is kept so a request
    can be attributed to the model whose API version it declares.
    """
    session = _session()
    index: dict[str, list[str]] = {}
    for service_id in session.get_available_services():
        try:
            metadata = session.get_service_model(service_id).metadata
        except Exception:  # noqa: BLE001 - skip malformed models
            continue
        for name in (metadata.get("signingName"), metadata.get("endpointPrefix"), service_id):
            if name and service_id not in index.setdefault(name, []):
                index[name].append(service_id)
    # The service that *is* the signing name comes first: docdb and neptune sign as
    # ``rds`` with the very same API version (they are the RDS API), so a version match
    # cannot separate them and the alphabetical winner used to be docdb — which turned
    # every RDS call into a denied "docdb" call for cases that only allow rds.
    for name, ids in index.items():
        ids.sort(key=lambda sid: (sid != name, sid))
    return index


def service_ids_for(signing_name: str) -> list[str]:
    """Every botocore service id that signs as ``signing_name``, most likely first."""
    return _signing_name_index().get(signing_name, [signing_name])


def service_id_for(signing_name: str, api_version: str | None = None) -> str:
    """The botocore service id for ``signing_name``.

    With ``api_version`` (the ``Version`` a query request carries) the candidate
    whose model declares that version wins, which is what tells an ELBv2 call
    apart from a classic ELB one.
    """
    candidates = service_ids_for(signing_name)
    if api_version:
        for candidate in candidates:
            try:
                if service_model(candidate).api_version == api_version:
                    return candidate
            except DecodeError:
                continue
    return candidates[0]


def service_model(service_id: str) -> ServiceModel:
    try:
        return _session().get_service_model(service_id)
    except Exception as exc:
        raise DecodeError(f"unknown service {service_id!r}") from exc


def endpoint_for(service_id: str, region: str) -> tuple[str, str]:
    """(hostname, signing_name) for the real regional endpoint."""
    model = service_model(service_id)
    prefix = model.endpoint_prefix
    signing = model.metadata.get("signingName") or prefix
    resolver = _session().get_component("endpoint_resolver")
    resolved = resolver.construct_endpoint(prefix, region)
    if not resolved:
        raise DecodeError(f"no endpoint for {service_id} in {region}")
    return resolved["hostname"], signing


# -- URI templates -----------------------------------------------------------

def _template_regex(template: str) -> tuple[re.Pattern[str], list[str]]:
    names: list[str] = []
    pattern = "^"
    pos = 0
    for match in re.finditer(r"\{([^}]+)\}", template):
        pattern += re.escape(template[pos:match.start()])
        name = match.group(1)
        if name.endswith("+"):
            names.append(name[:-1])
            pattern += "(.+)"
        else:
            names.append(name)
            pattern += "([^/]+)"
        pos = match.end()
    pattern += re.escape(template[pos:]) + "$"
    return re.compile(pattern), names


@lru_cache(maxsize=64)
def _rest_routes(service_id: str) -> tuple[tuple[str, re.Pattern[str], list[str], dict[str, str], OperationModel], ...]:
    model = service_model(service_id)
    routes = []
    for name in model.operation_names:
        op = model.operation_model(name)
        uri = op.http.get("requestUri", "/")
        path, _, query = uri.partition("?")
        static_query = dict(parse_qsl(query, keep_blank_values=True)) if query else {}
        regex, names = _template_regex(path.rstrip("/") or "/")
        routes.append((op.http.get("method", "POST").upper(), regex, names, static_query, op))
    # Longer literal templates first so "/a/b" beats "/{x}".
    routes.sort(key=lambda r: (-len(r[1].pattern), r[4].name))
    return tuple(routes)


def _required_headers(op: OperationModel) -> set[str]:
    shape = op.input_shape
    if shape is None:
        return set()
    return {shape.members[m].serialization.get("name", m).lower()
            for m in shape.required_members
            if shape.members[m].serialization.get("location") == "header"}


def _match_rest(service_id: str, method: str, path: str, query: Mapping[str, str],
                headers: Mapping[str, str]) -> tuple[OperationModel, dict[str, str]] | None:
    candidates = []
    # Route 53 templates end in "/" ("/2013-04-01/hostedzone/{Id}/rrset/") while the CLI
    # and Terraform disagree about sending it; a trailing slash never distinguishes
    # operations, so match without it.
    path = path.rstrip("/") or "/"
    for verb, regex, names, static_query, op in _rest_routes(service_id):
        if verb != method.upper():
            continue
        match = regex.match(path)
        if match is None:
            continue
        if any(query.get(k) != v for k, v in static_query.items()):
            continue
        # Same template, different operation (S3 PutObject vs CopyObject):
        # the one whose required headers are all present wins.
        required = _required_headers(op)
        if not required.issubset(headers.keys()):
            continue
        # Same template, different subresource (S3 CreateBucket "PUT /{Bucket}"
        # vs PutBucketLifecycleConfiguration "PUT /{Bucket}?lifecycle"): the
        # operation whose static query keys the request actually carries wins,
        # so a bucket-configuration write is never mistaken for CreateBucket.
        # Among otherwise equal matches (GetBucketLifecycle vs
        # GetBucketLifecycleConfiguration share "?lifecycle") prefer the
        # non-deprecated operation.
        candidates.append((len(static_query), len(required), not op.deprecated, op, match))
    if not candidates:
        return None
    candidates.sort(key=lambda c: (-c[0], -c[1], not c[2], c[3].name))
    _, _, _, op, match = candidates[0]
    names = next(n for _, r, n, _, o in _rest_routes(service_id) if o is op)
    return op, {name: unquote(value) for name, value in zip(names, match.groups())}


def _wire_to_member(op: OperationModel) -> dict[str, tuple[str, str]]:
    """wire name -> (member name, location) for the operation's input shape."""
    result: dict[str, tuple[str, str]] = {}
    shape = op.input_shape
    if shape is None:
        return result
    for member, child in shape.members.items():
        location = child.serialization.get("location", "body")
        wire = child.serialization.get("name", member)
        result[wire] = (member, location)
        result[member] = (member, location)
    return result


def _query_operation(model: ServiceModel, query: str, body: bytes) -> str:
    """Best-effort ``Action`` of a query request whose parameters failed to decode."""
    pairs = parse_qsl(query, keep_blank_values=True)
    pairs += parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
    actions = {value for key, value in pairs if key == "Action"}
    if len(actions) != 1:
        return ""
    try:
        return model.operation_model(actions.pop()).name
    except Exception:  # noqa: BLE001 - unknown action: no operation
        return ""


# -- entry point --------------------------------------------------------------

def _declared_version(query: str, body: bytes) -> str | None:
    """The ``Version`` a query/ec2 protocol request declares, if any."""
    pairs = parse_qsl(query, keep_blank_values=True)
    pairs += parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
    versions = {value for key, value in pairs if key == "Version"}
    return versions.pop() if len(versions) == 1 else None


def _target_version(headers: Mapping[str, str]) -> str | None:
    """The api version a JSON target prefix dates itself with (``KinesisAnalytics_20180523``).

    Two service ids can share one signing name, and for a JSON service the dated target prefix
    is what tells their calls apart, as ``Version`` does for a query request: Managed Service for
    Apache Flink (``kinesisanalyticsv2``, 2018-05-23) signs as ``kinesisanalytics``, exactly like
    the v1 service it replaced, so without this every v2 call is recorded under the v1 id — and
    the proxy's service allowlist, an api trigger and the refusal gate all key on that name.
    Unknown or undated prefixes change nothing: the first candidate wins as before.
    """
    prefix = headers.get("x-amz-target", "").split(".")[0]
    dated = re.search(r"_(\d{4})(\d{2})(\d{2})$", prefix)
    return "-".join(dated.groups()) if dated else None


def wire_protocol(model: ServiceModel, *, path: str, headers: Mapping[str, str], body: bytes) -> str:
    """The protocol this request is actually written in.

    A service model names a preferred protocol and, for services that speak several,
    the full list (CloudWatch: rpc-v2-cbor preferred, json and query also accepted).
    Clients pick freely: the AWS CLI sends CloudWatch calls as ``application/x-amz-json-1.0``
    with ``X-Amz-Target``, and Terraform's SDK sends query. Decoding by the preferred
    protocol alone left every such call with a blank operation (paper-config-1/2,
    528 calls), so the wire format decides, restricted to what the model supports.
    """
    preferred = model.metadata.get("protocol", "")
    supported = set(model.metadata.get("protocols") or [preferred])
    content_type = headers.get("content-type", "").lower()
    if len(supported) == 1:
        return preferred
    if "cbor" in content_type or headers.get("smithy-protocol") == "rpc-v2-cbor" or "/operation/" in path:
        wanted = "smithy-rpc-v2-cbor"
    elif "x-amz-target" in headers and "json" in content_type:
        wanted = "json"
    elif "x-www-form-urlencoded" in content_type or body.lstrip().startswith(b"Action="):
        wanted = "ec2" if "ec2" in supported else "query"
    else:
        wanted = preferred
    return wanted if wanted in supported else preferred


def error_code(status: int, headers: Mapping[str, str], body: bytes) -> str | None:
    """The AWS error code of a failed response, or None when the body carries none.

    REST-JSON services (Lambda) put it in ``x-amzn-ErrorType`` (sometimes suffixed with
    ``:http://...``); JSON services in ``__type`` (DynamoDB namespaces it as
    ``com.amazonaws.dynamodb.v20120810#ResourceNotFoundException``); query, ec2 and
    rest-xml services in ``<Code>``.
    """
    if status < 300:
        return None
    lowered = {k.lower(): v for k, v in headers.items()}
    header = lowered.get("x-amzn-errortype")
    if header:
        return header.split(":", 1)[0].rsplit("#", 1)[-1].strip() or None
    text = body[:4000].decode("utf-8", errors="replace").strip()
    if "<Code>" in text:
        return text.split("<Code>", 1)[1].split("</Code>", 1)[0].strip() or None
    if text.startswith("{"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        if isinstance(payload, dict):
            for key in ("__type", "code", "Code", "errorType"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    return value.rsplit("#", 1)[-1].split(":", 1)[0]
    return None


def decode_request(*, signing_name: str, region: str, method: str, path: str,
                   query: str, headers: Mapping[str, str], body: bytes) -> DecodedRequest:
    lowered = {k.lower(): v for k, v in headers.items()}
    service_id = service_id_for(signing_name,
                                _declared_version(query, body) or _target_version(lowered))
    try:
        model = service_model(service_id)
    except DecodeError as exc:
        return DecodedRequest(service_id, "", "", error=str(exc))
    protocol = wire_protocol(model, path=path, headers=lowered, body=body)
    query_pairs = dict(parse_qsl(query, keep_blank_values=True))

    try:
        if protocol in {"query", "ec2"}:
            try:
                canonical = decode_query_request(service=service_id, region=region, body=body,
                                                 query=query, session=_session())
            except CanonicalizationError as exc:
                # The parameters could not be decoded; keep the operation so a
                # trigger keyed on ``service.operation`` still sees the call.
                return DecodedRequest(service_id, _query_operation(model, query, body), protocol,
                                      model.api_version, {}, decoded=False,
                                      error=f"{type(exc).__name__}: {exc}")
            return DecodedRequest(service_id, canonical.operation, protocol, canonical.api_version,
                                  canonical.parameters, decoded=True)

        if protocol == "json":
            target = lowered.get("x-amz-target", "")
            operation = target.split(".")[-1]
            op = model.operation_model(operation)
            params = json.loads(body.decode("utf-8")) if body.strip() else {}
            return DecodedRequest(service_id, op.name, protocol, model.api_version, params, decoded=True)

        if protocol == "smithy-rpc-v2-cbor":
            # /service/<Target>/operation/<Operation>; body is CBOR (not decoded).
            match = re.search(r"/operation/([A-Za-z0-9_]+)", path)
            operation = model.operation_model(match.group(1)).name if match else ""
            return DecodedRequest(service_id, operation, protocol, model.api_version, {}, decoded=False,
                                  error=None if operation else "no operation in rpc-v2 path")

        if protocol in {"rest-json", "rest-xml"}:
            matched = _match_rest(service_id, method, path, query_pairs, lowered)
            if matched is None:
                return DecodedRequest(service_id, "", protocol, model.api_version, {}, decoded=False,
                                      error=f"no {protocol} route for {method} {path}")
            op, uri_params = matched
            if protocol == "rest-xml":
                return DecodedRequest(service_id, op.name, protocol, model.api_version, {}, decoded=False)
            params: dict[str, Any] = {}
            members = _wire_to_member(op)
            for wire, value in uri_params.items():
                member = members.get(wire, (wire, "uri"))[0]
                params[member] = value
            for wire, value in query_pairs.items():
                member = members.get(wire, (wire, "querystring"))[0]
                params[member] = value
            for wire, value in lowered.items():
                for candidate, (member, location) in members.items():
                    if location == "header" and candidate.lower() == wire:
                        params[member] = value
            if body.strip():
                payload = json.loads(body.decode("utf-8"))
                payload_member = op.input_shape.serialization.get("payload") if op.input_shape else None
                if payload_member:
                    params[payload_member] = payload
                elif isinstance(payload, dict):
                    for wire, value in payload.items():
                        params[members.get(wire, (wire, "body"))[0]] = value
            return DecodedRequest(service_id, op.name, protocol, model.api_version, params, decoded=True)

        return DecodedRequest(service_id, "", protocol, model.api_version, {}, decoded=False,
                              error=f"unsupported protocol {protocol}")
    except (CanonicalizationError, ValueError, KeyError, json.JSONDecodeError) as exc:
        return DecodedRequest(service_id, "", protocol, model.api_version, {}, decoded=False,
                              error=f"{type(exc).__name__}: {exc}")
