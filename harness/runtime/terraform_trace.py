"""Terraform AWS provider trace pipeline and Step 2 evidence sanitizer.

Two layers:

1. **Sanitized raw-event derivative** — the JSON log stream
   (``TF_LOG=JSON`` + ``TF_LOG_PROVIDER=DEBUG``) is parsed with an
   allowlist; the derivative plus its digest is the immutable execution
   evidence. Raw logs can contain credential-provider responses, so they are
   written 0600 by the workspace runner and **unlinked here on both success
   and failure**.

2. **Canonical operation compiler** — retained as a later-stage utility; it is
not called by Step 2. Request/response pairs from the clean
   main transition are compiled into the replayable canonical operation
   schema (id, service, operation, kind, input, depends_on, produces,
   observed_status, replayable). Reads/polls stay in evidence only; benign
   failed mutations are retained as non-replayable operations; physical IDs
   are substituted with ``${<address>}`` (initial-state bindings) or
   ``${op-NNN.<Key>}`` (produced values).

The parser is version-pinned together with the Terraform/provider versions
(harness/terraform/workspace.py). Provider log field names are declared once
below; they are validated against the pinned toolchain during real-AWS
capability certification, and every mutating plan change must be covered by
a compiled operation (fail closed otherwise).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from .canonicalize import CanonicalizationError, decode_query_request
from .events import canonical_digest, json_safe, sanitize_public

PARSER_VERSION = "tf-aws-trace-1"
TRACE_SCHEMA_VERSION = 1

# --- provider log field names (single source of truth; version-pinned) -----
F_MODULE = "@module"
F_MESSAGE = "@message"
F_TIMESTAMP = "@timestamp"
F_RESOURCE_TYPE = "tf_resource_type"
F_RPC = "tf_rpc"
F_REQ_ID = "tf_req_id"
F_RPC_SERVICE = "rpc.service"
F_RPC_METHOD = "rpc.method"
F_HTTP_STATUS = "http.status_code"
F_REQUEST_BODY = "http.request.body"
F_RESPONSE_BODY = "http.response.body"
F_REGION = "aws.region"
F_RETRY_ATTEMPT = "tf_aws.retry.attempt"

_DERIVATIVE_ALLOWLIST = (
    F_TIMESTAMP, F_MODULE, F_RESOURCE_TYPE, F_RPC, F_REQ_ID,
    F_RPC_SERVICE, F_RPC_METHOD, F_HTTP_STATUS, F_REGION, F_RETRY_ATTEMPT,
    F_REQUEST_BODY, F_RESPONSE_BODY,
)

# Services whose wire bodies the derivative may retain (typed-decoded).
_BODY_ALLOWED_SERVICES = {"ec2"}

_READ_METHOD = re.compile(r"^(Describe|Get|List)[A-Z]")

# Value patterns that are secrets wherever they appear.
_SECRET_VALUE_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"X-Amz-Signature=[0-9a-f]{16,}"),
    re.compile(r"aws4_request"),
)

# Keys whose values must never survive un-redacted in a derivative.
_SECRET_KEYS = frozenset({
    "accesskeyid", "secretaccesskey", "sessiontoken", "token",
    "authorization", "x-amz-security-token", "password", "expiration",
})


def _normalize_key(key: str) -> str:
    return key.lower().replace("_", "").replace("-", "")

# Response values an operation is known to produce (pilot scope).
_PRODUCES: dict[str, tuple[tuple[str, str], ...]] = {
    # operation -> ((produced key, xml tag), ...)
    "CreateSecurityGroup": (("GroupId", "groupId"),),
    "CreateVpc": (("VpcId", "vpcId"),),
    "CreateSubnet": (("SubnetId", "subnetId"),),
}


class TraceError(RuntimeError):
    """The trace cannot be parsed/compiled safely; fail closed."""


class SanitizationError(TraceError):
    """Credential-like material reached a derivative; fail closed."""


# ---------------------------------------------------------------------------
# Layer 1: parse + sanitized derivative
# ---------------------------------------------------------------------------

def parse_log_lines(text: str) -> list[dict]:
    """Every line of a TF_LOG=JSON stream as a dict; malformed line = error."""
    records = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise TraceError(f"malformed JSON log line {lineno}: {e}") from e
    return records


def _is_request(record: dict) -> bool:
    return F_RPC_METHOD in record and F_REQUEST_BODY in record \
        and F_HTTP_STATUS not in record


def _is_response(record: dict) -> bool:
    return F_RPC_METHOD in record and F_HTTP_STATUS in record


def _reduce(record: dict) -> dict:
    """One raw record -> its allowlisted, sanitized derivative."""
    reduced = {k: record[k] for k in _DERIVATIVE_ALLOWLIST if k in record}
    service = str(reduced.get(F_RPC_SERVICE, "")).lower()
    if service not in _BODY_ALLOWED_SERVICES:
        reduced.pop(F_REQUEST_BODY, None)
        reduced.pop(F_RESPONSE_BODY, None)
    return sanitize_public(json_safe(reduced))


def _is_redaction_marker(value: Any) -> bool:
    return isinstance(value, dict) and set(value) == {"$redacted_sha256"}


def _walk_sensitive_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, inner in value.items():
            if (_normalize_key(str(key)) in _SECRET_KEYS
                    and inner not in (None, "")
                    and not _is_redaction_marker(inner)):
                raise SanitizationError(
                    f"sensitive key {key!r} holds an un-redacted value "
                    f"in a derivative; refusing to keep it")
            _walk_sensitive_keys(inner)
    elif isinstance(value, list):
        for inner in value:
            _walk_sensitive_keys(inner)


def audit_no_secrets(value: Any) -> None:
    safe = json_safe(value)
    _walk_sensitive_keys(safe)
    text = json.dumps(safe, sort_keys=True)
    for pattern in _SECRET_VALUE_PATTERNS:
        if pattern.search(text):
            raise SanitizationError(
                f"credential-like material matched {pattern.pattern!r} "
                f"in a derivative; refusing to keep it")


def derive_events(records: list[dict]) -> list[dict]:
    """Sanitized raw-event derivative for provider HTTP request/response
    records, each stamped with a content digest of its own reduction."""
    derivative = []
    for record in records:
        if not (_is_request(record) or _is_response(record)):
            continue
        reduced = _reduce(record)
        reduced["raw_evidence_digest"] = canonical_digest(reduced)
        derivative.append(reduced)
    audit_no_secrets(derivative)
    return derivative


def extract_derivative(log_path: Path) -> list[dict]:
    """Parse one raw provider log, return its derivative, unlink the raw log.

    The unlink happens on success *and* failure: raw logs may contain
    credential-provider responses and must never outlive extraction.
    """
    try:
        records = parse_log_lines(log_path.read_text())
        return derive_events(records)
    finally:
        log_path.unlink(missing_ok=True)


def extract_evidence(log_path: Path) -> list[dict]:
    """Extract Step 2's paired, non-semantic Terraform API evidence.

    Pairing and provenance numbering happen before preprocessing. The result
    intentionally contains request/response facts only; semantic operation
    compilation belongs to Step 3.
    """
    try:
        records = parse_log_lines(log_path.read_text())
        pairs = _pair_calls(records)
        evidence: list[dict] = []
        for sequence, pair in enumerate(pairs, start=1):
            if pair.response is None:
                raise TraceError(
                    f"unpaired Terraform provider request at api_sequence {sequence}")
            request = _reduce(pair.request)
            response = _reduce(pair.response)
            record = {
                "schema_version": "terraform-api-evidence/v1",
                "api_sequence": sequence,
                "service": str(pair.request.get(F_RPC_SERVICE, "")).lower(),
                "operation": pair.request.get(F_RPC_METHOD),
                "request": request.get(F_REQUEST_BODY),
                "response": response.get(F_RESPONSE_BODY),
                "http_status": pair.response.get(F_HTTP_STATUS),
                "attempt_count": 1,
            }
            # Step 2 evidence retains mutating calls only. The sequence above
            # is assigned before this filter, so gaps preserve provenance.
            if _READ_METHOD.match(str(record["operation"] or "")):
                continue
            record = sanitize_public(json_safe(record))
            audit_no_secrets(record)
            evidence.append(record)
        return evidence
    finally:
        log_path.unlink(missing_ok=True)


def write_evidence(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(json_safe(record), sort_keys=True) + "\n"
                                       for record in records))


# ---------------------------------------------------------------------------
# Layer 2: canonical operation compiler
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CanonicalOperation:
    id: str
    service: str
    operation: str
    kind: str                       # mutation | benign_failed_mutation
    input: dict
    depends_on: tuple[str, ...]
    produces: dict[str, str]        # key -> "${op-NNN.key}" symbol
    observed_status: int
    replayable: bool
    terraform_address: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "service": self.service,
            "operation": self.operation,
            "kind": self.kind,
            "input": self.input,
            "depends_on": list(self.depends_on),
            "produces": dict(self.produces),
            "observed_status": self.observed_status,
            "replayable": self.replayable,
            "terraform_address": self.terraform_address,
        }


@dataclass
class _Pair:
    request: dict
    response: dict | None = None


def _pair_calls(records: list[dict]) -> list[_Pair]:
    """Pair provider HTTP requests with their responses, in order.

    Pairing key is (tf_req_id, rpc.method); within a key, responses attach
    to the oldest unanswered request (retries produce their own pairs via
    the retry-attempt metadata). An unanswered request fails closed later if
    it was a mutation.
    """
    pairs: list[_Pair] = []
    open_by_key: dict[tuple, list[_Pair]] = {}
    for record in records:
        if _is_request(record):
            pair = _Pair(request=record)
            pairs.append(pair)
            key = (record.get(F_REQ_ID), record.get(F_RPC_METHOD))
            open_by_key.setdefault(key, []).append(pair)
        elif _is_response(record):
            key = (record.get(F_REQ_ID), record.get(F_RPC_METHOD))
            waiting = open_by_key.get(key, [])
            if waiting:
                waiting.pop(0).response = record
            else:
                raise TraceError(
                    f"response without a matching request: "
                    f"{record.get(F_RPC_METHOD)!r} req_id={record.get(F_REQ_ID)!r}")
    return pairs


def _mutating_addresses(plan_json: dict) -> dict[str, list[str]]:
    """type -> addresses with real create/update/delete actions in the plan."""
    by_type: dict[str, list[str]] = {}
    for change in plan_json.get("resource_changes", []):
        actions = set(change.get("change", {}).get("actions", []))
        if actions & {"create", "update", "delete"}:
            by_type.setdefault(change["type"], []).append(change["address"])
    return by_type


def _join_address(record: dict, plan_addresses: dict[str, list[str]]) -> str:
    """Provider record -> full Terraform address, via the saved plan.

    Provider records carry only the resource type; the join is unambiguous
    only when the plan changes exactly one instance of that type.
    """
    tf_type = record.get(F_RESOURCE_TYPE)
    if not tf_type:
        raise TraceError(
            f"mutating call {record.get(F_RPC_METHOD)!r} has no "
            f"{F_RESOURCE_TYPE}; cannot join to a Terraform address")
    candidates = plan_addresses.get(tf_type, [])
    if len(candidates) != 1:
        raise TraceError(
            f"ambiguous address join for type {tf_type!r}: plan changes "
            f"{candidates!r}; refusing to guess")
    return candidates[0]


def _decode_input(record: dict) -> dict:
    service = str(record.get(F_RPC_SERVICE, "")).lower()
    region = str(record.get(F_REGION, ""))
    # Real provider logs terminate the body with a newline; without stripping
    # it the last parameter value carries "\n" and reference substitution
    # misses (observed in the first pilot run).
    body = str(record.get(F_REQUEST_BODY, "")).strip()
    try:
        canonical = decode_query_request(service=service, region=region, body=body)
    except CanonicalizationError as e:
        raise TraceError(
            f"cannot decode {record.get(F_RPC_METHOD)!r} request body: {e}") from e
    return canonical.parameters


_RESERVED_TAG_PREFIX = "cloudgym:"


def _strip_reserved_tags(value: Any) -> Any:
    """Remove reserved cloudgym:* tag entries from compiled inputs.

    The certification scaffold injects ownership default tags into every
    create call; they are run-specific harness metadata, not part of the
    intent, and must not appear in a replayable trace. Tag containers left
    empty by the strip are dropped entirely.
    """
    if isinstance(value, dict):
        out = {}
        for key, inner in value.items():
            stripped = _strip_reserved_tags(inner)
            if key in ("Tags", "TagSpecifications") and stripped == []:
                continue  # container emptied by the strip: drop the key
            out[key] = stripped
        return out
    if isinstance(value, list):
        result = []
        for item in value:
            if (isinstance(item, dict)
                    and str(item.get("Key", "")).startswith(_RESERVED_TAG_PREFIX)):
                continue  # a reserved ownership tag entry
            stripped = _strip_reserved_tags(item)
            if isinstance(stripped, dict) and set(stripped) == {"ResourceType"}:
                continue  # a TagSpecification whose tags were all reserved
            result.append(stripped)
        return result
    return value


def _extract_produced(operation: str, response: dict) -> dict[str, str]:
    """Produced physical IDs from an EC2 Query XML response body."""
    spec = _PRODUCES.get(operation)
    body = response.get(F_RESPONSE_BODY, "")
    if not spec or not body:
        return {}
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError as e:
        raise TraceError(f"unparseable {operation} response body: {e}") from e
    namespace = root.tag.partition("}")[0] + "}" if root.tag.startswith("{") else ""
    produced = {}
    for key, tag in spec:
        element = root.find(f".//{namespace}{tag}")
        if element is None or not (element.text or "").strip():
            raise TraceError(
                f"{operation} succeeded but produced no <{tag}>; "
                f"cannot bind its physical id")
        produced[key] = element.text.strip()
    return produced


def _substitute(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        return replacements.get(value, value)
    if isinstance(value, dict):
        return {k: _substitute(v, replacements) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, replacements) for v in value]
    return value


def _collect_refs(value: Any, out: set[str]) -> None:
    if isinstance(value, str):
        if value.startswith("${op-") and value.endswith("}"):
            out.add(value[2:-1].split(".", 1)[0])
    elif isinstance(value, dict):
        for v in value.values():
            _collect_refs(v, out)
    elif isinstance(value, list):
        for v in value:
            _collect_refs(v, out)


def compile_operations(
    records: list[dict],
    plan_json: dict,
    initial_bindings: dict[str, str],
    *,
    command_succeeded: bool,
) -> list[CanonicalOperation]:
    """Provider records of the clean main transition -> canonical operations.

    ``initial_bindings`` maps pre-existing physical IDs to Terraform logical
    addresses (e.g. ``vpc-0123 -> aws_vpc.main``); their occurrences become
    ``${aws_vpc.main.id}`` references. IDs created inside the trace become
    ``${op-NNN.<Key>}`` references. Reads/polls are excluded (they live in
    the sanitized derivative); failed mutations are benign only because the
    Terraform command itself succeeded — otherwise the transition failed and
    compilation refuses.
    """
    if not command_succeeded:
        raise TraceError(
            "refusing to compile T_main from a failed terraform command; "
            "classify the run as a transition failure instead")
    plan_addresses = _mutating_addresses(plan_json)
    replacements = {
        physical: f"${{{address}.id}}"
        for physical, address in initial_bindings.items()
    }
    # Only resource apply traffic is compiled: credential-chain calls, plan
    # reads, and other provider RPCs never carry ApplyResourceChange.
    apply_records = [r for r in records if r.get(F_RPC) == "ApplyResourceChange"]
    operations: list[CanonicalOperation] = []
    counter = 0
    for pair in _pair_calls(apply_records):
        request = pair.request
        method = str(request.get(F_RPC_METHOD, ""))
        if _READ_METHOD.match(method):
            continue  # observation/poll: evidence only
        if pair.response is None:
            raise TraceError(
                f"mutating call {method!r} has no response record; "
                f"incomplete pair")
        status = int(pair.response.get(F_HTTP_STATUS, 0))
        succeeded = 200 <= status < 300
        counter += 1
        op_id = f"op-{counter:03d}"
        address = _join_address(request, plan_addresses)
        raw_input = _decode_input(request)
        substituted = _strip_reserved_tags(_substitute(raw_input, replacements))
        produced_ids = _extract_produced(method, pair.response) if succeeded else {}
        produces = {}
        for key, physical in produced_ids.items():
            symbol = f"${{{op_id}.{key}}}"
            replacements[physical] = symbol
            produces[key] = symbol
        refs: set[str] = set()
        _collect_refs(substituted, refs)
        operations.append(CanonicalOperation(
            id=op_id,
            service=str(request.get(F_RPC_SERVICE, "")).lower(),
            operation=method,
            kind="mutation" if succeeded else "benign_failed_mutation",
            input=sanitize_public(json_safe(substituted)),
            depends_on=tuple(sorted(refs)),
            produces=produces,
            observed_status=status,
            replayable=succeeded,
            terraform_address=address,
        ))
    _verify_plan_coverage(operations, plan_addresses)
    audit_no_secrets([op.to_dict() for op in operations])
    return operations


def _verify_plan_coverage(operations: list[CanonicalOperation],
                          plan_addresses: dict[str, list[str]]) -> None:
    """Every planned change must be evidenced by at least one successful
    mutation — the fail-closed net against silently unparsed operations."""
    covered = {op.terraform_address for op in operations if op.replayable}
    planned = {a for addresses in plan_addresses.values() for a in addresses}
    missing = sorted(planned - covered)
    if missing:
        raise TraceError(
            f"planned changes with no parsed mutating operation: {missing}; "
            f"the provider log schema may have drifted — refusing to certify")


def trace_header(*, run_id: str, seed_id: str, region: str,
                 terraform_version: str, provider_version: str) -> dict:
    return {
        "schema_version": TRACE_SCHEMA_VERSION,
        "kind": "canonical-operation-trace",
        "parser_version": PARSER_VERSION,
        "run_id": run_id,
        "seed_id": seed_id,
        "capture": {
            "terraform_version": terraform_version,
            "aws_provider_version": provider_version,
            "region": region,
            "parallelism": 1,
            "log_encoding": "TF_LOG=JSON",
            "provider_log_level": "TF_LOG_PROVIDER=DEBUG",
        },
    }


def write_trace(path: Path, header: dict,
                operations: list[CanonicalOperation]) -> None:
    lines = [json.dumps(json_safe(header), sort_keys=True)]
    lines += [json.dumps(json_safe(op.to_dict()), sort_keys=True)
              for op in operations]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
