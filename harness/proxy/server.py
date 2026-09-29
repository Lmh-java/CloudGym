"""AWS API interception proxy.

Actors (the agent, distractors) are given dummy credentials and
``AWS_ENDPOINT_URL=http://127.0.0.1:<port>/<kind>/<token>``. Every request
lands here, is decoded, journaled as an ``api.lifecycle`` event, possibly
*held* until a matching distractor has started, then re-signed with the
harness credentials and forwarded to the real regional endpoint.

Because the actor's own signature is discarded, a request that bypasses the
proxy fails authentication upstream: the trace is complete by construction.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping
from xml.sax.saxutils import escape

import urllib3
from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import ReadOnlyCredentials

from harness.runtime.controller import EventController, EventControllerError
from harness.runtime.decode import DecodeError, decode_request, endpoint_for, error_code, parse_sigv4_scope
from harness.runtime.events import ActorKind, ApiEvent, ApiPhase

DUMMY_ACCESS_KEY_ID = "CLOUDGYMDUMMYKEY0"
DUMMY_SECRET_ACCESS_KEY = "cloudgym-dummy-secret-the-proxy-re-signs-every-request"

_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
               "trailer", "transfer-encoding", "upgrade", "host", "content-length",
               "authorization", "x-amz-date", "x-amz-security-token", "x-amz-content-sha256",
               "expect", "accept-encoding"}


@dataclass(frozen=True)
class Actor:
    actor_id: str
    kind: ActorKind
    token: str = field(default_factory=lambda: secrets.token_urlsafe(18))

    @property
    def path_prefix(self) -> str:
        return f"/{'a' if self.kind is ActorKind.MAIN else 'd'}/{self.token}"


def dummy_credential_environment(actor: Actor, proxy_url: str, region: str) -> dict[str, str]:
    """Environment for an actor routed through the proxy (no real credentials)."""
    return {
        "AWS_ACCESS_KEY_ID": DUMMY_ACCESS_KEY_ID,
        "AWS_SECRET_ACCESS_KEY": DUMMY_SECRET_ACCESS_KEY,
        "AWS_ENDPOINT_URL": proxy_url.rstrip("/") + actor.path_prefix,
        "AWS_REGION": region,
        "AWS_DEFAULT_REGION": region,
        "AWS_EC2_METADATA_DISABLED": "true",
        # Path-style S3 and no retries-on-403 surprises.
        "AWS_S3_ADDRESSING_STYLE": "path",
    }


def _aws_error(status: int, code: str, message: str, *, json_body: bool) -> tuple[int, dict[str, str], bytes]:
    if json_body:
        body = json.dumps({"__type": code, "message": message}).encode()
        return status, {"content-type": "application/x-amz-json-1.1"}, body
    body = (f'<?xml version="1.0" encoding="UTF-8"?><Response><Errors><Error><Code>{escape(code)}</Code>'
            f'<Message>{escape(message)}</Message></Error></Errors></Response>').encode()
    return status, {"content-type": "text/xml"}, body


class ApiProxy:
    def __init__(self, controller: EventController, *, run_id: str, run_dir: Path,
                 credentials: ReadOnlyCredentials, actors: Mapping[str, Actor], region: str,
                 allowed_services: set[str] | None = None, upstream_override: str | None = None,
                 timeout: float = 60.0):
        self.controller = controller
        self.run_id = run_id
        self.run_dir = Path(run_dir)
        self.credentials = credentials
        self.actors_by_token = {actor.token: actor for actor in actors.values()}
        self.region = region
        self.allowed_services = allowed_services
        self.upstream_override = upstream_override  # tests: forward everything here
        self.timeout = timeout
        self._pool = urllib3.PoolManager(num_pools=8, maxsize=16, timeout=urllib3.Timeout(total=timeout), retries=False)
        self._evidence = self.run_dir / "private" / "api"
        self.calls: dict[str, int] = {"main": 0, "distractor": 0, "denied": 0}

    # -- ASGI app -------------------------------------------------------------

    def asgi_app(self):
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import Response
        from starlette.routing import Route

        async def handle(request: Request) -> Response:
            body = await request.body()
            status, headers, payload = await self.handle(
                method=request.method, raw_path=request.url.path, query=request.url.query,
                headers=dict(request.headers), body=body,
            )
            return Response(content=payload, status_code=status, headers=headers)

        return Starlette(routes=[Route("/{path:path}", handle, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"])])

    # -- core ---------------------------------------------------------------

    async def handle(self, *, method: str, raw_path: str, query: str, headers: Mapping[str, str],
                     body: bytes) -> tuple[int, dict[str, str], bytes]:
        lowered = {k.lower(): v for k, v in headers.items()}
        json_client = "json" in lowered.get("content-type", "") or "x-amz-target" in lowered
        actor, path = self._resolve_actor(raw_path)
        if actor is None:
            self.calls["denied"] += 1
            await self._record_denied(None, method, raw_path, "unknown actor token")
            return _aws_error(403, "AccessDenied", "unknown CloudGym actor", json_body=json_client)
        try:
            _key, scope_region, signing_name = parse_sigv4_scope(lowered.get("authorization"))
        except DecodeError as exc:
            self.calls["denied"] += 1
            await self._record_denied(actor, method, path, str(exc))
            return _aws_error(403, "AccessDenied", str(exc), json_body=json_client)

        decoded = decode_request(signing_name=signing_name, region=scope_region, method=method,
                                 path=path, query=query, headers=lowered, body=body)
        call_id = uuid.uuid4().hex[:16]
        http = {"method": method, "path": path, "query": query,
                "content_type": lowered.get("content-type"), "body_length": len(body)}
        request_digest = self._write_evidence(call_id, "req", method, path, query, lowered, body)

        deny = self._policy(decoded.service, decoded.operation, scope_region)
        if deny:
            self.calls["denied"] += 1
            await self.controller.publish_api(ApiEvent(
                run_id=self.run_id, sequence=0, actor_id=actor.actor_id, actor_kind=actor.kind,
                call_id=call_id, phase=ApiPhase.AFTER_ERROR, service=decoded.service,
                operation=decoded.operation, region=scope_region, protocol=decoded.protocol,
                api_version=decoded.api_version, parameters=decoded.parameters,
                parameters_decoded=decoded.decoded, http=http,
                error={"code": "CloudGymDenied", "message": deny}, raw_evidence_digest=request_digest))
            return _aws_error(403, "AccessDenied", deny, json_body=json_client)

        before = ApiEvent(
            run_id=self.run_id, sequence=0, actor_id=actor.actor_id, actor_kind=actor.kind,
            call_id=call_id, phase=ApiPhase.BEFORE, service=decoded.service,
            operation=decoded.operation, region=scope_region, protocol=decoded.protocol,
            api_version=decoded.api_version, parameters=decoded.parameters,
            parameters_decoded=decoded.decoded, http={**http, "decode_error": decoded.error},
            raw_evidence_digest=request_digest,
        )
        try:
            await self.controller.publish_api(before)  # may hold here
        except EventControllerError as exc:
            return _aws_error(500, "InternalFailure", f"harness refused the call: {exc}", json_body=json_client)
        self.calls[actor.kind.value] += 1

        try:
            status, resp_headers, payload = await asyncio.to_thread(
                self._forward, decoded.service, signing_name, scope_region, method, path, query, headers, body)
        except Exception as exc:  # noqa: BLE001 - transport failure becomes after_error
            await self.controller.publish_api(ApiEvent(
                run_id=self.run_id, sequence=0, actor_id=actor.actor_id, actor_kind=actor.kind,
                call_id=call_id, phase=ApiPhase.AFTER_ERROR, service=decoded.service,
                operation=decoded.operation, region=scope_region, protocol=decoded.protocol,
                api_version=decoded.api_version, http=http,
                error={"code": "TransportError", "message": str(exc)[:500]}))
            return _aws_error(502, "InternalFailure", f"upstream failure: {exc}", json_body=json_client)

        response_digest = self._write_evidence(call_id, "res", str(status), "", "", resp_headers, payload)
        outcome = {"status": status, "aws_request_id": resp_headers.get("x-amzn-requestid") or resp_headers.get("x-amz-request-id"),
                   "body_sha256": hashlib.sha256(payload).hexdigest(), "body_length": len(payload)}
        phase = ApiPhase.AFTER_SUCCESS if status < 300 else ApiPhase.AFTER_ERROR
        await self.controller.publish_api(ApiEvent(
            run_id=self.run_id, sequence=0, actor_id=actor.actor_id, actor_kind=actor.kind,
            call_id=call_id, phase=phase, service=decoded.service, operation=decoded.operation,
            region=scope_region, protocol=decoded.protocol, api_version=decoded.api_version,
            http=http, outcome=outcome,
            # The provider's own code (x-amzn-ErrorType / <Code> / __type), "HTTP" only when
            # the response carries none; the status is kept so the two never conflate.
            error=None if status < 300 else {"code": error_code(status, resp_headers, payload) or "HTTP",
                                             "http_status": status,
                                             "message": payload[:500].decode(errors="replace")},
            raw_evidence_digest=response_digest))
        relay = {k: v for k, v in resp_headers.items() if k not in _HOP_BY_HOP}
        return status, relay, payload

    # -- helpers --------------------------------------------------------------

    def _resolve_actor(self, raw_path: str) -> tuple[Actor | None, str]:
        parts = raw_path.split("/", 3)
        # ["", "a"|"d", token, rest]
        if len(parts) >= 3 and parts[1] in {"a", "d"}:
            actor = self.actors_by_token.get(parts[2])
            if actor is not None:
                rest = parts[3] if len(parts) > 3 else ""
                return actor, "/" + rest
        return None, raw_path

    def _policy(self, service: str, operation: str, region: str) -> str | None:
        if region != self.region:
            return f"region {region} is outside this run ({self.region})"
        if service == "sts" and operation != "GetCallerIdentity":
            return "sts is limited to GetCallerIdentity"
        if self.allowed_services is not None and service not in self.allowed_services:
            return f"service {service} is not allowed in this case"
        return None

    def _forward(self, service_id: str, signing_name: str, region: str, method: str, path: str,
                 query: str, headers: Mapping[str, str], body: bytes) -> tuple[int, dict[str, str], bytes]:
        if self.upstream_override:
            base = self.upstream_override.rstrip("/")
        else:
            hostname, signing_name = endpoint_for(service_id, region)
            base = f"https://{hostname}"
        url = base + path
        if query:
            url += "?" + query
        clean = {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP}
        aws_request = AWSRequest(method=method.upper(), url=url, data=body, headers=clean)
        # S3 requires x-amz-content-sha256 (stripped above with the client's
        # other auth headers); S3SigV4Auth regenerates it, plain SigV4Auth never does.
        signer = S3SigV4Auth if signing_name == "s3" else SigV4Auth
        signer(self.credentials, signing_name, region).add_auth(aws_request)
        prepared = aws_request.prepare()
        response = self._pool.request(prepared.method, prepared.url, body=prepared.body,
                                      headers=dict(prepared.headers.items()), preload_content=True)
        return response.status, {k.lower(): v for k, v in response.headers.items()}, response.data

    def _write_evidence(self, call_id: str, suffix: str, line1: str, path: str, query: str,
                        headers: Mapping[str, str], body: bytes) -> str:
        self._evidence.mkdir(parents=True, exist_ok=True)
        self._evidence.chmod(0o700)
        header_text = "\n".join(f"{k}: {v}" for k, v in sorted(headers.items())
                                if k.lower() not in {"authorization", "x-amz-security-token"})
        blob = f"{line1} {path}{'?' + query if query else ''}\n{header_text}\n\n".encode() + body
        target = self._evidence / f"{call_id}.{suffix}"
        target.write_bytes(blob)
        target.chmod(0o600)
        return hashlib.sha256(blob).hexdigest()

    async def _record_denied(self, actor: Actor | None, method: str, path: str, reason: str) -> None:
        try:
            await self.controller.record_runtime("api.denied", {
                "actor_id": actor.actor_id if actor else None, "method": method, "path": path, "reason": reason})
        except Exception:  # noqa: BLE001 - a denied request must still get its 403
            pass


def credentials_from_env(env: Mapping[str, str]) -> ReadOnlyCredentials:
    return ReadOnlyCredentials(env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"],
                               env.get("AWS_SESSION_TOKEN"))


__all__ = ["Actor", "ApiProxy", "DUMMY_ACCESS_KEY_ID", "DUMMY_SECRET_ACCESS_KEY",
           "credentials_from_env", "dummy_credential_environment"]
