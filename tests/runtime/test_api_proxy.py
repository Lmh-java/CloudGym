"""The interception proxy against a fake upstream: trace, re-sign, deny, hold."""

from __future__ import annotations

import asyncio
import contextlib
import json
import tempfile
import unittest
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.credentials import ReadOnlyCredentials
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from harness.mcp.server import BackgroundServer
from harness.proxy import DUMMY_ACCESS_KEY_ID, Actor, ApiProxy
from harness.runtime.controller import EventController
from harness.runtime.events import ActorKind
from harness.runtime.matcher import ApiMatcher, TriggerSpec
from harness.runtime.store import JsonlEventStore

HARNESS_KEY = "AKIATEST000000000000"
DESCRIBE_VPCS = b"""<?xml version="1.0"?><DescribeVpcsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>req-1</requestId><vpcSet><item><vpcId>vpc-1</vpcId><state>available</state><cidrBlock>10.0.0.0/16</cidrBlock></item></vpcSet></DescribeVpcsResponse>"""
CREATE_SUBNET = b"""<?xml version="1.0"?><CreateSubnetResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>req-2</requestId><subnet><subnetId>subnet-9</subnetId><state>available</state><vpcId>vpc-1</vpcId><cidrBlock>10.0.1.0/24</cidrBlock></subnet></CreateSubnetResponse>"""


DEPENDENCY_VIOLATION = b"""<?xml version="1.0" encoding="UTF-8"?><Response><Errors><Error><Code>DependencyViolation</Code>
<Message>The vpc 'vpc-1' has dependencies and cannot be deleted.</Message></Error></Errors><RequestID>req-err</RequestID></Response>"""


def fake_upstream(seen: list[dict]) -> Starlette:
    async def handle(request: Request) -> Response:
        body = (await request.body()).decode()
        seen.append({"auth": request.headers.get("authorization", ""), "body": body,
                     "host": request.headers.get("host"),
                     "content_sha256": request.headers.get("x-amz-content-sha256")})
        if "Action=DeleteVpc" in body:
            return Response(DEPENDENCY_VIOLATION, status_code=400, media_type="text/xml",
                            headers={"x-amzn-requestid": "req-err"})
        payload = CREATE_SUBNET if "Action=CreateSubnet" in body else DESCRIBE_VPCS
        return Response(payload, media_type="text/xml", headers={"x-amzn-requestid": "req-x"})
    return Starlette(routes=[Route("/{path:path}", handle, methods=["GET", "POST"])])


class ApiProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.seen: list[dict] = []
        self.upstream = BackgroundServer(app=fake_upstream(self.seen))
        await self.upstream.__aenter__()
        self.store = JsonlEventStore(self.root / "events.jsonl")
        self.main = Actor(actor_id="main", kind=ActorKind.MAIN)
        self.distractor = Actor(actor_id="d1", kind=ActorKind.DISTRACTOR)

    async def asyncTearDown(self) -> None:
        await self.upstream.__aexit__(None, None, None)
        self.store.close()
        self._temp.cleanup()

    async def _proxy(self, controller: EventController, **kwargs) -> BackgroundServer:
        proxy = ApiProxy(controller, run_id="run", run_dir=self.root / "run",
                         credentials=ReadOnlyCredentials(HARNESS_KEY, "secret", None),
                         actors={"main": self.main, "d1": self.distractor}, region="us-east-1",
                         upstream_override=self.upstream.url, **kwargs)
        server = BackgroundServer(app=proxy.asgi_app())
        await server.__aenter__()
        server.proxy = proxy  # type: ignore[attr-defined]
        return server

    def _client(self, url: str, actor: Actor, *, region: str = "us-east-1"):
        return boto3.client("ec2", region_name=region, endpoint_url=url + actor.path_prefix,
                            aws_access_key_id=DUMMY_ACCESS_KEY_ID, aws_secret_access_key="dummy",
                            config=Config(retries={"max_attempts": 1}))

    def _events(self) -> list[dict]:
        return [json.loads(l) for l in (self.root / "events.jsonl").read_text().splitlines()]

    async def test_trace_and_resign(self) -> None:
        controller = EventController("run", self.store)
        server = await self._proxy(controller)
        try:
            client = self._client(server.url, self.main)
            vpcs = await asyncio.to_thread(client.describe_vpcs)
            self.assertEqual(vpcs["Vpcs"][0]["VpcId"], "vpc-1")
            await asyncio.to_thread(self._client(server.url, self.distractor).describe_vpcs)
        finally:
            await server.__aexit__(None, None, None)
        self.assertIn(f"Credential={HARNESS_KEY}/", self.seen[0]["auth"])
        api = [e for e in self._events() if e["kind"] == "api.lifecycle"]
        self.assertEqual([(e["actor_id"], e["phase"], e["operation"]) for e in api],
                         [("main", "before", "DescribeVpcs"), ("main", "after_success", "DescribeVpcs"),
                          ("d1", "before", "DescribeVpcs"), ("d1", "after_success", "DescribeVpcs")])
        self.assertEqual(api[1]["outcome"]["aws_request_id"], "req-x")
        self.assertTrue(api[0]["parameters_decoded"])
        self.assertEqual(server.proxy.calls, {"main": 1, "distractor": 1, "denied": 0})

    async def test_s3_resign_carries_content_sha256(self) -> None:
        """S3 rejects SigV4 requests without x-amz-content-sha256; the proxy strips the
        client's copy, so the S3 signer must regenerate it (plain SigV4Auth never does)."""
        controller = EventController("run", self.store)
        server = await self._proxy(controller)
        try:
            s3 = boto3.client("s3", region_name="us-east-1", endpoint_url=server.url + self.main.path_prefix,
                              aws_access_key_id=DUMMY_ACCESS_KEY_ID, aws_secret_access_key="dummy",
                              config=Config(retries={"max_attempts": 1}, s3={"addressing_style": "path"}))
            with contextlib.suppress(Exception):   # the fake upstream answers with EC2 XML; only the forwarded headers matter
                await asyncio.to_thread(s3.list_buckets)
        finally:
            await server.__aexit__(None, None, None)
        self.assertEqual(len(self.seen), 1)
        self.assertIn(f"Credential={HARNESS_KEY}/", self.seen[0]["auth"])
        self.assertIn("/s3/aws4_request", self.seen[0]["auth"])
        self.assertRegex(self.seen[0]["content_sha256"] or "", r"^[0-9a-f]{64}$|^UNSIGNED-PAYLOAD$")

    async def test_upstream_error_is_recorded_with_the_provider_code(self) -> None:
        controller = EventController("run", self.store)
        server = await self._proxy(controller)
        try:
            client = self._client(server.url, self.main)
            with self.assertRaises(Exception):
                await asyncio.to_thread(client.delete_vpc, VpcId="vpc-1")
        finally:
            await server.__aexit__(None, None, None)
        errors = [e for e in self._events() if e.get("kind") == "api.lifecycle" and e.get("phase") == "after_error"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["operation"], "DeleteVpc")
        self.assertEqual(errors[0]["error"]["code"], "DependencyViolation")
        self.assertEqual(errors[0]["error"]["http_status"], 400)
        self.assertEqual(errors[0]["outcome"]["status"], 400)

    async def test_unknown_actor_and_denied_service(self) -> None:
        controller = EventController("run", self.store)
        server = await self._proxy(controller, allowed_services={"sts"})
        try:
            bogus = Actor(actor_id="x", kind=ActorKind.MAIN)
            with self.assertRaises(Exception) as ctx:
                await asyncio.to_thread(self._client(server.url, bogus).describe_vpcs)
            self.assertIn("AccessDenied", str(ctx.exception))
            with self.assertRaises(Exception) as ctx:
                await asyncio.to_thread(self._client(server.url, self.main).describe_vpcs)
            self.assertIn("not allowed", str(ctx.exception))
            with self.assertRaises(Exception) as ctx:
                await asyncio.to_thread(self._client(server.url, self.main, region="eu-west-1").describe_vpcs)
            self.assertIn("outside this run", str(ctx.exception))
        finally:
            await server.__aexit__(None, None, None)
        self.assertEqual(self.seen, [])  # nothing reached upstream
        kinds = [e["kind"] for e in self._events()]
        self.assertIn("api.denied", kinds)
        errors = [e for e in self._events() if e["kind"] == "api.lifecycle"]
        self.assertTrue(all(e["phase"] == "after_error" for e in errors))

    async def _run_hold(self, release: str) -> tuple[list[dict], float]:
        started = asyncio.Event()
        finished = asyncio.Event()

        async def fake_distractor() -> None:
            await controller.record_runtime("distractor.started", {"distractor_id": "d1"})
            started.set()
            await asyncio.sleep(0.4)
            await controller.record_runtime("distractor.completed", {"distractor_id": "d1"})
            finished.set()

        async def starter(ids, observation):
            task = asyncio.create_task(fake_distractor())
            await started.wait()
            return [task]

        trigger = TriggerSpec(trigger_id="t", matcher=ApiMatcher("ec2", "CreateSubnet",
                              where=lambda p: p.get("VpcId") == "vpc-1"),
                              distractor_ids=("d1",), release=release)
        controller = EventController("run", self.store, triggers=(trigger,), distractor_starter=starter)
        server = await self._proxy(controller)
        loop = asyncio.get_running_loop()
        try:
            client = self._client(server.url, self.main)
            t0 = loop.time()
            await asyncio.to_thread(client.create_subnet, VpcId="vpc-1", CidrBlock="10.0.1.0/24")
            elapsed = loop.time() - t0
            await finished.wait()
        finally:
            await server.__aexit__(None, None, None)
        return self._events(), elapsed

    async def test_hold_until_distractor_started(self) -> None:
        events, elapsed = await self._run_hold("after_started")
        kinds = [(e["kind"], e.get("phase")) for e in events]
        self.assertLess(elapsed, 0.35, "after_started must not wait for completion")
        # before → trigger.matched → distractor.started → forwarded call (after_success)
        order = [k for k in kinds if k in {("api.lifecycle", "before"), ("trigger.matched", None),
                                           ("distractor.started", None), ("api.lifecycle", "after_success"),
                                           ("distractor.completed", None)}]
        self.assertEqual(order[:4], [("api.lifecycle", "before"), ("trigger.matched", None),
                                     ("distractor.started", None), ("api.lifecycle", "after_success")])
        matched = next(e for e in events if e["kind"] == "trigger.matched")
        self.assertEqual(matched["data"]["trigger_kind"], "api")

    async def test_after_success_trigger_holds_response_until_completed(self) -> None:
        """A phase="after_success" trigger fires on the main actor's successful call and,
        with release="after_completed", the response is held until the distractor has
        finished — so the distractor's write lands before the agent's call returns."""
        started = asyncio.Event()
        finished = asyncio.Event()

        async def fake_distractor() -> None:
            await controller.record_runtime("distractor.started", {"distractor_id": "d1"})
            started.set()
            await asyncio.sleep(0.4)
            await controller.record_runtime("distractor.completed", {"distractor_id": "d1"})
            finished.set()

        async def starter(ids, observation):
            task = asyncio.create_task(fake_distractor())
            await started.wait()
            return [task]

        trigger = TriggerSpec(trigger_id="t:api", matcher=ApiMatcher("ec2", "CreateSubnet", phase="after_success"),
                              distractor_ids=("d1",), release="after_completed")
        controller = EventController("run", self.store, triggers=(trigger,), distractor_starter=starter)
        server = await self._proxy(controller)
        loop = asyncio.get_running_loop()
        try:
            client = self._client(server.url, self.main)
            t0 = loop.time()
            await asyncio.to_thread(client.create_subnet, VpcId="vpc-1", CidrBlock="10.0.1.0/24")
            elapsed = loop.time() - t0
            self.assertTrue(finished.is_set(), "response must not be relayed before the distractor completed")
        finally:
            await server.__aexit__(None, None, None)
        self.assertGreaterEqual(elapsed, 0.35)
        events = self._events()
        kinds = [(e["kind"], e.get("phase")) for e in events]
        # the call reached upstream first, then the after_success event fired the trigger
        self.assertLess(kinds.index(("api.lifecycle", "after_success")), kinds.index(("trigger.matched", None)))
        self.assertLess(kinds.index(("trigger.matched", None)), kinds.index(("distractor.completed", None)))
        matched = next(e for e in events if e["kind"] == "trigger.matched")
        self.assertEqual(matched["data"]["trigger_ids"], ["t:api"])

    async def test_mutation_snapshots_immediately_inside_hold(self) -> None:
        """A successful mutating main call observes a snapshot before its response is
        relayed; a snapshot predicate that the new state satisfies fires there, and
        with release="after_completed" the distractor lands first. Read-only calls
        take no snapshot."""
        finished = asyncio.Event()
        observed: list[str] = []

        async def fake_distractor() -> None:
            await controller.record_runtime("distractor.started", {"distractor_id": "d1"})
            await asyncio.sleep(0.3)
            await controller.record_runtime("distractor.completed", {"distractor_id": "d1"})
            finished.set()

        async def starter(ids, observation):
            return [asyncio.create_task(fake_distractor())]

        async def observe(event):
            observed.append(event.operation)
            await controller.observe_snapshot({"resources": {"AWS::EC2::Subnet": {"subnet-1": {}}}},
                                              snapshot_id=f"after-{event.operation}")

        from harness.runtime.matcher import SnapshotMatcher
        trigger = TriggerSpec(
            trigger_id="d1",
            matcher=SnapshotMatcher(predicates=(lambda s: bool(s["resources"].get("AWS::EC2::Subnet")),)),
            distractor_ids=("d1",), release="after_completed")
        controller = EventController("run", self.store, triggers=(trigger,), distractor_starter=starter,
                                     on_main_mutation=observe)
        await controller.observe_snapshot({"resources": {}}, snapshot_id="S0", initial=True)
        server = await self._proxy(controller)
        try:
            client = self._client(server.url, self.main)
            await asyncio.to_thread(client.describe_vpcs)
            self.assertEqual(observed, [], "read-only calls must not snapshot")
            await asyncio.to_thread(client.create_subnet, VpcId="vpc-1", CidrBlock="10.0.1.0/24")
            self.assertEqual(observed, ["CreateSubnet"])
            self.assertTrue(finished.is_set(), "response relayed before the snapshot-fired distractor completed")
        finally:
            await server.__aexit__(None, None, None)
        events = self._events()
        kinds = [(e["kind"], e.get("phase"), e.get("snapshot_id")) for e in events]
        i_after = next(i for i, k in enumerate(kinds) if k[:2] == ("api.lifecycle", "after_success") and events[i]["operation"] == "CreateSubnet")
        i_snap = next(i for i, k in enumerate(kinds) if k[0] == "snapshot.observed" and k[2] == "after-CreateSubnet")
        i_match = next(i for i, k in enumerate(kinds) if k[0] == "trigger.matched")
        i_done = next(i for i, k in enumerate(kinds) if k[0] == "distractor.completed")
        self.assertLess(i_after, i_snap)
        self.assertLess(i_snap, i_match)
        self.assertLess(i_match, i_done)
        self.assertEqual(events[i_match]["data"]["trigger_kind"], "snapshot")
        self.assertEqual(events[i_match]["data"]["snapshot_id"], "after-CreateSubnet")

    async def test_occurrence_two_fires_on_second_call_inside_hold(self) -> None:
        """occurrence=2: the first matching call passes untouched; the second fires the
        trigger and, with release="after_completed", is held until the distractor wrote."""
        finished = asyncio.Event()

        async def fake_distractor() -> None:
            await controller.record_runtime("distractor.started", {"distractor_id": "d1"})
            await asyncio.sleep(0.3)
            await controller.record_runtime("distractor.completed", {"distractor_id": "d1"})
            finished.set()

        async def starter(ids, observation):
            return [asyncio.create_task(fake_distractor())]

        trigger = TriggerSpec(trigger_id="d1:api", occurrence=2,
                              matcher=ApiMatcher("ec2", "CreateSubnet", phase="after_success"),
                              distractor_ids=("d1",), release="after_completed")
        controller = EventController("run", self.store, triggers=(trigger,), distractor_starter=starter)
        server = await self._proxy(controller)
        try:
            client = self._client(server.url, self.main)
            await asyncio.to_thread(client.create_subnet, VpcId="vpc-1", CidrBlock="10.0.1.0/24")
            self.assertFalse(finished.is_set(), "first call must not fire an occurrence=2 trigger")
            await asyncio.to_thread(client.create_subnet, VpcId="vpc-1", CidrBlock="10.0.2.0/24")
            self.assertTrue(finished.is_set(), "second call must be held until the distractor completed")
        finally:
            await server.__aexit__(None, None, None)

    async def test_hold_until_distractor_completed(self) -> None:
        events, elapsed = await self._run_hold("after_completed")
        self.assertGreaterEqual(elapsed, 0.35)
        kinds = [(e["kind"], e.get("phase")) for e in events]
        self.assertLess(kinds.index(("distractor.completed", None)), kinds.index(("api.lifecycle", "after_success")))


if __name__ == "__main__":
    unittest.main()
