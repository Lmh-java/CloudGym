"""The `changes` tool: absent at awareness=none, roster-only at observed, roster plus activity at disclosed."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.mcp.server import create_server
from harness.runtime.controller import EventController
from harness.runtime.coordinator import RuntimeConfig, RuntimeCoordinator
from harness.runtime.events import ActorKind, ApiEvent, ApiPhase
from harness.runtime.matcher import ApiMatcher, TriggerSpec
from harness.runtime.store import JsonlEventStore


def _event(actor: str, kind: ActorKind, phase: ApiPhase, op: str = "CreateSubnet") -> ApiEvent:
    return ApiEvent(run_id="run", sequence=0, actor_id=actor, actor_kind=kind, call_id=f"{actor}-{op}",
                    phase=phase, service="ec2", operation=op, region="us-east-1",
                    parameters={"VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24"},
                    outcome={"status": 200} if phase is ApiPhase.AFTER_SUCCESS else None)


class AwarenessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        root = Path(self._temp.name)
        self.store = JsonlEventStore(root / "events.jsonl")
        trigger = TriggerSpec(trigger_id="squatter:api", matcher=ApiMatcher("ec2", "DescribeVpcs"),
                              distractor_ids=("squatter",), required=False,
                              metadata={"role": "platform engineer", "responsibility": "reserves blocks",
                                        "intent": "allocate 10.0.1.0/24"})
        self.controller = EventController("run", self.store, triggers=(trigger,))
        self.coordinator = RuntimeCoordinator(RuntimeConfig(run_id="run", run_dir=root / "run",
                                                            allow_unscoped_credentials=True))
        self.coordinator.controller = self.controller

    async def asyncTearDown(self) -> None:
        self.store.close()
        self._temp.cleanup()

    async def _tools(self, awareness: str) -> set[str]:
        server = create_server(self.coordinator, manage_lifecycle=False, awareness=awareness)
        return {tool.name for tool in await server.list_tools()}

    async def _changes(self, awareness: str) -> dict:
        server = create_server(self.coordinator, manage_lifecycle=False, awareness=awareness)
        result = await server.call_tool("changes", {})
        payload = result[1] if isinstance(result, tuple) else result
        return payload if isinstance(payload, dict) else payload.structured_content

    async def test_tool_surface_per_level(self) -> None:
        self.assertEqual(await self._tools("none"), {"finish"})
        self.assertEqual(await self._tools("observed"), {"finish", "changes"})
        self.assertEqual(await self._tools("disclosed"), {"finish", "changes"})
        with self.assertRaises(ValueError):
            create_server(self.coordinator, manage_lifecycle=False, awareness="all")

    ROSTER = [{"principal": "squatter", "role": "platform engineer",
               "responsibility": "reserves blocks", "intent": "allocate 10.0.1.0/24"}]

    async def test_observed_returns_roster_only_from_the_start(self) -> None:
        payload = await self._changes("observed")
        self.assertEqual(payload, {"principals": self.ROSTER})    # no activity key at all

    async def test_observed_never_reveals_distractor_calls(self) -> None:
        await self.controller.publish_api(_event("main", ActorKind.MAIN, ApiPhase.AFTER_SUCCESS, "DescribeVpcs"))
        await self.controller.publish_api(_event("squatter", ActorKind.DISTRACTOR, ApiPhase.BEFORE))
        await self.controller.publish_api(_event("squatter", ActorKind.DISTRACTOR, ApiPhase.AFTER_SUCCESS))
        payload = await self._changes("observed")
        self.assertNotIn("changes", payload)
        self.assertEqual(payload["principals"], self.ROSTER)

    async def test_disclosed_is_roster_plus_empty_activity_before_any_distractor_call(self) -> None:
        await self.controller.publish_api(_event("main", ActorKind.MAIN, ApiPhase.BEFORE, "DescribeSubnets"))
        payload = await self._changes("disclosed")
        self.assertEqual(payload, {"principals": self.ROSTER, "changes": []})

    async def test_disclosed_lists_distractor_calls_only(self) -> None:
        await self.controller.publish_api(_event("main", ActorKind.MAIN, ApiPhase.AFTER_SUCCESS, "DescribeVpcs"))
        await self.controller.publish_api(_event("squatter", ActorKind.DISTRACTOR, ApiPhase.BEFORE))
        await self.controller.publish_api(_event("squatter", ActorKind.DISTRACTOR, ApiPhase.AFTER_SUCCESS))
        payload = await self._changes("disclosed")
        self.assertEqual(payload["principals"], self.ROSTER)
        self.assertEqual(len(payload["changes"]), 1)
        change = payload["changes"][0]
        self.assertEqual((change["principal"], change["operation"], change["status"]), ("squatter", "CreateSubnet", 200))
        self.assertEqual(change["parameters"]["CidrBlock"], "10.0.1.0/24")

if __name__ == "__main__":
    unittest.main()


class ConsultServerTests(unittest.IsolatedAsyncioTestCase):
    """`ask_devops` over a real controller: routing on what a principal's writes carried."""

    async def asyncSetUp(self) -> None:
        from types import SimpleNamespace

        self._temp = tempfile.TemporaryDirectory()
        root = Path(self._temp.name)
        self.store = JsonlEventStore(root / "events.jsonl")
        trigger = TriggerSpec(trigger_id="squatter:api", matcher=ApiMatcher("ec2", "DescribeVpcs"),
                              distractor_ids=("squatter",), required=False,
                              metadata={"role": "network engineer", "responsibility": "reserves blocks",
                                        "intent": "hold a block", "resolution": "That block is held; pick another.",
                                        "subject": ("address space",)})
        self.controller = EventController("run", self.store, triggers=(trigger,))
        self.statuses = {"squatter": "not-fired"}
        self.coordinator = RuntimeCoordinator(RuntimeConfig(
            run_id="run", run_dir=root / "run", allow_unscoped_credentials=True,
            consult_excluded_terms=("vpc-1",)))
        self.coordinator.controller = self.controller
        self.coordinator.scheduler = SimpleNamespace(
            summary=lambda: {k: {"status": v} for k, v in self.statuses.items()})

    async def asyncTearDown(self) -> None:
        self.store.close()
        self._temp.cleanup()

    async def _ask(self, server, **args) -> dict:
        result = await server.call_tool("ask_devops", args)
        payload = result[1] if isinstance(result, tuple) else result
        return payload if isinstance(payload, dict) else payload.structured_content

    async def test_tool_surface(self) -> None:
        for level in ("consult", "consult_open"):
            server = create_server(self.coordinator, manage_lifecycle=False, awareness=level)
            self.assertEqual({t.name for t in await server.list_tools()}, {"finish", "ask_devops"})

    async def test_only_a_cited_and_read_fingerprint_routes(self) -> None:
        """The `consult` level end to end. An up-front question about the block stays silent
        for good: the principal's fact did not exist yet, and the agent never read it after
        the landing. A question citing what the agent read after the landing is answered."""
        import time
        server = create_server(self.coordinator, manage_lifecycle=False, awareness="consult")
        # Asked before the principal has done anything: a thread, no reply.
        first = await self._ask(server, about="10.0.1.0/24 in vpc-1", question="is this block free?")
        self.assertEqual(first["thread"], "t1")
        self.assertEqual(first["replies"], [])
        # The principal writes the block and lands, returning the subnet it made as its fingerprint.
        await self.controller.publish_api(_event("squatter", ActorKind.DISTRACTOR, ApiPhase.AFTER_SUCCESS, "CreateSubnet"))
        result = {"reserved": "subnet-0squat1234567890", "cidr": "10.0.1.0/24", "fingerprint": ["subnet-0squat1234567890"]}
        self.statuses["squatter"] = "succeeded"
        landed_ns = time.monotonic_ns()
        self.coordinator.scheduler.summary = lambda: {"squatter": {
            "status": "succeeded", "result": result,
            "outcomes": [{"status": "succeeded", "result": result, "landed_ns": landed_ns}]}}
        # Citing the fact without having read it: nothing. The earlier thread stays silent too.
        second = await self._ask(server, about="subnet-0squat1234567890", question="whose is this?")
        self.assertEqual(second["replies"], [])
        self.assertEqual(second["earlier_threads"], [])
        # The agent reads the subnet: a MAIN response carrying the id, stored by the proxy.
        api_dir = self.coordinator.run_dir / "private" / "api"
        api_dir.mkdir(parents=True)
        (api_dir / "main-DescribeSubnets.res").write_bytes(
            b"200 \ncontent-type: text/xml\n\n<subnetId>subnet-0squat1234567890</subnetId>")
        await self.controller.publish_api(_event("main", ActorKind.MAIN, ApiPhase.AFTER_SUCCESS, "DescribeSubnets"))
        # The next call, about something else, carries the citing thread's reply — late.
        third = await self._ask(server, about="results bucket", question="layout?")
        self.assertEqual(third["replies"], [])
        self.assertEqual([e["thread"] for e in third["earlier_threads"]], ["t2"])
        self.assertEqual(third["earlier_threads"][0]["replies"][0]["from"], "network engineer")
        reread = await self._ask(server, thread="t2")
        self.assertEqual(len(reread["replies"]), 1)
        self.assertEqual(reread["earlier_threads"], [])
        # The utterance's own word reaches nobody; the topic question never did.
        fourth = await self._ask(server, about="vpc-1", question="any address space conventions?")
        self.assertEqual(fourth["replies"], [])
        summary = self.coordinator.consult_channel.summary()
        self.assertEqual(summary["gate"], "fingerprint")
        self.assertEqual(summary["replies_delivered_late"], 1)
        self.assertEqual(summary["threads_silent"], 3)
        self.assertEqual(summary["unread_replies_at_finish"], 0)
        self.assertEqual([r["via"] for t in summary["threads"] for r in t["replies"]], ["subnet-0squat1234567890"])
        self.assertEqual([r["via_kind"] for t in summary["threads"] for r in t["replies"]], ["fingerprint"])
        self.assertEqual(summary["threads_answered"], 1)
        self.assertEqual(summary["answer_rate"], 0.25)
        self.assertEqual(summary["replies_per_ask"], 0.25)
