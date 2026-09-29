from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.analysis import build_timeline, compute_metrics, render_svg, render_text, write_run_artifacts

T0 = "2026-08-27T12:00:00+00:00"


def wall(offset: float) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset)).isoformat()


def epoch(offset: float) -> float:
    from datetime import datetime, timezone
    return datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc).timestamp() + offset


def api(seq, actor, phase, op, offset, **extra):
    record = {"kind": "api.lifecycle", "sequence": seq, "event_id": f"r:{seq}", "actor_id": actor,
              "phase": phase, "service": "ec2", "operation": op, "call_id": extra.pop("call_id", op),
              "wall_time": wall(offset), "parameters": extra.pop("parameters", {}), "outcome": {"status": 200}}
    record.update(extra)
    return record


class TimelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.run = Path(self._temp.name)
        (self.run / "agent").mkdir(parents=True)
        events = [
            {"kind": "run.started", "sequence": 1, "wall_time": wall(0), "data": {}},
            api(2, "main", "before", "DescribeVpcs", 5),
            api(3, "main", "after_success", "DescribeVpcs", 5.5),
            api(4, "main", "before", "CreateSubnet", 10, call_id="cs", parameters={"VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24"}),
            {"kind": "trigger.matched", "sequence": 5, "wall_time": wall(10.1),
             "data": {"observation_id": "r:4", "snapshot_id": "api:cs:before", "trigger_kind": "api",
                      "trigger_ids": ["d:api"], "distractor_ids": ["d"]}},
            {"kind": "distractor.started", "sequence": 6, "wall_time": wall(10.3), "data": {"distractor_id": "d"}},
            api(7, "d", "before", "CreateSubnet", 11),
            api(8, "d", "after_success", "CreateSubnet", 12),
            {"kind": "distractor.completed", "sequence": 9, "wall_time": wall(12.5), "data": {"distractor_id": "d"}},
            api(10, "main", "after_error", "CreateSubnet", 13, call_id="cs", outcome=None,
                error={"code": "HTTP", "message": "<Response><Errors><Error><Code>InvalidSubnet.Conflict</Code></Error></Errors></Response>"}),
            api(11, "main", "before", "CreateSubnet", 20, call_id="cs2", parameters={"CidrBlock": "10.0.2.0/24"}),
            api(12, "main", "after_success", "CreateSubnet", 21, call_id="cs2"),
        ]
        (self.run / "events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")
        turns = [
            {"turn": 1, "ts": epoch(4.8), "tool": "Bash", "command": "aws ec2 describe-vpcs", "duration_ms": 900, "is_error": False},
            {"turn": 2, "ts": epoch(9.8), "tool": "Bash", "command": "aws ec2 create-subnet --cidr-block 10.0.1.0/24", "duration_ms": 3300, "is_error": True},
            {"turn": 3, "ts": epoch(19.8), "tool": "Bash", "command": "aws ec2 create-subnet --cidr-block 10.0.2.0/24", "duration_ms": 1300, "is_error": False},
            {"turn": 4, "ts": epoch(25.0), "tool": "mcp__cloudgym__finish", "is_finish": True, "duration_ms": 10},
        ]
        (self.run / "agent" / "turns.jsonl").write_text("\n".join(json.dumps(t) for t in turns) + "\n")

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_timeline_order_and_lanes(self) -> None:
        entries = build_timeline(self.run)
        lanes = [(round(e.t_rel_s, 1), e.lane, e.kind) for e in entries]
        self.assertEqual(lanes[:4], [(0.0, "harness", "run.started"), (4.8, "agent", "tool_call"),
                                     (5.0, "api:main", "api.before"), (5.5, "api:main", "api.after_success")])
        self.assertIn((10.1, "trigger", "trigger.matched"), lanes)
        self.assertIn((13.0, "api:main", "api.after_error"), lanes)
        text = render_text(entries)
        self.assertIn("ec2.CreateSubnet ERROR InvalidSubnet.Conflict", text)
        self.assertIn("mcp__cloudgym__finish → finish", text)

    def test_svg_and_artifacts(self) -> None:
        svg = render_svg(build_timeline(self.run), title="t")
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn(">agent</text>", svg)            # api:main lane, labelled agent
        self.assertIn(">d</text>", svg)                # distractor lane
        for absent in ("trigger", "snapshot", "harness", "tool_call"):
            self.assertNotIn(f">{absent}</text>", svg)
        self.assertIn("CreateSubnet ✗", svg)          # errored call bar
        self.assertIn("InvalidSubnet.Conflict", svg)   # tooltip
        self.assertIn("#3C5488", svg)                  # NPG navy for the agent
        self.assertIn("#E64B35", svg)                  # NPG red for the first distractor
        (self.run / "result.json").write_text(json.dumps({
            "run_id": "r", "status": "completed", "verdict": "pass", "agent": {"provider": "claude", "cost_usd": 0.1},
            "metrics": compute_metrics(self.run), "triggers": {"fired": ["d:api"], "fired_kinds": {"d:api": "api"}},
            "api_calls": {"main": 3, "distractor": 1}, "leaked": []}))
        written = write_run_artifacts(self.run)
        self.assertEqual(sorted(written), ["summary_md", "timeline_svg", "timeline_txt"])
        summary = (self.run / "summary.md").read_text()
        self.assertIn("| verdict | pass |", summary)
        self.assertIn("| hold_duration_s | 3 |", summary)
        self.assertIn("![timeline](timeline.svg)", summary)
        self.assertIn("ec2.CreateSubnet ERROR", (self.run / "timeline.txt").read_text())

    def test_metrics(self) -> None:
        m = compute_metrics(self.run)
        self.assertEqual(m["time_to_first_api_call_s"], 5.0)
        self.assertEqual(m["time_to_trigger_s"], 10.1)
        self.assertEqual(m["hold_duration_s"], [3.0])
        self.assertTrue(m["interference_before_finish"])
        self.assertEqual(m["agent_calls_after_interference"], 1)
        self.assertEqual(m["turns_after_interference"], 2)
        self.assertEqual(m["errors_seen_by_agent"], [{"operation": "ec2.CreateSubnet", "code": "InvalidSubnet.Conflict"}])
        self.assertEqual(m["api_calls_by_operation"]["main"]["ec2.CreateSubnet"], 2)
        self.assertEqual(m["finish_called_at_s"], 25.0)
        self.assertEqual(m["tool_calls_errored"], 1)


if __name__ == "__main__":
    unittest.main()


class ErrorCodeRecoveryTests(unittest.TestCase):
    def test_recorded_code_wins_and_legacy_bodies_are_recovered(self) -> None:
        from harness.analysis.timeline import _error_code

        self.assertEqual(_error_code({"code": "ResourceConflictException", "http_status": 409, "message": "{}"}),
                         "ResourceConflictException")
        self.assertEqual(_error_code({"code": "HTTP", "message": "<Response><Errors><Error><Code>InvalidSubnet.Conflict"
                                                                 "</Code></Error></Errors></Response>"}),
                         "InvalidSubnet.Conflict")
        self.assertEqual(_error_code({"code": "HTTP", "message": '{"__type":"com.amazonaws.dynamodb.v20120810#'
                                                                 'ResourceNotFoundException","message":"x"}'}),
                         "ResourceNotFoundException")
        self.assertEqual(_error_code({"code": "HTTP", "message": '{"Type":"User","message":"Function already exist"}'}),
                         "HTTP")   # legacy REST-JSON bodies carry no code; the header was not kept
        self.assertEqual(_error_code({"code": "CloudGymDenied", "message": "service ssm is not allowed"}),
                         "CloudGymDenied")
