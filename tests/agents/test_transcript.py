"""Streamed transcripts: lossless events, rendered markdown, turn records, accounting."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from harness.agents import AgentCall, AgentRunner, AgentTimeoutError
from harness.agents.transcript import TranscriptRenderer

STREAM = [
    {"type": "system", "subtype": "init", "model": "claude-fable-5", "session_id": "s-1"},
    {"type": "assistant", "message": {"model": "claude-fable-5", "content": [
        {"type": "thinking", "thinking": "let me look"},
        {"type": "text", "text": "Checking VPCs."},
        {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "aws ec2 describe-vpcs"}}]}},
    {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "content": "vpc-1", "is_error": False}]}},
    {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "aws ec2 create-subnet"}}]}},
    {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t2",
                                              "content": [{"type": "text", "text": "InvalidSubnet.Conflict"}], "is_error": True}]}},
    {"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "t3", "name": "mcp__cloudgym__finish", "input": {}}]}},
    {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t3", "content": "{}"}]}},
    {"type": "assistant", "message": {"content": [{"type": "text", "text": "Done."}]}},
    {"type": "result", "subtype": "success", "result": "Done.", "session_id": "s-1", "num_turns": 4,
     "total_cost_usd": 0.5, "duration_api_ms": 1234, "usage": {"input_tokens": 10, "output_tokens": 20},
     "modelUsage": {"claude-haiku-4-5": {"costUSD": 0.001}, "claude-fable-5": {"costUSD": 0.499}},
     "permission_denials": [{"tool_name": "Bash", "tool_input": {"command": "for i in 1; do :; done"}}]},
]

FAKE_STREAM_CLI = '''#!PYTHON
import json, os, sys, time
events = json.loads(os.environ["FAKE_EVENTS"])
assert "--output-format" in sys.argv and sys.argv[sys.argv.index("--output-format") + 1] == "stream-json"
for event in events:
    print(json.dumps(event), flush=True)
    if os.environ.get("FAKE_SLOW"):
        time.sleep(0.2)
if os.environ.get("FAKE_HANG"):
    time.sleep(30)
'''


class TranscriptRendererTests(unittest.TestCase):
    def test_renders_markdown_and_turns(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            renderer = TranscriptRenderer(root)
            for i, event in enumerate(STREAM):
                renderer.feed(event, ts=1000.0 + i)
            renderer.close()
            md = (root / "transcript.md").read_text()
            self.assertIn("## Turn 1 — assistant", md)
            self.assertIn("Checking VPCs.", md)
            self.assertIn("_thinking (11 chars)_", md)
            self.assertIn("**tool_result** `Bash` (`t2`) — ERROR", md)
            self.assertIn("final message: no tool call", md)
            self.assertEqual(md.count("no tool call"), 1)
            turns = [json.loads(l) for l in (root / "turns.jsonl").read_text().splitlines()]
            self.assertEqual([t["tool"] for t in turns], ["Bash", "Bash", "mcp__cloudgym__finish"])
            self.assertEqual(turns[0]["command"], "aws ec2 describe-vpcs")
            self.assertEqual(turns[0]["duration_ms"], 1000)
            self.assertTrue(turns[1]["is_error"])
            self.assertTrue(turns[2]["is_finish"])
            self.assertEqual((renderer.turns, renderer.tool_calls, renderer.model), (4, 3, "claude-fable-5"))

    def test_codex_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            renderer = TranscriptRenderer(root, provider="codex")
            renderer.feed({"type": "thread.started", "thread_id": "th-1"})
            renderer.feed({"type": "turn.started"})
            renderer.feed({"type": "item.started", "item": {"id": "i1", "type": "command_execution", "command": "aws sts get-caller-identity"}}, ts=1.0)
            renderer.feed({"type": "item.completed", "item": {"id": "i1", "type": "command_execution", "command": "aws sts get-caller-identity",
                                                              "aggregated_output": "{}", "exit_code": 0}}, ts=2.5)
            renderer.feed({"type": "item.started", "item": {"id": "i2", "type": "mcp_tool_call", "server": "cloudgym", "tool": "finish", "arguments": {}}}, ts=3.0)
            renderer.feed({"type": "item.completed", "item": {"id": "i2", "type": "mcp_tool_call", "server": "cloudgym", "tool": "finish",
                                                              "arguments": {}, "result": {"content": [{"type": "text", "text": "{\"accepted\": true}"}]},
                                                              "error": None, "status": "completed"}}, ts=3.2)
            renderer.feed({"type": "turn.completed", "usage": {"input_tokens": 3}})
            renderer.close()
            turns = [json.loads(l) for l in (root / "turns.jsonl").read_text().splitlines()]
            self.assertEqual(turns[0]["tool"], "Bash")
            self.assertEqual(turns[0]["duration_ms"], 1500)
            self.assertFalse(turns[0]["is_error"])
            self.assertEqual(turns[1]["tool"], "mcp__cloudgym__finish")
            self.assertTrue(turns[1]["is_finish"])
            self.assertEqual(turns[1]["result_chars"], len('{"accepted": true}'))


class StreamingRunnerTests(unittest.IsolatedAsyncioTestCase):
    def _cli(self, root: Path) -> Path:
        cli = root / "claude"
        cli.write_text(FAKE_STREAM_CLI.replace("#!PYTHON", f"#!{sys.executable}", 1))
        cli.chmod(0o700)
        return cli

    async def test_streaming_result_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cli = self._cli(root)
            result = await AgentRunner().run(AgentCall(
                "claude", "go", cwd=root, executable=str(cli), transcript_dir=root / "t",
                env={"FAKE_EVENTS": json.dumps(STREAM)}))
            self.assertEqual((result.model, result.num_turns, result.cost_usd, result.session_id),
                             ("claude-fable-5", 4, 0.5, "s-1"))
            self.assertEqual(len(result.permission_denials), 1)
            self.assertEqual(result.duration_api_ms, 1234)
            self.assertEqual(result.tool_calls, 3)
            self.assertFalse(result.partial)
            events = [json.loads(l) for l in (root / "t" / "events.jsonl").read_text().splitlines()]
            self.assertEqual(events, STREAM)  # lossless
            self.assertTrue((root / "t" / "transcript.md").is_file())

    async def test_timeout_keeps_partial_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cli = self._cli(root)
            with self.assertRaises(AgentTimeoutError) as raised:
                await AgentRunner().run(AgentCall(
                    "claude", "go", cwd=root, executable=str(cli), transcript_dir=root / "t", timeout=1.5,
                    env={"FAKE_EVENTS": json.dumps(STREAM[:4]), "FAKE_HANG": "1"}))
            partial = raised.exception.partial
            self.assertIsNotNone(partial)
            self.assertTrue(partial.partial)
            self.assertEqual(partial.model, "claude-fable-5")
            self.assertEqual(partial.tool_calls, 2)  # t1 answered, t2 unanswered but recorded
            self.assertEqual(len((root / "t" / "events.jsonl").read_text().splitlines()), 4)


if __name__ == "__main__":
    unittest.main()
