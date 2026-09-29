"""Codex adapter: turns are model round trips, not codex 'turns'; stop reason from the stream."""

from __future__ import annotations

import unittest

from harness.agents.base import AgentCall
from harness.agents.codex import CodexAdapter, round_trips


def _call() -> AgentCall:
    return AgentCall(provider="codex", prompt="do the thing", cwd=None)


def _item(kind: str, **extra) -> dict:
    return {"type": "item.completed", "item": {"type": kind, **extra}}


class CodexTurnTests(unittest.TestCase):
    def test_round_trips_count_tool_items_plus_final_message(self) -> None:
        events = [{"type": "thread.started", "thread_id": "t1", "model": "gpt-5.5"}, {"type": "turn.started"},
                  _item("reasoning"), _item("command_execution"), _item("agent_message", text="looking"),
                  _item("command_execution"), _item("mcp_tool_call"), _item("agent_message", text="done"),
                  {"type": "turn.completed", "usage": {"input_tokens": 10}}]
        self.assertEqual(round_trips(events), 4)
        result = CodexAdapter().parse_stream(_call(), events=events, stderr="", output_text=None)
        self.assertEqual((result.num_turns, result.stop_reason, result.partial), (4, "end_turn", False))
        self.assertEqual(result.text, "looking\ndone")

    def test_failed_turn_reports_error(self) -> None:
        events = [{"type": "thread.started", "thread_id": "t1"}, {"type": "turn.started"},
                  {"type": "error", "message": "Selected model is at capacity"}, {"type": "turn.failed"}]
        result = CodexAdapter().parse_stream(_call(), events=events, stderr="", output_text=None)
        self.assertEqual((result.num_turns, result.stop_reason, result.partial), (None, "error", True))

    def test_empty_stream(self) -> None:
        result = CodexAdapter().parse_stream(_call(), events=[], stderr="", output_text=None)
        self.assertEqual((result.num_turns, result.stop_reason, result.partial), (None, None, True))


class CodexCostTests(unittest.TestCase):
    def test_cost_is_the_list_price_of_the_final_usage(self) -> None:
        events = [{"type": "thread.started", "thread_id": "t1", "model": "gpt-5.5"}, {"type": "turn.started"},
                  _item("agent_message", text="done"),
                  {"type": "turn.completed", "usage": {"input_tokens": 1_000_000, "cached_input_tokens": 0,
                                                       "output_tokens": 0}}]
        result = CodexAdapter().parse_stream(_call(), events=events, stderr="", output_text=None)
        self.assertAlmostEqual(result.cost_usd, 5.0)   # gpt-5.5 uncached input, $/1M

    def test_unknown_model_leaves_cost_unset(self) -> None:
        events = [{"type": "thread.started", "thread_id": "t1", "model": "gpt-9-nova"},
                  {"type": "turn.completed", "usage": {"input_tokens": 10, "output_tokens": 10}}]
        result = CodexAdapter().parse_stream(_call(), events=events, stderr="", output_text=None)
        self.assertIsNone(result.cost_usd)
