"""Verdict validity classes: invalid (no fair measurement), partial (scored but flagged), valid."""

from __future__ import annotations

import unittest

from harness.bench.report import classify_validity


def _result(**over):
    base = {"status": "completed", "verdict": "fail", "distractors_enabled": True,
            "distractors": ["a", "b"], "triggers": {"fired": ["a:api", "b:api"]},
            "interference_before_finish": True, "agent": {"error": None, "called_finish": True}}
    base.update(over)
    return base


class ValidityTests(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertEqual(classify_validity(_result()), ("valid", None))

    def test_invalid_without_verdict_or_when_cli_never_worked(self) -> None:
        self.assertEqual(classify_validity(_result(verdict=None, status="aborted", error="TerraformError: x"))[0], "invalid")
        v, why = classify_validity(_result(agent={"error": "AgentRunnerError: codex exited with status 1", "called_finish": False}))
        self.assertEqual(v, "invalid")
        self.assertIn("AgentRunnerError", why)

    def test_partial_reasons(self) -> None:
        v, why = classify_validity(_result(triggers={"fired": ["a:api"]}))
        self.assertEqual(v, "partial"); self.assertIn("never fired", why)
        v, why = classify_validity(_result(interference_before_finish=False))
        self.assertEqual(v, "partial"); self.assertIn("after the agent finished", why)
        v, why = classify_validity(_result(agent={"error": "AgentTimeoutError: claude timed out", "called_finish": False}))
        self.assertEqual(v, "partial"); self.assertIn("time budget", why)
        v, why = classify_validity(_result(agent={"error": "AgentRunnerError: codex exited with status 1", "called_finish": True}))
        self.assertEqual(v, "partial"); self.assertIn("after calling finish", why)
        v, why = classify_validity(_result(status="invalid", error="destroy failed"))
        self.assertEqual(v, "partial"); self.assertIn("run status invalid", why)

    def test_control_ignores_interference_flags(self) -> None:
        # interference_before_finish is False on every control run; it means nothing there
        self.assertEqual(classify_validity(_result(distractors_enabled=False, distractors=[], triggers={},
                                                   interference_before_finish=False)), ("valid", None))
