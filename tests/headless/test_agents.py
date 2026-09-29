from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from harness.agents import AgentCall, AgentRunner, AgentRunnerError, run_agent_sync


FAKE_CLI = '''#!/usr/bin/env python3
import json, pathlib, sys
args = sys.argv[1:]
if "claude" in pathlib.Path(sys.argv[0]).name:
    print(json.dumps({"result": "claude answer", "session_id": "c-1", "usage": {"input_tokens": 3}, "total_cost_usd": 0.02, "structured_output": {"ok": True}}))
else:
    out = args[args.index("--output-last-message") + 1] if "--output-last-message" in args else None
    if out:
        pathlib.Path(out).write_text('{"ok": true}' if "--output-schema" in args else "codex answer")
    print(json.dumps({"type": "thread.started", "thread_id": "x-1"}))
    print(json.dumps({"type": "turn.completed", "usage": {"input_tokens": 4}}))
'''


class HeadlessAgentTests(unittest.IsolatedAsyncioTestCase):
    async def test_codex_and_claude_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            codex = root / "codex"
            codex.write_text(FAKE_CLI)
            codex.chmod(0o700)
            claude = root / "claude"
            claude.write_text(FAKE_CLI.replace('"claude" in pathlib.Path(sys.argv[0]).name', 'True'))
            claude.chmod(0o700)
            runner = AgentRunner()
            one = await runner.run(AgentCall("codex", "hello", cwd=root, executable=str(codex), output_schema={"type": "object"}))
            two = await runner.run(AgentCall("claude", "hello", cwd=root, executable=str(claude), output_schema={"type": "object"}))
            self.assertEqual((one.text, one.session_id, one.structured_output, one.usage["input_tokens"]), ('{"ok": true}', "x-1", {"ok": True}, 4))
            self.assertEqual((two.text, two.session_id, two.structured_output, two.cost_usd), ("claude answer", "c-1", {"ok": True}, 0.02))

    async def test_batch_limits_concurrency_and_preserves_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cli = root / "claude"
            cli.write_text(FAKE_CLI.replace('"claude" in pathlib.Path(sys.argv[0]).name', 'True'))
            cli.chmod(0o700)
            runner = AgentRunner(max_concurrency=2)
            result = await runner.run_many([AgentCall("claude", str(i), cwd=root, executable=str(cli)) for i in range(4)])
            self.assertEqual([item.text for item in result], ["claude answer"] * 4)

    async def test_nonzero_exit_keeps_process_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cli = root / "bad"
            cli.write_text("#!/usr/bin/env python3\nimport sys\nprint('bad', file=sys.stderr)\nsys.exit(7)\n")
            cli.chmod(0o700)
            with self.assertRaises(AgentRunnerError) as raised:
                await AgentRunner().run(AgentCall("claude", "hello", cwd=root, executable=str(cli)))
            self.assertEqual((raised.exception.exit_code, raised.exception.stderr.strip()), (7, "bad"))

    def test_sync_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cli = root / "claude"
            cli.write_text(FAKE_CLI.replace('"claude" in pathlib.Path(sys.argv[0]).name', 'True'))
            cli.chmod(0o700)
            result = run_agent_sync(AgentCall("claude", "hello", cwd=root, executable=str(cli)))
            self.assertEqual(result.text, "claude answer")


if __name__ == "__main__":
    unittest.main()
