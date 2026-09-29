from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.mcp.server import create_server
from harness.runtime.coordinator import RuntimeConfig, RuntimeCoordinator


class McpServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_agent_surface_exposes_finish_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            coordinator = RuntimeCoordinator(
                RuntimeConfig(
                    run_id="run",
                    run_dir=Path(temp) / "run",
                    allow_unscoped_credentials=True,
                )
            )
            server = create_server(coordinator)
            tools = await server.list_tools()
            self.assertEqual(
                {tool.name for tool in tools},
                {"finish"},
            )


if __name__ == "__main__":
    unittest.main()
