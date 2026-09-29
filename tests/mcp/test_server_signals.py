"""An embedded uvicorn server must not replace the process's SIGINT/SIGTERM handlers."""

from __future__ import annotations

import asyncio
import signal
import unittest

from harness.mcp.server import BackgroundServer


async def _app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


class SignalHandlerTests(unittest.IsolatedAsyncioTestCase):
    async def test_background_server_leaves_signal_handlers_alone(self) -> None:
        before = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM))
        async with BackgroundServer(app=_app) as server:
            self.assertTrue(server.url.startswith("http://127.0.0.1:"))
            during = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM))
            self.assertEqual(during, before, "uvicorn captured the process signal handlers")
        await asyncio.sleep(0)
        self.assertEqual((signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)), before)
