"""Claude Code adapter for ``claude -p``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .base import AgentCall, AgentResult


class ClaudeAdapter:
    provider = "claude"
    prompt_via_stdin = False

    def command(self, call: AgentCall, *, schema_path: Path | None, output_path: Path | None) -> list[str]:
        del output_path
        # The prompt goes first: claude's variadic options (--allowedTools,
        # --mcp-config) would otherwise consume a trailing positional.
        argv = [call.executable or "claude", "-p", call.prompt]
        if call.streaming:
            argv += ["--output-format", "stream-json", "--verbose"]
        else:
            argv += ["--output-format", "json"]
        if call.max_turns:
            argv += ["--max-turns", str(call.max_turns)]
        # Never prompt (headless) and never blanket-approve: anything outside
        # the allowlist is auto-denied by `dontAsk`.
        argv += ["--permission-mode", "dontAsk"]
        if call.safe_mode:
            argv += ["--tools", "Read,Glob,Grep"]
        if call.mcp_servers:
            config = {"mcpServers": {name: {"type": "http", "url": url}
                                     for name, url in call.mcp_servers.items()}}
            argv += ["--mcp-config", json.dumps(config, separators=(",", ":")),
                     "--strict-mcp-config"]
        tools = list(call.allowed_tools)
        if not any(tool.startswith("mcp__") for tool in tools):
            tools += [f"mcp__{name}__*" for name in call.mcp_servers]
        if tools:
            # One comma-joined value: the variadic form would swallow the prompt.
            argv += ["--allowedTools", ",".join(tools)]
        if call.model:
            argv += ["--model", call.model]
        if call.output_schema is not None:
            argv += ["--json-schema", json.dumps(call.output_schema, separators=(",", ":"))]
        argv.extend(call.native_args)
        return argv

    def parse(self, call: AgentCall, *, stdout: str, stderr: str, output_text: str | None) -> AgentResult:
        del output_text
        payload = json.loads(stdout)
        return self._from_result(call, payload, stdout=stdout, stderr=stderr)

    def parse_stream(self, call: AgentCall, *, events: Sequence[Mapping[str, Any]], stderr: str,
                     output_text: str | None) -> AgentResult:
        del output_text
        payload: Mapping[str, Any] = {}
        model = None
        for event in events:
            if event.get("type") == "system" and event.get("subtype") == "init":
                model = event.get("model") or model
            elif event.get("type") == "assistant":
                model = (event.get("message") or {}).get("model") or model
            elif event.get("type") == "result":
                payload = event
        result = self._from_result(call, payload, stdout="", stderr=stderr)
        if model and not result.model:
            result = AgentResult(**{**result.__dict__, "model": model})
        if not payload:
            result = AgentResult(**{**result.__dict__, "partial": True})
        return result

    @staticmethod
    def _from_result(call: AgentCall, payload: Mapping[str, Any], *, stdout: str, stderr: str) -> AgentResult:
        cost = payload.get("total_cost_usd")
        model_usage = payload.get("modelUsage") or {}
        model = None
        if model_usage:
            # The model that did the work is the one that spent the most.
            model = max(model_usage, key=lambda m: (model_usage[m] or {}).get("costUSD", 0) or 0)
        return AgentResult(
            call.provider,
            payload.get("result", "") or "",
            payload.get("structured_output"),
            payload.get("session_id"),
            payload.get("usage") or {},
            float(cost) if cost is not None else None,
            stdout,
            stderr,
            model=model,
            num_turns=payload.get("num_turns"),
            model_usage=model_usage,
            permission_denials=tuple(payload.get("permission_denials") or ()),
            duration_api_ms=payload.get("duration_api_ms"),
            stop_reason=payload.get("stop_reason") or payload.get("subtype"),
        )
