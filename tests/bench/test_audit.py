"""Transcript audit: reads outside the workspace are found, classified and counted only when they delivered."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.bench.audit import audit_events, audit_run, classify, extract_paths, summarize

VM_RUN = "/home/ubuntu/cloudgym-bench/artifacts/experiments/paper-config-1/haiku-control-iac-eval-82-t1"
WS = VM_RUN + "/private/agent-workspace"


def _claude_events(calls: list[tuple[str, dict, str]]) -> list[dict]:
    events = []
    for i, (tool, tool_input, output) in enumerate(calls):
        events.append({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": f"t{i}", "name": tool, "input": tool_input}]}})
        events.append({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": output}]}})
    return events


def _codex_events(calls: list[tuple[str, str]]) -> list[dict]:
    return [{"type": "item.completed", "item": {"type": "command_execution", "command": cmd,
                                                 "aggregated_output": out}} for cmd, out in calls]


class PathTests(unittest.TestCase):
    def test_extracts_filesystem_paths_not_aws_names(self) -> None:
        paths = extract_paths("cat /home/u/x.txt; aws logs describe-log-groups --prefix /aws/lambda/fn; "
                              "curl https://sts.us-east-1.amazonaws.com/v1; ls ~/.claude; echo $HOME/y")
        self.assertIn("/home/u/x.txt", paths)
        self.assertIn("~/.claude", paths)
        self.assertIn("~/y", paths)
        self.assertNotIn("/v1", paths)
        self.assertIn("/aws/lambda/fn", paths)   # extracted, but classify() ignores it

    def test_classify_sandboxed_layout(self) -> None:
        self.assertIsNone(classify("/work/main.tf", workspace=None, mount="/work"))
        self.assertIsNone(classify("/usr/bin/aws", workspace=None, mount="/work"))
        self.assertIsNone(classify("/aws/lambda/fn", workspace=None, mount="/work"))
        self.assertEqual(classify("/home/ubuntu/cloudgym-bench/cases", workspace=None, mount="/work"), "outside")
        self.assertEqual(classify("/home/ubuntu/.claude/settings.json", workspace=None, mount="/work"), "tooling")
        self.assertEqual(classify("~/.codex/config.toml", workspace=None, mount="/work"), "tooling")

    def test_classify_legacy_layout(self) -> None:
        self.assertIsNone(classify(WS + "/main.tf", workspace=WS, mount=None))
        self.assertEqual(classify(VM_RUN + "/run.json", workspace=WS, mount=None), "outside")
        self.assertEqual(classify("/home/ubuntu/cloudgym-bench/cases/aws/x/expected.tf", workspace=WS, mount=None),
                         "outside")


class AuditTests(unittest.TestCase):
    def _audit(self, events: list[dict], *, mount=None, workspace=None, run_name="haiku-control-iac-eval-82-t1"):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / run_name
            (run_dir / "agent").mkdir(parents=True)
            path = run_dir / "agent" / "events.jsonl"
            path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
            return audit_events(path, run_dir=run_dir, mount=mount, workspace=workspace)

    def test_legacy_read_of_reference_answer_is_contamination(self) -> None:
        audit = self._audit(_claude_events([
            ("Bash", {"command": f"cd {WS} && ls"}, "main.tf"),
            ("Read", {"file_path": "/home/ubuntu/cloudgym-bench/cases/aws/iac-eval-82/expected.tf"},
             "1\t# IaC-Eval reference output for row 82"),
        ]))
        self.assertEqual(audit.workspace, WS)             # learned from the transcript
        self.assertFalse(audit.sandboxed)
        self.assertEqual((audit.calls, audit.outside_attempts, audit.outside_successes, audit.sensitive_successes),
                         (2, 1, 1, 1))
        self.assertTrue(audit.contaminated)

    def test_failed_read_is_an_attempt_not_contamination(self) -> None:
        audit = self._audit(_claude_events([
            ("Read", {"file_path": "/home/ubuntu/cloudgym-bench/cases/aws/iac-eval-82/design.md"},
             "File does not exist. Note: your current working directory is /work."),
        ]), mount="/work")
        self.assertTrue(audit.sandboxed)
        self.assertEqual((audit.outside_attempts, audit.outside_successes), (1, 0))
        self.assertFalse(audit.contaminated)

    def test_own_run_directory_is_outside_in_legacy_layout(self) -> None:
        audit = self._audit(_claude_events([
            ("Read", {"file_path": WS + "/main.tf"}, "resource {}"),
            ("Read", {"file_path": VM_RUN + "/run.json"}, '{"distractors": ["namesake-cpu-alarm"]}'),
        ]))
        self.assertEqual(audit.outside_successes, 1)
        self.assertTrue(audit.attempts[0].sensitive)
        self.assertEqual(audit.attempts[0].path, VM_RUN + "/run.json")

    def test_codex_commands_and_tooling_do_not_count(self) -> None:
        audit = self._audit(_codex_events([
            ("/bin/bash -lc 'cat ~/.codex/config.toml'", "[mcp]"),
            ("/bin/bash -lc 'cd build && zip ../fn.zip lambda.js'", "adding: lambda.js"),
            ("/bin/bash -lc 'aws logs describe-log-groups --log-group-name-prefix /aws/lambda/fn'", "{}"),
            ("/bin/bash -lc 'find /home/ubuntu -name lambda.js'", "/home/ubuntu/cloudgym-bench/cases/_staging/x/lambda.js"),
        ]), mount="/work")
        kinds = [a.kind for a in audit.attempts]
        self.assertEqual(kinds, ["tooling", "parent", "outside"])
        self.assertEqual(audit.outside_successes, 1)
        self.assertTrue(audit.contaminated)

    def test_sandboxed_false_positives_do_not_count(self) -> None:
        # 2026-09-24: EC2 user-data, commands over SSH on the agent's own instance and
        # `|| echo none` probes were counted as reads (cases 130/191/423, ~100 cells)
        audit = self._audit(_claude_events([
            ("Bash", {"command": "cat > /tmp/userdata.sh <<'EOF'\nmkdir -p /mnt/efs\nmount -t nfs4 fs:/ /mnt/efs\nEOF\ncat /tmp/userdata.sh | wc -l"}, "3"),
            ("Bash", {"command": "ssh ec2-user@10.0.0.5 'ls /mnt/edge-root/etc'"}, "os-release\nsystemd"),
            ("Bash", {"command": "cat ~/.aws/config 2>/dev/null || echo 'No AWS config found'"}, "No AWS config found"),
        ]), mount="/work")
        self.assertEqual(audit.outside_successes, 3)          # still recorded as attempts
        self.assertFalse(audit.contaminated)

    def test_session_records_count_in_any_run(self) -> None:
        for mount in ("/work", None):
            audit = self._audit(_claude_events([
                ("Bash", {"command": "tail ~/.claude/projects/-work/abc.jsonl"}, '{"type":"user","message":"..."}'),
            ]), mount=mount)
            self.assertEqual([a.kind for a in audit.attempts], ["sessions"])
            self.assertTrue(audit.contaminated, mount)

    def test_own_session_records_and_aws_output_are_not_evidence(self) -> None:
        events = _claude_events([
            ("Read", {"file_path": "/home/ubuntu/.claude/projects/-work/sess-own-1234/tool-results/b1.txt"}, "big output"),
            ("Bash", {"command": "ls /mnt/efs; aws efs describe-file-systems"}, '{"Name": "cloudgym-run-7"}'),
            ("Bash", {"command": "ls -la ~ /root 2>/dev/null"}, "total 0\ndrwxr-xr-x 2 ubuntu ubuntu 40 /home/ubuntu"),
        ])
        events = [{"type": "system", "subtype": "init", "session_id": "sess-own-1234"}] + events
        audit = self._audit(events, mount="/work")
        self.assertEqual([a.kind for a in audit.attempts if "claude" in a.path], ["tooling"])
        self.assertFalse(audit.contaminated)

    def test_written_content_mentioning_host_paths_is_not_a_read(self) -> None:
        audit = self._audit(_claude_events([
            ("Write", {"file_path": "/work/deploy.sh", "content": "cp /home/ubuntu/x /tmp"}, "ok"),
        ]), mount="/work")
        self.assertEqual(audit.attempts, [])

    def test_audit_run_uses_sandbox_record_and_summary_counts_by_arm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            batch = Path(tmp)
            audits = {}
            for name, sandboxed, out in (("opus-policy-iac-eval-1-t1", True, "File does not exist"),
                                         ("opus-policy-iac-eval-2-t1", False, "1\t# reference")):
                run_dir = batch / name
                (run_dir / "agent").mkdir(parents=True)
                (run_dir / "agent" / "events.jsonl").write_text("\n".join(json.dumps(e) for e in _claude_events([
                    ("Read", {"file_path": "/home/ubuntu/cloudgym-bench/cases/aws/c/expected.tf"}, out)])))
                (run_dir / "result.json").write_text(json.dumps({
                    "sandbox": "cloudgym-sbx-01",       # the account label, not the confinement
                    "confinement": {"backend": "bwrap", "workspace_mount": "/work"} if sandboxed else {"backend": "none"},
                    "agent": {"transcript": {"events": "agent/events.jsonl"}}}))
                audits[name] = audit_run(run_dir)
            self.assertTrue(audits["opus-policy-iac-eval-1-t1"].sandboxed)
            self.assertFalse(audits["opus-policy-iac-eval-1-t1"].contaminated)
            self.assertTrue(audits["opus-policy-iac-eval-2-t1"].contaminated)
            summary = summarize(audits)
            self.assertEqual(summary["arms"]["opus-policy"],
                             {"cells": 2, "attempted": 2, "contaminated": 1, "sensitive": 1})
            self.assertIsNone(audit_run(batch / "missing"))


if __name__ == "__main__":
    unittest.main()
