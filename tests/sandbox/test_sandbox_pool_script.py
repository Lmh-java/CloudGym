"""Pure helpers of the sandbox-pool provisioning script (no AWS)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.aws_safety import AwsTarget, PoolConfig
from scripts import sandbox_pool

CONFIG = PoolConfig(management_profile="mgmt", ou_id="ou-abcd-12345678",
                    email_template="me+sbx-{n:02d}@example.org")


class ProvisioningHelperTests(unittest.TestCase):
    def test_next_index_skips_used_emails(self) -> None:
        targets = [AwsTarget("cloudgym-pool-02", "2" * 12, "us-east-1")]
        org = [{"Name": "cloudgym-sbx-01"}, {"Name": "cloudgym-sbx-05", "Status": "SUSPENDED"},
               {"Name": "unrelated"}]
        self.assertEqual(sandbox_pool._next_index(CONFIG, targets, org), 6)
        self.assertEqual(sandbox_pool._next_index(CONFIG, [], []), 1)

    def test_profile_stanza_and_idempotent_write(self) -> None:
        stanza = sandbox_pool.profile_stanza("cloudgym-pool-03", "3" * 12, CONFIG, "us-east-1")
        self.assertIn("[profile cloudgym-pool-03]", stanza)
        self.assertIn("role_arn = arn:aws:iam::333333333333:role/OrganizationAccountAccessRole", stanza)
        self.assertIn("source_profile = mgmt", stanza)
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "config"
            cfg.write_text("[profile existing]\nregion = us-east-1")   # no trailing newline
            with patch.object(sandbox_pool, "AWS_CONFIG", cfg):
                self.assertTrue(sandbox_pool._write_aws_profile("cloudgym-pool-03", stanza))
                self.assertFalse(sandbox_pool._write_aws_profile("cloudgym-pool-03", stanza))
            text = cfg.read_text()
            self.assertEqual(text.count("[profile cloudgym-pool-03]"), 1)
            self.assertTrue(text.startswith("[profile existing]\nregion = us-east-1\n\n[profile"))

    def test_email_template_formats(self) -> None:
        self.assertEqual(CONFIG.email_template.format(n=7), "me+sbx-07@example.org")


class JanitorTests(unittest.TestCase):
    def test_dirty_due_respects_state_grace_and_backoff(self) -> None:
        now = 10_000.0
        rows = [{"account_id": "a", "state": "dirty", "since": now - 120},
                {"account_id": "b", "state": "dirty", "since": now - 10},        # inside the grace
                {"account_id": "c", "state": "quarantined", "since": 0},        # reserved: never
                {"account_id": "d", "state": "leased", "since": 0},             # a live cell: never
                {"account_id": "e", "state": "clean", "since": 0},
                {"account_id": "f", "state": "dirty", "since": 0},              # failed once, 100 s ago
                {"account_id": "g", "state": "dirty", "since": 0}]              # failed twice, 1000 s ago
        due = sandbox_pool.dirty_due(rows, now=now, grace_s=60, failures={"f": 1, "g": 2},
                                     last_try={"f": now - 100, "g": now - 1000}, backoff=(300, 900, 1800))
        self.assertEqual(due, ["a", "g"])

    def test_janitor_once_resets_only_dirty_accounts(self) -> None:
        from harness.sandbox import Pool
        targets = [AwsTarget(f"p{i}", str(i) * 12, "us-east-1", name=f"sbx-{i}") for i in range(1, 5)]
        with tempfile.TemporaryDirectory() as directory:
            pool = Pool(targets, Path(directory))
            held = pool.acquire("cell")                                   # 111111111111 leased (live pid)
            pool.mark("222222222222", "dirty", reason="leak")
            pool.mark("333333333333", "quarantined", reason="reserved: refusal probes")
            import json, time
            state = json.loads(pool.state_path.read_text())
            state["accounts"]["222222222222"]["since"] = time.time() - 300
            pool.state_path.write_text(json.dumps(state))
            swept = []

            def fake_reset(p, target, region, *, dry_run=False, log=None):
                swept.append(target.account_id)
                p.mark(target.account_id, "clean")
                return None

            args = type("A", (), {"allow_aws": True, "interval": 0.0, "grace": 60.0, "region": None, "once": True})()
            with patch.object(sandbox_pool, "_pool", lambda: pool), patch.object(sandbox_pool, "reset_account", fake_reset):
                self.assertEqual(sandbox_pool.cmd_janitor(args), 0)
            self.assertEqual(swept, ["222222222222"])
            states = {r["account_id"]: r["state"] for r in pool.status()}
            self.assertEqual(states, {"111111111111": "leased", "222222222222": "clean",
                                      "333333333333": "quarantined", "444444444444": "clean"})
            pool.release(held, clean=True)
