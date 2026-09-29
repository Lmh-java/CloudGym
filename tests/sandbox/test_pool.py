"""Lease broker: acquire/release, stale-holder reaping, exhaustion, cross-process contention."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from harness.aws_safety import AwsTarget
from harness.sandbox import Pool, PoolError, PoolExhausted

TARGETS = [AwsTarget("p0", "111111111111", "us-east-1", "SandboxAdministrator"),
           AwsTarget("p1", "222222222222", "us-east-1", "OrganizationAccountAccessRole", access="org-role"),
           AwsTarget("p2", "333333333333", "us-east-1", "OrganizationAccountAccessRole", access="org-role")]


class PoolTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.dir = Path(self._temp.name)
        self.pool = Pool(TARGETS, self.dir)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_acquire_in_pool_order_and_release(self) -> None:
        a = self.pool.acquire("cell-a", run_id="r1")
        b = self.pool.acquire("cell-b")
        self.assertEqual([a.account_id, b.account_id], ["111111111111", "222222222222"])
        self.assertEqual(self.pool.counts(), {"leased": 2, "clean": 1})
        self.assertEqual(self.pool.release(a, clean=True), "clean")
        self.assertEqual(self.pool.release(b, clean=False, error="leaked: AWS::IAM::Role x"), "dirty")
        rows = {r["account_id"]: r for r in self.pool.status()}
        self.assertEqual(rows["111111111111"]["state"], "clean")
        self.assertEqual(rows["222222222222"]["last_error"], "leaked: AWS::IAM::Role x")
        self.assertEqual(rows["111111111111"]["last_run"]["label"], "cell-a")
        # the dirty one is skipped; the primary is reused first
        c = self.pool.acquire("cell-c")
        self.assertEqual(c.account_id, "111111111111")
        with self.assertRaises(PoolError):
            self.pool.release(c, clean=True)
            self.pool.release(c, clean=True)      # double release

    def test_limited_pool_keeps_other_accounts_leases(self) -> None:
        # A casegen session opens the pool with --slots N (the first N targets); its writes
        # must not erase the leases a batch holds on the accounts outside its slice.
        batch = self.pool
        held = batch.acquire("cell", run_id="r1")
        self.assertEqual(held.account_id, "111111111111")
        casegen = Pool(TARGETS[2:], self.dir, pid=batch.pid + 1)      # only account 3
        lease = casegen.acquire("cert-B")
        self.assertEqual(lease.account_id, "333333333333")
        casegen.release(lease, clean=True)
        rows = {r["account_id"]: r for r in batch.status()}
        self.assertEqual(rows["111111111111"]["state"], "leased")      # survived the other pool's writes
        self.assertEqual(rows["333333333333"]["last_run"]["label"], "cert-B")
        self.assertEqual(batch.release(held, clean=True), "clean")
        self.assertEqual([r["account_id"] for r in casegen.status()], ["333333333333"])   # status stays scoped

    def test_exhaustion(self) -> None:
        leases = [self.pool.acquire(f"c{i}") for i in range(3)]
        with self.assertRaises(PoolExhausted):
            self.pool.acquire("late", wait=False)
        with self.assertRaises(PoolExhausted):
            self.pool.acquire("late", timeout=0.3, poll=0.1)
        for lease in leases:
            self.pool.release(lease, clean=False)
        # nothing leased and nothing clean: waiting could never succeed
        with self.assertRaisesRegex(PoolExhausted, "sandbox-pool reset"):
            self.pool.acquire("never", timeout=5)
        self.pool.mark("222222222222", "clean")
        self.assertEqual(self.pool.acquire("again").account_id, "222222222222")

    def test_dead_holder_reaps_to_dirty(self) -> None:
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()
        state = {"schema_version": 1, "accounts": {
            "111111111111": {"state": "leased", "holder": {"pid": dead.pid, "label": "ghost"}},
            "999999999999": {"state": "clean"},         # not configured any more: dropped
        }}
        (self.dir / "pool-state.json").write_text(json.dumps(state))
        rows = {r["account_id"]: r for r in self.pool.status()}
        self.assertEqual(rows["111111111111"]["state"], "dirty")
        self.assertIn("died while leased", rows["111111111111"]["last_error"])
        self.assertNotIn("999999999999", rows)
        self.assertEqual(self.pool.acquire("next").account_id, "222222222222")

    def test_mark_refuses_live_lease(self) -> None:
        lease = self.pool.acquire("busy")
        with self.assertRaisesRegex(PoolError, "leased by"):
            self.pool.mark(lease.account_id, "clean")
        with self.assertRaises(PoolError):
            self.pool.mark(lease.account_id, "leased")

    def test_cross_process_contention(self) -> None:
        """Eight processes each grab one of three accounts and release it; no two hold the same one."""
        script = textwrap.dedent(f"""
            import sys, time, json
            sys.path.insert(0, {str(Path(__file__).resolve().parents[2])!r})
            from pathlib import Path
            from harness.aws_safety import AwsTarget
            from harness.sandbox import Pool
            targets = [AwsTarget(f"p{{i}}", str(i + 1) * 12, "us-east-1") for i in range(3)]
            pool = Pool(targets, Path({str(self.dir)!r}))
            lease = pool.acquire(sys.argv[1], poll=0.05)
            marker = Path({str(self.dir)!r}) / ("held-" + lease.account_id)
            if marker.exists():
                print("DOUBLE", lease.account_id); sys.exit(2)
            marker.write_text(sys.argv[1]); time.sleep(0.2); marker.unlink()
            pool.release(lease, clean=True)
            print(lease.account_id)
        """)
        procs = [subprocess.Popen([sys.executable, "-c", script, f"w{i}"], stdout=subprocess.PIPE, text=True)
                 for i in range(8)]
        outs = [p.communicate(timeout=60)[0].strip() for p in procs]
        self.assertTrue(all(p.returncode == 0 for p in procs), outs)
        self.assertEqual(self.pool.counts(), {"clean": 3})
        self.assertTrue(set(outs) <= {"111111111111", "222222222222", "333333333333"}, outs)


class ConfigTests(unittest.TestCase):
    def test_load_pool_targets(self) -> None:
        from harness.aws_safety import AwsSafetyError, load_pool_config, load_pool_targets
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = root / ".cloudgym" / "aws.local.toml"
            cfg.parent.mkdir()
            cfg.write_text(textwrap.dedent('''
                [aws]
                profile = "sandbox"
                account_id = "111111111111"
                region = "us-east-1"
                role_name = "SandboxAdministrator"
                [aws.pool]
                management_profile = "mgmt"
                ou_id = "ou-abcd-12345678"
                email_template = "me+sbx-{n:02d}@example.org"
                [[aws.pool.accounts]]
                profile = "cloudgym-pool-01"
                account_id = "222222222222"
            '''))
            targets = load_pool_targets(root)
            self.assertEqual([t.account_id for t in targets], ["111111111111", "222222222222"])
            self.assertEqual(targets[0].access, "sso")
            self.assertEqual((targets[1].access, targets[1].role_name, targets[1].region),
                             ("org-role", "OrganizationAccountAccessRole", "us-east-1"))
            self.assertEqual(load_pool_config(root).email_template.format(n=3), "me+sbx-03@example.org")
            cfg.write_text(cfg.read_text() + '[[aws.pool.accounts]]\nprofile = "dup"\naccount_id = "222222222222"\n')
            with self.assertRaisesRegex(AwsSafetyError, "listed twice"):
                load_pool_targets(root)

    def test_verify_org_role(self) -> None:
        from unittest.mock import patch
        from harness.aws_safety import AwsSafetyError, verify_aws_target
        arn = "arn:aws:sts::222222222222:assumed-role/OrganizationAccountAccessRole/botocore-session-1"
        with patch("harness.aws_safety.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = json.dumps({"Account": "222222222222", "Arn": arn})
            run.return_value.stderr = ""
            org = AwsTarget("pool-01", "222222222222", "us-east-1", "OrganizationAccountAccessRole", access="org-role")
            self.assertEqual(verify_aws_target(org, {})["Account"], "222222222222")
            sso = AwsTarget("pool-01", "222222222222", "us-east-1", "OrganizationAccountAccessRole")
            with self.assertRaisesRegex(AwsSafetyError, "does not match"):
                verify_aws_target(sso, {})
