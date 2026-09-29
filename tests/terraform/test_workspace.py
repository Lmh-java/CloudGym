import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from harness.terraform.workspace import (
    AWS_PROVIDER_VERSION_PIN,
    TerraformError,
    Workspace,
    render_certify_scaffold,
)

STUB = """#!/bin/sh
echo "$@" >> "$STUB_DIR/args.txt"
echo "$TF_LOG|$TF_LOG_PROVIDER|$TF_LOG_PATH" >> "$STUB_DIR/env.txt"
case "$*" in
  *show*) echo '{"format_version": "1.0"}' ;;
esac
if [ -f "$STUB_DIR/exit" ]; then exit "$(cat "$STUB_DIR/exit")"; fi
exit 0
"""


class WorkspaceTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cw-ws-test-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.stub_dir = root / "stub"
        self.stub_dir.mkdir()
        stub = self.stub_dir / "terraform"
        stub.write_text(STUB)
        stub.chmod(0o755)
        self.ws = Workspace(
            root / "work", root / "logs", root / "cache",
            base_env={"STUB_DIR": str(self.stub_dir), "PATH": os.environ["PATH"]},
            terraform_bin=str(stub))
        self.src = root / "seed"
        self.src.mkdir()
        (self.src / "main.tf").write_text('resource "aws_vpc" "main" {}\n')

    def args_lines(self):
        path = self.stub_dir / "args.txt"
        return path.read_text().splitlines() if path.exists() else []

    def set_exit(self, code):
        (self.stub_dir / "exit").write_text(str(code))


class StagingTests(WorkspaceTestCase):
    def test_stage_replaces_tf_and_preserves_state(self):
        work = self.ws.workdir
        (work / "old.tf").write_text("# old")
        (work / ".terraform").mkdir()
        (work / ".terraform" / "keep").write_text("x")
        (work / "terraform.tfstate").write_text("{}")
        self.ws.stage([self.src / "main.tf"], "# scaffold")
        self.assertFalse((work / "old.tf").exists())
        self.assertEqual((work / "zz-scaffold.tf").read_text(), "# scaffold")
        self.assertTrue((work / "main.tf").exists())
        self.assertTrue((work / ".terraform" / "keep").exists())
        self.assertTrue((work / "terraform.tfstate").exists())

    def test_stage_seeds_pinned_lockfile(self):
        self.ws.stage([self.src / "main.tf"], "# scaffold")
        lockfile = self.ws.workdir / ".terraform.lock.hcl"
        self.assertTrue(lockfile.exists())
        content = lockfile.read_text()
        self.assertIn("hashicorp/aws", content)
        self.assertIn("hashicorp/archive", content)   # pinned too, so inits never rewrite the cache
        # dual-platform pin: two h1 (platform) hashes per provider
        self.assertEqual(content.count("h1:"), 4)


class ScaffoldTests(unittest.TestCase):
    def test_render_contains_ownership_tags_and_pin(self):
        text = render_certify_scaffold("r-123", "seed.tf_0")
        self.assertIn('"cloudgym:run-id"  = "r-123"', text)
        self.assertIn('"cloudgym:seed-id" = "seed.tf_0"', text)
        self.assertIn(f'version = "{AWS_PROVIDER_VERSION_PIN}"', text)

    def test_unsafe_ids_rejected(self):
        for bad in ('a"b', "a b", "", "a$b"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                render_certify_scaffold(bad, "ok")


class CommandTests(WorkspaceTestCase):
    def test_log_paths_are_fresh_unique_and_0600(self):
        self.ws.plan("setup.tfplan")
        self.ws.plan("main.tfplan")
        paths = [c.log_path for c in self.ws.commands]
        self.assertEqual(len(set(paths)), 2)
        for p in paths:
            mode = stat.S_IMODE(p.stat().st_mode)
            self.assertEqual(mode, 0o600, f"{p} mode {oct(mode)}")

    def test_tf_log_encoding_and_provider_level(self):
        self.ws.plan("setup.tfplan")
        env_line = (self.stub_dir / "env.txt").read_text().splitlines()[0]
        tf_log, provider, log_path = env_line.split("|")
        self.assertEqual(tf_log, "JSON")
        self.assertEqual(provider, "DEBUG")
        self.assertTrue(log_path.endswith(".log.jsonl"))

    def test_plan_forces_parallelism_one_except_destroy(self):
        self.ws.plan("setup.tfplan")
        self.ws.plan("destroy.tfplan", destroy=True)
        normal, destroy = self.args_lines()
        self.assertIn("-parallelism=1", normal)
        self.assertIn("-out setup.tfplan", normal)
        self.assertIn("-destroy", destroy)
        self.assertNotIn("-parallelism=1", destroy)

    def test_apply_uses_saved_plan(self):
        self.ws.apply("setup.tfplan")
        self.ws.apply("destroy.tfplan", destroy=True)
        normal, destroy = self.args_lines()
        self.assertIn("-parallelism=1", normal)
        self.assertTrue(normal.endswith("setup.tfplan"))
        self.assertNotIn("-parallelism=1", destroy)

    def test_detailed_exitcode_two_is_not_an_error(self):
        self.set_exit(2)
        result = self.ws.plan("noop.tfplan", detailed_exitcode=True)
        self.assertEqual(result.returncode, 2)
        with self.assertRaises(TerraformError):
            self.ws.plan("plain.tfplan")  # exit 2 without detailed_exitcode

    def test_nonzero_exit_raises_with_result(self):
        self.set_exit(1)
        with self.assertRaises(TerraformError) as ctx:
            self.ws.plan("boom.tfplan")
        self.assertEqual(ctx.exception.result.returncode, 1)

    def test_show_json_parses_stdout(self):
        self.assertEqual(self.ws.state_json(), {"format_version": "1.0"})

    def test_init_runs_backendless(self):
        self.ws.init()
        self.assertIn("init -backend=false -input=false", self.args_lines()[0])


class StateIdentityTests(WorkspaceTestCase):
    def test_missing_state_is_fresh(self):
        self.assertEqual(self.ws.state_identity(), (None, 0))

    def test_lineage_and_serial_are_read(self):
        (self.ws.workdir / "terraform.tfstate").write_text(
            json.dumps({"lineage": "abc", "serial": 7}))
        self.assertEqual(self.ws.state_identity(), ("abc", 7))


if __name__ == "__main__":
    unittest.main()


HEAL_STUB = """#!/bin/sh
echo "$@" >> "$STUB_DIR/args.txt"
case "$*" in
  *init*) touch "$STUB_DIR/healed"; exit 0 ;;
esac
if [ ! -f "$STUB_DIR/healed" ]; then
  echo "Error: Required plugins are not installed" >&2
  echo "registry.terraform.io/hashicorp/aws: the cached package for registry.terraform.io/hashicorp/aws 5.100.0 (in .terraform/providers) does not match any of the checksums recorded in the dependency lock file" >&2
  exit 1
fi
exit 0
"""


class LockMismatchHealTests(WorkspaceTestCase):
    """A cache binary that no longer matches the lock file is re-installed once, then the
    command is retried; a second mismatch is a real error."""

    def setUp(self):
        super().setUp()
        (self.stub_dir / "terraform").write_text(HEAL_STUB)
        cache = self.ws.plugin_cache
        bad = cache / "registry.terraform.io" / "hashicorp" / "aws" / "5.100.0" / "darwin_arm64"
        bad.mkdir(parents=True); (bad / "terraform-provider-aws_v5.100.0_x5").write_text("corrupt")
        other = cache / "registry.terraform.io" / "hashicorp" / "archive" / "2.8.0" / "darwin_arm64"
        other.mkdir(parents=True); (other / "terraform-provider-archive_v2.8.0_x5").write_text("fine")

    def test_mismatch_reinstalls_only_the_named_provider_and_retries(self):
        result = self.ws.plan("destroy.tfplan", destroy=True)
        self.assertEqual(result.returncode, 0)
        lines = self.args_lines()
        self.assertEqual(sum(1 for l in lines if l.startswith("plan") or "plan " in l), 2)   # failed, then retried
        self.assertTrue(any("init" in l for l in lines))
        cache = self.ws.plugin_cache / "registry.terraform.io" / "hashicorp"
        self.assertFalse((cache / "aws" / "5.100.0" / "darwin_arm64").exists())
        self.assertTrue((cache / "archive" / "2.8.0" / "darwin_arm64").exists())

    def test_persistent_mismatch_still_raises(self):
        (self.stub_dir / "terraform").write_text(HEAL_STUB.replace('touch "$STUB_DIR/healed"; ', ""))
        with self.assertRaises(TerraformError):
            self.ws.plan("destroy.tfplan", destroy=True)
