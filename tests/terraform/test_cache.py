import tempfile
import unittest
from pathlib import Path

from harness.terraform.cache import (
    PINNED_LOCKFILE,
    init_lock,
    prune_broken_providers,
    seed_lockfile,
)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cw-cache-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = self.root / "cache"
        self.workdir = self.root / "work"
        self.workdir.mkdir()

    def cache_platform_dir(self, with_binary: bool) -> Path:
        d = self.cache / "registry.terraform.io/hashicorp/aws/5.100.0/darwin_arm64"
        d.mkdir(parents=True)
        if with_binary:
            (d / "terraform-provider-aws_v5.100.0").write_text("bin")
        return d

    def test_dangling_workspace_symlinks_are_removed(self):
        providers = self.workdir / ".terraform" / "providers" / "x"
        providers.mkdir(parents=True)
        gone = self.root / "gone"
        link = providers / "aws"
        link.symlink_to(gone)
        self.cache.mkdir()
        prune_broken_providers(self.workdir, self.cache)
        self.assertFalse(link.exists(follow_symlinks=False))

    def test_incomplete_cache_platform_dirs_are_removed(self):
        empty = self.cache_platform_dir(with_binary=False)
        prune_broken_providers(self.workdir, self.cache)
        self.assertFalse(empty.exists())

    def test_complete_cache_platform_dirs_survive(self):
        full = self.cache_platform_dir(with_binary=True)
        prune_broken_providers(self.workdir, self.cache)
        self.assertTrue(full.exists())

    def test_init_lock_creates_and_releases(self):
        with init_lock(self.cache):
            self.assertTrue((self.cache / ".terraform-init.lock").exists())
        # Re-acquirable after release (same process, sequential).
        with init_lock(self.cache):
            pass

    def test_seed_lockfile_copies_pin_once(self):
        self.assertTrue(PINNED_LOCKFILE.is_file(),
                        "pinned lockfile must be committed")
        self.assertTrue(seed_lockfile(self.workdir))
        target = self.workdir / ".terraform.lock.hcl"
        self.assertEqual(target.read_text(), PINNED_LOCKFILE.read_text())
        target.write_text("local edit")
        self.assertFalse(seed_lockfile(self.workdir))
        self.assertEqual(target.read_text(), "local edit")


if __name__ == "__main__":
    unittest.main()


class SharedUseLockTests(unittest.TestCase):
    def test_use_lock_is_shared_and_init_lock_waits_for_it(self):
        import subprocess, sys, textwrap, time
        from harness.terraform.cache import init_lock, use_lock
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d)
            # two shared holders coexist
            with use_lock(cache), use_lock(cache):
                pass
            # an exclusive init in another process blocks while a shared user holds the lock
            script = textwrap.dedent(f"""
                import sys, time
                sys.path.insert(0, {str(Path(__file__).resolve().parents[2])!r})
                from pathlib import Path
                from harness.terraform.cache import init_lock
                t = time.monotonic()
                with init_lock(Path({d!r})):
                    pass
                print(round(time.monotonic() - t, 2))
            """)
            with use_lock(cache):
                proc = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
                time.sleep(0.6)
                self.assertIsNone(proc.poll(), "init must wait for the shared holder")
            waited = float(proc.communicate(timeout=30)[0].strip())
            self.assertGreaterEqual(waited, 0.5)
