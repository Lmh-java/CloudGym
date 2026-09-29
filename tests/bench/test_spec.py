from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.bench import SpecError, load_spec

SEED = "aws-provider_service_vpc_aws_vpc_p1.tf_0"


def make_tree(root: Path) -> tuple[Path, Path, Path]:
    seeds = root / "seeds"
    (seeds / SEED / "initial").mkdir(parents=True)
    (seeds / SEED / "source.json").write_text(json.dumps({"utterance": "x", "resource_types": ["aws_vpc"]}))
    (seeds / SEED / "initial" / "main.tf").write_text('resource "aws_vpc" "m" {}')
    case_a = root / "cases" / "case-a"
    (case_a / "agent").mkdir(parents=True)
    (case_a / "agent" / "task.json").write_text(json.dumps({"seed_id": SEED}))
    case_b = root / "cases" / "case-b"
    (case_b / "agent").mkdir(parents=True)
    (case_b / "agent" / "task.json").write_text(json.dumps({"seed_id": SEED}))
    return seeds, case_a, case_b


SPEC = """
batch: demo
defaults: {agent: claude, timeout: 60, trials: 2}
cases:
  - ../cases/case-a
  - ../cases/case-b
  - ../seeds/%s
arms:
  - name: base
    model: m1
  - name: alt
    model: m2
    intercept: false
    awareness: disclosed
    distractors: false
    trials: 1
    cases: [../cases/case-b]
    args: {max_turns: 5}
""" % SEED


class SpecTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name).resolve()
        self.seeds, self.case_a, self.case_b = make_tree(self.root)
        (self.root / "experiments").mkdir()
        self.spec_path = self.root / "experiments" / "demo.yml"
        self.spec_path.write_text(SPEC)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def load(self, text: str | None = None):
        if text is not None:
            self.spec_path.write_text(text)
        return load_spec(self.spec_path, seeds_dir=self.seeds, default_artifacts=self.root / "artifacts")

    def test_resolves_cases_and_arms(self) -> None:
        spec = self.load()
        self.assertEqual([c.name for c in spec.cases], ["case-a", "case-b", SEED])
        self.assertEqual(spec.cases[0].case_dir, self.case_a)
        self.assertIsNone(spec.cases[2].case_dir)
        self.assertEqual(spec.cases[2].seed_id, SEED)
        base, alt = spec.arms
        self.assertEqual((base.trials, base.timeout, base.cases), (2, 60.0, ("case-a", "case-b", SEED)))
        self.assertEqual((alt.trials, alt.intercept, alt.cases, dict(alt.args)), (1, False, ("case-b",), {"max_turns": 5}))
        self.assertEqual((base.awareness, alt.awareness), ("none", "disclosed"))
        self.assertEqual((base.distractors, alt.distractors), (True, False))
        self.assertEqual(spec.new_batch_dir().parent, self.root / "artifacts")
        self.assertRegex(spec.new_batch_dir().name, r"^demo-\d{8}-\d{6}$")
        self.assertEqual(spec.launches(), [])
        (self.root / "artifacts" / "demo-20260101-000000").mkdir(parents=True)
        (self.root / "artifacts" / "demo-20260102-000000").mkdir()
        (self.root / "artifacts" / "demo-other").mkdir()
        self.assertEqual(spec.latest_batch_dir(), self.root / "artifacts" / "demo-20260102-000000")

    def test_cells_are_trial_major(self) -> None:
        keys = [c.key for c in self.load().cells()]
        self.assertEqual(keys, ["base/case-a/t1", "base/case-b/t1", f"base/{SEED}/t1", "alt/case-b/t1",
                                "base/case-a/t2", "base/case-b/t2", f"base/{SEED}/t2"])
        self.assertEqual(self.load().cells()[0].run_id, "demo-base-case-a-t1")
        self.assertEqual(self.load().cells()[0].run_dir(Path("/b")), Path("/b/base-case-a-t1"))

    def test_hash_ignores_artifacts_but_not_trials(self) -> None:
        h1 = self.load().spec_hash
        h2 = self.load(SPEC + "\nartifacts: ../elsewhere\n").spec_hash
        h3 = self.load(SPEC.replace("trials: 2", "trials: 3")).spec_hash
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)

    def test_errors(self) -> None:
        with self.assertRaisesRegex(SpecError, "unknown key"):
            self.load(SPEC + "\nbogus: 1\n")
        with self.assertRaisesRegex(SpecError, "not in the batch"):
            self.load(SPEC.replace("cases: [../cases/case-b]", "cases: [../cases/case-a-missing]"))
        with self.assertRaisesRegex(SpecError, "owned by the runner"):
            self.load(SPEC.replace("args: {max_turns: 5}", "args: {run_id: x}"))
        with self.assertRaisesRegex(SpecError, "neither a case dir"):
            (self.root / "cases" / "empty").mkdir()
            self.load(SPEC.replace("../cases/case-b\n", "../cases/case-b\n  - ../cases/empty\n"))
        with self.assertRaisesRegex(SpecError, "awareness"):
            self.load(SPEC.replace("awareness: disclosed", "awareness: full"))

    def test_modality_defaults_to_hybrid_and_is_validated(self):
        spec = self.load(SPEC)
        self.assertEqual({a.modality for a in spec.arms}, {"hybrid"})
        pinned = self.load(SPEC.replace("awareness: disclosed", "awareness: disclosed\n    modality: iac"))
        self.assertEqual(sorted(a.modality for a in pinned.arms), ["hybrid", "iac"])
        # A pinned modality changes the spec hash; the default leaves it exactly as before.
        self.assertNotEqual(spec.spec_hash, pinned.spec_hash)
        self.assertEqual(spec.spec_hash, self.load(SPEC.replace("awareness: disclosed", "awareness: disclosed\n    modality: hybrid")).spec_hash)
        with self.assertRaisesRegex(SpecError, "modality"):
            self.load(SPEC.replace("awareness: disclosed", "modality: ansible"))
        with self.assertRaisesRegex(SpecError, "batch"):
            self.load(SPEC.replace("batch: demo", "batch: 'bad name'"))


if __name__ == "__main__":
    unittest.main()


class CasesFromTests(unittest.TestCase):
    """``cases_from``: an accumulating batch whose case list is the directory's active cases."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name).resolve()
        self.seeds, self.case_a, self.case_b = make_tree(self.root)
        (self.root / "experiments").mkdir()
        self.spec_path = self.root / "experiments" / "acc.yml"
        self.spec_path.write_text("batch: acc\ndefaults: {agent: claude, trials: 1}\ncases_from: ../cases\narms:\n  - {name: base, model: m1}\n")

    def tearDown(self) -> None:
        self._temp.cleanup()

    def load(self):
        return load_spec(self.spec_path, seeds_dir=self.seeds, default_artifacts=self.root / "artifacts")

    def _mark(self, case_dir: Path, status: str) -> None:
        task = case_dir / "agent" / "task.json"
        data = json.loads(task.read_text())
        data["lifecycle"] = {"status": status, "since": "2026-09-19", "reason": "test"}
        task.write_text(json.dumps(data))

    def test_rescans_and_skips_stale(self) -> None:
        spec = self.load()
        self.assertEqual([c.name for c in spec.cases], ["case-a", "case-b"])
        self.assertEqual(len(spec.cells()), 2)
        self._mark(self.case_b, "stale")
        self.assertEqual([c.name for c in self.load().cases], ["case-a"])
        case_c = self.root / "cases" / "case-c"
        (case_c / "agent").mkdir(parents=True)
        (case_c / "agent" / "task.json").write_text(json.dumps({"seed_id": SEED, "lifecycle": {"status": "active"}}))
        spec = self.load()
        self.assertEqual([c.name for c in spec.cases][-1], "case-c")   # newest appended last
        self.assertEqual([c.key for c in spec.cells()], ["base/case-a/t1", "base/case-c/t1"])

    def test_empty_directory_is_allowed(self) -> None:
        self._mark(self.case_a, "retired")
        self._mark(self.case_b, "stale")
        spec = self.load()
        self.assertEqual(spec.cases, ())
        self.assertEqual(spec.cells(), [])
        self.assertEqual(spec.arms[0].cases, ())

    def test_exclusive_with_cases(self) -> None:
        self.spec_path.write_text("batch: acc\ncases_from: ../cases\ncases: [../cases/case-a]\narms:\n  - {name: b, model: m}\n")
        with self.assertRaises(SpecError):
            self.load()
        self.spec_path.write_text("batch: acc\ncases_from: ../nowhere\narms:\n  - {name: b, model: m}\n")
        with self.assertRaises(SpecError):
            self.load()


class PolicyFlagTests(unittest.TestCase):
    def test_policy_false_is_parsed_and_only_then_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_tree(root)
            (root / "specs").mkdir()
            spec_path = root / "specs" / "s.yml"
            base = ("batch: demo\ndefaults: {agent: claude, timeout: 60}\ncases:\n  - ../cases/case-a\narms:\n"
                    "  - {name: a, model: m1}\n")
            spec_path.write_text(base)
            plain = load_spec(spec_path, seeds_dir=root / "seeds", default_artifacts=root / "artifacts")
            self.assertTrue(plain.arms[0].policy)
            spec_path.write_text(base.replace("{name: a, model: m1}", "{name: a, model: m1, policy: true}"))
            self.assertEqual(load_spec(spec_path, seeds_dir=root / "seeds", default_artifacts=root / "artifacts").spec_hash, plain.spec_hash)   # default: hash unchanged
            spec_path.write_text(base.replace("{name: a, model: m1}", "{name: a, model: m1, policy: false}"))
            ablated = load_spec(spec_path, seeds_dir=root / "seeds", default_artifacts=root / "artifacts")
            self.assertFalse(ablated.arms[0].policy)
            self.assertNotEqual(ablated.spec_hash, plain.spec_hash)
