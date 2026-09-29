"""Run every case's offline oracle tests (evaluator/oracle-tests.json) through opa.

Each case ships fixture inputs with the verdict they must produce, so an
oracle regression is caught without touching AWS. A verdict other than the
expected "pass"/"fail" (undefined, error) is a failure too: the harness
treats it as inconclusive, which invalidates a run.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from harness.runtime.case import evaluate_rego

REPO_ROOT = Path(__file__).resolve().parents[2]
CASES = sorted(REPO_ROOT.glob("cases/*/*/evaluator/oracle-tests.json"))

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH")


def _params():
    for tests_file in CASES:
        spec = json.loads(tests_file.read_text())
        oracle = tests_file.parent / "oracle.rego"
        for case in spec["cases"]:
            case_id = tests_file.parents[1].name
            yield pytest.param(oracle, spec["query"], case, id=f"{case_id}::{case['name']}")


@pytest.mark.parametrize("oracle, query, case", list(_params()))
def test_oracle_fixture(oracle: Path, query: str, case: dict) -> None:
    result = evaluate_rego(oracle, case["input"], query=query)
    assert result["verdict"] == case["expected"], result


def test_every_case_has_oracle_tests() -> None:
    oracles = sorted(REPO_ROOT.glob("cases/*/*/evaluator/oracle.rego"))
    missing = [o.parents[1].name for o in oracles if not (o.parent / "oracle-tests.json").is_file()]
    assert not missing, f"cases without oracle-tests.json: {missing}"
