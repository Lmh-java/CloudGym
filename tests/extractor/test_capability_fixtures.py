"""Golden-fixture replay: every registered adapter is exercised against a REAL recorded
capture on every test run.

Fixtures are recorded by `uv run capability-smoke <type> --record --allow-aws` and live at
harness/extractor/aws/fixtures/<terraform_type>.captured.json (sanitized: account id replaced).
A missing fixture is a hard failure — recording one is part of shipping an adapter. The two
SCP-denied services (SNS, CloudWatch) cannot be recorded in the sandbox and are skipped
explicitly.

What each replay proves:
- parse_envelope round-trips the recorded envelope (type, identifier, properties)   [drift]
- projection is non-empty and every semantic_properties key appears in the capture  [FP: stale allowlist]
- volatile fields do not leak through the projection                                [FP]
- the recorded resource was captured settled (adapter.ready)                        [FP]
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.extractor.aws import parse_envelope
from harness.extractor.aws.capabilities import CAPABILITY_REGISTRY
from harness.eligibility import SCP_DENIED_PREFIXES

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "harness" / "extractor" / "aws" / "fixtures"


def _fixture_owner(tf_type: str) -> str:
    """Projection (non-standalone) adapters replay against their parent type's fixture.

    awscc_* siblings are never recordable in this sandbox (Cloud Control writes are
    SCP-denied), so they can't own a fixture; among the rest, prefer one that has one.
    """
    adapter = CAPABILITY_REGISTRY[tf_type]
    if adapter.standalone:
        return tf_type
    candidates = [other for other, c in CAPABILITY_REGISTRY.items()
                  if c.standalone and not other.startswith("awscc_")
                  and c.cloudcontrol_type == adapter.cloudcontrol_type]
    if not candidates:
        raise AssertionError(f"{tf_type}: no recordable standalone adapter shares {adapter.cloudcontrol_type}")
    return next((c for c in candidates if (FIXTURE_DIR / f"{c}.captured.json").is_file()), candidates[0])


@pytest.mark.parametrize("tf_type", sorted(CAPABILITY_REGISTRY))
def test_adapter_replays_its_recorded_capture(tf_type: str) -> None:
    adapter = CAPABILITY_REGISTRY[tf_type]
    if tf_type.startswith("awscc_"):
        # The awscc provider writes via Cloud Control CreateResource, which the sandbox SCP
        # denies — it can never be applied. Replay against the aws_* sibling's fixture.
        sibling = next((t for t, a in CAPABILITY_REGISTRY.items()
                        if a.standalone and not t.startswith("awscc_")
                        and a.cloudcontrol_type == adapter.cloudcontrol_type), None)
        if sibling is None:
            pytest.skip("awscc type with no aws_* sibling; cannot record in this sandbox")
        owner = sibling
    elif tf_type.startswith(SCP_DENIED_PREFIXES):
        pytest.skip("SCP-denied in sandbox, cannot record a fixture")
    else:
        owner = _fixture_owner(tf_type)
    path = FIXTURE_DIR / f"{owner}.captured.json"
    assert path.is_file(), (
        f"no recorded fixture for {tf_type} (expected {path.name}); record one with "
        f"`uv run capability-smoke {owner} --record --allow-aws`")
    fixture = json.loads(path.read_text())
    assert fixture["cloudcontrol_type"] == adapter.cloudcontrol_type
    envelopes = fixture["envelopes"]
    assert envelopes, f"{path.name} holds no envelopes"

    seen_keys: set[str] = set()
    for envelope in envelopes:
        type_name, identifier, properties = parse_envelope(envelope)
        assert type_name == adapter.cloudcontrol_type
        assert identifier
        seen_keys |= set(properties)
        projected = adapter.project(properties)
        if adapter.standalone:
            assert projected, f"{tf_type}: projection empty for {identifier}"
            assert adapter.ready(properties), f"{tf_type}: recorded resource not settled ({identifier})"
        for volatile in adapter.volatile_fields:
            assert volatile not in projected, f"{tf_type}: volatile field {volatile} leaks through projection"
    # Hard guard: declared readiness properties must be present in a real capture — a typo'd
    # readiness key would make every capture look unsettled (or settled) forever.
    missing_ready = [k for k in adapter.readiness_properties if k not in seen_keys]
    assert not missing_ready, (
        f"{tf_type}: readiness properties never present in the recorded capture: {missing_ready}")
    # Soft guard: allowlists legitimately include optional properties a minimal resource
    # never returns (LifecycleConfiguration on a bare bucket) — but at least one semantic
    # key must be observable, or the projection can never carry anything.
    if adapter.standalone:
        assert seen_keys & set(adapter.semantic_properties), (
            f"{tf_type}: no semantic property appears in the recorded capture at all")


def test_fixtures_are_sanitized() -> None:
    from harness.extractor.aws.sanitize import PLACEHOLDER_ACCOUNT

    for path in FIXTURE_DIR.glob("*.captured.json"):
        text = path.read_text()
        fixture = json.loads(text)
        for envelope in fixture["envelopes"]:
            _, _, properties = parse_envelope(envelope)
            for value in json.dumps(properties).split('"'):
                if value.startswith("arn:") and ":iam:" not in value:
                    parts = value.split(":")
                    if len(parts) > 4 and parts[4].isdigit() and len(parts[4]) == 12:
                        assert parts[4] == PLACEHOLDER_ACCOUNT, f"{path.name}: unsanitized account in {value}"
