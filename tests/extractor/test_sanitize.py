from __future__ import annotations

import json

import pytest

from harness.extractor.aws.sanitize import PLACEHOLDER_ACCOUNT, SanitizeError, sanitize_envelopes

ACCOUNT = "000000000114"


def test_account_id_replaced_everywhere_and_shapes_kept():
    envelope = {
        "TypeName": "AWS::IAM::Role",
        "ResourceDescription": {
            "Identifier": "cron_assume_role",
            # Properties is the JSON *string* AWS returns — must stay a string.
            "Properties": json.dumps({
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/cron_assume_role",
                "RoleName": "cron_assume_role",
                "Tags": [{"Key": "CostCenter", "Value": "APP-3141"}],
            }),
        },
        "ReadAt": "2026-09-01T00:00:00+00:00",
        ACCOUNT: "even a key",
    }
    out = sanitize_envelopes([envelope], ACCOUNT)
    text = json.dumps(out)
    assert ACCOUNT not in text
    assert f"arn:aws:iam::{PLACEHOLDER_ACCOUNT}:role/cron_assume_role" in text
    # untouched apart from the account id; original not mutated
    props = json.loads(out[0]["ResourceDescription"]["Properties"])
    assert props["Tags"] == [{"Key": "CostCenter", "Value": "APP-3141"}]
    assert isinstance(out[0]["ResourceDescription"]["Properties"], str)
    assert ACCOUNT in json.dumps(envelope)


def test_rejects_bad_account_id():
    for bad in ("", None, "12345", "1234567890123", "12345678901a"):
        with pytest.raises(SanitizeError):
            sanitize_envelopes([], bad)
