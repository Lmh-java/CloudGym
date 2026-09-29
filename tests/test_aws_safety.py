from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.aws_safety import (
    AwsSafetyError,
    AwsTarget,
    aws_environment,
    load_aws_target,
    verify_aws_target,
)


class AwsSafetyTests(unittest.TestCase):
    def test_load_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / ".cloudgym" / "aws.local.toml"
            config.parent.mkdir()
            config.write_text(
                '[aws]\nprofile="sandbox"\naccount_id="123456789012"\n'
                'region="us-east-1"\nrole_name="SandboxAdministrator"\n'
            )
            target = load_aws_target(root)
        self.assertEqual(target.account_id, "123456789012")
        self.assertEqual(target.profile, "sandbox")

    def test_environment_removes_ambient_credentials(self) -> None:
        target = AwsTarget("sandbox", "123456789012", "us-east-1")
        env = aws_environment(
            target,
            base={"AWS_ACCESS_KEY_ID": "bad", "AWS_SESSION_TOKEN": "bad"},
        )
        self.assertNotIn("AWS_ACCESS_KEY_ID", env)
        self.assertNotIn("AWS_SESSION_TOKEN", env)
        self.assertEqual(env["AWS_PROFILE"], "sandbox")

    @patch("harness.aws_safety.subprocess.run")
    def test_verify_rejects_wrong_account(self, run) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps(
            {"Account": "999999999999", "Arn": "arn:aws:sts::999999999999:assumed-role/x/y"}
        )
        run.return_value.stderr = ""
        target = AwsTarget("sandbox", "123456789012", "us-east-1")
        with self.assertRaisesRegex(AwsSafetyError, "expected sandbox"):
            verify_aws_target(target, {})

    @patch("harness.aws_safety.subprocess.run")
    def test_verify_accepts_expected_sso_role(self, run) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps(
            {
                "Account": "123456789012",
                "Arn": (
                    "arn:aws:sts::123456789012:assumed-role/"
                    "AWSReservedSSO_SandboxAdministrator_abc/user"
                ),
            }
        )
        run.return_value.stderr = ""
        target = AwsTarget(
            "sandbox", "123456789012", "us-east-1", "SandboxAdministrator"
        )
        identity = verify_aws_target(target, {})
        self.assertEqual(identity["Account"], target.account_id)


if __name__ == "__main__":
    unittest.main()
