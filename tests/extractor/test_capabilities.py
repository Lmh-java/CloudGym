import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import hcl2

from harness.extractor.aws.capabilities import (
    CAPABILITY_REGISTRY,
    adapter_for,
    case_type_manifest,
)
from harness.extractor.errors import UnmappedResourceType


FIXTURE_DIR = (Path(__file__).resolve().parents[2] / "harness" / "extractor"
               / "aws" / "fixtures")


class CapabilityAdapterTests(unittest.TestCase):
    TOP_FIVE_STEP1_TYPES = {
        "aws_s3_bucket": "AWS::S3::Bucket",
        "awscc_iam_role": "AWS::IAM::Role",
        "aws_sns_topic": "AWS::SNS::Topic",
        "aws_iam_role": "AWS::IAM::Role",
        "aws_cloudwatch_metric_alarm": "AWS::CloudWatch::Alarm",
    }

    def test_registry_owns_cloudcontrol_mapping(self):
        self.assertEqual(
            CAPABILITY_REGISTRY["aws_vpc"].cloudcontrol_type,
            "AWS::EC2::VPC",
        )

    def test_case_manifest_uses_registry_for_initial_and_expected(self):
        with TemporaryDirectory() as directory:
            case_dir = Path(directory)
            (case_dir / "initial").mkdir()
            (case_dir / "expected").mkdir()
            (case_dir / "initial" / "main.tf").write_text(
                'resource "aws_vpc" "main" {}\n')
            (case_dir / "expected" / "main.tf").write_text(
                'resource "aws_security_group" "main" {}\n')

            self.assertEqual(case_type_manifest(case_dir), [
                "AWS::EC2::SecurityGroup",
                "AWS::EC2::VPC",
            ])

    def test_case_manifest_includes_awscc_resources(self):
        with TemporaryDirectory() as directory:
            case_dir = Path(directory)
            (case_dir / "initial").mkdir()
            (case_dir / "initial" / "main.tf").write_text(
                'resource "awscc_iam_role" "main" {}\n')

            self.assertEqual(case_type_manifest(case_dir), ["AWS::IAM::Role"])

    def test_case_manifest_rejects_type_without_adapter(self):
        with TemporaryDirectory() as directory:
            case_dir = Path(directory)
            (case_dir / "initial").mkdir()
            (case_dir / "initial" / "main.tf").write_text(
                'resource "aws_eks_cluster" "main" {}\n')

            with self.assertRaises(UnmappedResourceType):
                case_type_manifest(case_dir)

    def test_adapter_for_unknown_type_fails_closed(self):
        with self.assertRaises(UnmappedResourceType):
            adapter_for("aws_eks_cluster")

    def test_step1_top_five_types_are_registered(self):
        self.assertEqual(
            {tf_type: CAPABILITY_REGISTRY[tf_type].cloudcontrol_type
             for tf_type in self.TOP_FIVE_STEP1_TYPES},
            self.TOP_FIVE_STEP1_TYPES,
        )

    def test_step1_top_five_use_terraform_state_id(self):
        for tf_type in self.TOP_FIVE_STEP1_TYPES:
            with self.subTest(tf_type=tf_type):
                self.assertEqual(
                    adapter_for(tf_type).identifier_from_state({"id": "physical"}),
                    "physical",
                )

    def test_step1_top_five_projection_drops_provider_identity(self):
        examples = {
            "aws_s3_bucket": ({"BucketName": "generated", "Tags": []},
                              {"Tags": []}),
            "awscc_iam_role": ({"RoleName": "generated", "Description": "x"},
                               {"Description": "x"}),
            "aws_iam_role": ({"RoleName": "generated", "Description": "x"},
                             {"Description": "x"}),
            "aws_sns_topic": ({"TopicArn": "arn:topic", "TopicName": "topic"},
                              {"TopicName": "topic"}),
            "aws_cloudwatch_metric_alarm": (
                {"Arn": "arn:alarm", "AlarmName": "alarm"},
                {"AlarmName": "alarm"}),
        }
        for tf_type, (properties, expected) in examples.items():
            with self.subTest(tf_type=tf_type):
                self.assertEqual(adapter_for(tf_type).project(properties), expected)

    def test_identifier_from_state_requires_id(self):
        adapter = adapter_for("aws_vpc")
        self.assertEqual(adapter.identifier_from_state({"id": "vpc-1"}), "vpc-1")
        for attrs in ({}, {"id": ""}, {"id": None}, {"id": 7}):
            with self.subTest(attrs=attrs), self.assertRaises(ValueError):
                adapter.identifier_from_state(attrs)

    def test_projection_is_an_allowlist(self):
        adapter = adapter_for("aws_vpc")
        projected = adapter.project({
            "CidrBlock": "10.0.0.0/16",
            "VpcId": "vpc-1",                      # volatile: dropped
            "DefaultSecurityGroup": "sg-1",        # volatile: dropped
            "EnableDnsHostnames": True,
        })
        self.assertEqual(projected, {
            "CidrBlock": "10.0.0.0/16",
            "EnableDnsHostnames": True,
        })

    def test_readiness_requires_declared_properties(self):
        adapter = adapter_for("aws_security_group")
        self.assertTrue(adapter.ready({"GroupId": "sg-1", "GroupName": "x"}))
        self.assertFalse(adapter.ready({"GroupName": "x"}))
        self.assertFalse(adapter.ready({"GroupId": "", "GroupName": "x"}))

    def test_every_adapter_declares_core_fields(self):
        for tf_type, adapter in CAPABILITY_REGISTRY.items():
            with self.subTest(tf_type=tf_type):
                self.assertTrue(adapter.cloudcontrol_type.startswith("AWS::"))
                self.assertTrue(adapter.semantic_properties)
                self.assertTrue(adapter.readiness_properties)

    def test_optional_fixtures_have_one_target_and_supported_dependencies(self):
        for fixture in sorted(FIXTURE_DIR.glob("*.tf")):
            with self.subTest(fixture=fixture.name):
                self.assertIn(fixture.stem, CAPABILITY_REGISTRY)
                document = hcl2.loads(fixture.read_text())
                types = [resource_type
                         for block in document.get("resource", [])
                         for resource_type, instances in block.items()
                         for _ in instances]
                self.assertEqual(types.count(fixture.stem), 1)
                self.assertEqual(set(types) - set(CAPABILITY_REGISTRY), set())


if __name__ == "__main__":
    unittest.main()
