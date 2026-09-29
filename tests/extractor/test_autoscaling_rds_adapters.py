"""Auto Scaling and RDS option-group / snapshot adapters: identifiers, readiness, projections."""

from __future__ import annotations

import unittest

from harness.extractor.aws.capabilities import CAPABILITY_REGISTRY, adapter_for
from harness.extractor.aws.capabilities.autoscaling import scaling_policy_arn_parts
from harness.runtime.case import DELETE_ORDER

POLICY_ARN = ("arn:aws:autoscaling:us-east-1:123456789012:scalingPolicy:0f1e2d3c-1111-2222-3333-444455556666:"
              "autoScalingGroupName/cloudgym-capability-2026:policyName/cloudgym-capability-scale-down")


class AutoScalingAdapterTests(unittest.TestCase):
    def test_registered_with_cloudcontrol_types(self) -> None:
        self.assertEqual(adapter_for("aws_autoscaling_group").cloudcontrol_type, "AWS::AutoScaling::AutoScalingGroup")
        self.assertEqual(adapter_for("aws_launch_configuration").cloudcontrol_type,
                         "AWS::AutoScaling::LaunchConfiguration")
        self.assertEqual(adapter_for("aws_autoscaling_policy").cloudcontrol_type, "AWS::AutoScaling::ScalingPolicy")

    def test_policy_binds_on_arn_not_on_name(self) -> None:
        adapter = adapter_for("aws_autoscaling_policy")
        self.assertEqual(adapter.identifier_from_state({"id": "scale-down", "arn": POLICY_ARN}), POLICY_ARN)
        with self.assertRaises(ValueError):
            adapter.identifier_from_state({"id": "scale-down"})

    def test_attachment_is_a_projection_of_its_group(self) -> None:
        adapter = adapter_for("aws_autoscaling_attachment")
        self.assertFalse(adapter.standalone)
        self.assertEqual(adapter.cloudcontrol_type, "AWS::AutoScaling::AutoScalingGroup")
        self.assertEqual(adapter.identifier_from_state({"id": "x", "autoscaling_group_name": "asg-1"}), "asg-1")
        projected = adapter.project({"AutoScalingGroupName": "asg-1", "MinSize": "0",
                                     "TargetGroupARNs": ["arn:tg"], "LoadBalancerNames": []})
        self.assertEqual(projected, {"TargetGroupARNs": ["arn:tg"], "LoadBalancerNames": []})

    def test_group_projection_drops_service_linked_role(self) -> None:
        adapter = adapter_for("aws_autoscaling_group")
        props = {"AutoScalingGroupName": "asg-1", "MinSize": "0", "MaxSize": "1", "DesiredCapacity": "0",
                 "ServiceLinkedRoleARN": "arn:aws:iam::123456789012:role/aws-service-role/x"}
        self.assertTrue(adapter.ready(props))
        self.assertNotIn("ServiceLinkedRoleARN", adapter.project(props))
        self.assertFalse(adapter.ready({"AutoScalingGroupName": "asg-1"}))

    def test_policy_arn_parts(self) -> None:
        self.assertEqual(scaling_policy_arn_parts(POLICY_ARN),
                         ("cloudgym-capability-2026", "cloudgym-capability-scale-down"))
        with self.assertRaises(ValueError):
            scaling_policy_arn_parts("arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:uuid:x/y")

    def test_teardown_order_policies_then_groups_then_launch_configurations(self) -> None:
        self.assertLess(DELETE_ORDER["AWS::AutoScaling::ScalingPolicy"], DELETE_ORDER["AWS::AutoScaling::AutoScalingGroup"])
        self.assertLess(DELETE_ORDER["AWS::AutoScaling::AutoScalingGroup"],
                        DELETE_ORDER["AWS::AutoScaling::LaunchConfiguration"])
        self.assertLess(DELETE_ORDER["AWS::AutoScaling::AutoScalingGroup"], DELETE_ORDER.get("AWS::EC2::Subnet", 50))


class RdsAdapterTests(unittest.TestCase):
    def test_option_group_registered(self) -> None:
        adapter = adapter_for("aws_db_option_group")
        self.assertEqual(adapter.cloudcontrol_type, "AWS::RDS::OptionGroup")
        self.assertTrue(adapter.ready({"OptionGroupName": "og", "EngineName": "mysql", "MajorEngineVersion": "8.0"}))
        self.assertGreater(DELETE_ORDER["AWS::RDS::OptionGroup"], DELETE_ORDER["AWS::RDS::DBInstance"])

    def test_snapshot_reads_natively_and_settles_only_when_available(self) -> None:
        adapter = adapter_for("aws_db_snapshot")
        self.assertIsNot(type(adapter).native_describe, CAPABILITY_REGISTRY["aws_db_instance"].native_describe.__func__)
        base = {"DBSnapshotIdentifier": "s", "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:s"}
        self.assertFalse(adapter.ready({**base, "Status": "creating"}))
        self.assertTrue(adapter.ready({**base, "Status": "available"}))
        projected = adapter.project({**base, "Status": "available", "Engine": "postgres", "PercentProgress": 100})
        self.assertEqual(projected, {"DBSnapshotIdentifier": "s", "Engine": "postgres"})

    def test_snapshot_native_read_absent_on_not_found(self) -> None:
        from botocore.exceptions import ClientError

        class _Rds:
            def describe_db_snapshots(self, **kwargs):
                raise ClientError({"Error": {"Code": "DBSnapshotNotFound", "Message": "x"}}, "DescribeDBSnapshots")

        class _Session:
            def client(self, name, region_name=None):
                return _Rds()

        self.assertIsNone(adapter_for("aws_db_snapshot").native_read(_Session(), "us-east-1", "gone"))


if __name__ == "__main__":
    unittest.main()


class LaunchTemplateTests(unittest.TestCase):
    def test_reads_natively_with_latest_version_data(self) -> None:
        from botocore.exceptions import ClientError

        class _Ec2:
            def describe_launch_templates(self, **kwargs):
                if kwargs.get("LaunchTemplateIds") == ["lt-gone"]:
                    raise ClientError({"Error": {"Code": "InvalidLaunchTemplateId.NotFound", "Message": "x"}},
                                      "DescribeLaunchTemplates")
                return {"LaunchTemplates": [{"LaunchTemplateId": "lt-1", "LaunchTemplateName": "n",
                                             "LatestVersionNumber": 2, "DefaultVersionNumber": 1, "Tags": []}]}

            def describe_launch_template_versions(self, **kwargs):
                return {"LaunchTemplateVersions": [{"VersionNumber": 2, "VersionDescription": "v2",
                                                    "LaunchTemplateData": {"InstanceType": "t3.micro"}}]}

        class _Session:
            def client(self, name, region_name=None):
                return _Ec2()

        adapter = adapter_for("aws_launch_template")
        doc = adapter.native_read(_Session(), "us-east-1", "lt-1")
        self.assertEqual(doc["LaunchTemplateData"], {"InstanceType": "t3.micro"})
        self.assertTrue(adapter.ready(doc))
        self.assertEqual(adapter.project(doc), {"LaunchTemplateData": {"InstanceType": "t3.micro"},
                                                "LaunchTemplateName": "n", "Tags": [], "VersionDescription": "v2"})
        self.assertIsNone(adapter.native_read(_Session(), "us-east-1", "lt-gone"))
