"""Adapters added for the hand-authored cases: S3 sub-resource projections,
Lambda function/permission, EventBridge rule/target, IAM policy attachment.

Covers the three behaviours that make them different from the first eight:
projections never bind (so a bucket plus its lifecycle configuration is one
binding, not a duplicate-identifier error), parent-listed types are captured
per parent with a ResourceModel, and cleanup knows how to delete them.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.extractor.aws.capabilities import CAPABILITY_REGISTRY, adapter_for
from harness.extractor.aws.capture import capture_order, capture_snapshot
from harness.extractor.aws.targeted import bindings_from_state
from harness.extractor.errors import CaptureError
from harness.extractor.shape import shape_snapshot
from harness.extractor.aws import parse_envelope
from harness.runtime.case import DELETE_ORDER, delete_resource, load_case

REPO_ROOT = Path(__file__).resolve().parents[2]

NEW_TYPES = {
    "aws_s3_bucket_lifecycle_configuration": "AWS::S3::Bucket",
    "aws_s3_bucket_public_access_block": "AWS::S3::Bucket",
    "aws_s3_bucket_object_lock_configuration": "AWS::S3::Bucket",
    "aws_lambda_function": "AWS::Lambda::Function",
    "aws_lambda_permission": "AWS::Lambda::Permission",
    "aws_cloudwatch_event_rule": "AWS::Events::Rule",
    "aws_cloudwatch_event_target": "AWS::Events::Rule",
    "aws_iam_role_policy_attachment": "AWS::IAM::Role",
}
PROJECTIONS = {"aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_public_access_block",
               "aws_s3_bucket_object_lock_configuration", "aws_cloudwatch_event_target",
               "aws_iam_role_policy_attachment"}


def state_json(resources):
    return {"values": {"root_module": {"resources": resources}}}


def managed(address, tf_type, values):
    return {"address": address, "mode": "managed", "type": tf_type, "values": values}


class RegistryTests(unittest.TestCase):
    def test_new_types_map_to_cloudcontrol(self):
        for tf_type, cc_type in NEW_TYPES.items():
            with self.subTest(tf_type=tf_type):
                self.assertEqual(CAPABILITY_REGISTRY[tf_type].cloudcontrol_type, cc_type)

    def test_projections_are_not_standalone(self):
        for tf_type in NEW_TYPES:
            with self.subTest(tf_type=tf_type):
                self.assertEqual(adapter_for(tf_type).standalone, tf_type not in PROJECTIONS)

    def test_identifiers(self):
        self.assertEqual(adapter_for("aws_s3_bucket_lifecycle_configuration")
                         .identifier_from_state({"id": "my-bucket,123456789012"}), "my-bucket")
        self.assertEqual(adapter_for("aws_s3_bucket_public_access_block")
                         .identifier_from_state({"id": "my-bucket"}), "my-bucket")
        self.assertEqual(adapter_for("aws_lambda_function")
                         .identifier_from_state({"id": "fn"}), "fn")
        self.assertEqual(adapter_for("aws_lambda_permission")
                         .identifier_from_state({"function_name": "fn", "statement_id": "sid"}), "fn|sid")
        self.assertEqual(adapter_for("aws_cloudwatch_event_rule")
                         .identifier_from_state({"id": "nightly", "arn": "arn:aws:events:us-east-1:1:rule/nightly"}),
                         "arn:aws:events:us-east-1:1:rule/nightly")
        with self.assertRaises(ValueError):
            adapter_for("aws_cloudwatch_event_rule").identifier_from_state({"id": "nightly"})
        with self.assertRaises(ValueError):
            adapter_for("aws_lambda_permission").identifier_from_state({"function_name": "fn"})

    def test_lambda_permission_lists_per_function(self):
        adapter = adapter_for("aws_lambda_permission")
        self.assertEqual(adapter.list_parent, "AWS::Lambda::Function")
        self.assertEqual(adapter.list_resource_model({"FunctionName": "fn", "Arn": "x"}), {"FunctionName": "fn"})
        with self.assertRaises(NotImplementedError):
            adapter_for("aws_lambda_function").list_resource_model({})

    def test_projection_keeps_the_parent_document_shape(self):
        bucket = {"BucketName": "b", "Arn": "arn", "VersioningConfiguration": {"Status": "Enabled"},
                  "LifecycleConfiguration": {"Rules": []}}
        self.assertEqual(adapter_for("aws_s3_bucket_lifecycle_configuration").project(bucket),
                         adapter_for("aws_s3_bucket").project(bucket))
        self.assertEqual(adapter_for("aws_lambda_function").project(
            {"FunctionName": "fn", "Arn": "arn", "Runtime": "python3.12", "Code": {"ZipFile": "x"}}),
            {"FunctionName": "fn", "Runtime": "python3.12"})


class BindingTests(unittest.TestCase):
    def test_bucket_sub_resources_do_not_double_bind(self):
        bindings = bindings_from_state(state_json([
            managed("aws_s3_bucket.b", "aws_s3_bucket", {"id": "bucket-1"}),
            managed("aws_s3_bucket_public_access_block.b", "aws_s3_bucket_public_access_block", {"id": "bucket-1"}),
            managed("aws_s3_bucket_lifecycle_configuration.b", "aws_s3_bucket_lifecycle_configuration", {"id": "bucket-1"}),
            managed("aws_iam_role.r", "aws_iam_role", {"id": "role-1"}),
            managed("aws_iam_role_policy_attachment.r", "aws_iam_role_policy_attachment", {"id": "role-1-20240101"}),
        ]))
        self.assertEqual([(b.address, b.identifier) for b in bindings],
                         [("aws_s3_bucket.b", "bucket-1"), ("aws_iam_role.r", "role-1")])


class FakeCloudControl:
    """Enough of the cloudcontrol client for capture_snapshot."""

    def __init__(self, listing: dict[str, list[str]], properties: dict[str, dict]):
        self.listing = listing          # "Type" or "Type|<ResourceModel json>" -> identifiers
        self.properties = properties    # identifier -> properties
        self.list_calls: list[dict] = []

    def get_paginator(self, name):
        assert name == "list_resources"
        client = self

        class Paginator:
            def paginate(self, **kwargs):
                client.list_calls.append(kwargs)
                key = kwargs["TypeName"]
                if "ResourceModel" in kwargs:
                    key += "|" + kwargs["ResourceModel"]
                if key not in client.listing:
                    from botocore.exceptions import ClientError
                    raise ClientError({"Error": {"Code": "InvalidRequestException",
                                                 "Message": f"no listing for {key}"}}, "ListResources")
                if client.listing[key] == "NOT_FOUND":
                    # Lambda::Permission handler behaviour for a function without a policy.
                    from botocore.exceptions import ClientError

                    def boom():
                        raise ClientError({"Error": {"Code": "ResourceNotFoundException",
                                                     "Message": "The resource you requested does not exist."}},
                                          "ListResources")
                        yield  # pragma: no cover
                    return boom()
                return [{"ResourceDescriptions": [{"Identifier": i} for i in client.listing[key]]}]
        return Paginator()

    def get_resource(self, TypeName, Identifier):
        if Identifier not in self.properties:
            # Listed a moment ago, deleted since: the handler reports NotFound.
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "ResourceNotFoundException",
                                         "Message": f"{Identifier} does not exist"}},
                              "GetResource")
        return {"TypeName": TypeName,
                "ResourceDescription": {"Identifier": Identifier,
                                        "Properties": json.dumps(self.properties[Identifier])}}


class FakeSession:
    def __init__(self, cloudcontrol):
        self._cc = cloudcontrol

    def client(self, name, **kwargs):
        if name == "cloudcontrol":
            return self._cc
        if name == "sts":
            class Sts:
                def get_caller_identity(self):
                    return {"Account": "123456789012"}
            return Sts()
        raise AssertionError(name)


class CaptureTests(unittest.TestCase):
    def test_capture_order_puts_parents_first_and_fails_closed(self):
        self.assertEqual(capture_order(["AWS::Lambda::Permission", "AWS::Lambda::Function", "AWS::S3::Bucket"]),
                         ["AWS::Lambda::Function", "AWS::S3::Bucket", "AWS::Lambda::Permission"])
        with self.assertRaises(CaptureError):
            capture_order(["AWS::Lambda::Permission"])

    def test_region_wide_not_found_is_still_an_error(self):
        cc = FakeCloudControl(listing={"AWS::Lambda::Function": "NOT_FOUND"}, properties={})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(CaptureError):
                capture_snapshot(["AWS::Lambda::Function"], "us-east-1", Path(tmp), session=FakeSession(cc))

    def test_permissions_are_listed_per_captured_function(self):
        cc = FakeCloudControl(
            listing={
                "AWS::Lambda::Function": ["fn-a", "fn-b"],
                'AWS::Lambda::Permission|{"FunctionName": "fn-a"}': ["fn-a|events"],
                # fn-b has no resource policy: the handler 404s instead of paging empty
                'AWS::Lambda::Permission|{"FunctionName": "fn-b"}': "NOT_FOUND",
            },
            properties={
                "fn-a": {"FunctionName": "fn-a", "Arn": "arn:a"},
                "fn-b": {"FunctionName": "fn-b", "Arn": "arn:b"},
                "fn-a|events": {"FunctionName": "fn-a", "Id": "events", "Action": "lambda:InvokeFunction",
                                "Principal": "events.amazonaws.com"},
            })
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            manifest = capture_snapshot(["AWS::Lambda::Permission", "AWS::Lambda::Function"], "us-east-1", out,
                                        session=FakeSession(cc))
            self.assertEqual(manifest["resource_counts"],
                             {"AWS::Lambda::Function": 2, "AWS::Lambda::Permission": 1})
            self.assertEqual([c.get("ResourceModel") for c in cc.list_calls],
                             [None, '{"FunctionName": "fn-a"}', '{"FunctionName": "fn-b"}'])
            shaped = shape_snapshot(out, parse_envelope)
            self.assertEqual(shaped["resources"]["AWS::Lambda::Permission"]["fn-a|events"]["Principal"],
                             "events.amazonaws.com")
            self.assertEqual(set(shaped["resources"]["AWS::Lambda::Function"]), {"fn-a", "fn-b"})

    def test_a_resource_deleted_between_list_and_get_aborts_a_quiescent_capture(self):
        cc = FakeCloudControl(listing={"AWS::Events::Rule": ["arn:rule-a", "arn:rule-gone"]},
                              properties={"arn:rule-a": {"Name": "rule-a", "Arn": "arn:rule-a"}})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(CaptureError):
                capture_snapshot(["AWS::Events::Rule"], "us-east-1", Path(tmp), session=FakeSession(cc))

    def test_a_poll_capture_skips_a_resource_that_vanished_under_it(self):
        cc = FakeCloudControl(listing={"AWS::Events::Rule": ["arn:rule-a", "arn:rule-gone"]},
                              properties={"arn:rule-a": {"Name": "rule-a", "Arn": "arn:rule-a"}})
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            manifest = capture_snapshot(["AWS::Events::Rule"], "us-east-1", out,
                                        session=FakeSession(cc), tolerate_vanished=True)
            self.assertEqual(manifest["resource_counts"], {"AWS::Events::Rule": 1})
            self.assertEqual(set(shape_snapshot(out, parse_envelope)["resources"]["AWS::Events::Rule"]),
                             {"arn:rule-a"})


class FakeDeleteSession:
    region_name = "us-east-1"

    def __init__(self):
        self.calls: list[tuple] = []
        session = self

        class Client:
            def __init__(self, service):
                self.service = service

            def __getattr__(self, op):
                def call(**kwargs):
                    session.calls.append((self.service, op, kwargs))
                    if op == "list_targets_by_rule":
                        return {"Targets": [{"Id": "t1", "Arn": "arn:fn"}]}
                    return {}
                return call
        self._client = Client

    def client(self, service):
        return self._client(service)


class DeleteTests(unittest.TestCase):
    def test_delete_order_removes_children_before_parents(self):
        self.assertLess(DELETE_ORDER["AWS::Lambda::Permission"], DELETE_ORDER["AWS::Lambda::Function"])
        self.assertLess(DELETE_ORDER["AWS::Events::Rule"], DELETE_ORDER["AWS::Lambda::Function"])
        self.assertLess(DELETE_ORDER["AWS::Lambda::Function"], DELETE_ORDER["AWS::IAM::Role"])

    def test_native_deletes(self):
        session = FakeDeleteSession()
        delete_resource(session, "AWS::Lambda::Function", "fn")
        delete_resource(session, "AWS::Lambda::Permission", "fn|sid")
        delete_resource(session, "AWS::Events::Rule", "arn:aws:events:us-east-1:123456789012:rule/nightly")
        delete_resource(session, "AWS::Events::Rule", "arn:aws:events:us-east-1:123456789012:rule/custom-bus/nightly")
        self.assertEqual(session.calls, [
            # settle waits (State, then LastUpdateStatus) before the delete; an empty document
            # reads as "gone", which is settled
            ("lambda", "get_function_configuration", {"FunctionName": "fn"}),
            ("lambda", "get_function_configuration", {"FunctionName": "fn"}),
            ("lambda", "delete_function", {"FunctionName": "fn"}),
            ("lambda", "remove_permission", {"FunctionName": "fn", "StatementId": "sid"}),
            ("events", "list_targets_by_rule", {"Rule": "nightly", "EventBusName": "default"}),
            ("events", "remove_targets", {"Rule": "nightly", "EventBusName": "default", "Ids": ["t1"]}),
            ("events", "delete_rule", {"Name": "nightly", "EventBusName": "default"}),
            ("events", "list_targets_by_rule", {"Rule": "nightly", "EventBusName": "custom-bus"}),
            ("events", "remove_targets", {"Rule": "nightly", "EventBusName": "custom-bus", "Ids": ["t1"]}),
            ("events", "delete_rule", {"Name": "nightly", "EventBusName": "custom-bus"}),
        ])


class ActiveCasesLoadTests(unittest.TestCase):
    # Generated (certified) cases only; the hand-authored set was removed on 2026-09-09.
    ACTIVE = {
        "iac-eval-313-cloudwatch-event-rule-001": {'AWS::Events::Rule', 'AWS::IAM::Role', 'AWS::Lambda::Function', 'AWS::Lambda::Permission'},
        "iac-eval-301-codebuild-project-001": {'AWS::CodeBuild::Project', 'AWS::EC2::SecurityGroup', 'AWS::EC2::Subnet', 'AWS::EC2::VPC', 'AWS::IAM::ManagedPolicy', 'AWS::IAM::Role', 'AWS::S3::Bucket'},
        "iac-eval-165-dynamodb-table-001": {'AWS::DynamoDB::Table', 'AWS::IAM::ManagedPolicy', 'AWS::IAM::Role'},
        "iac-eval-427-internet-gateway-001": {'AWS::EC2::InternetGateway', 'AWS::EC2::Route', 'AWS::EC2::RouteTable', 'AWS::EC2::Subnet', 'AWS::EC2::SubnetRouteTableAssociation', 'AWS::EC2::VPC'},
    }

    def test_every_active_case_loads_with_expected_capture_scope(self):
        for case_id, expected in self.ACTIVE.items():
            with self.subTest(case=case_id):
                spec = load_case("unused", REPO_ROOT / "seeds" / "aws", REPO_ROOT / "cases" / "aws" / case_id)
                self.assertEqual(set(spec.cloudcontrol_types), expected)
                capture_order(list(spec.cloudcontrol_types))   # parents in scope


if __name__ == "__main__":
    unittest.main()


class VpcDrainTests(unittest.TestCase):
    """Interfaces released asynchronously by deleted load balancers must be gone before
    terraform destroys the VPC; detached ones are deleted on sight."""

    def test_waits_for_in_use_interfaces_and_deletes_available_ones(self):
        from harness.runtime.case import drain_vpc_interfaces

        pages = [
            [{"NetworkInterfaceId": "eni-lb", "Status": "in-use"}, {"NetworkInterfaceId": "eni-old", "Status": "available"}],
            [{"NetworkInterfaceId": "eni-lb", "Status": "in-use"}],
            [],
        ]
        calls = []

        class Ec2:
            def describe_network_interfaces(self, Filters):
                calls.append(("describe", Filters[0]["Values"][0]))
                return {"NetworkInterfaces": pages.pop(0) if pages else []}

            def delete_network_interface(self, NetworkInterfaceId):
                calls.append(("delete", NetworkInterfaceId))

        class Session:
            def client(self, name):
                assert name == "ec2"
                return Ec2()

        clock = [0.0]
        remaining = drain_vpc_interfaces(Session(), ["vpc-1"], deadline_s=100, interval_s=10,
                                         sleep=lambda s: clock.__setitem__(0, clock[0] + s), monotonic=lambda: clock[0])
        self.assertEqual(remaining, {})
        self.assertEqual(calls, [("describe", "vpc-1"), ("delete", "eni-old"), ("describe", "vpc-1"), ("describe", "vpc-1")])
        self.assertEqual(clock[0], 20.0)

    def test_gives_up_at_the_deadline_and_reports_what_is_left(self):
        from harness.runtime.case import drain_vpc_interfaces

        class Ec2:
            def describe_network_interfaces(self, Filters):
                return {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-stuck", "Status": "in-use"}]}

        class Session:
            def client(self, name):
                return Ec2()

        clock = [0.0]
        remaining = drain_vpc_interfaces(Session(), ["vpc-1"], deadline_s=25, interval_s=10,
                                         sleep=lambda s: clock.__setitem__(0, clock[0] + s), monotonic=lambda: clock[0])
        self.assertEqual(remaining, {"vpc-1": 1})
        self.assertGreater(clock[0], 25)
