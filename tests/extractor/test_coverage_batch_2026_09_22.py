"""DHCP options, API Gateway REST, Firehose and Glacier adapters; nested parent listing."""

from __future__ import annotations

import unittest

from botocore.exceptions import ClientError

from harness.extractor.aws.capabilities import adapter_for
from harness.extractor.aws.capture import capture_order
from harness.runtime.case import DELETE_ORDER


class _Session:
    def __init__(self, client):
        self._client = client
        self.region_name = "us-east-1"

    def client(self, name, region_name=None):
        return self._client


def _not_found(code: str, op: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "x"}}, op)


class ApiGatewayTests(unittest.TestCase):
    def test_identifiers_follow_the_cloudcontrol_pipe_forms(self) -> None:
        self.assertEqual(adapter_for("aws_api_gateway_rest_api").identifier_from_state({"id": "abc123"}), "abc123")
        self.assertEqual(adapter_for("aws_api_gateway_resource").identifier_from_state(
            {"id": "r1", "rest_api_id": "abc123"}), "abc123|r1")
        self.assertEqual(adapter_for("aws_api_gateway_method").identifier_from_state(
            {"id": "agm-abc123-r1-GET", "rest_api_id": "abc123", "resource_id": "r1", "http_method": "GET"}),
            "abc123|r1|GET")
        self.assertEqual(adapter_for("aws_api_gateway_deployment").identifier_from_state(
            {"id": "d1", "rest_api_id": "abc123"}), "d1|abc123")
        self.assertEqual(adapter_for("aws_api_gateway_stage").identifier_from_state(
            {"id": "ags-abc123-prod", "rest_api_id": "abc123", "stage_name": "prod"}), "abc123|prod")
        with self.assertRaises(ValueError):
            adapter_for("aws_api_gateway_method").identifier_from_state({"rest_api_id": "abc123"})

    def test_integration_is_a_projection_of_the_method(self) -> None:
        adapter = adapter_for("aws_api_gateway_integration")
        self.assertFalse(adapter.standalone)
        self.assertEqual(adapter.cloudcontrol_type, "AWS::ApiGateway::Method")
        self.assertEqual(adapter.project({"HttpMethod": "GET", "Integration": {"Type": "MOCK"}}),
                         {"Integration": {"Type": "MOCK"}})

    def test_listing_chain_and_models(self) -> None:
        self.assertEqual(adapter_for("aws_api_gateway_resource").list_resource_model({"RestApiId": "a"}),
                         {"RestApiId": "a"})
        self.assertEqual(adapter_for("aws_api_gateway_method").list_resource_model(
            {"RestApiId": "a", "ResourceId": "r"}), {"RestApiId": "a", "ResourceId": "r"})
        # methods list per resource, resources per API: the capture must place them in that order
        # whatever order the manifest hands them over in.
        ordered = capture_order(["AWS::ApiGateway::Method", "AWS::ApiGateway::Stage",
                                 "AWS::ApiGateway::Resource", "AWS::ApiGateway::RestApi"])
        self.assertLess(ordered.index("AWS::ApiGateway::RestApi"), ordered.index("AWS::ApiGateway::Resource"))
        self.assertLess(ordered.index("AWS::ApiGateway::Resource"), ordered.index("AWS::ApiGateway::Method"))
        self.assertLess(ordered.index("AWS::ApiGateway::RestApi"), ordered.index("AWS::ApiGateway::Stage"))

    def test_teardown_order_children_before_api(self) -> None:
        api = DELETE_ORDER["AWS::ApiGateway::RestApi"]
        for child in ("AWS::ApiGateway::Method", "AWS::ApiGateway::Stage", "AWS::ApiGateway::Resource",
                      "AWS::ApiGateway::Deployment"):
            self.assertLess(DELETE_ORDER[child], api)
        self.assertLess(DELETE_ORDER["AWS::ApiGateway::Stage"], DELETE_ORDER["AWS::ApiGateway::Deployment"])


class DhcpOptionsTests(unittest.TestCase):
    def test_association_reads_natively_from_describe_vpcs(self) -> None:
        class _Ec2:
            def describe_vpcs(self, **kwargs):
                if kwargs.get("VpcIds") == ["vpc-gone"]:
                    raise _not_found("InvalidVpcID.NotFound", "DescribeVpcs")
                return {"Vpcs": [{"VpcId": "vpc-1", "DhcpOptionsId": "dopt-1"},
                                 {"VpcId": "vpc-2", "DhcpOptionsId": "dopt-default"}]}

            def get_paginator(self, name):
                outer = self

                class _P:
                    def paginate(self, **kwargs):
                        return [outer.describe_vpcs()]
                return _P()

        adapter = adapter_for("aws_vpc_dhcp_options_association")
        session = _Session(_Ec2())
        self.assertEqual(adapter.native_describe(session, "us-east-1"),
                         [("dopt-1|vpc-1", {"DhcpOptionsId": "dopt-1", "VpcId": "vpc-1"}),
                          ("dopt-default|vpc-2", {"DhcpOptionsId": "dopt-default", "VpcId": "vpc-2"})])
        self.assertEqual(adapter.native_read(session, "us-east-1", "dopt-1|vpc-1"),
                         {"DhcpOptionsId": "dopt-1", "VpcId": "vpc-1"})
        self.assertIsNone(adapter.native_read(session, "us-east-1", "dopt-9|vpc-1"))   # re-associated elsewhere
        self.assertIsNone(adapter.native_read(session, "us-east-1", "dopt-1|vpc-gone"))
        self.assertEqual(adapter.identifier_from_state({"dhcp_options_id": "dopt-1", "vpc_id": "vpc-1"}), "dopt-1|vpc-1")

    def test_option_set_deleted_after_vpcs(self) -> None:
        self.assertGreater(DELETE_ORDER["AWS::EC2::DHCPOptions"], DELETE_ORDER.get("AWS::EC2::VPC", 50))
        self.assertLess(DELETE_ORDER["AWS::EC2::VPCDHCPOptionsAssociation"], DELETE_ORDER["AWS::EC2::DHCPOptions"])


class FirehoseAndGlacierTests(unittest.TestCase):
    def test_firehose_binds_on_name_and_is_not_billable(self) -> None:
        from harness.eligibility import BILLABLE_TYPES, assess

        adapter = adapter_for("aws_kinesis_firehose_delivery_stream")
        self.assertEqual(adapter.identifier_from_state({"id": "arn:aws:firehose:...", "name": "stream-1"}), "stream-1")
        self.assertNotIn("aws_kinesis_firehose_delivery_stream", BILLABLE_TYPES)
        self.assertTrue(assess('resource "aws_kinesis_firehose_delivery_stream" "s" {}\n', check_size=False).eligible)

    def test_glacier_folds_policy_notifications_and_tags_into_the_document(self) -> None:
        class _Glacier:
            def describe_vault(self, vaultName):
                if vaultName == "gone":
                    raise _not_found("ResourceNotFoundException", "DescribeVault")
                return {"VaultName": vaultName, "VaultARN": f"arn:aws:glacier:us-east-1:123456789012:vaults/{vaultName}",
                        "NumberOfArchives": 0, "SizeInBytes": 0, "ResponseMetadata": {}}

            def get_vault_access_policy(self, vaultName):
                raise _not_found("ResourceNotFoundException", "GetVaultAccessPolicy")

            def get_vault_notifications(self, vaultName):
                return {"vaultNotificationConfig": {"SNSTopic": "arn:sns", "Events": ["ArchiveRetrievalCompleted"]}}

            def list_tags_for_vault(self, vaultName):
                return {"Tags": {"Name": "v"}}

        adapter = adapter_for("aws_glacier_vault")
        doc = adapter.native_read(_Session(_Glacier()), "us-east-1", "v1")
        self.assertEqual(doc["Tags"], [{"Key": "Name", "Value": "v"}])
        self.assertEqual(doc["Notifications"]["SNSTopic"], "arn:sns")
        self.assertNotIn("AccessPolicy", doc)
        self.assertNotIn("ResponseMetadata", doc)
        self.assertTrue(adapter.ready(doc))
        self.assertNotIn("NumberOfArchives", adapter.project(doc))
        self.assertIsNone(adapter.native_read(_Session(_Glacier()), "us-east-1", "gone"))


if __name__ == "__main__":
    unittest.main()
