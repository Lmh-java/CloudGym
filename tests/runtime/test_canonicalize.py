from __future__ import annotations

import unittest

from harness.runtime.canonicalize import (
    CanonicalizationError,
    decode_query_request,
    encode_query,
)


class QueryCanonicalizerTests(unittest.TestCase):
    def test_nested_ec2_query_matches_boto3_shape(self) -> None:
        request = decode_query_request(
            service="ec2",
            region="us-east-1",
            body=(
                "Action=AuthorizeSecurityGroupIngress&Version=2016-11-15&GroupId=sg-1"
                "&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=22"
                "&IpPermissions.1.ToPort=22"
                "&IpPermissions.1.IpRanges.1.CidrIp=203.0.113.0%2F24"
            ),
        )
        self.assertEqual(request.operation, "AuthorizeSecurityGroupIngress")
        self.assertEqual(
            request.parameters,
            {
                "GroupId": "sg-1",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "203.0.113.0/24"}],
                    }
                ],
            },
        )

    def test_boolean_and_integer_types(self) -> None:
        request = decode_query_request(
            service="ec2",
            region="us-east-1",
            body="Action=CreateSubnet&Version=2016-11-15&VpcId=vpc-1&CidrBlock=10.0.0.0%2F24&DryRun=false",
        )
        self.assertIs(request.parameters["DryRun"], False)

    def test_unsupported_service_fails_closed(self) -> None:
        with self.assertRaises(CanonicalizationError):
            decode_query_request(
                service="s3", region="us-east-1", body="Action=ListBuckets"
            )

    def test_sts_query_uses_botocore_operation_name(self) -> None:
        request = decode_query_request(
            service="STS",
            region="us-east-1",
            body="Action=GetCallerIdentity&Version=2011-06-15",
        )
        self.assertEqual(request.service, "sts")
        self.assertEqual(request.operation, "GetCallerIdentity")
        self.assertEqual(request.parameters, {})

    def test_query_and_body_are_combined(self) -> None:
        request = decode_query_request(
            service="ec2",
            region="us-east-1",
            query="Action=DescribeVpcs&Version=2016-11-15",
            body="VpcId.1=vpc-1&VpcId.2=vpc-2",
        )
        self.assertEqual(request.parameters, {"VpcIds": ["vpc-1", "vpc-2"]})

    def test_duplicate_missing_and_unknown_actions_fail_closed(self) -> None:
        bodies = (
            "Version=2016-11-15",
            "Action=NotARealOperation&Version=2016-11-15",
            "Action=DescribeVpcs&Action=DescribeSubnets&Version=2016-11-15",
        )
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(CanonicalizationError):
                decode_query_request(service="ec2", region="us-east-1", body=body)

    def test_invalid_scalar_and_zero_list_index_fail_closed(self) -> None:
        bodies = (
            "Action=CreateSubnet&Version=2016-11-15&VpcId=vpc-1&CidrBlock=10.0.0.0%2F24&DryRun=maybe",
            "Action=DescribeVpcs&Version=2016-11-15&VpcId.0=vpc-1",
        )
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(CanonicalizationError):
                decode_query_request(service="ec2", region="us-east-1", body=body)

    def test_non_flattened_list_carries_member_element_name(self) -> None:
        # IAM (AWS Query) lists are not flattened: ``Tags.member.1.Key``.
        request = decode_query_request(
            service="iam",
            region="us-east-1",
            body=(
                "Action=CreateRole&Version=2010-05-08&RoleName=example"
                "&AssumeRolePolicyDocument=%7B%7D"
                "&Tags.member.1.Key=Workload&Tags.member.1.Value=orders-api"
            ),
        )
        self.assertEqual(request.operation, "CreateRole")
        self.assertEqual(
            request.parameters,
            {"RoleName": "example", "AssumeRolePolicyDocument": "{}",
             "Tags": [{"Key": "Workload", "Value": "orders-api"}]},
        )

    def test_wrong_list_element_name_fails_closed(self) -> None:
        bodies = (
            "Action=CreateRole&Version=2010-05-08&RoleName=r&AssumeRolePolicyDocument=%7B%7D"
            "&Tags.item.1.Key=Workload",
            "Action=CreateRole&Version=2010-05-08&RoleName=r&AssumeRolePolicyDocument=%7B%7D"
            "&Tags.member=Workload",
        )
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(CanonicalizationError):
                decode_query_request(service="iam", region="us-east-1", body=body)

    def test_unknown_parameter_and_parameter_on_no_input_operation_fail(self) -> None:
        bodies = (
            "Action=DescribeVpcs&Version=2016-11-15&NoSuchField=x",
            "Action=GetCallerIdentity&Version=2011-06-15&Unexpected=x",
        )
        services = ("ec2", "sts")
        for service, body in zip(services, bodies):
            with self.subTest(service=service), self.assertRaises(CanonicalizationError):
                decode_query_request(service=service, region="us-east-1", body=body)

    def test_encode_query_supports_mapping_pairs_and_verbatim_string(self) -> None:
        self.assertEqual(encode_query("Action=DescribeVpcs"), "Action=DescribeVpcs")
        self.assertEqual(encode_query({"VpcId": ["vpc-1", "vpc-2"]}), "VpcId=vpc-1&VpcId=vpc-2")
        self.assertEqual(encode_query([("A", "1"), ("A", "2")]), "A=1&A=2")


if __name__ == "__main__":
    unittest.main()
