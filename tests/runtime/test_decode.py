"""Request decoding is tested as the exact inverse of botocore's serializers."""

from __future__ import annotations

import unittest

import botocore.session
from botocore.serialize import create_serializer

from harness.runtime.decode import decode_request, endpoint_for, parse_sigv4_scope, service_id_for

SESSION = botocore.session.get_session()


def wire(service: str, operation: str, params: dict) -> tuple[dict, str]:
    model = SESSION.get_service_model(service)
    op = model.operation_model(operation)
    serializer = create_serializer(model.protocol, include_validation=False)
    request = serializer.serialize_to_request(params, op)
    return request, model.metadata.get("signingName") or model.endpoint_prefix


def decode(service: str, operation: str, params: dict):
    request, signing = wire(service, operation, params)
    body = request["body"]
    if isinstance(body, dict):  # query serializer returns a dict of form fields
        from urllib.parse import urlencode
        body = urlencode(body, doseq=True).encode()
    elif isinstance(body, str):
        body = body.encode()
    path, _, query = request["url_path"].partition("?")
    from urllib.parse import urlencode as _enc
    if request.get("query_string"):
        query = _enc(request["query_string"], doseq=True)
    return decode_request(signing_name=signing, region="us-east-1", method=request["method"],
                          path=path, query=query, headers=request["headers"], body=body or b"")


class DecodeTests(unittest.TestCase):
    def test_sigv4_scope(self) -> None:
        auth = ("AWS4-HMAC-SHA256 Credential=AKIAX/20260827/us-east-1/ec2/aws4_request, "
                "SignedHeaders=host;x-amz-date, Signature=abc")
        self.assertEqual(parse_sigv4_scope(auth), ("AKIAX", "us-east-1", "ec2"))

    def test_ec2_query_nested_tags(self) -> None:
        params = {"VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24",
                  "TagSpecifications": [{"ResourceType": "subnet",
                                         "Tags": [{"Key": "Name", "Value": "web"}]}]}
        result = decode("ec2", "CreateSubnet", params)
        self.assertEqual((result.service, result.operation, result.protocol), ("ec2", "CreateSubnet", "ec2"))
        self.assertTrue(result.decoded)
        self.assertEqual(result.parameters, params)

    def test_sts_and_sns_query(self) -> None:
        self.assertEqual(decode("sts", "GetCallerIdentity", {}).operation, "GetCallerIdentity")
        result = decode("sns", "Publish", {"TopicArn": "arn:aws:sns:us-east-1:1:t", "Message": "hi"})
        self.assertEqual(result.operation, "Publish")
        self.assertEqual(result.parameters["Message"], "hi")

    def test_iam_query_non_flattened_list(self) -> None:
        params = {"RoleName": "example", "AssumeRolePolicyDocument": "{}",
                  "Description": "build role",
                  "Tags": [{"Key": "Workload", "Value": "orders-api"}]}
        result = decode("iam", "CreateRole", params)
        self.assertEqual((result.service, result.operation, result.protocol), ("iam", "CreateRole", "query"))
        self.assertTrue(result.decoded)
        self.assertEqual(result.parameters, params)

    def test_query_operation_survives_parameter_decode_failure(self) -> None:
        # Query maps are not decoded yet; the operation must still be known so
        # triggers keyed on service.operation see the call.
        result = decode("sns", "Publish", {"TopicArn": "arn:aws:sns:us-east-1:1:t", "Message": "hi",
                                           "MessageAttributes": {"k": {"DataType": "String",
                                                                       "StringValue": "v"}}})
        self.assertEqual((result.service, result.operation), ("sns", "Publish"))
        self.assertFalse(result.decoded)
        self.assertEqual(result.parameters, {})
        self.assertIn("CanonicalizationError", result.error or "")

    def test_json_protocol_via_target_header(self) -> None:
        params = {"TableName": "t", "Item": {"pk": {"S": "1"}}}
        result = decode("dynamodb", "PutItem", params)
        self.assertEqual((result.operation, result.protocol, result.decoded), ("PutItem", "json", True))
        self.assertEqual(result.parameters, params)

    def test_rest_json_uri_template(self) -> None:
        result = decode("lambda", "GetFunction", {"FunctionName": "fn", "Qualifier": "1"})
        self.assertEqual((result.operation, result.decoded), ("GetFunction", True))
        self.assertEqual(result.parameters["FunctionName"], "fn")
        self.assertEqual(result.parameters["Qualifier"], "1")

    def test_rest_xml_operation_only(self) -> None:
        result = decode("s3", "PutObject", {"Bucket": "b", "Key": "k/v", "Body": b"x"})
        self.assertEqual((result.operation, result.protocol, result.decoded), ("PutObject", "rest-xml", False))

    def test_rest_xml_bucket_subresources_are_not_create_bucket(self) -> None:
        """S3 bucket-configuration writes share CreateBucket's "PUT /{Bucket}" template and
        differ only by a static query key; the subresource operation must win, and the
        non-deprecated name must be chosen where two operations share a subresource."""
        cases = [
            ("CreateBucket", {"Bucket": "b"}),
            ("PutBucketVersioning", {"Bucket": "b", "VersioningConfiguration": {"Status": "Enabled"}}),
            ("PutBucketTagging", {"Bucket": "b", "Tagging": {"TagSet": [{"Key": "k", "Value": "v"}]}}),
            ("PutBucketLifecycleConfiguration", {"Bucket": "b", "LifecycleConfiguration": {"Rules": [
                {"ID": "r", "Status": "Enabled", "Filter": {}, "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}]}]}}),
            ("PutBucketEncryption", {"Bucket": "b", "ServerSideEncryptionConfiguration": {"Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}),
            ("PutPublicAccessBlock", {"Bucket": "b", "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}),
            ("PutObjectLockConfiguration", {"Bucket": "b", "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}),
            ("GetBucketLifecycleConfiguration", {"Bucket": "b"}),
            ("GetBucketVersioning", {"Bucket": "b"}),
            ("DeleteBucket", {"Bucket": "b"}),
        ]
        for operation, params in cases:
            with self.subTest(operation=operation):
                self.assertEqual(decode("s3", operation, params).operation, operation)

    def test_flink_v2_shares_its_signing_name_with_v1_and_is_told_apart_by_the_target_prefix(self) -> None:
        # Managed Service for Apache Flink (kinesisanalyticsv2) signs as `kinesisanalytics`; the dated
        # target prefix is the only thing that tells its calls from the v1 service's.
        v2 = decode_request(signing_name="kinesisanalytics", region="us-east-1", method="POST", path="/", query="",
                            headers={"X-Amz-Target": "KinesisAnalytics_20180523.UpdateApplication",
                                     "Content-Type": "application/x-amz-json-1.1"},
                            body=b'{"ApplicationName": "app", "CurrentApplicationVersionId": 1}')
        self.assertEqual((v2.service, v2.operation), ("kinesisanalyticsv2", "UpdateApplication"))
        v1 = decode_request(signing_name="kinesisanalytics", region="us-east-1", method="POST", path="/", query="",
                            headers={"X-Amz-Target": "KinesisAnalytics_20150814.ListApplications",
                                     "Content-Type": "application/x-amz-json-1.1"}, body=b"{}")
        self.assertEqual((v1.service, v1.operation), ("kinesisanalytics", "ListApplications"))

    def test_cloudwatch_rpc_v2_operation_only(self) -> None:
        result = decode_request(signing_name="monitoring", region="us-east-1", method="POST",
                                path="/service/GraniteServiceVersion20100801/operation/PutMetricAlarm",
                                query="", headers={"content-type": "application/cbor"}, body=b"\xa0")
        self.assertEqual((result.service, result.operation, result.decoded), ("cloudwatch", "PutMetricAlarm", False))

    def test_cloudwatch_json_wire_format_decodes_by_what_the_client_sent(self) -> None:
        # The model prefers rpc-v2-cbor; the AWS CLI sends json with X-Amz-Target (528 such
        # calls in paper-config-1/2 were recorded with a blank operation).
        result = decode_request(signing_name="monitoring", region="us-east-1", method="POST", path="/", query="",
                                headers={"content-type": "application/x-amz-json-1.0",
                                         "x-amz-target": "GraniteServiceVersion20100801.DescribeAlarms"},
                                body=b'{"AlarmNames": ["foobar"]}')
        self.assertEqual((result.service, result.operation, result.protocol, result.decoded),
                         ("cloudwatch", "DescribeAlarms", "json", True))
        self.assertEqual(result.parameters, {"AlarmNames": ["foobar"]})

    def test_cloudwatch_query_wire_format(self) -> None:
        result = decode_request(signing_name="monitoring", region="us-east-1", method="POST", path="/", query="",
                                headers={"content-type": "application/x-www-form-urlencoded; charset=utf-8"},
                                body=b"Action=PutMetricAlarm&Version=2010-08-01&AlarmName=cpu-high")
        self.assertEqual((result.service, result.operation, result.protocol), ("cloudwatch", "PutMetricAlarm", "query"))

    def test_route53_record_changes_match_with_or_without_trailing_slash(self) -> None:
        for path in ("/2013-04-01/hostedzone/Z0785498158HRW47F9L4S/rrset", "/2013-04-01/hostedzone/Z0785498158HRW47F9L4S/rrset/"):
            result = decode_request(signing_name="route53", region="us-east-1", method="POST", path=path, query="",
                                    headers={}, body=b"<ChangeResourceRecordSetsRequest/>")
            self.assertEqual((result.service, result.operation), ("route53", "ChangeResourceRecordSets"), path)
            self.assertIsNone(result.error)

    def test_unknown_operation_does_not_raise(self) -> None:
        result = decode_request(signing_name="ec2", region="us-east-1", method="POST", path="/",
                                query="", headers={}, body=b"Action=NoSuchThing&Version=2016-11-15")
        self.assertFalse(result.decoded)
        self.assertIn("NoSuchThing", result.error or "")

    def test_endpoint_resolution(self) -> None:
        self.assertEqual(service_id_for("monitoring"), "cloudwatch")
        self.assertEqual(endpoint_for("ec2", "us-east-1"), ("ec2.us-east-1.amazonaws.com", "ec2"))
        self.assertEqual(endpoint_for("cloudwatch", "us-east-1")[0], "monitoring.us-east-1.amazonaws.com")
        self.assertEqual(endpoint_for("iam", "us-east-1")[0], "iam.amazonaws.com")


if __name__ == "__main__":
    unittest.main()


def test_signing_name_owner_wins_a_version_tie():
    """docdb and neptune share rds's signing name *and* API version; the call is an RDS call."""
    from harness.runtime.decode import service_id_for, service_ids_for

    assert service_ids_for("rds")[0] == "rds"
    assert service_id_for("rds", "2014-10-31") == "rds"
    assert service_id_for("rds") == "rds"
    # The version still separates the two ELB APIs.
    assert service_id_for("elasticloadbalancing", "2015-12-01") == "elbv2"
    assert service_id_for("elasticloadbalancing", "2012-06-01") == "elb"


class ErrorCodeTests(unittest.TestCase):
    def test_header_xml_and_json_forms(self) -> None:
        from harness.runtime.decode import error_code

        self.assertEqual(error_code(404, {"x-amzn-errortype": "ResourceNotFoundException"},
                                    b'{"Type":"User","Message":"Function not found"}'), "ResourceNotFoundException")
        self.assertEqual(error_code(409, {"X-Amzn-ErrorType": "ResourceConflictException:http://internal.amazon.com/coral/x/"},
                                    b"{}"), "ResourceConflictException")
        self.assertEqual(error_code(400, {}, b'{"__type":"com.amazonaws.dynamodb.v20120810#ResourceInUseException","message":"x"}'),
                         "ResourceInUseException")
        self.assertEqual(error_code(400, {}, b'{"__type":"InvalidInputException","message":"CodeBuild is not"}'),
                         "InvalidInputException")
        self.assertEqual(error_code(400, {}, b'<ErrorResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/"><Error>'
                                            b'<Type>Sender</Type><Code>InvalidDBInstanceState</Code></Error></ErrorResponse>'),
                         "InvalidDBInstanceState")
        self.assertEqual(error_code(400, {}, b'<?xml version="1.0"?><Response><Errors><Error><Code>DependencyViolation</Code>'
                                            b'</Error></Errors></Response>'), "DependencyViolation")
        self.assertIsNone(error_code(200, {}, b"<Code>Never</Code>"))
        self.assertIsNone(error_code(503, {}, b""))
