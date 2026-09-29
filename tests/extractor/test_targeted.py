import json
import unittest

from botocore.exceptions import ClientError

from harness.extractor.aws.targeted import (
    Binding,
    absence_verified,
    bindings_from_state,
    find_present,
    normalize,
    stable_snapshot,
    targeted_capture,
)
from harness.extractor.errors import (
    BindingError,
    CaptureError,
    StabilityTimeout,
    UnmappedResourceType,
)


def state_json(resources):
    return {"values": {"root_module": {"resources": resources}}}


def managed(address, tf_type, values):
    return {"address": address, "mode": "managed", "type": tf_type,
            "values": values}


VPC_PROPS = {
    "VpcId": "vpc-1",
    "CidrBlock": "10.0.0.0/16",
    "EnableDnsHostnames": True,
    "Tags": [
        {"Key": "cloudgym:run-id", "Value": "r-1"},
        {"Key": "Name", "Value": "example"},
    ],
}

SG_PROPS = {
    "GroupId": "sg-1",
    "Id": "sg-1",
    "GroupName": "allow_ssh",
    "GroupDescription": "Allow SSH inbound traffic",
    "VpcId": "vpc-1",
    "SecurityGroupIngress": [
        {"CidrIp": "0.0.0.0/0", "FromPort": 22, "IpProtocol": "tcp", "ToPort": 22},
    ],
    "SecurityGroupEgress": [
        {"CidrIp": "0.0.0.0/0", "FromPort": -1, "IpProtocol": "-1", "ToPort": -1},
    ],
    "Tags": [{"Key": "cloudgym:seed-id", "Value": "s-1"}],
}

BINDINGS = [
    Binding("aws_vpc.main", "aws_vpc", "vpc-1"),
    Binding("aws_security_group.allow_ssh", "aws_security_group", "sg-1"),
]


class FakeClient:
    """Cloud Control fake for targeted get_resource calls."""

    def __init__(self, resources):
        # resources: {identifier: properties}
        self.resources = resources
        self.get_calls = []

    def get_resource(self, TypeName, Identifier):
        self.get_calls.append((TypeName, Identifier))
        if Identifier not in self.resources:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "gone"}},
                "GetResource")
        return {"ResourceDescription": {
            "Identifier": Identifier,
            "Properties": json.dumps(self.resources[Identifier]),
        }}

class BindingTests(unittest.TestCase):
    def test_bindings_from_state(self):
        state = state_json([
            managed("aws_vpc.main", "aws_vpc", {"id": "vpc-1"}),
            managed("aws_security_group.x", "aws_security_group", {"id": "sg-1"}),
        ])
        bindings = bindings_from_state(state)
        self.assertEqual(
            [(b.address, b.identifier) for b in bindings],
            [("aws_vpc.main", "vpc-1"), ("aws_security_group.x", "sg-1")])

    def test_child_modules_are_walked(self):
        state = {"values": {"root_module": {
            "resources": [managed("aws_vpc.main", "aws_vpc", {"id": "vpc-1"})],
            "child_modules": [{"resources": [
                managed("module.m.aws_subnet.s", "aws_subnet", {"id": "subnet-1"}),
            ]}],
        }}}
        self.assertEqual(len(bindings_from_state(state)), 2)

    def test_unmapped_type_fails_closed(self):
        state = state_json([
            managed("aws_instance.f", "aws_eks_cluster", {"id": "i-1"})
        ])
        with self.assertRaises(UnmappedResourceType):
            bindings_from_state(state)

    def test_duplicate_identifier_rejected(self):
        state = state_json([
            managed("aws_vpc.a", "aws_vpc", {"id": "vpc-1"}),
            managed("aws_vpc.b", "aws_vpc", {"id": "vpc-1"}),
        ])
        with self.assertRaises(BindingError):
            bindings_from_state(state)

    def test_borrowed_identifier_shared_across_types_is_allowed(self):
        # A bucket and its AWS::S3::BucketPolicy are both identified by the bucket name.
        bindings = bindings_from_state(state_json([
            managed("aws_s3_bucket.b", "aws_s3_bucket", {"id": "bkt"}),
            managed("aws_s3_bucket_policy.p", "aws_s3_bucket_policy", {"id": "bkt"}),
        ]))
        self.assertEqual([b.identifier for b in bindings], ["bkt", "bkt"])
        normalized = normalize({
            "aws_s3_bucket.b": {"BucketName": "bkt", "Tags": []},
            "aws_s3_bucket_policy.p": {"Bucket": "bkt", "PolicyDocument": {"Statement": []}},
        }, bindings)
        # The reference resolves to the identifier's owner, never to the borrower.
        self.assertEqual(normalized["resources"]["aws_s3_bucket_policy.p"]["Bucket"],
                         "${aws_s3_bucket.b}")

    def test_missing_id_rejected(self):
        state = state_json([managed("aws_vpc.a", "aws_vpc", {})])
        with self.assertRaises(ValueError):
            bindings_from_state(state)


class TargetedCaptureTests(unittest.TestCase):
    def test_capture_reads_each_binding_once(self):
        client = FakeClient({"vpc-1": VPC_PROPS, "sg-1": SG_PROPS})
        raw = targeted_capture(BINDINGS, client)
        self.assertEqual(set(raw), {"aws_vpc.main", "aws_security_group.allow_ssh"})
        self.assertEqual(client.get_calls, [
            ("AWS::EC2::VPC", "vpc-1"),
            ("AWS::EC2::SecurityGroup", "sg-1"),
        ])

    def test_missing_resource_fails_closed(self):
        client = FakeClient({"vpc-1": VPC_PROPS})
        with self.assertRaises(CaptureError):
            targeted_capture(BINDINGS, client)


class NormalizeTests(unittest.TestCase):
    def normalized(self):
        raw = {"aws_vpc.main": VPC_PROPS,
               "aws_security_group.allow_ssh": SG_PROPS}
        return normalize(raw, BINDINGS)

    def test_reserved_tags_and_volatile_fields_removed(self):
        resources = self.normalized()["resources"]
        vpc = resources["aws_vpc.main"]
        self.assertNotIn("VpcId", vpc)
        self.assertEqual(vpc["Tags"], [{"Key": "Name", "Value": "example"}])
        sg = resources["aws_security_group.allow_ssh"]
        self.assertNotIn("GroupId", sg)
        self.assertEqual(sg["Tags"], [])

    def test_cross_references_rewritten_to_logical_addresses(self):
        sg = self.normalized()["resources"]["aws_security_group.allow_ssh"]
        self.assertEqual(sg["VpcId"], "${aws_vpc.main}")

    def test_reset_equivalence_with_changed_physical_ids(self):
        after_reset_bindings = [
            Binding("aws_vpc.main", "aws_vpc", "vpc-9"),
            Binding("aws_security_group.allow_ssh", "aws_security_group", "sg-9"),
        ]
        vpc2 = dict(VPC_PROPS, VpcId="vpc-9", DefaultSecurityGroup="sg-def-9")
        sg2 = dict(SG_PROPS, GroupId="sg-9", Id="sg-9", VpcId="vpc-9")
        # Rule ordering differs too — normalization must not care.
        sg2["SecurityGroupIngress"] = list(reversed(SG_PROPS["SecurityGroupIngress"]))
        again = normalize(
            {"aws_vpc.main": vpc2, "aws_security_group.allow_ssh": sg2},
            after_reset_bindings)
        self.assertEqual(self.normalized(), again)

    def test_missing_address_fails_closed(self):
        with self.assertRaises(BindingError):
            normalize({"aws_vpc.main": VPC_PROPS}, BINDINGS)


class StableSnapshotTests(unittest.TestCase):
    def run_sequence(self, captures, **kwargs):
        sequence = iter(captures)

        def capture(bindings, client):
            return next(sequence)

        clock = {"t": 0.0}

        def monotonic():
            clock["t"] += 1.0
            return clock["t"]

        return stable_snapshot(
            BINDINGS, client=None, capture=capture,
            sleep=lambda s: None, monotonic=monotonic, **kwargs)

    def test_converges_on_two_equal_ready_reads(self):
        full = {"aws_vpc.main": VPC_PROPS,
                "aws_security_group.allow_ssh": SG_PROPS}
        changed = {"aws_vpc.main": dict(VPC_PROPS, CidrBlock="10.9.0.0/16"),
                   "aws_security_group.allow_ssh": SG_PROPS}
        snapshot, raw = self.run_sequence([changed, full, full])
        self.assertEqual(
            snapshot["resources"]["aws_vpc.main"]["CidrBlock"], "10.0.0.0/16")
        self.assertEqual(raw, full)

    def test_premature_not_ready_reads_do_not_converge(self):
        not_ready_sg = dict(SG_PROPS)
        not_ready_sg.pop("GroupId")
        premature = {"aws_vpc.main": VPC_PROPS,
                     "aws_security_group.allow_ssh": not_ready_sg}
        with self.assertRaises(StabilityTimeout):
            self.run_sequence([premature] * 50, deadline_seconds=10)

    def test_no_bindings_rejected(self):
        with self.assertRaises(BindingError):
            stable_snapshot([], client=None)


class LeakDetectionTests(unittest.TestCase):
    def test_find_present_checks_only_recorded_identifiers(self):
        client = FakeClient({"vpc-1": VPC_PROPS, "unrelated": {}})
        present = find_present(BINDINGS, client)
        self.assertEqual([r["identifier"] for r in present], ["vpc-1"])
        self.assertEqual(client.get_calls, [
            ("AWS::EC2::VPC", "vpc-1"),
            ("AWS::EC2::SecurityGroup", "sg-1"),
        ])

    def test_absence_verified_polls_until_clean(self):
        resources = {"vpc-1": VPC_PROPS}

        class Client(FakeClient):
            def get_resource(self, TypeName, Identifier):
                result = super().get_resource(TypeName, Identifier)
                self.resources.pop(Identifier)
                return result

        ok, present = absence_verified(
            [BINDINGS[0]], Client(resources), sleep=lambda s: None)
        self.assertTrue(ok)
        self.assertEqual(present, [])

    def test_non_not_found_error_fails_closed(self):
        class Client(FakeClient):
            def get_resource(self, TypeName, Identifier):
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException",
                               "Message": "no"}}, "GetResource")

        with self.assertRaises(CaptureError):
            find_present([BINDINGS[0]], Client({}))


if __name__ == "__main__":
    unittest.main()
