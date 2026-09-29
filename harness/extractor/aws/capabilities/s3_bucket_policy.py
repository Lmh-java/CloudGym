"""Capability adapter for ``aws_s3_bucket_policy``.

``AWS::S3::BucketPolicy`` is its own Cloud Control type (the policy is not a
property of the bucket document); it lists region-wide and its identifier is
the bucket name, which is also Terraform's id.
"""

import json

from .base import CapabilityAdapter


class S3BucketPolicyAdapter(CapabilityAdapter):
    terraform_type = "aws_s3_bucket_policy"
    cloudcontrol_type = "AWS::S3::BucketPolicy"
    identifier_is_borrowed = True  # identified by the bucket's name
    semantic_properties = (
        "Bucket",  # rewritten to a logical address during normalization
        "PolicyDocument",
    )
    volatile_fields = ()
    readiness_properties = ("Bucket", "PolicyDocument")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        document = dict(properties.get("PolicyDocument") or {})
        statements = list(document.get("Statement") or [])
        statements.append({
            "Sid": "CloudGymSmokeMutation", "Effect": "Deny",
            "Principal": "*", "Action": "s3:DeleteBucketPolicy",
            "Resource": f"arn:aws:s3:::{identifier}",
            "Condition": {"StringEquals": {"aws:PrincipalTag/cloudgym-smoke": "never-set"}},
        })
        document = {"Version": document.get("Version", "2012-10-17"), "Statement": statements}
        session.client("s3").put_bucket_policy(Bucket=identifier, Policy=json.dumps(document))
        return {"PolicyDocument": document}
