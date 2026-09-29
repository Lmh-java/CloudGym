"""Capability adapters for EC2 Auto Scaling: launch configuration, group, scaling
policy, and the attachment projection.

Added 2026-09-22 for the execution-conflict (EC) seed pool: an Auto Scaling group is the
fastest resource with a real in-flight window (an instance refresh or a scaling activity
refuses a second refresh / a group delete with ``InstanceRefreshInProgressFault`` /
``ScalingActivityInProgressFault``). ``autoscaling:*`` is in the SCP allowlist. Groups
launch through the service-linked role, which the ``OnlyCheapInstanceTypes`` guardrail
does not reach, so fixtures and cases pin ``t3.micro`` themselves.

Cloud Control identifiers: the group and launch configuration are identified by name
(also Terraform's id); a scaling policy by its ARN (Terraform's id is the policy name,
so the adapter binds on ``arn``). ``aws_autoscaling_attachment`` is a projection: the
attached target groups and classic load balancers are the group document's
``TargetGroupARNs`` / ``LoadBalancerNames``.
"""

from datetime import datetime

from .base import CapabilityAdapter


def _jsonable(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _asg_tags(session, group_name: str, existing: list | None) -> list[dict]:
    # The group document's tag entries carry the resource fields too (smoke 2026-09-22).
    tag = {"ResourceId": group_name, "ResourceType": "auto-scaling-group",
           "Key": "cloudgym-smoke", "Value": "mutation-visible", "PropagateAtLaunch": False}
    session.client("autoscaling").create_or_update_tags(Tags=[tag])
    return [t for t in (existing or []) if t.get("Key") != "cloudgym-smoke"] + [tag]


class LaunchConfigurationAdapter(CapabilityAdapter):
    terraform_type = "aws_launch_configuration"
    cloudcontrol_type = "AWS::AutoScaling::LaunchConfiguration"
    semantic_properties = (
        "AssociatePublicIpAddress",
        "BlockDeviceMappings",
        "EbsOptimized",
        "IamInstanceProfile",      # rewritten to a logical address during normalization
        "ImageId",
        "InstanceMonitoring",
        "InstanceType",
        "KeyName",
        "LaunchConfigurationName",
        "MetadataOptions",
        "PlacementTenancy",
        "SecurityGroups",          # rewritten to logical addresses during normalization
        "SpotPrice",
        "UserData",
    )
    volatile_fields = ()
    readiness_properties = ("LaunchConfigurationName", "ImageId", "InstanceType")

    # A launch configuration is immutable: no out-of-band write can change a semantic
    # property, so the smoke reports "mutation: unproven" for this type by design.


class LaunchTemplateAdapter(CapabilityAdapter):
    """``aws_launch_template``: what new accounts must use instead of a launch configuration
    (``CreateLaunchConfiguration`` returns UnsupportedOperation there, smoke 2026-09-22).

    Read natively: Cloud Control's GetResource on ``AWS::EC2::LaunchTemplate`` returns only
    the id, name and version numbers (``LaunchTemplateData`` is write-only there, smoke
    2026-09-22), so the envelope is the ``DescribeLaunchTemplates`` record with the latest
    version's ``LaunchTemplateData`` and ``VersionDescription`` folded in.
    """

    terraform_type = "aws_launch_template"
    cloudcontrol_type = "AWS::EC2::LaunchTemplate"
    semantic_properties = (
        "LaunchTemplateData",
        "LaunchTemplateName",
        "Tags",
        "VersionDescription",
    )
    volatile_fields = ("LaunchTemplateId", "LatestVersionNumber", "DefaultVersionNumber", "CreateTime",
                       "CreatedBy", "VersionNumber")
    readiness_properties = ("LaunchTemplateId", "LaunchTemplateName", "LaunchTemplateData")

    def _client(self, session, region: str):
        return session.client("ec2", region_name=region)

    def _document(self, ec2, template: dict) -> dict:
        doc = _jsonable(dict(template))
        versions = ec2.describe_launch_template_versions(
            LaunchTemplateId=template["LaunchTemplateId"], Versions=["$Latest"]).get("LaunchTemplateVersions", [])
        if versions:
            latest = _jsonable(versions[0])
            doc["LaunchTemplateData"] = latest.get("LaunchTemplateData", {})
            doc["VersionDescription"] = latest.get("VersionDescription", "")
            doc["VersionNumber"] = latest.get("VersionNumber")
        return doc

    def native_describe(self, session, region: str) -> list[tuple[str, dict]]:
        ec2 = self._client(session, region)
        out: list[tuple[str, dict]] = []
        for page in ec2.get_paginator("describe_launch_templates").paginate():
            for template in page.get("LaunchTemplates", []):
                out.append((template["LaunchTemplateId"], self._document(ec2, template)))
        return out

    def native_read(self, session, region: str, identifier: str) -> dict | None:
        from botocore.exceptions import ClientError

        ec2 = self._client(session, region)
        try:
            templates = ec2.describe_launch_templates(LaunchTemplateIds=[identifier]).get("LaunchTemplates", [])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "").startswith("InvalidLaunchTemplateId"):
                return None
            raise
        return self._document(ec2, templates[0]) if templates else None

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        description = "cloudgym-smoke mutation-visible"
        session.client("ec2").create_launch_template_version(
            LaunchTemplateId=identifier, VersionDescription=description, SourceVersion="$Latest",
            LaunchTemplateData={"InstanceType": "t3.micro"})
        return {"VersionDescription": description}


class AutoScalingGroupAdapter(CapabilityAdapter):
    terraform_type = "aws_autoscaling_group"
    cloudcontrol_type = "AWS::AutoScaling::AutoScalingGroup"
    semantic_properties = (
        "AutoScalingGroupName",
        "AvailabilityZones",
        "CapacityRebalance",
        "Cooldown",
        "DefaultInstanceWarmup",
        "DesiredCapacity",
        "DesiredCapacityType",
        "HealthCheckGracePeriod",
        "HealthCheckType",
        "InstanceMaintenancePolicy",
        "LaunchConfigurationName",   # rewritten to a logical address during normalization
        "LaunchTemplate",            # LaunchTemplateId rewritten to a logical address
        "LoadBalancerNames",
        "MaxInstanceLifetime",
        "MaxSize",
        "MetricsCollection",
        "MinSize",
        "MixedInstancesPolicy",
        "NewInstancesProtectedFromScaleIn",
        "PlacementGroup",
        "Tags",
        "TargetGroupARNs",           # rewritten to logical addresses during normalization
        "TerminationPolicies",
        "VPCZoneIdentifier",         # rewritten to logical addresses during normalization
    )
    volatile_fields = ("ServiceLinkedRoleARN",)
    readiness_properties = ("AutoScalingGroupName", "MinSize", "MaxSize")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        return {"Tags": _asg_tags(session, identifier, properties.get("Tags"))}


class AutoScalingAttachmentAdapter(AutoScalingGroupAdapter):
    """``aws_autoscaling_attachment``: the group's attached target groups / classic ELBs."""

    terraform_type = "aws_autoscaling_attachment"
    standalone = False
    semantic_properties = ("LoadBalancerNames", "TargetGroupARNs")

    def identifier_from_state(self, attributes: dict) -> str:
        name = attributes.get("autoscaling_group_name")
        if not name or not isinstance(name, str):
            raise ValueError(f"{self.terraform_type}: state instance has no autoscaling_group_name")
        return name


class ScalingPolicyAdapter(CapabilityAdapter):
    terraform_type = "aws_autoscaling_policy"
    cloudcontrol_type = "AWS::AutoScaling::ScalingPolicy"
    semantic_properties = (
        "AdjustmentType",
        "AutoScalingGroupName",   # rewritten to a logical address during normalization
        "Cooldown",
        "EstimatedInstanceWarmup",
        "MetricAggregationType",
        "MinAdjustmentMagnitude",
        "PolicyName",
        "PolicyType",
        "PredictiveScalingConfiguration",
        "ScalingAdjustment",
        "StepAdjustments",
        "TargetTrackingConfiguration",
    )
    volatile_fields = ("Arn",)
    readiness_properties = ("Arn", "PolicyName", "AutoScalingGroupName")

    def identifier_from_state(self, attributes: dict) -> str:
        # Terraform's id is the policy name; Cloud Control identifies a policy by ARN.
        arn = attributes.get("arn")
        if not arn or not isinstance(arn, str):
            raise ValueError(f"{self.terraform_type}: state instance has no 'arn'")
        return arn

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        if properties.get("PolicyType") not in (None, "SimpleScaling"):
            return None
        cooldown = int(properties.get("Cooldown") or 0) + 30
        session.client("autoscaling").put_scaling_policy(
            AutoScalingGroupName=properties["AutoScalingGroupName"], PolicyName=properties["PolicyName"],
            PolicyType="SimpleScaling", AdjustmentType=properties.get("AdjustmentType", "ChangeInCapacity"),
            ScalingAdjustment=int(properties.get("ScalingAdjustment", 1)), Cooldown=cooldown)
        return {"Cooldown": str(cooldown)}     # the handler reports numbers as strings


def scaling_policy_arn_parts(arn: str) -> tuple[str, str]:
    """(group name, policy name) from a scaling-policy ARN:
    ``arn:aws:autoscaling:<region>:<acct>:scalingPolicy:<uuid>:autoScalingGroupName/<g>:policyName/<p>``."""
    group = policy = None
    for part in arn.split(":"):
        if part.startswith("autoScalingGroupName/"):
            group = part.split("/", 1)[1]
        elif part.startswith("policyName/"):
            policy = part.split("/", 1)[1]
    if not group or not policy:
        raise ValueError(f"not a scaling-policy ARN: {arn}")
    return group, policy
