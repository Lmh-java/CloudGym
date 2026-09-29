"""Capability adapters for Elastic Beanstalk: application and environment.

Opened 2026-09-08. Beanstalk provisions its environments through CloudFormation
*with the caller's credentials*, which is why the SCP now allowlists
``cloudformation:*`` and ``autoscaling:*`` alongside ``elasticbeanstalk:*``
(the Cloud Control write path is re-denied in the guardrails). An
environment's EC2 capacity is launched by the Auto Scaling service-linked
role, which SCPs do not govern, so the fixture pins ``InstanceType`` itself.

Identifiers: application = ``ApplicationName`` (Terraform's id); environment
= ``EnvironmentName``, while Terraform's id is the environment id (``e-…``),
so the adapter binds on ``name``. Environments take 5-10 minutes to create
and about as long to terminate.
"""

from .base import CapabilityAdapter


class ElasticBeanstalkApplicationAdapter(CapabilityAdapter):
    terraform_type = "aws_elastic_beanstalk_application"
    cloudcontrol_type = "AWS::ElasticBeanstalk::Application"
    semantic_properties = ("ApplicationName", "Description", "ResourceLifecycleConfig")
    volatile_fields = ()
    readiness_properties = ("ApplicationName",)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        description = "cloudgym-smoke mutation-visible"
        session.client("elasticbeanstalk").update_application(
            ApplicationName=identifier, Description=description)
        return {"Description": description}


class ElasticBeanstalkEnvironmentAdapter(CapabilityAdapter):
    terraform_type = "aws_elastic_beanstalk_environment"
    cloudcontrol_type = "AWS::ElasticBeanstalk::Environment"
    semantic_properties = (
        "ApplicationName",   # rewritten to a logical address during normalization
        "CNAMEPrefix",
        "Description",
        "EnvironmentName",
        "OperationsRole",
        "OptionSettings",
        "PlatformArn",
        "SolutionStackName",
        "Tags",
        "TemplateName",
        "Tier",
        "VersionLabel",
    )
    volatile_fields = ("EndpointURL", "EnvironmentId")
    readiness_properties = ("EnvironmentName", "ApplicationName", "EndpointURL")

    def identifier_from_state(self, attributes: dict) -> str:
        name = attributes.get("name")
        if not name or not isinstance(name, str):
            raise ValueError(f"{self.terraform_type}: state instance has no 'name'")
        return name

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        description = "cloudgym-smoke mutation-visible"
        session.client("elasticbeanstalk").update_environment(
            EnvironmentName=identifier, Description=description)
        return {"Description": description}
