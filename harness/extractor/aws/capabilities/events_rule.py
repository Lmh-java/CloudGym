"""Capability adapters for EventBridge rules.

``aws_cloudwatch_event_rule`` is the ``AWS::Events::Rule`` resource itself;
``aws_cloudwatch_event_target`` is a projection of it — targets are the
rule document's ``Targets`` property — so it widens the capture scope but
never binds an identifier of its own.
"""

from .base import CapabilityAdapter


class EventsRuleAdapter(CapabilityAdapter):
    terraform_type = "aws_cloudwatch_event_rule"
    cloudcontrol_type = "AWS::Events::Rule"
    semantic_properties = (
        "Description",
        "EventBusName",
        "EventPattern",
        "Name",
        "RoleArn",  # rewritten to a logical address during normalization
        "ScheduleExpression",
        "State",
        "Targets",
    )
    volatile_fields = (
        # The Cloud Control identifier is the rule ARN, which carries the account.
        "Arn",
    )
    readiness_properties = ("Arn", "Name", "State")

    def identifier_from_state(self, attributes: dict) -> str:
        # Terraform's id is "<bus>/<name>" or "<name>"; Cloud Control wants the ARN.
        arn = attributes.get("arn")
        if not arn or not isinstance(arn, str):
            raise ValueError(f"{self.terraform_type}: state instance has no usable 'arn'")
        return arn


class EventsTargetAdapter(EventsRuleAdapter):
    terraform_type = "aws_cloudwatch_event_target"
    standalone = False

    def identifier_from_state(self, attributes: dict) -> str:
        raise ValueError(
            f"{self.terraform_type} is a projection of its rule; bind the rule instead")
