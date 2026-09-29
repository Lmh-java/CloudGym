"""Capability adapters for ``aws_lambda_event_source_mapping`` and ``aws_lambda_alias``.

Added 2026-09-23 (rows 152, 153; lambda already allowlisted).

- Event-source mapping: Cloud Control ``AWS::Lambda::EventSourceMapping``, identified by its
  UUID (Terraform's id). A mapping has its own state machine (Creating, Enabling, Enabled,
  Disabling, Disabled, Updating, Deleting) and refuses ``UpdateEventSourceMapping`` /
  ``DeleteEventSourceMapping`` with ``ResourceInUseException`` while it moves; Cloud Control's
  read omits that state, which the refusal catalogue reads natively.
- Alias: ``AWS::Lambda::Alias``, identified by its ARN (Terraform's id), listed per function.
"""

from .base import CapabilityAdapter


class LambdaEventSourceMappingAdapter(CapabilityAdapter):
    terraform_type = "aws_lambda_event_source_mapping"
    cloudcontrol_type = "AWS::Lambda::EventSourceMapping"
    semantic_properties = (
        "BatchSize",
        "BisectBatchOnFunctionError",
        "DestinationConfig",
        "Enabled",
        "EventSourceArn",
        "FilterCriteria",
        "FunctionName",
        "FunctionResponseTypes",
        "MaximumBatchingWindowInSeconds",
        "MaximumRecordAgeInSeconds",
        "MaximumRetryAttempts",
        "ParallelizationFactor",
        "ScalingConfig",
        "StartingPosition",
        "Tags",
        "TumblingWindowInSeconds",
    )
    volatile_fields = ("Id", "EventSourceMappingArn")
    readiness_properties = ("Id", "FunctionName", "EventSourceArn")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        import time

        lam = session.client("lambda")
        for _ in range(30):                     # the mapping refuses updates while Creating
            state = lam.get_event_source_mapping(UUID=identifier).get("State")
            if state in ("Enabled", "Disabled"):
                break
            time.sleep(5)
        lam.update_event_source_mapping(UUID=identifier, BatchSize=7)
        return {"BatchSize": 7}


class LambdaAliasAdapter(CapabilityAdapter):
    terraform_type = "aws_lambda_alias"
    cloudcontrol_type = "AWS::Lambda::Alias"
    list_parent = "AWS::Lambda::Function"
    semantic_properties = ("Description", "FunctionName", "FunctionVersion", "Name",
                           "ProvisionedConcurrencyConfig", "RoutingConfig")
    volatile_fields = ("AliasArn",)
    readiness_properties = ("AliasArn", "Name", "FunctionVersion")

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"FunctionName": parent_properties["FunctionName"]}

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        # arn:aws:lambda:<region>:<account>:function:<name>:<alias>
        parts = identifier.split(":")
        session.client("lambda").update_alias(FunctionName=parts[6], Name=parts[7],
                                              Description="cloudgym-smoke mutation-visible")
        return {"Description": "cloudgym-smoke mutation-visible"}
