"""Capability adapter for ``aws_lambda_permission``.

``AWS::Lambda::Permission`` cannot be listed region-wide: its Cloud Control
``list`` handler requires the owning ``FunctionName`` as ResourceModel, so
capture enumerates permissions per captured ``AWS::Lambda::Function``.
"""

from .base import CapabilityAdapter


class LambdaPermissionAdapter(CapabilityAdapter):
    terraform_type = "aws_lambda_permission"
    cloudcontrol_type = "AWS::Lambda::Permission"
    list_parent = "AWS::Lambda::Function"
    semantic_properties = (
        "Action",
        "EventSourceToken",
        "FunctionName",  # rewritten to a logical address during normalization
        "FunctionUrlAuthType",
        "Id",
        "Principal",
        "PrincipalOrgID",
        "SourceAccount",
        "SourceArn",
    )
    volatile_fields = ()
    readiness_properties = ("Id", "FunctionName", "Action", "Principal")

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"FunctionName": parent_properties["FunctionName"]}

    def capture_identifier_matches(self, state_identifier: str, captured_identifier: str) -> bool:
        # Listing emits "<function ARN>|<sid>"; state yields "<function name>|<sid>".
        # GetResource accepts both forms (verified live, capability smoke 2026-09-01).
        state_fn, _, state_sid = state_identifier.partition("|")
        captured_fn, _, captured_sid = captured_identifier.partition("|")
        if state_sid != captured_sid or not state_sid:
            return False
        return captured_fn == state_fn or captured_fn.endswith(f":function:{state_fn}")

    def identifier_from_state(self, attributes: dict) -> str:
        # GetResource accepts "<FunctionName>|<StatementId>"; listing returns the ARN form
        # (see capture_identifier_matches).
        function_name = attributes.get("function_name")
        statement_id = attributes.get("statement_id")
        if not function_name or not statement_id:
            raise ValueError(
                f"{self.terraform_type}: state instance needs function_name and statement_id")
        return f"{function_name}|{statement_id}"
