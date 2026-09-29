"""Capability adapters for API Gateway REST APIs: API, resource, method (with the
integration as a projection), deployment, stage.

Added 2026-09-22 (4 IaC-Eval rows). Needs ``apigateway:*`` in the sandbox SCP
(``infra/aws/sandbox-scp.json``); APIs, resources, methods and stages without traffic
cost nothing. Cloud Control lists resources, deployments and stages per API; methods have no LIST
handler at all and are discovered natively from ``GetResources`` (which reports each
resource's methods), then read through GetResource. Identifiers
are the pipe-joined forms the handlers use; Terraform's ids differ for every type but
the API, so each adapter builds the identifier from state attributes.

``aws_api_gateway_integration`` has no type of its own: the integration is the
``Integration`` property of the method document.
"""

from .base import CapabilityAdapter


def _patch(session, **kwargs) -> None:
    session.client("apigateway").update_rest_api(**kwargs)


class RestApiAdapter(CapabilityAdapter):
    terraform_type = "aws_api_gateway_rest_api"
    cloudcontrol_type = "AWS::ApiGateway::RestApi"
    semantic_properties = (
        "ApiKeySourceType",
        "BinaryMediaTypes",
        "Description",
        "DisableExecuteApiEndpoint",
        "EndpointConfiguration",
        "MinimumCompressionSize",
        "Name",
        "Policy",
        "Tags",
    )
    volatile_fields = ("RestApiId", "RootResourceId")
    readiness_properties = ("RestApiId", "Name", "RootResourceId")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        description = "cloudgym-smoke mutation-visible"
        session.client("apigateway").update_rest_api(
            restApiId=identifier, patchOperations=[{"op": "replace", "path": "/description", "value": description}])
        return {"Description": description}


class ApiResourceAdapter(CapabilityAdapter):
    terraform_type = "aws_api_gateway_resource"
    cloudcontrol_type = "AWS::ApiGateway::Resource"
    list_parent = "AWS::ApiGateway::RestApi"
    semantic_properties = (
        "ParentId",    # rewritten to a logical address during normalization
        "PathPart",
        "RestApiId",   # rewritten to a logical address during normalization
    )
    volatile_fields = ("ResourceId",)
    readiness_properties = ("ResourceId", "RestApiId")

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"RestApiId": parent_properties["RestApiId"]}

    def identifier_from_state(self, attributes: dict) -> str:
        api, rid = attributes.get("rest_api_id"), attributes.get("id")
        if not api or not rid:
            raise ValueError(f"{self.terraform_type}: state instance lacks rest_api_id / id")
        return f"{api}|{rid}"

    def get_error_means_absent(self, identifier: str, error: Exception) -> bool:
        return "NotFoundException" in str(error) or "Invalid API identifier" in str(error)


class ApiMethodAdapter(CapabilityAdapter):
    terraform_type = "aws_api_gateway_method"
    cloudcontrol_type = "AWS::ApiGateway::Method"
    list_parent = "AWS::ApiGateway::Resource"
    semantic_properties = (
        "ApiKeyRequired",
        "AuthorizationScopes",
        "AuthorizationType",
        "AuthorizerId",
        "HttpMethod",
        "Integration",
        "MethodResponses",
        "OperationName",
        "RequestModels",
        "RequestParameters",
        "RequestValidatorId",
        "ResourceId",   # rewritten to a logical address during normalization
        "RestApiId",    # rewritten to a logical address during normalization
    )
    volatile_fields = ()
    readiness_properties = ("HttpMethod", "ResourceId", "RestApiId")

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"RestApiId": parent_properties["RestApiId"], "ResourceId": parent_properties["ResourceId"]}

    def native_list(self, session, region: str) -> list[str]:
        # AWS::ApiGateway::Method has no Cloud Control LIST handler (UnsupportedActionException,
        # smoke 2026-09-22). GetResources returns each resource's methods, so discovery walks
        # every API's resources natively; envelopes still come from GetResource.
        apigw = session.client("apigateway", region_name=region)
        identifiers: list[str] = []
        for apis in apigw.get_paginator("get_rest_apis").paginate():
            for api in apis.get("items", []):
                for page in apigw.get_paginator("get_resources").paginate(restApiId=api["id"]):
                    for resource in page.get("items", []):
                        for method in sorted(resource.get("resourceMethods") or {}):
                            identifiers.append(f"{api['id']}|{resource['id']}|{method}")
        return identifiers

    def identifier_from_state(self, attributes: dict) -> str:
        parts = (attributes.get("rest_api_id"), attributes.get("resource_id"), attributes.get("http_method"))
        if not all(parts):
            raise ValueError(f"{self.terraform_type}: state instance lacks rest_api_id / resource_id / http_method")
        return "|".join(parts)

    def get_error_means_absent(self, identifier: str, error: Exception) -> bool:
        return "NotFoundException" in str(error) or "Invalid API identifier" in str(error)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        api, resource, method = identifier.split("|")
        session.client("apigateway").update_method(
            restApiId=api, resourceId=resource, httpMethod=method,
            patchOperations=[{"op": "replace", "path": "/apiKeyRequired", "value": "true"}])
        return {"ApiKeyRequired": True}


class ApiIntegrationAdapter(ApiMethodAdapter):
    """``aws_api_gateway_integration``: the method document's ``Integration``."""

    terraform_type = "aws_api_gateway_integration"
    standalone = False
    semantic_properties = ("Integration",)


class ApiDeploymentAdapter(CapabilityAdapter):
    terraform_type = "aws_api_gateway_deployment"
    cloudcontrol_type = "AWS::ApiGateway::Deployment"
    list_parent = "AWS::ApiGateway::RestApi"
    semantic_properties = (
        "Description",
        "RestApiId",   # rewritten to a logical address during normalization
    )
    volatile_fields = ("DeploymentId",)
    readiness_properties = ("DeploymentId", "RestApiId")

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"RestApiId": parent_properties["RestApiId"]}

    def identifier_from_state(self, attributes: dict) -> str:
        api, did = attributes.get("rest_api_id"), attributes.get("id")
        if not api or not did:
            raise ValueError(f"{self.terraform_type}: state instance lacks rest_api_id / id")
        return f"{did}|{api}"

    def get_error_means_absent(self, identifier: str, error: Exception) -> bool:
        return "NotFoundException" in str(error) or "Invalid API identifier" in str(error)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        did, _, api = identifier.partition("|")
        description = "cloudgym-smoke mutation-visible"
        session.client("apigateway").update_deployment(
            restApiId=api, deploymentId=did,
            patchOperations=[{"op": "replace", "path": "/description", "value": description}])
        return {"Description": description}


class ApiStageAdapter(CapabilityAdapter):
    terraform_type = "aws_api_gateway_stage"
    cloudcontrol_type = "AWS::ApiGateway::Stage"
    list_parent = "AWS::ApiGateway::RestApi"
    semantic_properties = (
        "AccessLogSetting",
        "CacheClusterEnabled",
        "CacheClusterSize",
        "CanarySettings",
        "ClientCertificateId",
        "DeploymentId",   # rewritten to a logical address during normalization
        "Description",
        "DocumentationVersion",
        "MethodSettings",
        "RestApiId",      # rewritten to a logical address during normalization
        "StageName",
        "Tags",
        "TracingEnabled",
        "Variables",
    )
    volatile_fields = ()
    readiness_properties = ("StageName", "RestApiId", "DeploymentId")

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"RestApiId": parent_properties["RestApiId"]}

    def identifier_from_state(self, attributes: dict) -> str:
        api, stage = attributes.get("rest_api_id"), attributes.get("stage_name")
        if not api or not stage:
            raise ValueError(f"{self.terraform_type}: state instance lacks rest_api_id / stage_name")
        return f"{api}|{stage}"

    def get_error_means_absent(self, identifier: str, error: Exception) -> bool:
        return "NotFoundException" in str(error) or "Invalid API identifier" in str(error)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        api, _, stage = identifier.partition("|")
        region = session.region_name
        arn = f"arn:aws:apigateway:{region}::/restapis/{api}/stages/{stage}"
        session.client("apigateway").tag_resource(resourceArn=arn, tags={"cloudgym-smoke": "mutation-visible"})
        tags = dict(properties.get("Tags") or {}) if isinstance(properties.get("Tags"), dict) else None
        if tags is not None:
            tags["cloudgym-smoke"] = "mutation-visible"
            return {"Tags": tags}
        existing = [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"]
        return {"Tags": existing + [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]}
