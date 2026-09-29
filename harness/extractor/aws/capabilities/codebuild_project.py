"""Capability adapter for ``aws_codebuild_project``.

AWS::CodeBuild::Project has NO Cloud Control support at all — both LIST and
READ return UnsupportedActionException (verified live 2026-09-01). Capture
therefore goes through ``native_describe``/``native_read``: envelopes carry
the verbatim ``codebuild:BatchGetProjects`` response, so semantic properties
use the service API's camelCase names. Projects are free — only builds are
billed, and codebuild:StartBuild* is denied by the SCP guardrails.
"""

from datetime import datetime

from .base import CapabilityAdapter


def _jsonable(value):
    """boto3 parses timestamps into datetime objects; envelopes must be JSON."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


class CodeBuildProjectAdapter(CapabilityAdapter):
    terraform_type = "aws_codebuild_project"
    cloudcontrol_type = "AWS::CodeBuild::Project"
    semantic_properties = (
        "artifacts",
        "cache",
        "concurrentBuildLimit",
        "description",
        "encryptionKey",
        "environment",
        "logsConfig",
        "name",
        "queuedTimeoutInMinutes",
        "secondaryArtifacts",
        "secondarySources",
        "serviceRole",
        "source",
        "sourceVersion",
        "tags",
        "timeoutInMinutes",
        "vpcConfig",
    )
    volatile_fields = ("arn", "created", "lastModified", "badge", "webhook")
    readiness_properties = ("name", "serviceRole", "arn")

    def _client(self, session, region: str):
        return session.client("codebuild", region_name=region)

    def native_describe(self, session, region: str) -> list[tuple[str, dict]]:
        codebuild = self._client(session, region)
        names: list[str] = []
        for page in codebuild.get_paginator("list_projects").paginate():
            names.extend(page.get("projects", []))
        out: list[tuple[str, dict]] = []
        for start in range(0, len(names), 100):  # BatchGetProjects caps at 100
            got = codebuild.batch_get_projects(names=names[start:start + 100])
            out.extend((p["name"], _jsonable(p)) for p in got.get("projects", []))
        return out

    def native_read(self, session, region: str, identifier: str) -> dict | None:
        got = self._client(session, region).batch_get_projects(names=[identifier])
        projects = got.get("projects", [])
        return _jsonable(projects[0]) if projects else None

    def identifier_from_state(self, attributes: dict) -> str:
        # Terraform's aws_codebuild_project id is the ARN; the capture identifier
        # is the project name.
        name = attributes.get("name")
        if not name:
            raise ValueError(f"{self.terraform_type}: state instance has no 'name'")
        return name

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        description = "cloudgym-smoke mutation-visible"
        session.client("codebuild").update_project(name=identifier, description=description)
        return {"description": description}
