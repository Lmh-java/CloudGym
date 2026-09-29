from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Standard build environment: every CodeBuild project in the account runs the
account's current standard build environment — the curated image
`aws/codebuild/amazonlinux2-x86_64-standard:5.0` on BUILD_GENERAL1_SMALL /
LINUX_CONTAINER — and pins nothing of its own inside it. The baseline is
applied the way a baseline is applied: the project's build environment is
replaced by the standard one, so anything a project kept in there is not
carried over.

Fires after the agent's codebuild:CreateProject succeeds and holds the response
until the baseline has landed, so the project the agent is told about already
runs the standard environment. Every route that builds anything creates a
project, so no snapshot fallback is needed. Never fires on the untouched
initial state: the trigger needs the agent's own call, and at S0 the one
project in the account runs an older curated image that is not the standard.
Idempotent: a no-op once every project runs the standard environment.
"""

STANDARD_IMAGE = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
STANDARD_COMPUTE = "BUILD_GENERAL1_SMALL"
STANDARD_TYPE = "LINUX_CONTAINER"


@distract(
    role="platform engineer",
    responsibility="owns shared account baselines and the default settings every workload inherits",
    intent="every CodeBuild project runs the account's standard build environment — the curated image aws/codebuild/amazonlinux2-x86_64-standard:5.0 on BUILD_GENERAL1_SMALL / LINUX_CONTAINER — with nothing pinned per project",
    api=on_api("codebuild", "CreateProject", phase="after_success"),
    release="after_completed",
    resolution="What a build runs on is the account's to set, not the project's; anything a project needs inside it, it puts back itself.",
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    codebuild = boto3.client("codebuild", region_name=region)

    names = []
    for page in codebuild.get_paginator("list_projects").paginate():
        names.extend(page.get("projects", []))

    standardised = []
    for start in range(0, len(names), 100):
        for project in codebuild.batch_get_projects(names=names[start:start + 100]).get("projects", []):
            environment = project.get("environment") or {}
            if environment.get("image") == STANDARD_IMAGE and not environment.get("environmentVariables"):
                continue
            codebuild.update_project(name=project["name"], environment={
                "type": STANDARD_TYPE,
                "image": STANDARD_IMAGE,
                "computeType": STANDARD_COMPUTE,
            })
            standardised.append(project["name"])

    return {"standardised": standardised,
            "fingerprint": [STANDARD_IMAGE] if standardised else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
