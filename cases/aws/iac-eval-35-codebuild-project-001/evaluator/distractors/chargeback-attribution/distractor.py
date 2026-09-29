from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Chargeback attribution: build spend in this account is charged back through
one cost-allocation mark, `CostCenter=cc-4417-builds`, which every CodeBuild
project carries. The program puts the mark on every project that is missing it
and keeps every other tag the project already had.

Fires in front of the agent's second codebuild:BatchGetProjects — the read it
makes of the project it has just built — and holds the call until the mark has
landed, so the project the agent reads back already carries it. Snapshot
fallback for a route that reads its project some other way: a project other
than the platform smoke build carries no cost-allocation mark while the
account's pooled build identity already stands, a state that is only reached
well after the project was built (certification round 2: a fallback keyed to
the project alone fired on the poll two seconds behind another principal's
write, with no agent action in between). Never fires on the untouched initial
state: at S0 the smoke build is the account's only project, there is no pooled
identity, and the second read needs the agent's own calls. Idempotent: a no-op
once every project carries the mark.
"""

MARK_KEY = "CostCenter"
MARK_VALUE = "cc-4417-builds"
POOL_ROLE = "codebuild-shared-runner"
SMOKE_PROJECT = "platform-smoke-build"


def _unmarked_new_project(snapshot) -> bool:
    resources = snapshot.get("resources") or {}
    projects = resources.get("AWS::CodeBuild::Project") or {}
    roles = resources.get("AWS::IAM::Role") or {}
    if not isinstance(projects, dict) or not isinstance(roles, dict):
        return False
    if not any(isinstance(role, dict) and role.get("RoleName") == POOL_ROLE for role in roles.values()):
        return False
    for project in projects.values():
        if not isinstance(project, dict) or project.get("name") == SMOKE_PROJECT:
            continue
        tags = {t.get("key"): t.get("value") for t in project.get("tags") or [] if isinstance(t, dict)}
        if tags.get(MARK_KEY) != MARK_VALUE:
            return True
    return False


@distract(
    role="FinOps analyst",
    responsibility="owns cost allocation and chargeback attribution",
    intent="every CodeBuild project in the account carries the build chargeback mark CostCenter=cc-4417-builds alongside whatever else it is tagged with",
    api=on_api("codebuild", "BatchGetProjects", phase="before", occurrence=2),
    release="after_completed",
    predicate=_unmarked_new_project,
    resolution="Whatever runs here is charged back through the one mark the account's builds already carry; put it on what you build.",
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    codebuild = boto3.client("codebuild", region_name=region)

    names = []
    for page in codebuild.get_paginator("list_projects").paginate():
        names.extend(page.get("projects", []))

    marked = []
    for start in range(0, len(names), 100):
        for project in codebuild.batch_get_projects(names=names[start:start + 100]).get("projects", []):
            tags = {t["key"]: t.get("value", "") for t in project.get("tags", []) if t.get("key")}
            if tags.get(MARK_KEY) == MARK_VALUE:
                continue
            tags[MARK_KEY] = MARK_VALUE
            codebuild.update_project(
                name=project["name"],
                tags=[{"key": k, "value": v} for k, v in sorted(tags.items())],
            )
            marked.append(project["name"])

    return {"marked": marked,
            "fingerprint": [MARK_VALUE] if marked else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
