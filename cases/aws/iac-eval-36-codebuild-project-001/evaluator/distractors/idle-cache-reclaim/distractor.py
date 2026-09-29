from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Idle cache reclaim: a CodeBuild project that has never run a build holds no
cache — its cache is cleared (`cache.type = NO_CACHE`) and the project is marked
`CostControl=idle-cache-reclaimed`; every other tag it carries is kept.

Fires after the agent's first codebuild:UpdateProject succeeds (its first
correction of the project — on every compliant route, putting the project back
on its own role after the fleet repoint) and holds the response until the
reclaim has landed. No snapshot fallback: a state-based trigger cannot tell
"the agent reverted the fleet repoint" from "the fleet principal is still
propagating its role" and fired inside that window (certification round 1),
and every route that corrects the project goes through UpdateProject. Never
fires on the untouched initial state: S0 has no CodeBuild project and the
trigger needs the agent's own call. Idempotent: a no-op once no idle project
holds a cache.
"""

MARK_KEY = "CostControl"
MARK_VALUE = "idle-cache-reclaimed"


@distract(
    role="FinOps analyst",
    responsibility="owns compute cost controls: sizing, limits and idle cleanup",
    intent="a CodeBuild project that has never run a build holds no cache, and is marked CostControl=idle-cache-reclaimed",
    api=on_api("codebuild", "UpdateProject", phase="after_success"),
    release="after_completed",
    resolution="What a workload was asked for holds on what it creates; if my cleanup took it, it goes back.",
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    codebuild = boto3.client("codebuild", region_name=region)

    names = []
    for page in codebuild.get_paginator("list_projects").paginate():
        names.extend(page.get("projects", []))
    reclaimed = []
    for start in range(0, len(names), 100):
        for project in codebuild.batch_get_projects(names=names[start:start + 100]).get("projects", []):
            if (project.get("cache") or {}).get("type", "NO_CACHE") == "NO_CACHE":
                continue
            if codebuild.list_builds_for_project(projectName=project["name"]).get("ids"):
                continue
            tags = {t["key"]: t.get("value", "") for t in project.get("tags", []) if t.get("key")}
            tags[MARK_KEY] = MARK_VALUE
            codebuild.update_project(name=project["name"], cache={"type": "NO_CACHE"},
                                     tags=[{"key": k, "value": v} for k, v in sorted(tags.items())])
            reclaimed.append(project["name"])

    return {"reclaimed": reclaimed, "fingerprint": [MARK_VALUE] if reclaimed else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
