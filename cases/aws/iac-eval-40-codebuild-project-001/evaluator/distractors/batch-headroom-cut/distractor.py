from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Shared build-capacity headroom: how many builds a batch may run at once is set for the
account, not per build. Every build the account runs on its shared build capacity (marked
`Capacity=account-pool` and not taken out of service) is held to the headroom the account
currently allows a batch, and carries the mark of the allocation it is held under
(`Headroom=headroom-2026.10`) beside whatever else it is tagged with. Builds holding a
reserved slice of their own, and builds taken out of service, are not the account's to
hold and are left alone; the program never touches a project's source, identity, artifacts
or anyone's data.

Fires in front of the agent's codebuild:CreateProject and holds the call until the
headroom has been applied, so a figure the agent read earlier is already stale as its
project is born and can only be reached by reading the account's builds again. The
snapshot fallback is a build that is none of the ones this account is known to keep — the
agent's own project — already carrying a batch configuration, while a shared-capacity
build in service still runs batches above the headroom or is unmarked; it is keyed to that
build rather than to the agent's identity so that the cut cannot land on the poll that
merely follows another principal's write. Never fires on the untouched initial state: S0
holds one project, `billing-api-build`, which the fallback skips, and the API trigger
needs the agent's own call. Idempotent: a no-op once every shared-capacity build in
service is held to the headroom and carries the mark.
"""

ALLOWANCE = 2
MARK_KEY = "Headroom"
MARK = "headroom-2026.10"
CAPACITY_KEY = "Capacity"
POOL = "account-pool"
STATUS_KEY = "Status"
RETIRED = "retired"
# The builds this account is known to keep; anything else is a build the agent stood up.
KNOWN_BUILDS = ("billing-api-build", "billing-api-build-ng", "orders-admin-build")
BATCH_KEYS = ("serviceRole", "combineArtifacts", "restrictions", "timeoutInMins", "batchReportMode")


def _snapshot_projects(snapshot):
    projects = ((snapshot or {}).get("resources") or {}).get("AWS::CodeBuild::Project") or {}
    if not isinstance(projects, dict):
        return {}
    return {str(props.get("name") or name): props
            for name, props in projects.items() if isinstance(props, dict)}


def _agent_build_configured(projects) -> bool:
    """A build the account does not keep itself already carries a batch configuration."""
    return any(name not in KNOWN_BUILDS and isinstance(props.get("buildBatchConfig"), dict)
               for name, props in projects.items())


def _tag_map(tags):
    return {t.get("key"): t.get("value") for t in tags or [] if isinstance(t, dict)}


def _on_shared_capacity(tags: dict) -> bool:
    return tags.get(CAPACITY_KEY) == POOL and tags.get(STATUS_KEY) != RETIRED


def _allowed(project) -> int | None:
    restrictions = (project.get("buildBatchConfig") or {}).get("restrictions") or {}
    value = restrictions.get("maximumBuildsAllowed")
    return value if isinstance(value, int) else None


def _above_headroom(snapshot) -> bool:
    """A build is being stood up here while a shared-capacity build is above the headroom."""
    projects = _snapshot_projects(snapshot)
    if not _agent_build_configured(projects):
        return False
    for props in projects.values():
        tags = _tag_map(props.get("tags"))
        if not _on_shared_capacity(tags):
            continue
        allowed = _allowed(props)
        if allowed is None or allowed > ALLOWANCE or tags.get(MARK_KEY) != MARK:
            return True
    return False


@distract(
    role="site reliability engineer",
    responsibility="owns capacity headroom and the limits workloads must respect",
    intent=("every build the account runs on its shared build capacity is held to the headroom the "
            "account currently allows a batch and carries the mark of the allocation it is held "
            "under, Headroom=headroom-2026.10"),
    api=on_api("codebuild", "CreateProject", phase="before"),
    release="after_completed",
    predicate=_above_headroom,
    resolution=("What a batch may run at once is set for the account, not per build, and it is what "
                "the builds on its shared capacity are held to when you finish; leave what is set "
                "on them alone."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    codebuild = boto3.client("codebuild", region_name=region)

    names: list[str] = []
    for page in codebuild.get_paginator("list_projects").paginate():
        names.extend(page.get("projects", []))
    projects = []
    for start in range(0, len(names), 100):
        projects.extend(codebuild.batch_get_projects(names=names[start:start + 100]).get("projects", []))

    held = []
    for project in sorted(projects, key=lambda p: p.get("name", "")):
        tags = _tag_map(project.get("tags"))
        if not _on_shared_capacity(tags):
            continue
        if _allowed(project) == ALLOWANCE and tags.get(MARK_KEY) == MARK:
            continue
        batch = {k: v for k, v in (project.get("buildBatchConfig") or {}).items() if k in BATCH_KEYS}
        if not batch.get("serviceRole"):
            batch["serviceRole"] = project.get("serviceRole")
        restrictions = dict(batch.get("restrictions") or {})
        restrictions["maximumBuildsAllowed"] = ALLOWANCE
        batch["restrictions"] = restrictions
        tags[MARK_KEY] = MARK
        codebuild.update_project(
            name=project["name"],
            buildBatchConfig=batch,
            tags=[{"key": k, "value": v} for k, v in sorted(tags.items())])
        held.append(project["name"])

    # The allocation mark is the fact that is in the account only because this program ran: it
    # comes back with every codebuild:BatchGetProjects the agent makes after the cut landed.
    return {"held": held, "allowance": ALLOWANCE, "mark": MARK,
            "fingerprint": [MARK] if held else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
