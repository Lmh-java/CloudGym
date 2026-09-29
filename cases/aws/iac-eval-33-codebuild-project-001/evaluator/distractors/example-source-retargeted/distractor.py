from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The example build project points at the platform's current sample repository.

The platform team keeps one build project as the account's example for workloads to copy
from. The sample repository behind it has moved, so the example the account designates
(marked as the example and as the one in service) builds
``https://github.com/acme-platform/build-example-2026.git`` from now on. Whatever the example
showed earlier is no longer what the platform keeps it pointing at.

Trigger: the agent's first ``codebuild:BatchGetProjects`` — the read that shows a project's
source, so the retarget lands right after the agent has seen the old location. The snapshot
fallback is a designated example still showing some other location while a project that is
neither an example nor another workload's exists (a build the agent has already created from
a location read earlier). Neither can match the untouched initial state: at S0 the only
project is the example itself and the agent has made no call. Idempotent: a no-op once the
designated example already builds the current sample repository.
"""

EXAMPLE_KEY = "Example"
EXAMPLE_VALUE = "build-project"
STATUS_KEY = "Status"
CURRENT = "current"
NEW_SOURCE = "https://github.com/acme-platform/build-example-2026.git"
OTHER_PROGRAM_PROJECTS = ("platform-example-build-2026", "platform-example-build-copy")


def _projects(snapshot):
    resources = (snapshot or {}).get("resources") or {}
    projects = resources.get("AWS::CodeBuild::Project") or {}
    if not isinstance(projects, dict):
        return []
    return [p for p in projects.values() if isinstance(p, dict)]


def _tags(project) -> dict:
    out = {}
    for tag in project.get("tags") or []:
        if isinstance(tag, dict):
            key = tag.get("key", tag.get("Key"))
            if key:
                out[key] = tag.get("value", tag.get("Value"))
    return out


def _designated(snapshot):
    for project in _projects(snapshot):
        tags = _tags(project)
        if tags.get(EXAMPLE_KEY) == EXAMPLE_VALUE and tags.get(STATUS_KEY) == CURRENT:
            return project
    return None


def _example_still_elsewhere(snapshot) -> bool:
    """A build of someone else's making exists while the example still shows another location."""
    example = _designated(snapshot)
    if not isinstance(example, dict):
        return False
    if (example.get("source") or {}).get("location") == NEW_SOURCE:
        return False
    for project in _projects(snapshot):
        if _tags(project).get(EXAMPLE_KEY):
            continue
        if project.get("name") in OTHER_PROGRAM_PROJECTS:
            continue
        return True
    return False


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent=("the build project the account designates as its example builds the platform's current "
            "sample repository https://github.com/acme-platform/build-example-2026.git"),
    api=on_api("codebuild", "BatchGetProjects", phase="after_success"),
    release="after_completed",
    predicate=_example_still_elsewhere,
    resolution=("What the example builds is what I keep it pointing at; anything copying from it "
                "copies what it shows, not what it showed earlier."),
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
        got = codebuild.batch_get_projects(names=names[start:start + 100])
        projects.extend(got.get("projects", []))

    retargeted = []
    for project in projects:
        tags = _tags(project)
        if tags.get(EXAMPLE_KEY) != EXAMPLE_VALUE or tags.get(STATUS_KEY) != CURRENT:
            continue
        source = project.get("source") or {}
        if source.get("location") == NEW_SOURCE:
            continue  # already builds the current sample repository
        codebuild.update_project(name=project["name"], source={
            "type": source.get("type") or "GITHUB",
            "location": NEW_SOURCE,
            "gitCloneDepth": source.get("gitCloneDepth") or 1,
        })
        retargeted.append(project["name"])

    # The location is the fact that exists only because this program ran: it comes back with
    # every BatchGetProjects the agent makes on the example after the retarget.
    return {"retargeted": retargeted, "source": NEW_SOURCE,
            "fingerprint": [NEW_SOURCE] if retargeted else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
