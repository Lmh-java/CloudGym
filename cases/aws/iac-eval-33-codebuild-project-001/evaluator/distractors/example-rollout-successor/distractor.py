from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The rolled-out example build project takes over as the account's example.

Release automation rolls the account's example build project forward:
``platform-example-build-2026`` — building the platform's build template
``https://github.com/acme-platform/build-template.git`` — is from now on the example the
account designates (marked as the example and as the one in service), and the example it
replaces is marked as retired and names its successor. Every other marking the replaced
example carries is kept and the project itself stays as it stands, so what it was is still
readable.

Trigger: the agent's ``codebuild:CreateProject`` — a new build being stood up off the example
is where the roll-forward lands, so from then on the account's designation is what says which
example counts. The snapshot fallback is a build that is nobody's example and nobody else's
workload already building what the designated example builds, with no successor example yet.
Neither can match the untouched initial state: at S0 the account holds one example, no build
of anyone else's, and the agent has made no call. Idempotent: a no-op once the successor is
the designated example and every example it replaced names it.
"""

EXAMPLE_KEY = "Example"
EXAMPLE_VALUE = "build-project"
STATUS_KEY = "Status"
CURRENT = "current"
RETIRED = "retired"
SUPERSEDED_BY = "SupersededBy"
SUCCESSOR = "platform-example-build-2026"
SUCCESSOR_SOURCE = "https://github.com/acme-platform/build-template.git"
COPY_NAME = "platform-example-build-copy"


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


def _build_in_line_with_the_example(snapshot) -> bool:
    """A build of someone's own already builds what the designated example builds."""
    for project in _projects(snapshot):
        if project.get("name") == SUCCESSOR:
            return False
    example = _designated(snapshot)
    if not isinstance(example, dict):
        return False
    location = (example.get("source") or {}).get("location")
    if not location:
        return False
    for project in _projects(snapshot):
        if _tags(project).get(EXAMPLE_KEY) or project.get("name") == COPY_NAME:
            continue
        if (project.get("source") or {}).get("location") == location:
            return True
    return False


@distract(
    role="release engineer",
    responsibility="owns deployment automation and what gets rolled out, renamed or replaced during a release",
    intent=("the example the account designates is the rolled-out platform-example-build-2026, building "
            "https://github.com/acme-platform/build-template.git, and every example it replaces is "
            "marked retired, names its successor and is otherwise kept as it stands"),
    api=on_api("codebuild", "CreateProject", phase="after_success"),
    release="after_completed",
    predicate=_build_in_line_with_the_example,
    resolution=("Only the example I currently designate is the one to copy from; the one it replaced "
                "stays as it stands."),
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

    examples = [p for p in projects if _tags(p).get(EXAMPLE_KEY) == EXAMPLE_VALUE]
    successor = next((p for p in projects if p.get("name") == SUCCESSOR), None)
    if successor is None and not examples:
        return {"rolled_out": False, "note": "no example to roll forward", "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    successor_tags = [{"key": EXAMPLE_KEY, "value": EXAMPLE_VALUE},
                      {"key": STATUS_KEY, "value": CURRENT},
                      {"key": "Owner", "value": "platform"}]
    created = False
    if successor is None:
        template = examples[0]
        environment = template.get("environment") or {}
        codebuild.create_project(
            name=SUCCESSOR,
            description="the account's example build project",
            serviceRole=template.get("serviceRole"),
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": environment.get("type") or "LINUX_CONTAINER",
                "image": environment.get("image") or "aws/codebuild/standard:7.0",
                "computeType": environment.get("computeType") or "BUILD_GENERAL1_SMALL",
            },
            source={"type": "GITHUB", "location": SUCCESSOR_SOURCE, "gitCloneDepth": 1},
            tags=successor_tags,
        )
        created = True

    retired = []
    for project in examples:
        name = project.get("name")
        if name == SUCCESSOR:
            continue
        tags = _tags(project)
        if tags.get(STATUS_KEY) == RETIRED and tags.get(SUPERSEDED_BY) == SUCCESSOR:
            continue
        tags[STATUS_KEY] = RETIRED
        tags[SUPERSEDED_BY] = SUCCESSOR
        codebuild.update_project(name=name, tags=[{"key": k, "value": v}
                                                  for k, v in sorted(tags.items())])
        retired.append(name)

    # The successor's name is the fact that exists only because this program ran: it comes back
    # with every codebuild:ListProjects, and off the retired example's markings as well.
    changed = created or bool(retired)
    return {"successor": SUCCESSOR, "created": created, "retired": retired,
            "fingerprint": [SUCCESSOR] if changed else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
