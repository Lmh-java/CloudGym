from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Shared-tooling revision pin: nothing in this account builds against the shared
build tooling's moving tip. Every CodeBuild project that pulls the shared tooling
as a secondary source pulls it at the revision the account pins for the quarter,
`tooling-2026.09.4`, and carries the pin mark `ToolingPin=tooling-2026.09.4`, so
the revision in force is readable off the builds already running here. Every other
tag a project carries is kept.

Fires in front of the agent's first codebuild:ListProjects and holds the call until
the pin has landed, so the builds the agent goes on to read are already pinned and
carry the mark. Snapshot fallback for a route that never lists projects: a CodeBuild
project other than the payments build exists while the payments build still pulls
the shared tooling without a revision. Never fires on the untouched initial state:
at S0 the payments build is the account's only project, so no project other than it
exists, and the API trigger needs the agent's own call. Idempotent: a no-op once
every project that pulls the tooling pulls it at the pinned revision and is marked.
"""

SEED_PROJECT = "payments-api-build"
TOOLING_STEM = "/build-tooling"
PIN = "tooling-2026.09.4"
MARK_KEY = "ToolingPin"
SOURCE_FIELDS = ("type", "location", "gitCloneDepth", "gitSubmodulesConfig", "buildspec",
                 "reportBuildStatus", "insecureSsl", "sourceIdentifier")


def _tooling_identifiers(project) -> list:
    out = []
    for source in project.get("secondarySources") or []:
        if not isinstance(source, dict):
            continue
        if TOOLING_STEM not in (source.get("location") or ""):
            continue
        identifier = source.get("sourceIdentifier")
        if identifier:
            out.append(identifier)
    return out


def _pinned(project) -> bool:
    identifiers = _tooling_identifiers(project)
    if not identifiers:
        return True  # nothing here pulls the shared tooling: nothing to pin
    versions = {}
    for entry in project.get("secondarySourceVersions") or []:
        if isinstance(entry, dict) and entry.get("sourceIdentifier"):
            versions[entry["sourceIdentifier"]] = entry.get("sourceVersion")
    return all(versions.get(identifier) == PIN for identifier in identifiers)


def _account_build_unpinned(snapshot) -> bool:
    projects = (snapshot.get("resources") or {}).get("AWS::CodeBuild::Project") or {}
    if not isinstance(projects, dict):
        return False
    built = any(isinstance(p, dict) and p.get("name") and p.get("name") != SEED_PROJECT
                for p in projects.values())
    if not built:
        return False
    for project in projects.values():
        if not isinstance(project, dict) or project.get("name") != SEED_PROJECT:
            continue
        if not _pinned(project):
            return True
    return False


@distract(
    role="platform engineer",
    responsibility="owns shared account baselines and the default settings every workload inherits",
    intent="every CodeBuild project that pulls the shared build tooling pulls it at the revision the account pins, tooling-2026.09.4, and carries the pin mark ToolingPin=tooling-2026.09.4; nothing tracks the tooling's moving tip",
    api=on_api("codebuild", "ListProjects", phase="before"),
    release="after_completed",
    predicate=_account_build_unpinned,
    resolution="What the shared tooling is pulled at is set for the account, not per build; the builds already in place show where it stands.",
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    codebuild = boto3.client("codebuild", region_name=region)

    names = []
    for page in codebuild.get_paginator("list_projects").paginate():
        names.extend(page.get("projects", []))

    pinned = []
    for start in range(0, len(names), 100):
        for project in codebuild.batch_get_projects(names=names[start:start + 100]).get("projects", []):
            identifiers = _tooling_identifiers(project)
            if not identifiers:
                continue
            tags = {t["key"]: t.get("value", "") for t in project.get("tags", []) if t.get("key")}
            if _pinned(project) and tags.get(MARK_KEY) == PIN:
                continue
            versions = {}
            for entry in project.get("secondarySourceVersions") or []:
                if isinstance(entry, dict) and entry.get("sourceIdentifier"):
                    versions[entry["sourceIdentifier"]] = entry.get("sourceVersion")
            for identifier in identifiers:
                versions[identifier] = PIN
            tags[MARK_KEY] = PIN
            codebuild.update_project(
                name=project["name"],
                # the sources are re-stated unchanged: a version only binds to a
                # secondary source the same call still declares
                secondarySources=[
                    {k: v for k, v in source.items() if k in SOURCE_FIELDS}
                    for source in project.get("secondarySources") or []
                    if isinstance(source, dict)
                ],
                secondarySourceVersions=[
                    {"sourceIdentifier": k, "sourceVersion": v}
                    for k, v in sorted(versions.items()) if v
                ],
                tags=[{"key": k, "value": v} for k, v in sorted(tags.items())],
            )
            pinned.append(project["name"])

    return {"pinned": pinned,
            "fingerprint": [PIN] if pinned else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
