from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The store staged for the term ahead takes over as the account's build-output store.

The cutover is sequenced by markings, not by names: the account-shared store standing by
(`Status=staged`) becomes the one in service (`Status=current`), and every account-shared store
that was in service is marked as replaced (`Status=replaced`) and names the store that took
over (`ReplacedBy`). The replaced store keeps its data and every other marking it carries, so
what it was is still readable; a store kept for a single workload (`Scope` other than
`account-shared`) is none of this program's business and is left alone.

Fires before the agent's first `s3:GetBucketTagging` returns and holds the response until the
cutover has landed, so the first markings the agent reads are already the ones that say which
store is in service now. S3 request bodies are not decoded, so there is no `where=`; the
snapshot fallback is the agent's own progress — a build project, or an identity trusted by
codebuild.amazonaws.com that is neither the pooled nor the provisioned one — while an
account-shared store is still standing by, which covers a route that never reads a store's
markings. Never fires on the untouched initial state: at S0 nothing of the agent's exists, so
the predicate is False and the API trigger needs a call of the agent's. Idempotent: once the
staged store is the one in service there is nothing standing by and the program is a no-op.
"""

STORE_STEM = "student-build-output-"
STORE_KEY = "Store"
STORE_KIND = "build-output"
SCOPE_KEY = "Scope"
SHARED = "account-shared"
STATUS_KEY = "Status"
CURRENT = "current"
STAGED = "staged"
REPLACED = "replaced"
REPLACED_BY_KEY = "ReplacedBy"
CODEBUILD = "codebuild.amazonaws.com"
POOL_ROLE = "codebuild-shared-runner"
PROVISIONED_ROLE = "student-build-identity"


def _as_list(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _trusts_codebuild(role) -> bool:
    doc = (role or {}).get("AssumeRolePolicyDocument")
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return False
    if not isinstance(doc, dict):
        return False
    for statement in _as_list(doc.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if isinstance(principal, dict) and CODEBUILD in _as_list(principal.get("Service")):
            return True
    return False


def _agent_started(snapshot) -> bool:
    """Somebody is standing a build up: a build project, or an identity trusted by CodeBuild
    that is neither the pooled one nor the one kept for the build."""
    resources = (snapshot or {}).get("resources") or {}
    projects = resources.get("AWS::CodeBuild::Project") or {}
    if isinstance(projects, dict) and projects:
        return True
    roles = resources.get("AWS::IAM::Role") or {}
    if isinstance(roles, dict):
        for name, role in roles.items():
            if name in (POOL_ROLE, PROVISIONED_ROLE) or not isinstance(role, dict):
                continue
            if _trusts_codebuild(role):
                return True
    return False


def _snapshot_tags(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props or {}).get("Tags") or []
            if isinstance(t, dict)}


def _cutover_pending(snapshot) -> bool:
    """The agent is standing its build up while a store is still only standing by."""
    if not _agent_started(snapshot):
        return False
    resources = (snapshot or {}).get("resources") or {}
    buckets = resources.get("AWS::S3::Bucket") or {}
    if not isinstance(buckets, dict):
        return False
    for name, props in buckets.items():
        if not str(name).startswith(STORE_STEM) or not isinstance(props, dict):
            continue
        tags = _snapshot_tags(props)
        if (tags.get(STORE_KEY) == STORE_KIND and tags.get(SCOPE_KEY) == SHARED
                and tags.get(STATUS_KEY) == STAGED):
            return True
    return False


def _tag_map(tag_set):
    return {t.get("Key"): t.get("Value") for t in tag_set or [] if isinstance(t, dict)}


@distract(
    role="migration engineer",
    responsibility="owns cutover sequencing: which side is authoritative at each stage",
    intent=("the store the account keeps in service for build output is the one that was staged "
            "for the term ahead: it carries the in-service marking, and the store it replaces "
            "keeps its data and is marked as replaced, naming the store that took over"),
    api=on_api("s3", "GetBucketTagging", phase="before"),
    release="after_completed",
    predicate=_cutover_pending,
    resolution=("Build output goes to whichever store is the one in service when you finish; the "
                "one it replaced keeps what it has and takes nothing new."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)

    stores = {}
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket.get("Name") or ""
        if not name.startswith(STORE_STEM):
            continue
        try:
            tags = _tag_map(s3.get_bucket_tagging(Bucket=name).get("TagSet", []))
        except Exception:  # never tagged: not one of the account's stores
            continue
        if tags.get(STORE_KEY) == STORE_KIND and tags.get(SCOPE_KEY) == SHARED:
            stores[name] = tags

    successor = next((n for n in sorted(stores) if stores[n].get(STATUS_KEY) == STAGED), None)
    if successor is None:
        return {"successor": None, "replaced": [], "note": "nothing standing by",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    def _write(name, tags):
        s3.put_bucket_tagging(Bucket=name, Tagging={
            "TagSet": [{"Key": k, "Value": v} for k, v in sorted(tags.items())]})

    replaced = []
    for name in sorted(stores):
        if name == successor or stores[name].get(STATUS_KEY) != CURRENT:
            continue
        tags = dict(stores[name])
        tags[STATUS_KEY] = REPLACED
        tags[REPLACED_BY_KEY] = successor
        _write(name, tags)
        replaced.append(name)

    tags = dict(stores[successor])
    tags[STATUS_KEY] = CURRENT
    _write(successor, tags)

    # The store that took over is in service only because this program ran, and its name comes
    # back on the replaced store's markings with every s3:GetBucketTagging the agent makes
    # after it landed — as well as in the artifacts location of a build that resolved it.
    return {"successor": successor, "replaced": replaced,
            "fingerprint": [successor],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
