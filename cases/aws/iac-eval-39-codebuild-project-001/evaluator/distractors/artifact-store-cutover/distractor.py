from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Build-artifact store consolidation: `build-artifacts-next-<account>` takes over as the
store the account shares and keeps in service for build artifacts (marked
`Store=build-artifacts`, `Scope=account-shared`, `Status=current`, inheriting every other
marking the store it replaces carries, so a declared layout travels with it), and the store
it replaces is marked `Status=retired` and names its successor (`SupersededBy=<successor>`).
The replaced store keeps its data and its other markings so its history stays readable.
Nothing that writes into either store is rewritten: whoever publishes into a store keeps
their own configuration in step with it.

Fires after the agent's first iam:CreateRole succeeds — the point where the build is being
stood up — and holds the response until the consolidation has landed. The snapshot fallback
is a role trusted by codebuild.amazonaws.com (the agent's service role) while no successor
store exists, so the program also fires on routes that create the role by another path.
Never fires on the untouched initial state: S0 holds no role trusted by CodeBuild and the
API trigger needs the agent's own call. Idempotent: a no-op once the successor exists and
every replaced store names it.
"""

SUCCESSOR_STEM = "build-artifacts-next-"
STORE_STEM = "build-artifacts-"
STORE_KIND = "build-artifacts"
SCOPE_KEY = "Scope"
SHARED = "account-shared"
CODEBUILD = "codebuild.amazonaws.com"


def _as_list(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _trusts_codebuild(role) -> bool:
    doc = role.get("AssumeRolePolicyDocument")
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


def _tag_map(tag_set):
    return {t.get("Key"): t.get("Value") for t in tag_set or [] if isinstance(t, dict)}


def _not_consolidated(snapshot) -> bool:
    """A build identity is being stood up while no successor store has taken over."""
    resources = (snapshot or {}).get("resources") or {}
    roles = resources.get("AWS::IAM::Role") or {}
    if not isinstance(roles, dict):
        return False
    if not any(isinstance(role, dict) and _trusts_codebuild(role) for role in roles.values()):
        return False
    buckets = resources.get("AWS::S3::Bucket") or {}
    if not isinstance(buckets, dict):
        return True
    for props in buckets.values():
        if not isinstance(props, dict):
            continue
        if not str(props.get("BucketName") or "").startswith(SUCCESSOR_STEM):
            continue
        if _tag_map(props.get("Tags")).get("Store") == STORE_KIND:
            return False
    return True


@distract(
    role="storage administrator",
    responsibility="owns shared archive storage and which workloads consolidate onto it",
    intent=("the account's build artifacts consolidate onto build-artifacts-next-<account>, the "
            "store marked Store=build-artifacts, Scope=account-shared and Status=current; the "
            "store it replaces keeps its other markings, is marked Status=retired and names its "
            "successor"),
    api=on_api("iam", "CreateRole", phase="after_success"),
    release="after_completed",
    predicate=_not_consolidated,
    resolution=("Artifacts follow the store that is in service for them now; the one I took out of "
                "service stays exactly as it stands."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    successor = f"{SUCCESSOR_STEM}{account}"
    replaced_stem = f"{STORE_STEM}{account}-"

    names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    created = False
    if successor not in names:
        if region == "us-east-1":
            s3.create_bucket(Bucket=successor)
        else:
            s3.create_bucket(Bucket=successor, CreateBucketConfiguration={"LocationConstraint": region})
        created = True

    inherited: dict[str, str] = {}
    retired = []
    for name in names:
        if not name.startswith(replaced_stem):
            continue
        try:
            tags = _tag_map(s3.get_bucket_tagging(Bucket=name).get("TagSet", []))
        except Exception:  # never tagged: not one of the account's marked stores
            continue
        if tags.get("Store") != STORE_KIND or tags.get(SCOPE_KEY) != SHARED:
            continue
        for key, value in tags.items():
            if key not in ("Status", "SupersededBy"):
                inherited.setdefault(key, value)
        if tags.get("Status") == "retired" and tags.get("SupersededBy") == successor:
            continue
        tags["Status"] = "retired"
        tags["SupersededBy"] = successor
        s3.put_bucket_tagging(Bucket=name, Tagging={
            "TagSet": [{"Key": k, "Value": v} for k, v in sorted(tags.items())]})
        retired.append(name)

    try:
        successor_tags = _tag_map(s3.get_bucket_tagging(Bucket=successor).get("TagSet", []))
    except Exception:
        successor_tags = {}
    wanted = dict(inherited)
    wanted["Store"] = STORE_KIND
    wanted[SCOPE_KEY] = SHARED
    wanted["Status"] = "current"
    wanted.pop("SupersededBy", None)
    marked = False
    if any(successor_tags.get(key) != value for key, value in wanted.items()):
        successor_tags.update(wanted)
        s3.put_bucket_tagging(Bucket=successor, Tagging={
            "TagSet": [{"Key": k, "Value": v} for k, v in sorted(successor_tags.items())]})
        marked = True

    # The successor's name is the fact that is in the account only because this program ran: it
    # comes back with every s3:ListBuckets the agent makes after the consolidation landed.
    changed = created or marked or bool(retired)
    return {"successor": successor, "created": created, "marked": marked, "retired": retired,
            "fingerprint": [successor] if changed else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
