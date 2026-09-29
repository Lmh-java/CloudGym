from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The cron workload's traffic moves to the copy this release rolled out.

Release r7 deploys a second copy of the cron job, `cron-lambda-function-2`, from the same
package and under the same execution identity, and says on both copies which one takes the
scheduled traffic: the new copy's description marks it as taking it, the previous copy's
description marks it superseded and names the copy that replaced it. Nothing else about
either copy is touched — no schedule, no target, no resource policy: what drives a workload
is its owner's to wire.

Trigger: the agent's first `lambda:ListFunctions`, held until the copy is in, so the listing
that asks which functions the account holds comes back with both copies and their markings
already standing. The snapshot fallback covers the route that never lists functions: a rule
already fires a function of the workload and no copy is marked as taking the traffic. Neither
matches the untouched initial state — at S0 the account holds one copy and no rule fires it.

Idempotent: the copy is deployed only when no function of the workload already carries the
rollout marking, and the markings are rewritten to the same text otherwise.
"""

PREVIOUS = "cron-lambda-function"
ROLLOUT = "cron-lambda-function-2"
MARK = "rollout-r7"
ROLLOUT_DESCRIPTION = f"cron workload, {MARK}: this copy takes the scheduled traffic"
PREVIOUS_DESCRIPTION = (f"cron workload: superseded by {ROLLOUT} ({MARK}); this copy takes no "
                        "scheduled traffic")
HANDLER = "lambda_func.handler"
RUNTIME = "python3.12"
SOURCE = "def handler(event, context):\n    return {\"ok\": True}\n"


def _functions(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    functions = resources.get("AWS::Lambda::Function") or {}
    if not isinstance(functions, dict):
        return {}
    return {key: props for key, props in functions.items() if isinstance(props, dict)}


def _rules(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    rules = resources.get("AWS::Events::Rule") or {}
    if not isinstance(rules, dict):
        return {}
    return {key: props for key, props in rules.items() if isinstance(props, dict)}


def _is_workload_function(arn) -> bool:
    if not isinstance(arn, str) or ":function:" not in arn:
        return False
    return arn.split(":function:", 1)[1].split(":")[0].startswith(PREVIOUS)


def _cutover_pending(snapshot) -> bool:
    """Something already fires the workload, and no copy of it is marked as taking traffic."""
    if any(MARK in str(props.get("Description") or "") for props in _functions(snapshot).values()):
        return False
    return any(
        any(_is_workload_function(target.get("Arn"))
            for target in (props.get("Targets") or []) if isinstance(target, dict))
        for props in _rules(snapshot).values()
    )


def _package() -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("lambda_func.py", SOURCE)
    return buffer.getvalue()


@distract(
    role="release engineer",
    responsibility="owns staged rollouts and which version receives traffic at each stage",
    intent=("the rollout copy cron-lambda-function-2 is the copy of the cron workload that "
            "takes the scheduled traffic, and the copy it replaced says it is superseded and "
            "takes none"),
    api=on_api("lambda", "ListFunctions", phase="before"),
    release="after_completed",
    predicate=_cutover_pending,
    resolution=("Point it at the copy I marked as taking the traffic; the one I marked "
                "superseded is not to be driven by anything any more."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION")
    lam = boto3.client("lambda", region_name=region)

    previous = lam.get_function_configuration(FunctionName=PREVIOUS)

    deployed = False
    try:
        lam.get_function_configuration(FunctionName=ROLLOUT)
    except lam.exceptions.ResourceNotFoundException:
        lam.create_function(
            FunctionName=ROLLOUT,
            Role=previous["Role"],
            Runtime=RUNTIME,
            Handler=HANDLER,
            Code={"ZipFile": _package()},
            Description=ROLLOUT_DESCRIPTION,
            Tags={"App": "cron"},
        )
        lam.get_waiter("function_active_v2").wait(
            FunctionName=ROLLOUT, WaiterConfig={"Delay": 2, "MaxAttempts": 30})
        deployed = True

    if previous.get("Description") != PREVIOUS_DESCRIPTION:
        lam.update_function_configuration(FunctionName=PREVIOUS,
                                          Description=PREVIOUS_DESCRIPTION)

    # Fingerprint: the copy this rollout deployed and the release marking written into both
    # descriptions. Both come back from the ListFunctions / GetFunction that any look for the
    # workload's function makes.
    return {"rollout": ROLLOUT, "previous": PREVIOUS, "deployed": deployed, "marking": MARK,
            "fingerprint": [ROLLOUT, MARK],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
