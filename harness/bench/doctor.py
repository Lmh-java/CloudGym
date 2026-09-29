"""Machine-readiness checks for a benchmark run. Cheap: spends no tokens, touches no cloud resource."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Check:
    name: str
    status: str            # PASS | WARN | FAIL
    detail: str
    fix: str | None = None


def _run(argv: list[str], timeout: float = 20) -> tuple[int, str]:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return completed.returncode, (completed.stdout or completed.stderr).strip()


def run_checks(repo_root: Path, *, agents: tuple[str, ...] = ("claude", "codex")) -> list[Check]:
    checks: list[Check] = []
    for tool, fix in (("terraform", "install Terraform and add it to PATH"), ("opa", "install OPA and add it to PATH"), ("aws", "install the AWS CLI v2")):
        if shutil.which(tool):
            _, out = _run([tool, "version"] if tool in {"terraform", "opa"} else [tool, "--version"])
            checks.append(Check(tool, "PASS", out.splitlines()[0] if out else "found"))
        else:
            checks.append(Check(tool, "FAIL", "not on PATH", fix))
    for agent in agents:
        if shutil.which(agent):
            _, out = _run([agent, "--version"])
            checks.append(Check(f"agent:{agent}", "PASS", out.splitlines()[0] if out else "found"))
        else:
            checks.append(Check(f"agent:{agent}", "WARN", "not on PATH", f"install the {agent} CLI or drop it from the spec"))
    try:
        from harness.aws_safety import AwsSafetyError, aws_environment, load_aws_target, verify_aws_target
        target = load_aws_target(repo_root)
        checks.append(Check("aws:config", "PASS", f"profile={target.profile} account={target.account_id} region={target.region}"))
        try:
            identity = verify_aws_target(target, aws_environment(target))
            checks.append(Check("aws:identity", "PASS", identity.get("Arn", "")))
        except AwsSafetyError as exc:
            checks.append(Check("aws:identity", "FAIL", str(exc).splitlines()[0][:160],
                                f"aws sso login --profile {target.profile}"))
    except Exception as exc:  # noqa: BLE001 - missing config is the finding
        checks.append(Check("aws:config", "FAIL", str(exc)[:160], "copy .cloudgym/aws.example.toml to aws.local.toml"))
    from harness.bench.spec import active_case_dirs
    cases = active_case_dirs(repo_root / "cases" / "aws")
    checks.append(Check("cases", "PASS" if cases else "FAIL", f"{len(cases)} active case(s)",
                        None if cases else "restore cases/aws from a complete CloudGym checkout"))
    return checks


def render(checks: list[Check]) -> str:
    lines = []
    for check in checks:
        line = f"{check.status:<4} {check.name:<16} {check.detail}"
        if check.fix and check.status != "PASS":
            line += f"\n     fix: {check.fix}"
        lines.append(line)
    return "\n".join(lines)
