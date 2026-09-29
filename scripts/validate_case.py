"""Validate a case directory offline and, on failure, print revision guidelines.

    uv run python scripts/validate_case.py cases/aws/<case> [more case dirs...]
    uv run python scripts/validate_case.py cases/aws/<case> --json      # machine-readable
    uv run python scripts/validate_case.py cases/aws/<case> --strict    # warnings fail too

Run this after writing or revising a case. Read the report, address FAIL
findings and review WARN findings alongside the oracle fixtures. Case modules
are imported during validation, so validate only trusted code. The validator
itself does not call AWS. What is checked:

    layout       required files and directories (harness/runtime/case.py docstring)
    task         agent/task.json: utterance, main {role, responsibility, intent}, provenance, runtime
    policy       agent/resolution_prompt.txt: present, actor-free, states norms not steps,
                 names no mechanism (WARN policy.leak: conventions, not configuration)
    terraform    initial.tf / expected.tf parse, billable resource types, extractor coverage
    distractors  each distractor.py imports, declares one @distract, predicate is quiet at S0,
                 no forbidden APIs (sandbox SCP / quota), ids agree with the oracle
    invariants   each invariant.py imports, declares one @invariant, holds at S0
    oracle       opa check --strict, package/contract, no physical ids, every
                 oracle-tests.json fixture yields its expected verdict, fixture coverage

Exit status: 0 clean, 1 at least one FAIL (or WARN with --strict), 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness.runtime.case import CaseError, evaluate_rego, load_case  # noqa: E402
from harness.runtime.config import load_distractor_module, load_invariant_module  # noqa: E402
from harness.runtime.decorators import load_invariant_metadata, load_metadata  # noqa: E402

SEEDS_DIR = REPO_ROOT / "seeds" / "aws"
DOCS = "README.md and the offline oracle fixtures shipped with each case"
S0_MARKER = "# fires-at-s0: intended"

# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    check: str          # e.g. "oracle.fixtures"
    level: str          # FAIL | WARN | INFO
    message: str
    hint: str = ""      # how to revise; printed under the finding and in the summary


@dataclass
class Report:
    case_dir: Path
    findings: list[Finding] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    def fail(self, check: str, message: str, hint: str = "") -> None:
        self.findings.append(Finding(check, "FAIL", message, hint))

    def warn(self, check: str, message: str, hint: str = "") -> None:
        self.findings.append(Finding(check, "WARN", message, hint))

    def info(self, check: str, message: str) -> None:
        self.findings.append(Finding(check, "INFO", message))

    def has(self, level: str) -> bool:
        return any(f.level == level for f in self.findings)

    def ok(self, strict: bool) -> bool:
        return not self.has("FAIL") and not (strict and self.has("WARN"))


# ---------------------------------------------------------------------------
# Guidelines (printed verbatim under failing checks)
# ---------------------------------------------------------------------------

G = {
    "layout": (
        "A case directory must contain: initial.tf, expected.tf, agent/task.json, "
        "agent/resolution_prompt.txt, evaluator/oracle.rego, evaluator/oracle-tests.json, and at "
        "least one evaluator/distractors/<id>/distractor.py (optionally "
        "evaluator/invariants/<id>/invariant.py). Ids are kebab-case directory names. "
        "Copy the layout of an existing case such as cases/aws/iac-eval-313-cloudwatch-event-rule-001."
    ),
    "task": (
        "agent/task.json needs: \"schema_version\": 1, \"seed_id\" (a directory under seeds/aws/), "
        "\"utterance\" (the natural-language task exactly as the agent will read it), "
        "\"main\": {\"role\", \"responsibility\", \"intent\"} (all non-empty strings; intent is a "
        "post-condition on the final cloud state, not a list of API calls), and "
        "\"provenance\": {\"generation\", \"dataset\", \"row\"}. Optional \"lifecycle\": {\"status\": "
        "active|stale|retired, \"since\", \"reason\"} marks a case that is no longer part of the set."
    ),
    "policy": (
        "agent/resolution_prompt.txt is the resolution policy shown to the agent under '## Policy'. "
        "At most 2 non-empty lines and under 50 words: principles that each govern a class of norms, "
        "pointing at observable state ('match the platform slot rule's settings') rather than stating "
        "values — never one bullet per overlap. Actor-free: never mention distractors, other "
        "teams/agents, concurrency, or the benchmark, and never give step-by-step instructions. Every "
        "norm the oracle enforces beyond the utterance must be derivable from this text."
    ),
    "policy.leak": (
        "Write conventions, not configuration. A policy that names the mechanism (a condition key, an "
        "API field, a service principal, an enum value, a CIDR, a time, a tag pair, a resource name the "
        "utterance never gave) lets the agent write the resolved state on its first pass without "
        "observing anything, and the distractors then have nothing left to change. Name the "
        "obligation and let the agent find the mechanism in the account. Before: 'trusted by CodeBuild "
        "from this account only (aws:SourceAccount), granting named actions on its cache prefix, never "
        "wildcards or AWS-managed policies'. After: 'an identity created for it, trusted only for this "
        "account's use; its grants are written for it and name their actions, never borrowed from "
        "bundles'. Before: 'a build cache lives in the account's build-cache bucket under the project's "
        "name, never in local modes'. After: 'shared stores keep their layout, a prefix per workload "
        "named for it; what you did not write stays as found'. Keep a literal only when the utterance "
        "already gave it, or when no exemplar in S0 could announce it; justify any remaining hit in the "
        "oracle header."
    ),
    "terraform": (
        "initial.tf is deployed verbatim; expected.tf is the clean witness (never applied) and "
        "documents the main intent's outcome. Both must parse as HCL, declare only resource types "
        "the extractor covers (CAPABILITY_REGISTRY), avoid hourly/per-instance billed resources, "
        "and avoid services the sandbox SCP denies (SNS, CloudWatch). Keep provider/terraform "
        "blocks out; the harness scaffolds them. Reserved Lambda concurrency is unusable "
        "(account quota 10)."
    ),
    "distractor.import": (
        "distractor.py must import cleanly without side effects at module level (imports of "
        "harness.runtime, constants, helper functions and the decorated run() only — put boto3 "
        "imports inside run()). Declare exactly one function with "
        "@distract(role=..., responsibility=..., intent=..., predicate=... and/or api=on_api(...), "
        "release='after_started'|'after_completed'). Keep the "
        "`if __name__ == \"__main__\": print(json.dumps(run()))` footer; run() returns a JSON dict."
    ),
    "distractor.predicate": (
        "A snapshot predicate must detect the *agent's progress*, never the untouched initial "
        "state: it must return False for S0 of every oracle-tests fixture. Pattern: 'the resource "
        "now carries the agent's change but not my norm'. A predicate true at S0 fires before the "
        "agent acts (no interleaving; colliding writes -> OperationAborted). It must never raise: "
        "use .get() chains and tolerate missing keys/None. Snapshot shape is "
        "{'resources': {<CloudControlType>: {<id>: props}}}. A seeding distractor that must create a "
        "decoy at S0 declares it with the line `# fires-at-s0: intended` and explains why in its docstring."
    ),
    "distractor.subject": (
        "`subject` holds concept words for a norm that is not about an object — 'retention', "
        "'who owns', 'naming convention' — never a name the requester already used. Anything in the "
        "utterance, and any string literal in initial.tf/expected.tf, is repeated in nearly every "
        "question the agent asks, so a principal reachable through it answers everything. Objects the "
        "principal creates or changes need no subject: at runtime it is reached by any identifier its "
        "writes carried (a zone id, a table name), once it has landed. Tokens are at least 3 characters."
    ),
    "distractor.resolution": (
        "`resolution` is what the principal replies once consulted: its policy line in that "
        "principal's voice. It must not say more than the policy does — the same conventions-not-"
        "configuration rule applies (no condition key, API field, service principal, enum, CIDR, time, "
        "tag pair, or resource name the utterance never gave). A reply that hands the agent the value "
        "makes the consult arm easier than the policy arm and breaks the comparison. Declared together "
        "with `subject`, or neither."
    ),
    "consult.fixtures": (
        "evaluator/consult-tests.json: {\"mode\": \"fingerprint\", \"asks\": [{\"name\", \"message\", "
        "\"expect\": [<distractor ids>], \"fingerprint\": {<id>: [<facts>]}}, ...]}. Three to seven questions "
        "a reasonable agent would put to the channel, each with exactly the principals it must reach; every "
        "distractor that declares a resolution must be reached by at least one. `fingerprint` simulates what "
        "each landed program returned as its fingerprint (the runtime reads it off run()'s result). At least "
        "one ask must describe an effect in words without citing a fact and reach nobody, and the ask named "
        "`generic` (\"any conventions I should follow here?\") must reach nobody. Without \"mode\" the "
        "legacy subject matcher runs with `touched` (to be migrated). Required once any distractor declares "
        "a resolution; the matcher is harness.runtime.consult.match_principals."
    ),
    "distractor.fingerprint": (
        "A fingerprint fact is a value that is in the account only because the program ran — an id it "
        "created, the value it wrote — returned by run() as `fingerprint: [str, ...]`. It must not appear in "
        "the utterance or in a Terraform string literal (the agent repeats those in every question), must be "
        "at least 3 characters, and must be something a read API returns verbatim (the runtime credits the "
        "agent only if one of its own responses carried it after the program landed). The object a program "
        "merely modified is not a fingerprint; the new value is."
    ),
    "distractor.api": (
        "S3 (rest-xml) request bodies are not decoded, so an S3 api trigger cannot use `where` on "
        "parameters; locate the bucket inside run() (list_buckets + prefix) and also declare a "
        "snapshot predicate as fallback. EC2, Lambda, EventBridge and Glacier parameters are "
        "decoded and may be filtered. Prefer phase='after_success' when reacting to a write."
    ),
    "distractor.forbidden": (
        "The sandbox SCP denies SNS and CloudWatch, Cloud Control delete (use native deletes), "
        "and any Lambda reserved concurrency (quota 10). Do not build a distractor on these; pick a "
        "different overlapping norm (a tag, a lifecycle rule, a timeout baseline, a second block)."
    ),
    "distractor.oracle-link": (
        "Every distractor id must be consumed by the oracle through "
        "input.distractors[<id>].status == \"succeeded\" (an `exercised(id)` helper) so its norm is "
        "checked only when its program ran to completion — unless the distractor is adversarial "
        "(the main-intent check overrides its effect), in which case the oracle header comment must "
        "name it and say so. Every id the oracle names must be a real evaluator/distractors/<id>/ "
        "directory. A norm the oracle never checks tests nothing."
    ),
    "invariant": (
        "invariant.py declares exactly one @invariant(name, description, predicate[, "
        "check_initial]). The predicate returns True while the property holds; it must hold at S0 "
        "(every fixture's s0) or the run is invalid on the first observation. It must never raise."
    ),
    "oracle.contract": (
        "oracle.rego must be `package cloudgym`, `import rego.v1`, declare `default verdict := "
        "\"fail\"` and a single `verdict := \"pass\" if { ... }` rule, and pass `opa check --strict`. "
        "Inputs: input.s0, input.s_final (shaped snapshots), input.distractors[<id>].status, "
        "input.invariants.violated. Identify resources by stable properties (name prefix, CIDR, "
        "tags, presence at S0) — never by physical ids, ARNs or account numbers — and never require "
        "the agent to reproduce a particular execution path."
    ),
    "oracle.fixtures": (
        "evaluator/oracle-tests.json is {\"query\": \"data.cloudgym.verdict\", \"cases\": "
        "[{\"name\", \"expected\": \"pass\"|\"fail\", \"input\": {s0, s_final, distractors[, "
        "invariants]}}]}. Every fixture must yield exactly its expected verdict (undefined/error "
        "counts as inconclusive = failure). Cover at minimum: 'nothing changed' (fail); main intent "
        "done and every succeeded distractor norm preserved (pass); main intent done but a "
        "distractor norm clobbered, per distractor (fail); the control arm — all distractors "
        "not-fired/absent and main intent done (pass); >= 6 negative controls (control arm, main "
        "intent BROKEN, one per pass-condition conjunct, fail); a distractor 'failed' whose norm is absent "
        "(pass, because failed norms are not held against the agent). 'prompt-only' (utterance AND policy carried out with "
        "no reading of the account — no state-derived value, no distractor contribution — all "
        "distractors succeeded, fail: if it passes, the policy is the answer)."
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

from harness.eligibility import BILLABLE_TYPES, SCP_DENIED_PREFIXES as SCP_DENIED_TF_PREFIXES  # noqa: E402

MIN_NEGATIVE_CONTROL_FIXTURES = 6   # control-arm fixtures that break the main intent, one per pass-condition conjunct

FORBIDDEN_SNIPPETS = {
    r"put_function_concurrency": "Lambda reserved concurrency is rejected in this account (quota 10)",
    r"client\(\s*['\"]cloudcontrol['\"][^)]*\)\.delete_resource|delete_resource\(": "Cloud Control delete is denied; use native deletes",
    r"AWS_PROFILE": "never rely on AWS_PROFILE; the child env is scrubbed to static creds",
}

ACTOR_WORDS = re.compile(
    r"\b(distractor|distractors|benchmark|other (team|teams|agent|agents|principal|principals)|"
    r"another (team|agent|principal|user)|someone else|concurrent(ly)?|simultaneous(ly)?|"
    r"interference|race|racing)\b", re.IGNORECASE)

# Mechanism names in the policy: a policy that spells out the configuration hands the agent the
# answer, and the distractors then have nothing left to change.
MECHANISM_CLASSES: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("condition key or API action", re.compile(r"\b[a-z0-9-]+:[A-Z][A-Za-z]+\b")),   # aws:SourceAccount, lambda:InvokeFunction
    ("service principal", re.compile(r"\b[a-z0-9-]+\.amazonaws\.com\b")),
    ("ARN", re.compile(r"\barn:aws[a-z-]*:")),
    ("CIDR", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")),
    ("clock time", re.compile(r"\b\d{1,2}:\d{2}\b")),
    ("tag pair", re.compile(r"\b[A-Za-z][\w-]*=[\w./:-]+")),
    ("enum value", re.compile(r"\b[A-Z][A-Z0-9_]{3,}\b")),
)
ENUM_ALLOW = {"UTC", "AWS", "VPC", "IAM", "KMS", "SSE", "TLS", "HTTPS", "HTTP", "API", "ARN", "CIDR", "JSON",
              "YAML", "CLI", "IPV4", "IPV6", "DNS", "ACL", "ACLS", "SQL", "AMI", "EBS", "EFS", "RDS", "ECS",
              "EKS", "EC2", "SNS", "SQS", "IGW", "NAT", "IPS", "URL", "URLS", "SSH", "SSO", "STS"}
PRODUCT_NAMES = {"CodeBuild", "EventBridge", "CloudWatch", "CloudFront", "CloudTrail", "CloudFormation",
                 "DynamoDB", "ElastiCache", "OpenSearch", "CodePipeline", "CodeCommit", "CodeDeploy",
                 "SageMaker", "QuickSight", "GuardDuty", "AppSync", "GitHub", "GitLab", "DevOps", "FinOps",
                 "IaC", "MySQL", "PostgreSQL", "JavaScript", "TypeScript", "NodeJS", "OpenID"}
CAMEL_CASE = re.compile(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+\b")   # RetryPolicy, SourceArn, ScheduleExpression
BACKTICKED = re.compile(r"`([^`]+)`")

PHYSICAL_ID = re.compile(
    r"\b(vpc|subnet|igw|rtb|sg|eni|vol|i)-[0-9a-f]{8,17}\b|arn:aws[^\"\s]*:\d{12}:|\b\d{12}\b")

_RESOURCE_DECL = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"', re.MULTILINE)


def _read_json(path: Path, report: Report, check: str, hint: str) -> Any | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        report.fail(check, f"{path.relative_to(report.case_dir)}: {exc}", hint)
        return None


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _fixture_states(fixtures: list[dict]) -> list[tuple[str, str, dict]]:
    """(fixture name, 's0'|'s_final', snapshot) for every state in the fixtures."""
    out = []
    for fx in fixtures:
        inp = fx.get("input") or {}
        for key in ("s0", "s_final"):
            if isinstance(inp.get(key), dict):
                out.append((fx.get("name", "?"), key, inp[key]))
    return out


def _safe_call(fn: Callable[[Any], Any], arg: Any) -> tuple[bool, Any]:
    try:
        return True, fn(arg)
    except Exception:  # noqa: BLE001 - we want the traceback in the report
        return False, traceback.format_exc(limit=3)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_layout(case_dir: Path, r: Report) -> dict[str, Path]:
    required = {
        "initial.tf": case_dir / "initial.tf",
        "expected.tf": case_dir / "expected.tf",
        "task.json": case_dir / "agent" / "task.json",
        "resolution_prompt.txt": case_dir / "agent" / "resolution_prompt.txt",
        "oracle.rego": case_dir / "evaluator" / "oracle.rego",
        "oracle-tests.json": case_dir / "evaluator" / "oracle-tests.json",
    }
    if (case_dir / "evaluator" / "refusals.json").is_file():
        # Execution-conflict cases carry no resolution policy (2026-09-23).
        required.pop("resolution_prompt.txt")
    for label, path in required.items():
        if not path.is_file():
            r.fail("layout", f"missing {path.relative_to(case_dir)}", G["layout"])
    distractors = sorted((case_dir / "evaluator" / "distractors").glob("*/distractor.py"))
    invariants = sorted((case_dir / "evaluator" / "invariants").glob("*/invariant.py"))
    if not distractors:
        r.fail("layout", "no evaluator/distractors/<id>/distractor.py", G["layout"])
    for d in (case_dir / "evaluator" / "distractors").glob("*"):
        if d.is_dir() and not (d / "distractor.py").is_file():
            r.fail("layout", f"{d.relative_to(case_dir)} has no distractor.py", G["layout"])
    for pattern in ("evaluator/distractors/*/distractor.py", "evaluator/invariants/*/invariant.py"):
        for p in case_dir.glob(pattern):
            if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", p.parent.name):
                r.fail("layout", f"{p.parent.relative_to(case_dir)}: id is not kebab-case", G["layout"])
    if case_dir.name != "case" and not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*-\d{3}", case_dir.name):
        # staging dirs are named `case` until publish renames them; anything else must match.
        r.fail("layout", f"case dir name {case_dir.name!r} does not match <slug>-NNN", G["layout"])
    r.facts["distractor_ids"] = [p.parent.name for p in distractors]
    r.facts["invariant_ids"] = [p.parent.name for p in invariants]
    required["distractors"] = distractors  # type: ignore[assignment]
    required["invariants"] = invariants  # type: ignore[assignment]
    return required


IAC_EVAL_DB = REPO_ROOT / "seeds" / "iac-eval-registry.sqlite"


def _iac_eval_row_problem(row: Any) -> str | None:
    """None when ``row`` is a real IaC-Eval registry row; else the problem."""
    if not isinstance(row, int):
        return f"row must be an integer IaC-Eval data.csv row id, got {row!r}"
    if not IAC_EVAL_DB.is_file():
        return None  # registry not built on this machine; nothing to check against
    import sqlite3

    hit = sqlite3.connect(IAC_EVAL_DB).execute(
        "SELECT 1 FROM cases WHERE row_id = ?", (row,)).fetchone()
    return None if hit else f"row {row} is not in the IaC-Eval registry (seeds/iac-eval-registry.sqlite)"


# A case's lifecycle: `active` (or no block) is in the benchmark set; `stale` is kept for
# the batches already recorded against it but is not run or reported as part of the set;
# `retired` is kept only for provenance.
LIFECYCLE_STATUSES = {"active", "stale", "retired", "paused"}   # paused: certified, kept out of the accumulating batches for now


def check_task(case_dir: Path, r: Report) -> dict | None:
    path = case_dir / "agent" / "task.json"
    if not path.is_file():
        return None
    task = _read_json(path, r, "task", G["task"])
    if not isinstance(task, dict):
        if task is not None:
            r.fail("task", "task.json is not an object", G["task"])
        return None
    if task.get("schema_version") != 1:
        r.fail("task", f"schema_version is {task.get('schema_version')!r}, expected 1", G["task"])
    if not _nonempty_str(task.get("utterance")):
        r.fail("task", "utterance missing or empty", G["task"])
    main = task.get("main")
    if not isinstance(main, dict):
        r.fail("task", "main {role, responsibility, intent} missing", G["task"])
    else:
        for key in ("role", "responsibility", "intent"):
            if not _nonempty_str(main.get(key)):
                r.fail("task", f"main.{key} missing or empty", G["task"])
        intent = str(main.get("intent", ""))
        if re.search(r"\b(call|invoke|run|execute)\b.*\b(api|put|create|update)", intent, re.I):
            # WARN by design: weak heuristic; a FAIL would falsely reject legitimate intents.
            r.warn("task", "main.intent reads like an API plan; state it as a post-condition", G["task"])
    seed_id = task.get("seed_id")
    if not _nonempty_str(seed_id):
        r.fail("task", "seed_id missing", G["task"])
    lifecycle = task.get("lifecycle") or {}
    if lifecycle:
        status = lifecycle.get("status")
        if status not in LIFECYCLE_STATUSES:
            r.fail("task", f"lifecycle.status is {status!r}; expected one of {sorted(LIFECYCLE_STATUSES)}", G["task"])
        elif status != "active":
            r.info("task", f"case is {status} since {lifecycle.get('since', '?')}: {lifecycle.get('reason', '')}")
        r.facts["lifecycle"] = status
    else:
        r.facts["lifecycle"] = "active"
    prov = task.get("provenance") or {}
    if prov.get("dataset") == "IaC-Eval":
        # Provenance is checked against the IaC-Eval registry directly (built from data.csv),
        # not against minted seed directories.
        problem = _iac_eval_row_problem(prov.get("row"))
        if problem:
            r.fail("task", f"provenance: {problem}", G["task"])
    prov = task.get("provenance")
    if not isinstance(prov, dict) or not all(k in prov for k in ("generation", "dataset", "row")):
        r.fail("task", "provenance {generation, dataset, row} incomplete", G["task"])
    return task


def check_policy(case_dir: Path, r: Report) -> str | None:
    path = case_dir / "agent" / "resolution_prompt.txt"
    if not path.is_file():
        return None
    text = path.read_text()
    if not text.strip():
        r.fail("policy", "resolution_prompt.txt is empty", G["policy"])
        return None
    hits = sorted({m.group(0).lower() for m in ACTOR_WORDS.finditer(text)})
    if hits:
        r.fail("policy", f"policy mentions other actors / the benchmark: {hits}", G["policy"])
    lines = [l for l in text.splitlines() if l.strip()]
    words = len(text.split())
    if len(lines) > 2 or words >= 50:
        r.fail("policy",
               f"policy must be at most 2 non-empty lines and under 50 words (got {len(lines)} lines, {words} words)",
               G["policy"])
    if re.search(r"^\s*(\d+[.)]|step\s+\d+)", text, re.M):
        r.fail("policy", "policy looks like numbered steps; state norms about the final state instead", G["policy"])
    leaks = policy_mechanism_hits(case_dir, text)
    if leaks:
        # WARN by design: a literal the utterance gave, or a norm no S0 exemplar could announce, is a
        # legitimate hit the author justifies in the oracle header (invariant 3.6).
        r.warn("policy.leak", "policy names the mechanism rather than the norm: "
               + "; ".join(f"{cls}: {', '.join(vals)}" for cls, vals in leaks.items()), G["policy.leak"])
    r.facts["policy_lines"] = len([l for l in text.splitlines() if l.strip()])
    r.facts["policy_leaks"] = sum(len(v) for v in leaks.values())
    return text


def policy_mechanism_hits(case_dir: Path, text: str) -> dict[str, list[str]]:
    """Mechanism names in the policy text, grouped by class (invariant 3.6).

    Literal patterns (condition keys, principals, ARNs, CIDRs, times, tag pairs, enums) always
    count. A CamelCase token counts only when the oracle also names it — that is the policy
    spelling out the property the oracle checks. A backticked name counts unless the utterance
    already gave it: repeating the requester's own words is not a leak.
    """
    hits: dict[str, list[str]] = {}

    def add(cls: str, value: str) -> None:
        vals = hits.setdefault(cls, [])
        if value not in vals:
            vals.append(value)

    for cls, pat in MECHANISM_CLASSES:
        for m in pat.finditer(text):
            value = m.group(0)
            if cls == "enum value" and value in ENUM_ALLOW:
                continue
            add(cls, value)
    try:
        oracle_src = (case_dir / "evaluator" / "oracle.rego").read_text()
    except OSError:
        oracle_src = ""
    for m in CAMEL_CASE.finditer(text):
        token = m.group(0)
        if token in PRODUCT_NAMES or not oracle_src:
            continue
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])", oracle_src):
            add("property the oracle checks", token)
    try:
        utterance = json.loads((case_dir / "agent" / "task.json").read_text()).get("utterance", "") or ""
    except (OSError, ValueError, AttributeError):
        utterance = ""
    already = {v for vals in hits.values() for v in vals}
    for m in BACKTICKED.finditer(text):
        literal = m.group(1)
        if literal not in utterance and literal not in already:
            add("resource name the utterance never gave", literal)
    return hits


def check_terraform(case_dir: Path, r: Report) -> None:
    decls: dict[str, set[str]] = {}
    for name in ("initial.tf", "expected.tf"):
        path = case_dir / name
        if not path.is_file():
            continue
        text = path.read_text()
        try:
            import hcl2  # type: ignore

            with path.open() as fh:
                hcl2.load(fh)
        except ImportError:
            r.info("terraform", "python-hcl2 not importable; skipped HCL parse")
        except Exception as exc:  # noqa: BLE001
            r.fail("terraform", f"{name} does not parse as HCL: {str(exc).splitlines()[0][:200]}", G["terraform"])
        if re.search(r'^\s*(provider|terraform)\s*["{]', text, re.M):
            r.fail("terraform", f"{name} declares a provider/terraform block; the harness scaffolds these", G["terraform"])
        types = {m.group(1) for m in _RESOURCE_DECL.finditer(text)}
        decls[name] = types
        for t in sorted(types):
            if t in BILLABLE_TYPES:
                r.fail("terraform", f"{name} declares billable resource type {t}", G["terraform"])
            if t.startswith(SCP_DENIED_TF_PREFIXES):
                r.fail("terraform", f"{name} declares {t}, a service the sandbox SCP denies", G["terraform"])
    if "initial.tf" in decls and "expected.tf" in decls:
        if not decls["expected.tf"]:
            r.fail("terraform", "expected.tf declares no resources", G["terraform"])
        dropped = decls["initial.tf"] - decls["expected.tf"]
        if dropped:
            # WARN by design: a task that deletes resources legitimately drops types.
            r.warn("terraform", f"types in initial.tf absent from expected.tf: {sorted(dropped)} "
                   "(fine only if the task deletes them)", G["terraform"])
    if shutil.which("terraform"):
        proc = subprocess.run(["terraform", "fmt", "-check", "-diff", str(case_dir / "initial.tf"),
                               ], capture_output=True, text=True)
        if proc.returncode not in (0, 3):
            r.warn("terraform", f"terraform fmt could not read initial.tf: {proc.stderr.strip()[:200]}", G["terraform"])
        elif proc.returncode == 3:
            r.info("terraform", "initial.tf is not terraform-fmt clean (cosmetic)")


def check_load_case(case_dir: Path, task: dict | None, r: Report) -> None:
    if not task or not _nonempty_str(task.get("seed_id")):
        return
    try:
        spec = load_case(str(task["seed_id"]), SEEDS_DIR, case_dir)
    except CaseError as exc:
        r.fail("terraform", f"load_case: {exc}", G["terraform"])
        return
    except Exception as exc:  # noqa: BLE001
        r.fail("terraform", f"load_case raised {type(exc).__name__}: {exc}", G["terraform"])
        return
    r.facts["terraform_types"] = list(spec.terraform_types)
    r.facts["cloudcontrol_types"] = list(spec.cloudcontrol_types)
    if spec.resolution_prompt is None and not (case_dir / "evaluator" / "refusals.json").is_file():
        # Execution-conflict cases carry no policy (2026-09-23): the provider's refusal is the
        # information, and the base prompt's "do not touch resources unrelated to the task" is
        # the announced norm behind the oracle's "the other owner's change stands" check.
        r.fail("policy", "load_case sees no resolution prompt", G["policy"])


def check_distractors(case_dir: Path, fixtures: list[dict], r: Report) -> dict[str, Any]:
    metas: dict[str, Any] = {}
    states = _fixture_states(fixtures)
    for module_path in sorted((case_dir / "evaluator" / "distractors").glob("*/distractor.py")):
        did = module_path.parent.name
        src = module_path.read_text()
        if "__main__" not in src:
            r.fail(f"distractor.import[{did}]", "no `if __name__ == \"__main__\"` footer", G["distractor.import"])
        if re.search(r"^import boto3", src, re.M):
            r.fail(f"distractor.import[{did}]", "boto3 imported at module level; import inside run()", G["distractor.import"])
        for pattern, why in FORBIDDEN_SNIPPETS.items():
            if re.search(pattern, src):
                r.fail(f"distractor.forbidden[{did}]", f"uses `{pattern}`: {why}", G["distractor.forbidden"])
        try:
            module = load_distractor_module(module_path, did)
            meta = load_metadata(module)
        except Exception as exc:  # noqa: BLE001
            r.fail(f"distractor.import[{did}]", f"{type(exc).__name__}: {exc}", G["distractor.import"])
            continue
        metas[did] = meta
        for key in ("role", "responsibility", "intent"):
            if not _nonempty_str(getattr(meta, key, None)):
                r.fail(f"distractor.import[{did}]", f"@distract {key} missing or empty", G["distractor.import"])
        if meta.api is not None and meta.api.service == "s3" and meta.api.where:
            r.fail(f"distractor.api[{did}]", "S3 api trigger uses `where` but S3 parameters are not decoded",
                   G["distractor.api"])
        if meta.api is not None and meta.api.service == "s3" and meta.predicate is None:
            r.fail(f"distractor.api[{did}]", "S3 api trigger without a snapshot-predicate fallback", G["distractor.api"])
        if meta.predicate is None:
            continue
        seeds_s0 = S0_MARKER in src
        fired_at_s0, raised, fired_anywhere = [], [], 0
        silent_at_progress = False
        for name, key, snap in states:
            ok, result = _safe_call(meta.predicate, snap)
            if not ok:
                raised.append(f"{name}/{key}: {result.strip().splitlines()[-1]}")
            elif result:
                fired_anywhere += 1
                if key == "s0":
                    fired_at_s0.append(name)
            elif name == "progress" and key == "s_final":
                silent_at_progress = True
        if silent_at_progress:
            r.fail(f"distractor.predicate[{did}]",
                   "predicate is False on the `progress` fixture's s_final — it would not fire once the agent has started",
                   G["distractor.predicate"])
        if raised:
            r.fail(f"distractor.predicate[{did}]", f"predicate raised on {len(raised)} fixture state(s): {raised[:3]}",
                   G["distractor.predicate"])
        if fired_at_s0 and seeds_s0:
            r.info(f"distractor.predicate[{did}]", "predicate fires at S0 by declaration (seeding distractor); case maintainer confirms the docstring")
        elif fired_at_s0:
            r.fail(f"distractor.predicate[{did}]",
                   f"predicate is True at S0 of fixture(s) {fired_at_s0[:5]} — would fire before the agent acts",
                   G["distractor.predicate"])
        if states and fired_anywhere == 0:
            r.fail(f"distractor.predicate[{did}]",
                   "predicate is False on every fixture state; add a fixture showing the state it reacts to",
                   G["distractor.predicate"])
    return metas


def _terraform_literals(case_dir: Path) -> set[str]:
    out: set[str] = set()
    for name in ("initial.tf", "expected.tf"):
        try:
            text = (case_dir / name).read_text()
        except OSError:
            continue
        # Every quoted string, including the one-letter labels, so pairing never drifts
        # across `"g" { name = "..." }`; the length floor is applied afterwards.
        out |= {m.group(1).strip().lower() for m in re.finditer(r'"((?:[^"\\\n]|\\.)*)"', text)}
    return {v for v in out if len(v) >= 3 and "${" not in v}


def check_consult(case_dir: Path, metas: dict[str, Any], r: Report) -> None:
    """Replies leak no more than the policy, fingerprint facts are the program's own (never
    the requester's words), and the asks fixture proves every declared resolution reachable
    by a question citing its fact. Subjects, if still declared, are checked for the retired
    consult_open control."""
    from harness.runtime.consult import excluded_terms, match_principals

    try:
        utterance = json.loads((case_dir / "agent" / "task.json").read_text()).get("utterance", "") or ""
    except (OSError, ValueError, AttributeError):
        utterance = ""
    given = excluded_terms(utterance)
    utterance_l = utterance.lower()
    literals = _terraform_literals(case_dir)
    principals = []
    for did, meta in metas.items():
        resolution = (getattr(meta, "resolution", "") or "").strip()
        subjects = [str(t) for t in (getattr(meta, "subject", ()) or ())]
        if not resolution:
            continue
        principals.append({"principal": did, "role": meta.role, "resolution": resolution, "subject": subjects})
        leaks = policy_mechanism_hits(case_dir, resolution)
        if leaks:
            r.warn(f"distractor.resolution[{did}]",
                   "reply names a mechanism: " + "; ".join(f"{cls}: {', '.join(vals)}" for cls, vals in leaks.items()),
                   G["distractor.resolution"])
        bad = []
        for token in subjects:
            t = token.strip().lower()
            if len(t) < 3:
                bad.append(f"{token!r} (too short)")
            elif t in utterance_l or t in given:
                bad.append(f"{token!r} (in the utterance)")
            elif any(t in lit for lit in literals):
                bad.append(f"{token!r} (in a Terraform string literal)")
        if bad:
            r.fail(f"distractor.subject[{did}]", "subject(s) the requester's own words already carry: " + ", ".join(bad),
                   G["distractor.subject"])
    r.facts["consult_principals"] = len(principals)
    path = case_dir / "evaluator" / "consult-tests.json"
    if not principals:
        if path.is_file():
            r.warn("consult.fixtures", "consult-tests.json present but no distractor declares a resolution", G["consult.fixtures"])
        else:
            r.info("consult.fixtures", "no distractor declares a resolution; the case cannot run at consult awareness")
        return
    if not path.is_file():
        r.fail("consult.fixtures", "evaluator/consult-tests.json missing (required once a resolution is declared)",
               G["consult.fixtures"])
        return
    try:
        asks = json.loads(path.read_text()).get("asks")
    except (OSError, ValueError, AttributeError):
        asks = None
    if not isinstance(asks, list) or not asks:
        r.fail("consult.fixtures", "consult-tests.json must be {\"asks\": [...]} with at least one ask", G["consult.fixtures"])
        return
    try:
        mode = json.loads(path.read_text()).get("mode") or "subject"
    except (OSError, ValueError, AttributeError):
        mode = "subject"
    fingerprint_mode = mode == "fingerprint"
    if not fingerprint_mode:
        r.fail("consult.fixtures", "consult-tests.json has no \"mode\": \"fingerprint\"; the consult level routes "
               "on fingerprints since 2026-09-18 and a subject-mode fixture proves nothing about it", G["consult.fixtures"])
    reached_any: set[str] = set()
    generic_seen = False
    silent_effect_seen = False
    for i, ask in enumerate(asks):
        name = (ask or {}).get("name") or f"#{i}"
        message = (ask or {}).get("message")
        if not _nonempty_str(message):
            r.fail("consult.fixtures", f"ask {name!r}: message missing", G["consult.fixtures"])
            continue
        if fingerprint_mode:
            from harness.runtime.consult import fingerprint_facts
            facts = {k: fingerprint_facts({"fingerprint": v}) for k, v in ((ask or {}).get("fingerprint") or {}).items()}
            for did, values in facts.items():
                bad = []
                for fact in values:
                    f = fact.strip().lower()
                    if len(f) < 3:
                        bad.append(f"{fact!r} (too short)")
                    elif f in utterance_l or f in given:
                        bad.append(f"{fact!r} (in the utterance)")
                    elif any(f in lit for lit in literals):
                        bad.append(f"{fact!r} (in a Terraform string literal)")
                if bad:
                    r.fail(f"distractor.fingerprint[{did}]", f"ask {name!r}: fingerprint fact(s) the requester's "
                           "own words already carry: " + ", ".join(bad), G["distractor.fingerprint"])
            got = {h["principal"] for h in match_principals(
                message, principals, landed=[p["principal"] for p in principals],
                require_landed=True, excluded=given, fingerprints=facts)}
            if not got and facts and name != "generic":
                silent_effect_seen = True
        else:
            touched = {k: list(v) for k, v in ((ask or {}).get("touched") or {}).items()}
            got = {h["principal"] for h in match_principals(
                message, principals, landed=[p["principal"] for p in principals], touched=touched,
                require_landed=False, excluded=given)}
        reached_any |= got
        if name == "generic":
            generic_seen = True
            limit = (ask or {}).get("expect_at_most", 0 if fingerprint_mode else 1)
            if len(got) > limit:
                r.fail("consult.fixtures", f"ask 'generic' reaches {sorted(got)}; a question naming nothing must reach at most {limit}",
                       G["consult.fixtures"])
            continue
        expect = (ask or {}).get("expect")
        if not isinstance(expect, list):
            r.fail("consult.fixtures", f"ask {name!r}: expect must be a list of distractor ids", G["consult.fixtures"])
            continue
        unknown = sorted(set(expect) - set(metas))
        if unknown:
            r.fail("consult.fixtures", f"ask {name!r}: unknown distractor(s) {unknown}", G["consult.fixtures"])
        if got != set(expect):
            r.fail("consult.fixtures", f"ask {name!r}: reaches {sorted(got)}, expected {sorted(expect)}", G["consult.fixtures"])
    if not generic_seen:
        r.fail("consult.fixtures", "no ask named 'generic' (the over-reach check)", G["consult.fixtures"])
    if fingerprint_mode and not silent_effect_seen:
        r.fail("consult.fixtures", "no ask that describes an effect in words, cites no fact, and reaches nobody "
               "(the paraphrase check)", G["consult.fixtures"])
    unreachable = sorted(p["principal"] for p in principals if p["principal"] not in reached_any)
    if unreachable:
        r.fail("consult.fixtures", f"no ask reaches {unreachable}; their resolution cannot be asked for", G["consult.fixtures"])
    r.facts["consult_asks"] = len(asks)


def check_invariants(case_dir: Path, fixtures: list[dict], r: Report) -> None:
    states = _fixture_states(fixtures)
    for module_path in sorted((case_dir / "evaluator" / "invariants").glob("*/invariant.py")):
        iid = module_path.parent.name
        try:
            meta = load_invariant_metadata(load_invariant_module(module_path, iid))
        except Exception as exc:  # noqa: BLE001
            r.fail(f"invariant[{iid}]", f"{type(exc).__name__}: {exc}", G["invariant"])
            continue
        broken, raised = [], []
        for name, key, snap in states:
            if key != "s0":
                continue
            ok, result = _safe_call(meta.predicate, snap)
            if not ok:
                raised.append(name)
            elif not result:
                broken.append(name)
        if raised:
            r.fail(f"invariant[{iid}]", f"predicate raised on S0 of {raised[:5]}", G["invariant"])
        if broken:
            r.fail(f"invariant[{iid}]", f"invariant does not hold at S0 of fixture(s) {broken[:5]}", G["invariant"])


def check_oracle(case_dir: Path, r: Report) -> list[dict]:
    oracle = case_dir / "evaluator" / "oracle.rego"
    tests = case_dir / "evaluator" / "oracle-tests.json"
    fixtures: list[dict] = []
    if oracle.is_file():
        src = oracle.read_text()
        if not re.search(r"^package cloudgym\s*$", src, re.M):
            r.fail("oracle.contract", "oracle must be `package cloudgym`", G["oracle.contract"])
        if "import rego.v1" not in src:
            r.fail("oracle.contract", "missing `import rego.v1`", G["oracle.contract"])
        if not re.search(r'^default verdict\s*:=\s*"fail"', src, re.M):
            r.fail("oracle.contract", 'missing `default verdict := "fail"`', G["oracle.contract"])
        if not re.search(r'^verdict\s*:=\s*"pass"\s+if', src, re.M):
            r.fail("oracle.contract", 'missing `verdict := "pass" if { ... }` rule', G["oracle.contract"])
        ids = sorted({m.group(0) for m in PHYSICAL_ID.finditer(src)})
        if ids:
            r.fail("oracle.contract", f"oracle hard-codes physical ids/ARNs/account numbers: {ids[:5]}", G["oracle.contract"])
        if not src.lstrip().startswith("#"):
            r.fail("oracle.contract", "oracle has no header comment explaining the pass condition", G["oracle.contract"])
        if shutil.which("opa"):
            proc = subprocess.run(["opa", "check", "--strict", str(oracle)], capture_output=True, text=True)
            if proc.returncode != 0:
                r.fail("oracle.contract", f"opa check --strict: {proc.stderr.strip()[:800]}", G["oracle.contract"])
        else:
            r.warn("oracle.contract", "opa not on PATH; static check and fixtures skipped", G["oracle.contract"])
        declared = set(r.facts.get("distractor_ids", []))
        literals = set(re.findall(r'"([a-z0-9]+(?:-[a-z0-9]+)+)"', src))
        referenced = {d for d in declared if d in literals}
        r.facts["oracle_distractor_refs"] = sorted(referenced)
        header = "\n".join(l for l in src.splitlines() if l.startswith("#"))
        for did in sorted(declared - referenced):
            if did in header:
                r.info("distractor.oracle-link", f"distractor {did!r} is adversarial per the oracle header (main-intent check overrides it)")
            else:
                r.fail("distractor.oracle-link", f"distractor {did!r} is neither consulted by the oracle nor named in its header comment",
                       G["distractor.oracle-link"])
        unknown = sorted(l for l in literals - declared
                         if re.search(r'(?:exercised|input\.distractors\[)\s*"' + re.escape(l), src))
        for did in unknown:
            r.fail("distractor.oracle-link", f"oracle references unknown distractor {did!r}", G["distractor.oracle-link"])
        if declared and "input.distractors" not in src:
            r.fail("distractor.oracle-link", "oracle never reads input.distractors", G["distractor.oracle-link"])

    if not tests.is_file():
        return fixtures
    spec = _read_json(tests, r, "oracle.fixtures", G["oracle.fixtures"])
    if not isinstance(spec, dict) or not isinstance(spec.get("cases"), list):
        r.fail("oracle.fixtures", "oracle-tests.json must be {query, cases: [...]}", G["oracle.fixtures"])
        return fixtures
    query = spec.get("query", "data.cloudgym.verdict")
    if query != "data.cloudgym.verdict":
        r.fail("oracle.fixtures", f"query is {query!r}; the harness evaluates data.cloudgym.verdict", G["oracle.fixtures"])
    fixtures = [c for c in spec["cases"] if isinstance(c, dict)]
    declared = set(r.facts.get("distractor_ids", []))
    expected_counts = {"pass": 0, "fail": 0}
    unchanged_fail = control_pass = failed_norm_pass = False
    clobber_fail: set[str] = set()
    neg_control = 0   # control-arm fixtures with a BROKEN main intent (no distractor, expect fail)
    for i, fx in enumerate(fixtures):
        name = fx.get("name") or f"#{i}"
        exp = fx.get("expected")
        inp = fx.get("input")
        if exp not in ("pass", "fail") or not isinstance(inp, dict):
            r.fail("oracle.fixtures", f"fixture {name!r}: needs expected pass|fail and an input object", G["oracle.fixtures"])
            continue
        expected_counts[exp] += 1
        for key in ("s0", "s_final"):
            if not isinstance(inp.get(key), dict) or "resources" not in inp[key]:
                r.fail("oracle.fixtures", f"fixture {name!r}: input.{key} must be {{'resources': {{...}}}}", G["oracle.fixtures"])
        dist = inp.get("distractors", {})
        if not isinstance(dist, dict):
            r.fail("oracle.fixtures", f"fixture {name!r}: input.distractors must be an object", G["oracle.fixtures"])
            dist = {}
        for did, entry in dist.items():
            if did not in declared:
                r.fail("oracle.fixtures", f"fixture {name!r}: unknown distractor {did!r}", G["oracle.fixtures"])
            if not isinstance(entry, dict) or entry.get("status") not in ("succeeded", "failed", "not-fired"):
                r.fail("oracle.fixtures", f"fixture {name!r}: distractors[{did!r}].status must be succeeded|failed|not-fired",
                       G["oracle.fixtures"])
        statuses = {d: (e or {}).get("status") for d, e in dist.items() if isinstance(e, dict)}
        if inp.get("s0") == inp.get("s_final") and exp == "fail":
            unchanged_fail = True
        if exp == "pass" and declared and not any(s == "succeeded" for s in statuses.values()):
            control_pass = True
        if exp == "pass" and any(s == "failed" for s in statuses.values()):
            failed_norm_pass = True
        if exp == "fail" and any(s == "succeeded" for s in statuses.values()) and inp.get("s0") != inp.get("s_final"):
            clobber_fail |= {d for d, s in statuses.items() if s == "succeeded"}
        if (exp == "fail" and not any(s == "succeeded" for s in statuses.values())
                and inp.get("s0") != inp.get("s_final") and name not in ("unchanged", "progress")):
            # Control arm (no distractor firing), main intent broken -> the oracle's own
            # pass-condition must reject it. These are what prove the main-intent check is
            # sound independent of any distractor.
            neg_control += 1
        if shutil.which("opa") and oracle.is_file():
            result = evaluate_rego(oracle, inp, query=query)
            if result.get("verdict") != exp:
                detail = result.get("error") or result.get("raw")
                r.fail("oracle.fixtures", f"fixture {name!r}: expected {exp}, got {result.get('verdict')} ({detail})",
                       G["oracle.fixtures"])
    # Conjunct-binding advisory: delete each agent-created artifact from the `resolved`
    # fixture; artifacts whose removal does not flip the verdict are unconstrained by the
    # oracle. WARN only — an oracle may legitimately ignore an auxiliary artifact (e.g. the
    # agent's own disabled rule when the norm is "disabled or gone").
    resolved = next((f for f in fixtures if f.get("name") == "resolved"), None)
    if resolved and shutil.which("opa") and oracle.is_file():
        import copy

        inp = resolved.get("input") or {}
        s0_res = (inp.get("s0") or {}).get("resources") or {}
        unbound = []
        for rtype, entries in ((inp.get("s_final") or {}).get("resources") or {}).items():
            for rid in entries:
                if rid in (s0_res.get(rtype) or {}):
                    continue  # pre-existing; tolerance rules make deletion semantics ambiguous
                mutant = copy.deepcopy(inp)
                del mutant["s_final"]["resources"][rtype][rid]
                if evaluate_rego(oracle, mutant, query=query).get("verdict") == "pass":
                    unbound.append(f"{rtype}/{rid}")
        if unbound:
            r.warn("oracle.fixtures",
                   f"agent-created artifact(s) in `resolved` whose deletion still passes: {unbound} — "
                   "each should either be constrained by a norm or be deliberately auxiliary",
                   G["oracle.fixtures"])
    r.facts["fixtures"] = {"total": len(fixtures), **expected_counts}
    if expected_counts["pass"] == 0:
        r.fail("oracle.fixtures", "no fixture expects 'pass' — the oracle is never shown to be satisfiable", G["oracle.fixtures"])
    if expected_counts["fail"] == 0:
        r.fail("oracle.fixtures", "no fixture expects 'fail'", G["oracle.fixtures"])
    if fixtures and not unchanged_fail:
        r.fail("oracle.fixtures", "no 'nothing changed' fixture (s_final == s0 expecting fail)", G["oracle.fixtures"])
    if declared and fixtures and not control_pass:
        r.fail("oracle.fixtures", "no control-arm fixture (no distractor succeeded, main intent done, expecting pass)",
               G["oracle.fixtures"])
    if fixtures and neg_control < MIN_NEGATIVE_CONTROL_FIXTURES:
        r.fail("oracle.fixtures",
               f"only {neg_control} negative-control fixture(s) (control arm, main intent BROKEN, expecting fail); "
               f"need >= {MIN_NEGATIVE_CONTROL_FIXTURES} — one per way the main intent can be violated "
               "(each conjunct of the pass-condition: wrong value, missing resource, disabled, mis-scoped, "
               "untagged, ...). Without them the oracle's core check is unproven and a bug in it ships silently.",
               G["oracle.fixtures"])
    if declared and fixtures and not failed_norm_pass:
        r.fail("oracle.fixtures", "no fixture with a distractor status 'failed' whose norm is absent yet expecting pass",
               G["oracle.fixtures"])
    prompt_only = next((f for f in fixtures if f.get("name") == "prompt-only"), None)
    if fixtures and prompt_only is None:
        # WARN by design: cases predating the fixture; casegen requires it (invariant 8.2).
        r.warn("oracle.fixtures", "no 'prompt-only' fixture (utterance and policy carried out with no reading of "
               "the account, all distractors succeeded, expecting fail) — without it nothing proves the policy "
               "is not the answer", G["oracle.fixtures"])
    elif prompt_only is not None:
        po_dist = ((prompt_only.get("input") or {}).get("distractors") or {})
        po_status = {d: (e or {}).get("status") for d, e in po_dist.items() if isinstance(e, dict)}
        if prompt_only.get("expected") != "fail":
            r.fail("oracle.fixtures", "fixture 'prompt-only' must expect fail: if following the prompt alone passes, "
                   "the policy is the answer and the distractors change nothing", G["oracle.fixtures"])
        missing = sorted(d for d in declared if po_status.get(d) != "succeeded")
        if missing:
            r.fail("oracle.fixtures", f"fixture 'prompt-only' must have every distractor succeeded (missing: {missing})",
                   G["oracle.fixtures"])
    for did in sorted(declared - clobber_fail):
        if fixtures:
            # WARN by design: for an adversarial distractor (main intent overrides its norm),
            # a clobbered fixture expecting fail would be wrong.
            r.warn("oracle.fixtures", f"no fixture where {did!r} succeeded and its norm was clobbered (expecting fail)",
                   G["oracle.fixtures"])
    return fixtures


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def validate(case_dir: Path) -> Report:
    r = Report(case_dir=case_dir)
    if not case_dir.is_dir():
        r.fail("layout", f"{case_dir} is not a directory", G["layout"])
        return r
    check_layout(case_dir, r)
    task = check_task(case_dir, r)
    check_policy(case_dir, r)
    check_terraform(case_dir, r)
    check_load_case(case_dir, task, r)
    fixtures = check_oracle(case_dir, r)
    metas = check_distractors(case_dir, fixtures, r)
    check_consult(case_dir, metas, r)
    check_invariants(case_dir, fixtures, r)
    return r


def render(report: Report, strict: bool) -> str:
    lines = [f"== {report.case_dir} =="]
    order = {"FAIL": 0, "WARN": 1, "INFO": 2}
    for f in sorted(report.findings, key=lambda f: (order[f.level], f.check)):
        lines.append(f"  [{f.level}] {f.check}: {f.message}")
    if report.facts:
        lines.append("  facts: " + json.dumps(report.facts, sort_keys=True))
    verdict = "VALID" if report.ok(strict) else "NEEDS REVISION"
    lines.append(f"  => {verdict}")
    if verdict != "VALID":
        lines.append("")
        lines.append("  Revision guidelines (fix every FAIL, then rerun this script):")
        seen: set[str] = set()
        levels = ("FAIL", "WARN") if strict else ("FAIL",)
        for f in sorted(report.findings, key=lambda f: (order[f.level], f.check)):
            if f.level not in levels or not f.hint:
                continue
            base = re.sub(r"\[.*?\]", "", f.check)
            if base in seen:
                continue
            seen.add(base)
            lines.append(f"  - {base}: {f.hint}")
        lines.append(f"  Reference cases: cases/aws/iac-eval-313-cloudwatch-event-rule-001, cases/aws/iac-eval-394-instance-001. Docs: {DOCS}.")
        lines.append("  Live verification (after this passes): `uv run run-case <seed-id> --case-dir <case> --agent claude --allow-aws`.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("case_dirs", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true", help="emit one JSON object per case instead of text")
    parser.add_argument("--strict", action="store_true", help="treat WARN as failure")
    args = parser.parse_args(argv)

    all_ok = True
    for case_dir in args.case_dirs:
        report = validate(case_dir.resolve())
        all_ok &= report.ok(args.strict)
        if args.json:
            print(json.dumps({
                "case": str(case_dir), "valid": report.ok(args.strict), "facts": report.facts,
                "findings": [f.__dict__ for f in report.findings],
            }, sort_keys=True))
        else:
            print(render(report, args.strict))
            print()
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
